"""Threat detectors.

Each detector inspects the capture and returns zero or more :class:`Finding`
objects. Detectors that are naturally set-based run SQL against the views in
:mod:`netsec_analyzer.database`; detectors that need numerical analysis
(Shannon entropy, beacon-interval statistics, volume outliers) use pandas and
numpy. Findings are mapped to MITRE ATT&CK techniques and carry an evidence
table plus a concrete remediation.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from collections import Counter
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Ports whose repeated connection attempts usually mean credential brute force.
AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL",
              1433: "MSSQL", 5432: "PostgreSQL", 5900: "VNC", 445: "SMB"}
# Application protocols that transmit credentials/content without encryption.
CLEARTEXT_PROTOS = {"FTP", "TELNET", "HTTP", "IMAP", "POP", "SMTP"}


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    mitre: str
    description: str
    recommendation: str
    metrics: dict = field(default_factory=dict)
    evidence: pd.DataFrame = field(default_factory=pd.DataFrame)

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


def shannon_entropy(text: str | None) -> float:
    """Shannon entropy (bits/byte) of a string - high for encoded/random data."""
    if not text:
        return 0.0
    arr = np.frombuffer(str(text).encode("utf-8", "ignore"), dtype=np.uint8)
    if arr.size == 0:
        return 0.0
    counts = np.bincount(arr)
    probs = counts[counts > 0] / arr.size
    return float(-(probs * np.log2(probs)).sum())


def is_internal(ip: str | None) -> bool:
    """True for RFC1918/loopback/link-local addresses (i.e. inside the LAN)."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def registered_domain(name: str | None) -> str:
    """Best-effort second-level domain (e.g. a.b.evil.com -> evil.com)."""
    if not name:
        return ""
    parts = str(name).rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else parts[-1]

def detect_port_scan(conn: sqlite3.Connection, min_ports: int = 100) -> list[Finding]:
    """Reconnaissance: one source sending SYNs to an unusual number of ports."""
    df = pd.read_sql_query(
        "SELECT src_ip, distinct_ports, distinct_hosts, "
        "COALESCE(syn_only, 0) AS syn_only, packets "
        "FROM port_activity "
        "WHERE distinct_ports >= ? AND COALESCE(syn_only,0) >= ? * 0.5 "
        "ORDER BY distinct_ports DESC",
        conn, params=(min_ports, min_ports),
    )
    findings: list[Finding] = []
    for r in df.itertuples(index=False):
        vertical = r.distinct_hosts <= 2  # many ports, few hosts => vertical scan
        kind = "vertical (many ports, one host)" if vertical else \
               "mixed (many ports, many hosts)"
        findings.append(Finding(
            id=f"portscan-{r.src_ip}",
            title=f"Port scan from {r.src_ip}",
            category="Reconnaissance",
            severity="High",
            mitre="T1046 - Network Service Discovery",
            description=(
                f"{r.src_ip} sent {r.syn_only} SYN-only probes covering "
                f"{r.distinct_ports} distinct ports across {r.distinct_hosts} "
                f"host(s) - a {kind} scan."
            ),
            recommendation=(
                "Block/quarantine the source, confirm it is authorised, and "
                "rate-limit inbound SYNs at the firewall. If internal, treat as "
                "a possibly compromised host performing discovery."
            ),
            metrics={"syn_only": int(r.syn_only), "distinct_ports": int(r.distinct_ports),
                     "distinct_hosts": int(r.distinct_hosts)},
            evidence=df[df.src_ip == r.src_ip].reset_index(drop=True),
        ))
    return findings


def _window_bounds(times: np.ndarray, window_s: float):
    """Inclusive rolling windows; bursts may cross arbitrary clock boundaries."""
    left = 0
    for right, timestamp in enumerate(times):
        while timestamp - times[left] > window_s:
            left += 1
        yield left, right + 1


def detect_service_sweep(df: pd.DataFrame, min_hosts: int = 20,
                         window_s: float = 60.0) -> list[Finding]:
    """One source probes one TCP service across many hosts in a short window."""
    if min_hosts < 2 or not np.isfinite(window_s) or window_s <= 0:
        raise ValueError("min_hosts must be >= 2 and window_s must be positive")
    probes = df[(df["transport"] == "TCP") & (df["tcp_syn"] == 1)
                & (df["tcp_ack"] == 0)].dropna(
                    subset=["src_ip", "dst_ip", "dst_port", "ts"])
    probes = probes[np.isfinite(probes["ts"])].sort_values("ts", kind="stable")
    findings = []
    for (src, port), group in probes.groupby(["src_ip", "dst_port"], sort=True):
        if group["dst_ip"].nunique() < min_hosts:
            continue
        targets = group["dst_ip"].tolist()
        counts = Counter()
        previous_left = 0
        best = None
        peak_hosts = min_hosts - 1
        for left, end in _window_bounds(group["ts"].to_numpy(), window_s):
            counts[targets[end - 1]] += 1
            while previous_left < left:
                host = targets[previous_left]
                counts[host] -= 1
                if counts[host] == 0:
                    del counts[host]
                previous_left += 1
            if len(counts) > peak_hosts:
                peak_hosts = len(counts)
                best = (left, end)
        if best is None:
            continue
        burst = group.iloc[best[0]:best[1]]
        service = AUTH_PORTS.get(int(port), f"TCP/{int(port)}")
        evidence = burst.groupby("dst_ip", sort=True).agg(
            syn_packets=("ts", "size"), first_ts=("ts", "min"),
            last_ts=("ts", "max")).reset_index()
        findings.append(Finding(
            id=f"sweep-{src}-{int(port)}",
            title=f"Possible {service} service sweep from {src}",
            category="Reconnaissance", severity="High",
            mitre="T1046 - Network Service Discovery",
            description=(
                f"{src} sent {len(burst)} SYN-only packets to port {int(port)} "
                f"on {peak_hosts} distinct hosts within {window_s:g} seconds. "
                "This is consistent with horizontal service discovery, which "
                "can precede lateral movement. SYNs do not prove successful "
                "connections or exploitation; authorised scanners can look similar."
            ),
            recommendation=(
                "Check whether the source is an approved scanner or management "
                "host. Correlate unexpected activity with endpoint and login "
                "logs. Restrict SMB/RDP and other administration services to "
                "approved hosts and review network segmentation."
            ),
            metrics={"distinct_hosts": peak_hosts, "syn_packets": len(burst),
                     "dst_port": int(port), "service": service,
                     "window_s": window_s,
                     "first_ts": float(burst["ts"].iloc[0]),
                     "last_ts": float(burst["ts"].iloc[-1])},
            evidence=evidence,
        ))
    return findings


def detect_dns_failures(df: pd.DataFrame, min_failures: int = 30,
                        min_failure_ratio: float = 0.5,
                        window_s: float = 300.0) -> list[Finding]:
    """DNS availability: bursts of NXDOMAIN, SERVFAIL or REFUSED per client."""
    if (min_failures < 1 or not 0 < min_failure_ratio <= 1
            or not np.isfinite(window_s) or window_s <= 0):
        raise ValueError("Invalid DNS failure threshold or window")
    responses = df[(df["dns_response"] == 1)
                   & (df["protocol"].str.upper() == "DNS")].dropna(
                       subset=["dst_ip", "src_ip", "ts", "dns_rcode"])
    responses = responses[np.isfinite(responses["ts"])].sort_values("ts", kind="stable")
    findings = []
    for client, group in responses.groupby("dst_ip", sort=True):
        failed = group["dns_rcode"].isin([2, 3, 5]).to_numpy(dtype=int)
        cumulative = np.concatenate(([0], np.cumsum(failed)))
        best = None
        peak_failures = min_failures - 1
        for left, end in _window_bounds(group["ts"].to_numpy(), window_s):
            failures = int(cumulative[end] - cumulative[left])
            if failures > peak_failures and failures / (end - left) >= min_failure_ratio:
                peak_failures = failures
                best = (left, end)
        if best is None:
            continue
        burst = group.iloc[best[0]:best[1]]
        errors = burst[burst["dns_rcode"].isin([2, 3, 5])]
        codes = errors["dns_rcode"].value_counts()
        ratio = len(errors) / len(burst)
        evidence = errors[["frame_no", "ts", "src_ip", "dst_ip", "dns_qry_name",
                           "dns_rcode"]].copy()
        evidence["response"] = evidence["dns_rcode"].map(
            {2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"})
        findings.append(Finding(
            id=f"dnsfail-{client}",
            title=f"DNS lookup failure burst for {client}",
            category="Network Reliability", severity="Medium",
            mitre="Not applicable - operational DNS signal",
            description=(
                f"{len(errors)} of {len(burst)} observed DNS responses to {client} "
                f"failed ({ratio:.0%}) within {window_s:g} seconds: "
                f"{int(codes.get(3, 0))} NXDOMAIN, {int(codes.get(2, 0))} SERVFAIL, "
                f"{int(codes.get(5, 0))} REFUSED. This may explain application "
                "connectivity failures. NXDOMAIN bursts can also accompany "
                "domain-generation malware, but failures alone do not prove it. "
                "The rate is based on captured responses, not all client lookups."
            ),
            recommendation=(
                "For SERVFAIL, inspect resolver health, upstream reachability "
                "and DNSSEC validation. For REFUSED, review resolver access "
                "policy. For NXDOMAIN, check application names, search suffixes "
                "and filtering policy; investigate diverse random-looking "
                "names using endpoint process logs before treating them as malware. "
                "A resolver-side capture may attribute downstream clients to a forwarder."
            ),
            metrics={"failed_responses": len(errors), "responses": len(burst),
                     "failure_ratio": round(ratio, 3),
                     "nxdomain": int(codes.get(3, 0)),
                     "servfail": int(codes.get(2, 0)),
                     "refused": int(codes.get(5, 0)),
                     "unique_failed_names": int(errors["dns_qry_name"].nunique()),
                     "resolvers": int(burst["src_ip"].nunique()),
                     "window_s": window_s,
                     "first_ts": float(burst["ts"].iloc[0]),
                     "last_ts": float(burst["ts"].iloc[-1])},
            evidence=evidence.reset_index(drop=True),
        ))
    return findings


def detect_syn_flood(conn: sqlite3.Connection, min_syns: int = 200,
                     min_rate: float = 20.0) -> list[Finding]:
    """DoS: a flood of SYNs to one service from many (often spoofed) sources."""
    df = pd.read_sql_query(
        """
        SELECT dst_ip, dst_port,
               COUNT(*)                    AS syns,
               COUNT(DISTINCT src_ip)      AS sources,
               MAX(ts) - MIN(ts)           AS duration_s
        FROM packets
        WHERE transport='TCP' AND tcp_syn=1 AND tcp_ack=0 AND dst_ip IS NOT NULL
        GROUP BY dst_ip, dst_port
        HAVING syns >= ?
        ORDER BY syns DESC
        """,
        conn, params=(min_syns,),
    )
    findings: list[Finding] = []
    for r in df.itertuples(index=False):
        rate = r.syns / r.duration_s if r.duration_s else float(r.syns)
        # High rate AND many distinct sources distinguishes a flood from a scan.
        if rate < min_rate or r.sources < 50:
            continue
        findings.append(Finding(
            id=f"synflood-{r.dst_ip}-{r.dst_port}",
            title=f"SYN flood against {r.dst_ip}:{r.dst_port}",
            category="Denial of Service",
            severity="High",
            mitre="T1499.002 - Endpoint DoS: Service Exhaustion Flood",
            description=(
                f"{r.syns} SYNs from {r.sources} distinct sources hit "
                f"{r.dst_ip}:{r.dst_port} at ~{rate:.0f} SYN/s, consistent with a "
                f"half-open connection (SYN) flood."
            ),
            recommendation=(
                "Enable SYN cookies, lower the half-open backlog timeout, and "
                "deploy upstream rate-limiting/scrubbing. Many distinct sources "
                "suggest spoofed or distributed origins."
            ),
            metrics={"syns": int(r.syns), "sources": int(r.sources),
                     "syn_per_sec": round(rate, 1)},
            evidence=df[df.dst_ip == r.dst_ip].reset_index(drop=True),
        ))
    return findings

def detect_arp_spoofing(df: pd.DataFrame) -> list[Finding]:
    """MITM: a single IP advertised at two or more different MAC addresses."""
    arp = df[(df["transport"] == "ARP") & df["arp_src_ip"].notna()
             & df["arp_src_mac"].notna()]
    if arp.empty:
        return []
    grp = arp.groupby("arp_src_ip")["arp_src_mac"].agg(
        macs=lambda s: sorted(set(s)), replies="size")
    conflicted = grp[grp["macs"].map(len) > 1]
    findings: list[Finding] = []
    for ip, row in conflicted.iterrows():
        ev = (arp[arp["arp_src_ip"] == ip]
              .groupby("arp_src_mac").size().reset_index(name="arp_replies"))
        findings.append(Finding(
            id=f"arpspoof-{ip}",
            title=f"ARP spoofing / IP conflict for {ip}",
            category="Man-in-the-Middle",
            severity="Critical",
            mitre="T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning",
            description=(
                f"IP {ip} was claimed by {len(row['macs'])} different MAC "
                f"addresses ({', '.join(row['macs'])}). This is the classic "
                f"signature of ARP cache poisoning used to intercept traffic."
            ),
            recommendation=(
                "Identify the rogue MAC's switch port and disable it. Enable "
                "Dynamic ARP Inspection (DAI) with DHCP snooping, and pin the "
                "gateway's MAC via static ARP on critical hosts."
            ),
            metrics={"claimed_macs": len(row["macs"]), "arp_replies": int(row["replies"])},
            evidence=ev,
        ))
    return findings


def detect_dns_tunneling(df: pd.DataFrame, min_queries: int = 40) -> list[Finding]:
    """Exfil/C2: long, high-entropy DNS queries concentrated on one domain."""
    dns = df[(df["protocol"].str.upper() == "DNS") & (df["dns_response"] == 0)
             & df["dns_qry_name"].notna()].copy()
    if dns.empty:
        return []
    dns["qlen"] = dns["dns_qry_name"].str.len()
    dns["entropy"] = dns["dns_qry_name"].map(shannon_entropy)
    dns["sld"] = dns["dns_qry_name"].map(registered_domain)
    dns["is_txt"] = (dns["dns_qry_type"] == 16).astype(int)
    grp = dns.groupby("sld").agg(
        queries=("dns_qry_name", "size"),
        unique_names=("dns_qry_name", "nunique"),
        mean_len=("qlen", "mean"),
        max_len=("qlen", "max"),
        mean_entropy=("entropy", "mean"),
        txt_frac=("is_txt", "mean"),
    ).reset_index()
    # Suspicious = high volume + long names + high entropy (encoded payloads).
    suspects = grp[(grp["queries"] >= min_queries) & (grp["mean_len"] >= 35)
                   & (grp["mean_entropy"] >= 3.5)]
    findings: list[Finding] = []
    for r in suspects.itertuples(index=False):
        findings.append(Finding(
            id=f"dnstunnel-{r.sld}",
            title=f"Possible DNS tunnelling to {r.sld}",
            category="Exfiltration / C2",
            severity="High",
            mitre="T1071.004 - Application Layer Protocol: DNS",
            description=(
                f"{r.queries} queries to *.{r.sld} with {r.unique_names} unique "
                f"names, mean length {r.mean_len:.0f} chars, mean entropy "
                f"{r.mean_entropy:.2f} bits/char, {r.txt_frac*100:.0f}% TXT. "
                f"High-entropy random subdomains are a hallmark of DNS tunnelling."
            ),
            recommendation=(
                "Block the domain, inspect the querying host for malware, and "
                "route DNS through a resolver that flags long/random names and "
                "high per-domain query volume."
            ),
            metrics={"queries": int(r.queries), "unique_names": int(r.unique_names),
                     "mean_len": round(r.mean_len, 1),
                     "mean_entropy": round(r.mean_entropy, 2)},
            evidence=dns[dns["sld"] == r.sld][["ts", "src_ip", "dns_qry_name",
                        "qlen", "entropy"]].head(8).reset_index(drop=True),
        ))
    return findings

def _session_starts(ts: np.ndarray, gap: float = 5.0) -> np.ndarray:
    """Collapse a sorted timestamp array into session start times."""
    if ts.size == 0:
        return ts
    breaks = np.diff(ts) > gap
    keep = np.concatenate(([True], breaks))
    return ts[keep]


def detect_beaconing(df: pd.DataFrame, min_events: int = 6,
                     max_cv: float = 0.15) -> list[Finding]:
    """C2: a host that calls out to the same peer at very regular intervals."""
    tcp = df[df["transport"].isin(["TCP", "UDP"]) & df["src_ip"].notna()
             & df["dst_ip"].notna()]
    # Collect qualifying flows keyed by the unordered pair so a beacon and its
    # reply are reported once, in the internal -> external direction.
    candidates: dict[frozenset, dict] = {}
    for (src, dst), grp in tcp.groupby(["src_ip", "dst_ip"], sort=False):
        ts = np.sort(grp["ts"].to_numpy(dtype=float))
        starts = _session_starts(ts)
        if starts.size < min_events:
            continue
        intervals = np.diff(starts)
        mean = float(intervals.mean())
        if mean <= 0:
            continue
        cv = float(intervals.std(ddof=0) / mean)  # coefficient of variation
        if not (cv <= max_cv and 1.0 <= mean <= 3600.0):
            continue
        cand = {"src": src, "dst": dst, "starts": starts, "intervals": intervals,
                "mean": mean, "cv": cv}
        key = frozenset((src, dst))
        prev = candidates.get(key)
        prefers = is_internal(src) and not is_internal(dst)
        if prev is None or (prefers and not (is_internal(prev["src"])
                                             and not is_internal(prev["dst"]))):
            candidates[key] = cand

    findings: list[Finding] = []
    for c in candidates.values():
        src, dst, starts = c["src"], c["dst"], c["starts"]
        mean, cv, intervals = c["mean"], c["cv"], c["intervals"]
        findings.append(Finding(
            id=f"beacon-{src}-{dst}",
            title=f"C2 beaconing {src} -> {dst}",
            category="Command and Control",
            severity="High",
            mitre="T1071 - Application Layer Protocol (beaconing)",
            description=(
                f"{src} contacted {dst} {starts.size} times with a near-"
                f"constant interval of {mean:.1f}s (jitter CV={cv:.03f}). "
                f"Regular low-jitter callbacks are typical of C2 beacons."
            ),
            recommendation=(
                "Isolate the source host and inspect it for implants. Block "
                f"the destination {dst} and hunt for the same cadence to "
                "other external IPs."
            ),
            metrics={"events": int(starts.size), "interval_s": round(mean, 1),
                     "cv": round(cv, 3), "external_dst": not is_internal(dst)},
            evidence=pd.DataFrame({"session_start_ts": starts,
                                   "interval_s": np.concatenate(([np.nan], intervals))}).head(10),
        ))
    return findings


def detect_data_exfiltration(conn: sqlite3.Connection,
                             min_bytes: int = 300_000,
                             min_ratio: float = 5.0) -> list[Finding]:
    """Exfiltration: large, strongly outbound-skewed transfer to an external IP."""
    convs = pd.read_sql_query(
        "SELECT src_ip, dst_ip, bytes, packets FROM conversations "
        "WHERE transport='TCP'", conn)
    if convs.empty:
        return []
    byte_map = {(r.src_ip, r.dst_ip): r.bytes for r in convs.itertuples(index=False)}
    findings: list[Finding] = []
    for r in convs.sort_values("bytes", ascending=False).itertuples(index=False):
        if not (is_internal(r.src_ip) and not is_internal(r.dst_ip)):
            continue
        if r.bytes < min_bytes:
            continue
        back = byte_map.get((r.dst_ip, r.src_ip), 0) or 0
        ratio = r.bytes / max(back, 1)
        if ratio < min_ratio:
            continue
        findings.append(Finding(
            id=f"exfil-{r.src_ip}-{r.dst_ip}",
            title=f"Possible data exfiltration {r.src_ip} -> {r.dst_ip}",
            category="Exfiltration",
            severity="High",
            mitre="T1048 - Exfiltration Over Alternative Protocol",
            description=(
                f"Internal host {r.src_ip} uploaded {r.bytes/1e6:.2f} MB to "
                f"external {r.dst_ip} while receiving only {back/1e3:.1f} KB back "
                f"(outbound/inbound ratio {ratio:.0f}x) - a strongly asymmetric "
                f"transfer suggestive of bulk exfiltration."
            ),
            recommendation=(
                "Verify whether the destination and volume are expected. If not, "
                "block the destination, capture full payloads, and investigate "
                "the source host for staging/collection activity."
            ),
            metrics={"out_bytes": int(r.bytes), "in_bytes": int(back),
                     "ratio": round(ratio, 1)},
            evidence=pd.DataFrame([{"src_ip": r.src_ip, "dst_ip": r.dst_ip,
                                    "out_MB": round(r.bytes/1e6, 3),
                                    "in_KB": round(back/1e3, 2),
                                    "packets": int(r.packets)}]),
        ))
    return findings

def detect_brute_force(conn: sqlite3.Connection, min_attempts: int = 20) -> list[Finding]:
    """Credential access: many connection attempts to one auth service."""
    port_list = ",".join(str(p) for p in AUTH_PORTS)
    df = pd.read_sql_query(
        f"""
        SELECT src_ip, dst_ip, dst_port,
               SUM(CASE WHEN tcp_syn=1 AND tcp_ack=0 THEN 1 ELSE 0 END) AS attempts,
               MAX(ts) - MIN(ts) AS duration_s
        FROM packets
        WHERE transport='TCP' AND dst_port IN ({port_list})
        GROUP BY src_ip, dst_ip, dst_port
        HAVING attempts >= ?
        ORDER BY attempts DESC
        """,
        conn, params=(min_attempts,),
    )
    findings: list[Finding] = []
    for r in df.itertuples(index=False):
        service = AUTH_PORTS.get(int(r.dst_port), str(r.dst_port))
        rate = r.attempts / r.duration_s if r.duration_s else float(r.attempts)
        findings.append(Finding(
            id=f"brute-{r.src_ip}-{r.dst_ip}-{r.dst_port}",
            title=f"{service} brute force {r.src_ip} -> {r.dst_ip}",
            category="Credential Access",
            severity="High",
            mitre="T1110 - Brute Force",
            description=(
                f"{r.src_ip} made {r.attempts} connection attempts to the "
                f"{service} service on {r.dst_ip}:{r.dst_port} "
                f"(~{rate:.1f}/s) - consistent with a password brute-force."
            ),
            recommendation=(
                f"Rate-limit and lock out repeated {service} failures, require "
                "key-based auth/MFA, and restrict the service to trusted source "
                "ranges. Check the target for any successful login."
            ),
            metrics={"attempts": int(r.attempts), "service": service,
                     "attempts_per_sec": round(rate, 2)},
            evidence=df[(df.src_ip == r.src_ip) & (df.dst_ip == r.dst_ip)].reset_index(drop=True),
        ))
    return findings


def detect_cleartext_credentials(conn: sqlite3.Connection) -> list[Finding]:
    """Exposure: credential-bearing traffic over unencrypted protocols."""
    protos = ",".join(f"'{p}'" for p in CLEARTEXT_PROTOS)
    df = pd.read_sql_query(
        f"""
        SELECT UPPER(protocol) AS protocol, COUNT(*) AS packets,
               COUNT(DISTINCT src_ip) AS clients, COUNT(DISTINCT dst_ip) AS servers
        FROM packets
        WHERE UPPER(protocol) IN ({protos})
        GROUP BY UPPER(protocol)
        ORDER BY packets DESC
        """,
        conn,
    )
    if df.empty:
        return []
    total = int(df["packets"].sum())
    return [Finding(
        id="cleartext-protocols",
        title="Credentials/data over unencrypted protocols",
        category="Credential Access / Exposure",
        severity="Medium",
        mitre="T1040 - Network Sniffing",
        description=(
            f"{total} packets used cleartext protocols ("
            + ", ".join(f"{r.protocol}:{r.packets}" for r in df.itertuples(index=False))
            + "). Anyone on-path can capture credentials and content."
        ),
        recommendation=(
            "Migrate to encrypted equivalents (HTTPS, SFTP/FTPS, SSH). Disable "
            "Telnet/FTP entirely and enforce TLS via HSTS and firewall rules."
        ),
        metrics={"cleartext_packets": total},
        evidence=df,
    )]


ALL_DETECTORS = [
    ("port_scan", lambda df, conn: detect_port_scan(conn)),
    ("service_sweep", lambda df, conn: detect_service_sweep(df)),
    ("syn_flood", lambda df, conn: detect_syn_flood(conn)),
    ("arp_spoofing", lambda df, conn: detect_arp_spoofing(df)),
    ("dns_tunneling", lambda df, conn: detect_dns_tunneling(df)),
    ("dns_failures", lambda df, conn: detect_dns_failures(df)),
    ("beaconing", lambda df, conn: detect_beaconing(df)),
    ("data_exfiltration", lambda df, conn: detect_data_exfiltration(conn)),
    ("brute_force", lambda df, conn: detect_brute_force(conn)),
    ("cleartext_credentials", lambda df, conn: detect_cleartext_credentials(conn)),
]


def run_all(df: pd.DataFrame, conn: sqlite3.Connection) -> list[Finding]:
    """Run every detector and return findings sorted by severity (worst first)."""
    findings: list[Finding] = []
    for _, fn in ALL_DETECTORS:
        findings.extend(fn(df, conn))
    findings.sort(key=lambda f: f.rank, reverse=True)
    return findings



