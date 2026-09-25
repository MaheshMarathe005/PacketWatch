"""Synthetic Wireshark capture generator.

Real captures are large and often contain private data, and this environment has
no live network. To make the whole pipeline runnable and testable out of the
box, this module synthesises a realistic capture that mixes benign background
traffic with several textbook attack patterns taken from real SOC/Wireshark
investigations:

* horizontal/vertical port scanning   (reconnaissance)
* SYN flood                           (DoS / half-open connections)
* ARP cache poisoning                 (man-in-the-middle)
* DNS tunnelling / exfiltration       (long high-entropy queries)
* C2 beaconing                        (regular low-jitter callbacks)
* bulk data exfiltration              (asymmetric outbound volume)
* SSH brute force                     (many auth attempts)
* cleartext credentials               (HTTP / FTP / Telnet)
* SMB service sweep                   (many hosts on one port)
* DNS lookup failures                 (NXDOMAIN / SERVFAIL / REFUSED)

The output is a pandas DataFrame using the shared ``PACKET_COLUMNS`` schema, so
downstream code cannot tell it apart from a real tshark extraction.
"""

from __future__ import annotations

import string

import numpy as np
import pandas as pd

from . import PACKET_COLUMNS

BASE_TS = 1_700_000_000.0  # fixed epoch => reproducible timelines

GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "00:11:22:33:44:01"
CLIENTS = [f"10.0.0.{i}" for i in range(100, 111)]
POPULAR_DOMAINS = [
    "google.com", "cloudflare.com", "wikipedia.org", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "mozilla.org",
]


def _mac(rng: np.random.Generator) -> str:
    return "02:" + ":".join(f"{int(rng.integers(0, 256)):02x}" for _ in range(5))


def _row(**kwargs) -> dict:
    """Return a packet row with every schema column present (defaults None)."""
    row = {col: None for col in PACKET_COLUMNS}
    row.update(kwargs)
    return row


def _rand_label(rng: np.random.Generator, n: int) -> str:
    """Random label emulating an encoded DNS-tunnel subdomain."""
    alphabet = string.ascii_lowercase + string.digits
    idx = rng.integers(0, len(alphabet), size=n)
    return "".join(alphabet[int(i)] for i in idx)

def _benign(rng: np.random.Generator) -> list[dict]:
    """Ordinary web browsing: DNS lookups + HTTPS/TLS sessions + some ARP."""
    rows: list[dict] = []
    client_macs = {c: _mac(rng) for c in CLIENTS}
    for _ in range(220):
        client = str(rng.choice(CLIENTS))
        cmac = client_macs[client]
        t = BASE_TS + float(rng.uniform(0, 600))
        domain = str(rng.choice(POPULAR_DOMAINS))
        server = f"93.184.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
        sport = int(rng.integers(49152, 65535))
        # DNS query + response
        rows.append(_row(ts=t, src_ip=client, dst_ip=GATEWAY_IP, src_mac=cmac,
                         dst_mac=GATEWAY_MAC, protocol="DNS", transport="UDP",
                         src_port=sport, dst_port=53, length=int(rng.integers(70, 90)),
                         dns_qry_name=domain, dns_qry_type=1, dns_response=0,
                         info=f"Standard query A {domain}"))
        rows.append(_row(ts=t + 0.02, src_ip=GATEWAY_IP, dst_ip=client,
                         src_mac=GATEWAY_MAC, dst_mac=cmac, protocol="DNS",
                         transport="UDP", src_port=53, dst_port=sport,
                         length=int(rng.integers(90, 130)), dns_qry_name=domain,
                         dns_qry_type=1, dns_response=1, dns_rcode=0,
                         info=f"Standard query response A {domain}"))
        # TCP handshake + a short TLS session to the resolved server
        rows.append(_row(ts=t + 0.05, src_ip=client, dst_ip=server, src_mac=cmac,
                         dst_mac=GATEWAY_MAC, protocol="TCP", transport="TCP",
                         src_port=sport, dst_port=443, length=74, tcp_syn=1,
                         tcp_ack=0, tcp_fin=0, tcp_rst=0, info="SYN"))
        rows.append(_row(ts=t + 0.08, src_ip=server, dst_ip=client,
                         src_mac=GATEWAY_MAC, dst_mac=cmac, protocol="TCP",
                         transport="TCP", src_port=443, dst_port=sport, length=74,
                         tcp_syn=1, tcp_ack=1, tcp_fin=0, tcp_rst=0, info="SYN, ACK"))
        for _ in range(int(rng.integers(3, 9))):
            up = rng.random() < 0.5
            rows.append(_row(
                ts=t + 0.1 + float(rng.uniform(0, 3)),
                src_ip=client if up else server,
                dst_ip=server if up else client,
                src_mac=cmac if up else GATEWAY_MAC,
                dst_mac=GATEWAY_MAC if up else cmac,
                protocol="TLS", transport="TCP",
                src_port=sport if up else 443,
                dst_port=443 if up else sport,
                length=int(rng.integers(200, 1400)),
                tcp_syn=0, tcp_ack=1, tcp_fin=0, tcp_rst=0,
                info="Application Data"))
    return rows


def _port_scan(rng: np.random.Generator) -> list[dict]:
    """Vertical SYN scan: one attacker probes many ports on one target."""
    rows: list[dict] = []
    attacker, amac = "10.0.0.66", _mac(rng)
    target = "10.0.0.10"
    t0 = BASE_TS + 120.0
    ports = rng.choice(np.arange(1, 1025), size=400, replace=False)
    for i, port in enumerate(ports):
        t = t0 + i * 0.01
        rows.append(_row(ts=t, src_ip=attacker, dst_ip=target, src_mac=amac,
                         dst_mac=GATEWAY_MAC, protocol="TCP", transport="TCP",
                         src_port=44444, dst_port=int(port), length=58,
                         tcp_syn=1, tcp_ack=0, tcp_fin=0, tcp_rst=0, info="SYN"))
        # target refuses most ports with RST (closed) -> classic scan signature
        if rng.random() < 0.9:
            rows.append(_row(ts=t + 0.002, src_ip=target, dst_ip=attacker,
                             src_mac=GATEWAY_MAC, dst_mac=amac, protocol="TCP",
                             transport="TCP", src_port=int(port), dst_port=44444,
                             length=54, tcp_syn=0, tcp_ack=1, tcp_fin=0,
                             tcp_rst=1, info="RST, ACK"))
    return rows

def _syn_flood(rng: np.random.Generator) -> list[dict]:
    """SYN flood: a burst of SYNs to one service, few ever complete."""
    rows: list[dict] = []
    victim = "10.0.0.20"
    t0 = BASE_TS + 200.0
    for i in range(600):
        src = f"172.16.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
        t = t0 + i * 0.02
        rows.append(_row(ts=t, src_ip=src, dst_ip=victim, src_mac=_mac(rng),
                         dst_mac=GATEWAY_MAC, protocol="TCP", transport="TCP",
                         src_port=int(rng.integers(1024, 65535)), dst_port=80,
                         length=58, tcp_syn=1, tcp_ack=0, tcp_fin=0, tcp_rst=0,
                         info="SYN"))
        # victim answers SYN-ACK but the handshake almost never completes
        rows.append(_row(ts=t + 0.001, src_ip=victim, dst_ip=src,
                         src_mac=GATEWAY_MAC, dst_mac=_mac(rng), protocol="TCP",
                         transport="TCP", src_port=80,
                         dst_port=int(rng.integers(1024, 65535)), length=58,
                         tcp_syn=1, tcp_ack=1, tcp_fin=0, tcp_rst=0,
                         info="SYN, ACK"))
    return rows


def _arp_spoof(rng: np.random.Generator) -> list[dict]:
    """ARP poisoning: attacker MAC repeatedly claims the gateway IP."""
    rows: list[dict] = []
    attacker_mac = "de:ad:be:ef:00:99"
    t0 = BASE_TS + 60.0
    # legitimate ARP replies from the real gateway
    for i in range(5):
        rows.append(_row(ts=t0 + i * 30, src_ip=GATEWAY_IP, dst_ip="10.0.0.100",
                         src_mac=GATEWAY_MAC, dst_mac="ff:ff:ff:ff:ff:ff",
                         protocol="ARP", transport="ARP", length=42,
                         arp_src_ip=GATEWAY_IP, arp_src_mac=GATEWAY_MAC,
                         arp_opcode=2, info=f"{GATEWAY_IP} is at {GATEWAY_MAC}"))
    # attacker floods gratuitous ARP mapping the gateway IP to its own MAC
    for i in range(40):
        rows.append(_row(ts=t0 + i * 5 + 2, src_ip=GATEWAY_IP,
                         dst_ip="10.0.0.255", src_mac=attacker_mac,
                         dst_mac="ff:ff:ff:ff:ff:ff", protocol="ARP",
                         transport="ARP", length=42, arp_src_ip=GATEWAY_IP,
                         arp_src_mac=attacker_mac, arp_opcode=2,
                         info=f"{GATEWAY_IP} is at {attacker_mac} (gratuitous)"))
    return rows


def _dns_tunnel(rng: np.random.Generator) -> list[dict]:
    """DNS tunnelling: long, high-entropy subdomains + TXT queries to one zone."""
    rows: list[dict] = []
    client, cmac = "10.0.0.105", _mac(rng)
    zone = "tunnel.exfil-c2.net"
    t0 = BASE_TS + 300.0
    for i in range(180):
        label = _rand_label(rng, int(rng.integers(28, 45)))
        name = f"{label}.{zone}"
        qtype = 16 if rng.random() < 0.6 else 1  # mostly TXT
        t = t0 + i * 0.4
        sport = int(rng.integers(49152, 65535))
        rows.append(_row(ts=t, src_ip=client, dst_ip=GATEWAY_IP, src_mac=cmac,
                         dst_mac=GATEWAY_MAC, protocol="DNS", transport="UDP",
                         src_port=sport, dst_port=53, length=int(len(name) + 40),
                         dns_qry_name=name, dns_qry_type=qtype, dns_response=0,
                         info=f"Standard query {'TXT' if qtype == 16 else 'A'} {name}"))
        rows.append(_row(ts=t + 0.05, src_ip=GATEWAY_IP, dst_ip=client,
                         src_mac=GATEWAY_MAC, dst_mac=cmac, protocol="DNS",
                         transport="UDP", src_port=53, dst_port=sport,
                         length=int(len(name) + 120), dns_qry_name=name,
                         dns_qry_type=qtype, dns_response=1, dns_rcode=0,
                         info="Standard query response"))
    return rows

def _c2_beacon(rng: np.random.Generator) -> list[dict]:
    """C2 beacon: infected host calls out every ~30s with tiny jitter."""
    rows: list[dict] = []
    infected, imac = "10.0.0.108", _mac(rng)
    c2 = "185.220.101.47"
    interval, t = 30.0, BASE_TS + 20.0
    while t < BASE_TS + 600:
        sport = int(rng.integers(49152, 65535))
        t += interval + float(rng.normal(0, 0.4))  # very low jitter
        rows.append(_row(ts=t, src_ip=infected, dst_ip=c2, src_mac=imac,
                         dst_mac=GATEWAY_MAC, protocol="TLS", transport="TCP",
                         src_port=sport, dst_port=443, length=int(rng.integers(180, 240)),
                         tcp_syn=0, tcp_ack=1, tcp_fin=0, tcp_rst=0,
                         info="Application Data (beacon check-in)"))
        rows.append(_row(ts=t + 0.1, src_ip=c2, dst_ip=infected,
                         src_mac=GATEWAY_MAC, dst_mac=imac, protocol="TLS",
                         transport="TCP", src_port=443, dst_port=sport,
                         length=int(rng.integers(120, 200)), tcp_syn=0, tcp_ack=1,
                         tcp_fin=0, tcp_rst=0, info="Application Data"))
    return rows


def _exfil(rng: np.random.Generator) -> list[dict]:
    """Bulk exfiltration: one host pushes a large asymmetric upload outbound."""
    rows: list[dict] = []
    host, hmac = "10.0.0.108", _mac(rng)
    dest = "91.203.145.9"
    t0 = BASE_TS + 450.0
    sport = int(rng.integers(49152, 65535))
    for i in range(500):
        rows.append(_row(ts=t0 + i * 0.03, src_ip=host, dst_ip=dest, src_mac=hmac,
                         dst_mac=GATEWAY_MAC, protocol="TLS", transport="TCP",
                         src_port=sport, dst_port=443, length=1460, tcp_syn=0,
                         tcp_ack=1, tcp_fin=0, tcp_rst=0, info="Application Data"))
        if i % 8 == 0:  # sparse tiny ACKs coming back => strongly asymmetric
            rows.append(_row(ts=t0 + i * 0.03 + 0.005, src_ip=dest, dst_ip=host,
                             src_mac=GATEWAY_MAC, dst_mac=hmac, protocol="TCP",
                             transport="TCP", src_port=443, dst_port=sport,
                             length=54, tcp_syn=0, tcp_ack=1, tcp_fin=0,
                             tcp_rst=0, info="ACK"))
    return rows


def _brute_force(rng: np.random.Generator) -> list[dict]:
    """SSH brute force: many short auth attempts to port 22 on one target."""
    rows: list[dict] = []
    attacker, amac = "10.0.0.77", _mac(rng)
    target = "10.0.0.30"
    t0 = BASE_TS + 350.0
    for i in range(150):
        sport = int(rng.integers(1024, 65535))
        t = t0 + i * 0.5
        rows.append(_row(ts=t, src_ip=attacker, dst_ip=target, src_mac=amac,
                         dst_mac=GATEWAY_MAC, protocol="TCP", transport="TCP",
                         src_port=sport, dst_port=22, length=74, tcp_syn=1,
                         tcp_ack=0, tcp_fin=0, tcp_rst=0, info="SYN"))
        rows.append(_row(ts=t + 0.3, src_ip=attacker, dst_ip=target, src_mac=amac,
                         dst_mac=GATEWAY_MAC, protocol="SSH", transport="TCP",
                         src_port=sport, dst_port=22, length=int(rng.integers(80, 120)),
                         tcp_syn=0, tcp_ack=1, tcp_fin=0, tcp_rst=0,
                         info="Client: encrypted packet (auth attempt)"))
        rows.append(_row(ts=t + 0.45, src_ip=target, dst_ip=attacker,
                         src_mac=GATEWAY_MAC, dst_mac=amac, protocol="TCP",
                         transport="TCP", src_port=22, dst_port=sport, length=54,
                         tcp_syn=0, tcp_ack=1, tcp_fin=1, tcp_rst=0,
                         info="FIN, ACK (auth failed)"))
    return rows

def _cleartext(rng: np.random.Generator) -> list[dict]:
    """Credentials exposed over unencrypted HTTP / FTP / Telnet."""
    rows: list[dict] = []
    client, cmac = "10.0.0.103", _mac(rng)
    server = "10.0.0.50"
    t0 = BASE_TS + 500.0
    sport = int(rng.integers(49152, 65535))
    rows.append(_row(ts=t0, src_ip=client, dst_ip=server, src_mac=cmac,
                     dst_mac=GATEWAY_MAC, protocol="HTTP", transport="TCP",
                     src_port=sport, dst_port=80, length=320, tcp_syn=0, tcp_ack=1,
                     tcp_fin=0, tcp_rst=0, http_method="POST", http_host="intranet.local",
                     http_uri="/login", info="POST /login (username=admin&password=...)"))
    rows.append(_row(ts=t0 + 5, src_ip=client, dst_ip=server, src_mac=cmac,
                     dst_mac=GATEWAY_MAC, protocol="FTP", transport="TCP",
                     src_port=int(rng.integers(1024, 65535)), dst_port=21, length=70,
                     tcp_syn=0, tcp_ack=1, tcp_fin=0, tcp_rst=0,
                     info="Request: PASS s3cr3t"))
    rows.append(_row(ts=t0 + 9, src_ip=client, dst_ip=server, src_mac=cmac,
                     dst_mac=GATEWAY_MAC, protocol="TELNET", transport="TCP",
                     src_port=int(rng.integers(1024, 65535)), dst_port=23, length=60,
                     tcp_syn=0, tcp_ack=1, tcp_fin=0, tcp_rst=0,
                     info="Telnet Data: login/password"))
    return rows


def _service_sweep(rng: np.random.Generator) -> list[dict]:
    """Horizontal SMB discovery, invisible to a distinct-port-only detector."""
    mac = _mac(rng)
    return [_row(ts=BASE_TS + 120 + i * 0.4, src_ip="10.0.0.88",
                 dst_ip=f"10.0.1.{i + 1}", src_mac=mac, dst_mac=GATEWAY_MAC,
                 protocol="TCP", transport="TCP", src_port=51000 + i,
                 dst_port=445, length=74, tcp_syn=1, tcp_ack=0,
                 tcp_fin=0, tcp_rst=0, info="SYN") for i in range(32)]


def _dns_failures(rng: np.random.Generator) -> list[dict]:
    """A client experiences a mix of DNS errors; no confirmed malware claim."""
    rows = []
    for i in range(45):
        name = f"service-{i}.example.invalid"
        code = (3, 2, 5)[i % 3]
        for response in (0, 1):
            rows.append(_row(
                ts=BASE_TS + 250 + i * 0.7 + response * 0.02,
                src_ip=GATEWAY_IP if response else "10.0.0.109",
                dst_ip="10.0.0.109" if response else GATEWAY_IP,
                src_port=53 if response else 53000 + i,
                dst_port=53000 + i if response else 53,
                protocol="DNS", transport="UDP", length=90,
                dns_qry_name=name, dns_qry_type=1,
                dns_response=response, dns_rcode=code if response else None,
                info="Synthetic DNS failure" if response else "Standard query"))
    return rows


_GENERATORS = [
    _benign, _port_scan, _syn_flood, _arp_spoof, _dns_tunnel,
    _c2_beacon, _exfil, _brute_force, _cleartext, _service_sweep, _dns_failures,
]


def generate_capture(seed: int = 42) -> pd.DataFrame:
    """Build the full synthetic capture as a normalised packet DataFrame."""
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    for gen in _GENERATORS:
        rows.extend(gen(rng))
    df = pd.DataFrame(rows, columns=PACKET_COLUMNS)
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df["frame_no"] = np.arange(1, len(df) + 1)
    # Enforce nullable-integer dtypes so SQL/analytics see clean types.
    int_cols = ["src_port", "dst_port", "tcp_syn", "tcp_ack", "tcp_fin",
                "tcp_rst", "dns_qry_type", "dns_response", "dns_rcode", "arp_opcode"]
    for col in int_cols:
        df[col] = df[col].astype("Int64")
    df["length"] = df["length"].astype("int64")
    return df


def save_csv(df: pd.DataFrame, path: str) -> None:
    """Persist a capture in a Wireshark-style CSV (re-loadable via ingest)."""
    df.to_csv(path, index=False)


if __name__ == "__main__":  # pragma: no cover - manual utility
    cap = generate_capture()
    out = "sample_captures/synthetic_capture.csv"
    save_csv(cap, out)
    print(f"Wrote {len(cap)} packets to {out}")



