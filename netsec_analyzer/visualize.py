"""Matplotlib visualisations for a capture and its findings.

All figures are written as PNGs into an output directory and the mapping of
``name -> path`` is returned so the report can embed them. Rendering uses the
non-interactive ``Agg`` backend, and the matplotlib cache is redirected to a
writable temp directory so this runs headless anywhere.
"""

from __future__ import annotations

import os
import tempfile

# Redirect matplotlib's cache/config somewhere guaranteed writable *before*
# importing pyplot, then force the headless Agg backend.
os.environ.setdefault("MPLCONFIGDIR",
                      os.path.join(tempfile.gettempdir(), "netthreat-mpl"))
os.makedirs(os.environ["MPLCONFIGDIR"], exist_ok=True)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

plt.rcParams.update({
    "figure.autolayout": True,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.titlesize": 12,
    "font.size": 9,
})

_SEV_COLORS = {"Critical": "#8e0152", "High": "#d6604d", "Medium": "#f4a582",
               "Low": "#92c5de", "Info": "#c7c7c7"}


def _save(fig, outdir: str, name: str) -> str:
    path = os.path.join(outdir, name)
    fig.savefig(path, dpi=110)
    plt.close(fig)
    return path

def chart_protocols(df: pd.DataFrame, outdir: str) -> str:
    counts = df["protocol"].fillna("?").value_counts().head(12)[::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(counts.index.astype(str), counts.to_numpy(), color="#4292c6")
    ax.set_title("Protocol distribution")
    ax.set_xlabel("packets")
    return _save(fig, outdir, "protocols.png")


def chart_timeline(df: pd.DataFrame, outdir: str) -> str:
    t = df["ts"].to_numpy(dtype=float)
    rel = t - t.min()
    span = max(rel.max(), 1.0)
    bins = np.arange(0, span + 1, max(1.0, round(span / 120)))
    pps, edges = np.histogram(rel, bins=bins)
    # Bytes per bin (weighted histogram).
    bps, _ = np.histogram(rel, bins=bins, weights=df["length"].to_numpy(dtype=float))
    centers = (edges[:-1] + edges[1:]) / 2
    width = edges[1] - edges[0] if len(edges) > 1 else 1.0
    fig, ax1 = plt.subplots(figsize=(9, 4))
    ax1.bar(centers, pps / width, width=width, color="#6baed6", label="packets/s")
    ax1.set_xlabel("time since capture start (s)")
    ax1.set_ylabel("packets/s", color="#2171b5")
    ax2 = ax1.twinx()
    ax2.plot(centers, bps / width / 1e3, color="#cb181d", lw=1.4, label="KB/s")
    ax2.set_ylabel("KB/s", color="#cb181d")
    ax2.grid(False)
    ax1.set_title("Traffic rate over time")
    return _save(fig, outdir, "timeline.png")


def chart_top_talkers(conn, outdir: str) -> str:
    df = pd.read_sql_query(
        "SELECT host, sent_bytes, recv_bytes FROM host_traffic "
        "ORDER BY sent_bytes + recv_bytes DESC LIMIT 12", conn)
    df = df[::-1]
    fig, ax = plt.subplots(figsize=(8, 5))
    y = np.arange(len(df))
    ax.barh(y, df["sent_bytes"] / 1e3, color="#ef6548", label="sent")
    ax.barh(y, df["recv_bytes"] / 1e3, left=df["sent_bytes"] / 1e3,
            color="#74a9cf", label="received")
    ax.set_yticks(y)
    ax.set_yticklabels(df["host"])
    ax.set_xlabel("KB")
    ax.set_title("Top talkers (by total bytes)")
    ax.legend(loc="lower right")
    return _save(fig, outdir, "top_talkers.png")

def chart_scan_scatter(df: pd.DataFrame, outdir: str) -> str:
    syn = df[(df["transport"] == "TCP") & (df["tcp_syn"] == 1) & (df["tcp_ack"] == 0)]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    if not syn.empty:
        t = syn["ts"].to_numpy(dtype=float)
        rel = t - df["ts"].min()
        ax.scatter(rel, syn["dst_port"].to_numpy(dtype=float), s=6, alpha=0.35,
                   color="#08519c", edgecolors="none")
    ax.set_title("SYN targets over time (port sweeps = vertical spread, "
                 "floods = horizontal band)")
    ax.set_xlabel("time since capture start (s)")
    ax.set_ylabel("destination port")
    return _save(fig, outdir, "syn_scatter.png")


def chart_dns_entropy(df: pd.DataFrame, outdir: str) -> str:
    from .detectors import shannon_entropy, registered_domain
    dns = df[(df["protocol"].str.upper() == "DNS") & (df["dns_response"] == 0)
             & df["dns_qry_name"].notna()].copy()
    fig, ax = plt.subplots(figsize=(8, 4.5))
    if not dns.empty:
        dns["qlen"] = dns["dns_qry_name"].str.len()
        dns["entropy"] = dns["dns_qry_name"].map(shannon_entropy)
        dns["sld"] = dns["dns_qry_name"].map(registered_domain)
        # Flag the suspicious cluster (long + high entropy) in red.
        susp = (dns["qlen"] >= 35) & (dns["entropy"] >= 3.5)
        ax.scatter(dns.loc[~susp, "qlen"], dns.loc[~susp, "entropy"], s=12,
                   alpha=0.5, color="#74a9cf", label="normal")
        ax.scatter(dns.loc[susp, "qlen"], dns.loc[susp, "entropy"], s=16,
                   alpha=0.7, color="#cb181d", label="suspicious")
        ax.axvline(35, ls="--", color="grey", lw=0.8)
        ax.axhline(3.5, ls="--", color="grey", lw=0.8)
        ax.legend(loc="lower right")
    ax.set_title("DNS query length vs entropy (tunnelling lives top-right)")
    ax.set_xlabel("query name length (chars)")
    ax.set_ylabel("Shannon entropy (bits/char)")
    return _save(fig, outdir, "dns_entropy.png")


def chart_findings(findings, outdir: str) -> str:
    order = ["Critical", "High", "Medium", "Low", "Info"]
    counts = {s: 0 for s in order}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    labels = [s for s in order if counts[s] > 0] or ["Info"]
    vals = [counts[s] for s in labels]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(labels, vals, color=[_SEV_COLORS[s] for s in labels])
    ax.set_title(f"Findings by severity ({len(findings)} total)")
    ax.set_ylabel("count")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.05, str(v), ha="center", va="bottom")
    return _save(fig, outdir, "findings_by_severity.png")


def generate_all(df: pd.DataFrame, conn, findings, outdir: str) -> dict:
    """Render every chart; skip (and note) any that fail rather than aborting."""
    os.makedirs(outdir, exist_ok=True)
    jobs = {
        "protocols": lambda: chart_protocols(df, outdir),
        "timeline": lambda: chart_timeline(df, outdir),
        "top_talkers": lambda: chart_top_talkers(conn, outdir),
        "syn_scatter": lambda: chart_scan_scatter(df, outdir),
        "dns_entropy": lambda: chart_dns_entropy(df, outdir),
        "findings": lambda: chart_findings(findings, outdir),
    }
    made: dict[str, str] = {}
    for name, fn in jobs.items():
        try:
            made[name] = fn()
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[warn] chart '{name}' failed: {exc}")
    return made


