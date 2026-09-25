"""Capture ingestion: turn pcap/pcapng/CSV into a normalised packet DataFrame.

Two sources are supported:

* **pcap / pcapng** - parsed with the ``tshark`` CLI (Wireshark's engine). No
  Python capture library is required; we simply ask tshark for a fixed set of
  fields and reshape the result into :data:`netsec_analyzer.PACKET_COLUMNS`.
* **CSV** - canonical columns, headered ``tshark -T fields`` exports, or
  Wireshark packet-list exports (with reduced detection coverage).

Everything downstream (SQL load, detectors, charts) consumes the normalised
DataFrame, so the rest of the pipeline is identical regardless of source.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import numpy as np
import pandas as pd

from . import PACKET_COLUMNS

# (tshark field, intermediate column) pairs, in a stable extraction order.
_TSHARK_FIELDS: list[tuple[str, str]] = [
    ("frame.number", "frame_no"),
    ("frame.time_epoch", "ts"),
    ("ip.src", "src_ip"),
    ("ip.dst", "dst_ip"),
    ("ipv6.src", "ipv6_src"),
    ("ipv6.dst", "ipv6_dst"),
    ("ipv6.nxt", "ipv6_next"),
    ("eth.src", "src_mac"),
    ("eth.dst", "dst_mac"),
    ("_ws.col.Protocol", "protocol"),
    ("ip.proto", "ip_proto"),
    ("tcp.srcport", "tcp_srcport"),
    ("tcp.dstport", "tcp_dstport"),
    ("udp.srcport", "udp_srcport"),
    ("udp.dstport", "udp_dstport"),
    ("frame.len", "length"),
    ("tcp.flags.syn", "tcp_syn"),
    ("tcp.flags.ack", "tcp_ack"),
    ("tcp.flags.fin", "tcp_fin"),
    ("tcp.flags.reset", "tcp_rst"),
    ("dns.qry.name", "dns_qry_name"),
    ("dns.qry.type", "dns_qry_type"),
    ("dns.flags.response", "dns_response"),
    ("dns.flags.rcode", "dns_rcode"),
    ("http.request.method", "http_method"),
    ("http.host", "http_host"),
    ("http.request.uri", "http_uri"),
    ("arp.src.proto_ipv4", "arp_src_ip"),
    ("arp.src.hw_mac", "arp_src_mac"),
    ("arp.opcode", "arp_opcode"),
    ("_ws.col.Info", "info"),
]

_INT_COLS = ["src_port", "dst_port", "dns_qry_type", "dns_rcode", "arp_opcode"]
# Flag-like fields: tshark emits these as "True"/"False"; our own CSV uses 0/1.
_BOOL_COLS = ["tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "dns_response"]

_WIRESHARK_COLUMNS = {
    "No.": "frame_no", "Time": "ts", "Source": "src_ip",
    "Destination": "dst_ip", "Protocol": "protocol", "Length": "length",
    "Info": "info",
}


def _column(df: pd.DataFrame, name: str) -> pd.Series:
    """Missing optional fields stay aligned Series, never scalar NaN values."""
    return df[name] if name in df else pd.Series(pd.NA, index=df.index, dtype="string")


def _validate_capture(df: pd.DataFrame) -> pd.DataFrame:
    """Reject unusable input instead of producing a misleading empty report."""
    if not np.isfinite(df["ts"]).all():
        raise ValueError("Capture timestamps must be numeric seconds. In Wireshark, "
                         "select a seconds-based Time column before exporting CSV.")
    if (df["length"] < 0).any():
        raise ValueError("Packet lengths must be non-negative.")
    return df


def _to_bool_int(series: pd.Series) -> pd.Series:
    """Map True/False/1/0 style strings to a nullable 0/1 integer series."""
    s = series.astype("string").str.strip().str.lower()
    mapped = s.map({"true": 1, "false": 0, "1": 1, "0": 0})
    # Fall back to numeric parsing for anything not covered above.
    return pd.to_numeric(mapped.fillna(s), errors="coerce").astype("Int64")

def _coerce_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Force a frame into the canonical schema with clean dtypes."""
    df = df.copy()
    for col in PACKET_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
    df = df[PACKET_COLUMNS]
    # Numeric coercions (nullable ints for flags/ports/DNS fields).
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce").astype("float64")
    df["frame_no"] = pd.to_numeric(df["frame_no"], errors="coerce").astype("Int64")
    df["length"] = pd.to_numeric(df["length"], errors="coerce").fillna(0).astype("int64")
    for col in _INT_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
    for col in _BOOL_COLS:
        df[col] = _to_bool_int(df[col])
    # String columns: normalise empties to NA.
    str_cols = ["src_ip", "dst_ip", "src_mac", "dst_mac", "protocol", "transport",
                "dns_qry_name", "http_method", "http_host", "http_uri",
                "arp_src_ip", "arp_src_mac", "info"]
    for col in str_cols:
        s = df[col].astype("string")
        df[col] = s.replace({"": pd.NA})
    return df.sort_values("ts", kind="stable").reset_index(drop=True)


def _derive_transport(df: pd.DataFrame, ip_proto: pd.Series) -> pd.Series:
    """Classify each packet's transport from ports / ip.proto / ARP."""
    proto = pd.to_numeric(ip_proto, errors="coerce")
    transport = pd.Series(["OTHER"] * len(df), index=df.index, dtype="object")
    label = df["protocol"].astype("string").str.upper()
    for name in ("TCP", "UDP", "ICMP", "ICMPV6"):
        transport = transport.mask(label.eq(name).fillna(False), name)
    transport = transport.mask((proto == 17).fillna(False), "UDP")
    transport = transport.mask((proto == 6).fillna(False), "TCP")
    transport = transport.mask((proto == 1).fillna(False), "ICMP")
    transport = transport.mask((proto == 58).fillna(False), "ICMPV6")
    for name, field in (("UDP", "udp_srcport"), ("UDP", "udp_dstport"),
                        ("TCP", "tcp_srcport"), ("TCP", "tcp_dstport")):
        transport = transport.mask(
            pd.to_numeric(_column(df, field), errors="coerce").notna(), name)
    is_arp = df["protocol"].astype("string").str.upper().eq("ARP")
    transport = transport.mask(is_arp.fillna(False), "ARP")
    return transport


def read_pcap(path: str) -> pd.DataFrame:
    """Parse a pcap/pcapng file with tshark into the normalised schema."""
    if shutil.which("tshark") is None:
        raise RuntimeError(
            "tshark not found on PATH. Install Wireshark/tshark, or export the "
            "capture to CSV and load that instead."
        )
    fields: list[str] = []
    for tsf, _ in _TSHARK_FIELDS:
        fields += ["-e", tsf]
    # Packet text can contain quotes, delimiters and newlines. TShark's field
    # quoting is not reliably CSV-compatible, so use structured JSON instead.
    cmd = ["tshark", "-r", path, "-T", "json", *fields]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()[:500]}")
    try:
        packets = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("tshark returned invalid JSON packet data") from exc
    rows = []
    for packet in packets:
        layers = packet["_source"]["layers"]
        row = {}
        for field, column in _TSHARK_FIELDS:
            # Some versions lowercase generated column names (_ws.col.Info).
            value = layers.get(field, layers.get(field.lower()))
            # Preserve the previous occurrence=f behavior for repeated fields.
            row[column] = (value[0] if value else None) if isinstance(value, list) else value
        rows.append(row)
    raw = pd.DataFrame(rows, columns=[col for _, col in _TSHARK_FIELDS])
    return _validate_capture(_from_raw(raw.replace({"": pd.NA})))


def _from_raw(raw: pd.DataFrame) -> pd.DataFrame:
    """Map a raw tshark-field frame onto the canonical schema."""
    out = pd.DataFrame(index=raw.index)
    passthrough = [
        "frame_no", "ts", "src_ip", "dst_ip", "src_mac", "dst_mac", "protocol",
        "length", "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "dns_qry_name",
        "dns_qry_type", "dns_response", "dns_rcode", "http_method", "http_host",
        "http_uri", "arp_src_ip", "arp_src_mac", "arp_opcode", "info",
    ]
    for col in passthrough:
        out[col] = raw[col] if col in raw.columns else pd.NA
    # Coalesce TCP/UDP ports into a single src/dst port column.
    for direction in ("src", "dst"):
        out[f"{direction}_ip"] = _column(raw, f"{direction}_ip").fillna(
            _column(raw, f"ipv6_{direction}"))
        out[f"{direction}_port"] = pd.to_numeric(
            _column(raw, f"{direction}_port"), errors="coerce").fillna(
                pd.to_numeric(_column(raw, f"tcp_{direction}port"), errors="coerce")
            ).fillna(pd.to_numeric(_column(raw, f"udp_{direction}port"), errors="coerce"))
    ip_proto = _column(raw, "ip_proto").fillna(_column(raw, "ipv6_next"))
    out["transport"] = _column(raw, "transport").fillna(_derive_transport(raw, ip_proto))
    return _coerce_schema(out)


def read_csv(path: str) -> pd.DataFrame:
    """Load canonical, headered tshark, or Wireshark packet-list CSV."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df = df.replace({"": pd.NA})
    df.columns = df.columns.str.strip()
    summary_export = {"Time", "Source", "Destination", "Protocol", "Length"}.issubset(df.columns)
    aliases = dict(_TSHARK_FIELDS)
    aliases.update(_WIRESHARK_COLUMNS)
    df = df.rename(columns=aliases)
    if df.columns.duplicated().any():
        raise ValueError("CSV has duplicate packet fields after header mapping.")
    required = {"ts", "protocol", "length"}
    if not required.issubset(df.columns):
        raise ValueError("Unrecognised capture CSV. Use canonical ts/protocol/length "
                         "columns, headered tshark fields, or a Wireshark packet-list export.")
    lengths = pd.to_numeric(df["length"], errors="coerce")
    if lengths.isna().any() or not np.isfinite(lengths).all() or (lengths % 1 != 0).any():
        raise ValueError("Packet lengths must be whole numbers of bytes.")
    out = _validate_capture(_from_raw(df))
    if summary_export:
        out.attrs["analysis_warnings"] = [
            "Wireshark packet-list CSV imported. Only exported columns are analysed; "
            "the Info text is not parsed into TCP flags or DNS response fields. "
            "Use pcap/pcapng or detailed tshark fields for full detector coverage. "
            "No findings does not establish that this capture is safe."
        ]
    return out


def load(path: str) -> pd.DataFrame:
    """Dispatch on file extension: pcap/pcapng -> tshark, csv -> pandas."""
    lower = path.lower()
    if lower.endswith((".pcap", ".pcapng", ".cap")):
        return read_pcap(path)
    if lower.endswith(".csv"):
        return read_csv(path)
    raise ValueError(f"Unsupported capture format: {path!r} (use pcap/pcapng/csv)")
