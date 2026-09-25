"""SQLite analysis database for a normalised packet capture.

The DataFrame produced by :mod:`netsec_analyzer.ingest` is loaded into a typed
``packets`` table with indexes tuned for the queries the detectors run. A set of
SQL **views** pre-computes the aggregates that show up again and again in
network-security work:

* ``conversations`` - per (src, dst, transport) flow rollups (bytes, packets,
  SYN/RST counts, duration).
* ``host_traffic``  - bytes/packets sent and received per host.
* ``port_activity`` - fan-out of distinct destination ports per source.

Detectors that are naturally set-based (top talkers, brute force, port-scan
fan-out) are expressed as SQL against these views; detectors that need
per-packet numerical analysis (entropy, beacon interval statistics) use pandas
and numpy. That split is deliberate - use the right tool for each question.
"""

from __future__ import annotations

import math
import sqlite3

import pandas as pd

# column -> SQLite storage class
_SCHEMA: dict[str, str] = {
    "frame_no": "INTEGER", "ts": "REAL", "src_ip": "TEXT", "dst_ip": "TEXT",
    "src_mac": "TEXT", "dst_mac": "TEXT", "protocol": "TEXT", "transport": "TEXT",
    "src_port": "INTEGER", "dst_port": "INTEGER", "length": "INTEGER",
    "tcp_syn": "INTEGER", "tcp_ack": "INTEGER", "tcp_fin": "INTEGER",
    "tcp_rst": "INTEGER", "dns_qry_name": "TEXT", "dns_qry_type": "INTEGER",
    "dns_response": "INTEGER", "dns_rcode": "INTEGER", "http_method": "TEXT",
    "http_host": "TEXT", "http_uri": "TEXT", "arp_src_ip": "TEXT",
    "arp_src_mac": "TEXT", "arp_opcode": "INTEGER", "info": "TEXT",
}


def _py(value):
    """Convert a pandas/numpy cell into a plain Python value sqlite3 accepts."""
    if value is None or value is pd.NA:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    item = getattr(value, "item", None)
    return item() if callable(item) else value

_VIEWS: dict[str, str] = {
    # One row per directed flow (src -> dst over a transport).
    "conversations": """
        CREATE VIEW conversations AS
        SELECT src_ip, dst_ip, transport,
               COUNT(*)                         AS packets,
               SUM(length)                      AS bytes,
               MIN(ts)                          AS first_ts,
               MAX(ts)                          AS last_ts,
               MAX(ts) - MIN(ts)                AS duration_s,
               SUM(COALESCE(tcp_syn, 0))        AS syn_count,
               SUM(COALESCE(tcp_rst, 0))        AS rst_count,
               COUNT(DISTINCT dst_port)         AS distinct_dst_ports
        FROM packets
        WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
        GROUP BY src_ip, dst_ip, transport
    """,
    # Bytes/packets a host sent and received (union of both directions).
    "host_traffic": """
        CREATE VIEW host_traffic AS
        SELECT host,
               SUM(sent_bytes)   AS sent_bytes,
               SUM(recv_bytes)   AS recv_bytes,
               SUM(sent_pkts)    AS sent_pkts,
               SUM(recv_pkts)    AS recv_pkts
        FROM (
            SELECT src_ip AS host, SUM(length) AS sent_bytes, 0 AS recv_bytes,
                   COUNT(*) AS sent_pkts, 0 AS recv_pkts
            FROM packets WHERE src_ip IS NOT NULL GROUP BY src_ip
            UNION ALL
            SELECT dst_ip AS host, 0, SUM(length), 0, COUNT(*)
            FROM packets WHERE dst_ip IS NOT NULL GROUP BY dst_ip
        )
        GROUP BY host
    """,
    # Distinct destination ports contacted by each source (scan fan-out).
    "port_activity": """
        CREATE VIEW port_activity AS
        SELECT src_ip,
               COUNT(DISTINCT dst_port)                            AS distinct_ports,
               COUNT(DISTINCT dst_ip)                              AS distinct_hosts,
               SUM(CASE WHEN tcp_syn = 1 AND tcp_ack = 0 THEN 1 END) AS syn_only,
               COUNT(*)                                            AS packets
        FROM packets
        WHERE transport = 'TCP' AND src_ip IS NOT NULL
        GROUP BY src_ip
    """,
}

_INDEXES = [
    "CREATE INDEX idx_pkt_src ON packets(src_ip)",
    "CREATE INDEX idx_pkt_dst ON packets(dst_ip)",
    "CREATE INDEX idx_pkt_dport ON packets(dst_port)",
    "CREATE INDEX idx_pkt_ts ON packets(ts)",
    "CREATE INDEX idx_pkt_transport ON packets(transport)",
    "CREATE INDEX idx_pkt_proto ON packets(protocol)",
]

def build_database(df: pd.DataFrame, db_path: str = ":memory:") -> sqlite3.Connection:
    """Create the ``packets`` table, indexes and views; return a connection."""
    conn = sqlite3.connect(db_path)
    cols_ddl = ", ".join(f"{name} {typ}" for name, typ in _SCHEMA.items())
    conn.execute(f"CREATE TABLE packets ({cols_ddl})")

    order = list(_SCHEMA.keys())
    frame = df.reindex(columns=order)
    placeholders = ", ".join("?" for _ in order)
    rows = [tuple(_py(v) for v in rec)
            for rec in frame.itertuples(index=False, name=None)]
    conn.executemany(f"INSERT INTO packets VALUES ({placeholders})", rows)

    for stmt in _INDEXES:
        conn.execute(stmt)
    for ddl in _VIEWS.values():
        conn.execute(ddl)
    conn.commit()
    return conn


def query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> pd.DataFrame:
    """Run a SQL query and return the result as a DataFrame."""
    return pd.read_sql_query(sql, conn, params=params)


def summary(conn: sqlite3.Connection) -> dict:
    """High-level capture statistics used in the report header."""
    row = conn.execute(
        "SELECT COUNT(*), MIN(ts), MAX(ts), SUM(length), "
        "COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip) FROM packets"
    ).fetchone()
    packets, first_ts, last_ts, total_bytes, n_src, n_dst = row
    duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0
    return {
        "packets": packets or 0,
        "duration_s": round(duration, 3),
        "total_bytes": int(total_bytes or 0),
        "avg_pps": round((packets or 0) / duration, 2) if duration else 0.0,
        "distinct_sources": n_src or 0,
        "distinct_destinations": n_dst or 0,
    }

