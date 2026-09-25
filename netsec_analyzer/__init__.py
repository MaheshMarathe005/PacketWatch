"""PacketWatch.

A Wireshark/pcap security analytics toolkit that turns raw packet captures into
actionable threat findings using pandas/numpy analytics, a SQLite analysis
database, and matplotlib visualisations.

Public entry points live in :mod:`netsec_analyzer.cli`.
"""

from __future__ import annotations

__version__ = "1.0.0"

# The normalised packet schema every analysis stage relies on. Ingestors are
# responsible for producing a pandas DataFrame with (at least) these columns.
PACKET_COLUMNS = [
    "frame_no",      # int   - packet number within the capture
    "ts",            # float - capture timestamp (epoch seconds)
    "src_ip",        # str   - source IP (may be NaN for L2-only frames)
    "dst_ip",        # str   - destination IP
    "src_mac",       # str   - source MAC
    "dst_mac",       # str   - destination MAC
    "protocol",      # str   - highest-layer protocol label (e.g. TCP, DNS)
    "transport",     # str   - TCP / UDP / ICMP / ARP / OTHER
    "src_port",      # Int64 - transport source port (nullable)
    "dst_port",      # Int64 - transport destination port (nullable)
    "length",        # int   - frame length in bytes
    "tcp_syn",       # Int64 - TCP SYN flag (0/1)
    "tcp_ack",       # Int64 - TCP ACK flag (0/1)
    "tcp_fin",       # Int64 - TCP FIN flag (0/1)
    "tcp_rst",       # Int64 - TCP RST flag (0/1)
    "dns_qry_name",  # str   - queried domain name
    "dns_qry_type",  # Int64 - DNS query type (1=A, 28=AAAA, 16=TXT, ...)
    "dns_response",  # Int64 - DNS response flag (0=query, 1=response)
    "dns_rcode",     # Int64 - DNS response code (0=NOERROR, 3=NXDOMAIN, ...)
    "http_method",   # str   - HTTP request method
    "http_host",     # str   - HTTP Host header
    "http_uri",      # str   - HTTP request URI
    "arp_src_ip",    # str   - ARP sender protocol (IPv4) address
    "arp_src_mac",   # str   - ARP sender hardware (MAC) address
    "arp_opcode",    # Int64 - ARP opcode (1=request, 2=reply)
    "info",          # str   - free-form summary text
]
