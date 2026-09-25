# PacketWatch

Turn a Wireshark capture into an actionable **network-security report**. PacketWatch
ingests a `.pcap`/`.pcapng`/CSV capture, loads it into a **SQLite** analysis
database, runs a battery of **pandas/numpy** threat detectors, draws
**matplotlib** charts, and writes a Markdown report that maps every finding to a
MITRE ATT&CK technique where applicable, with concrete remediation. Operational
DNS findings are labelled separately from suspected attacks.

It ships with a synthetic capture generator so the whole pipeline runs out of
the box — no live network or sample pcap required.

```
python analyze.py --demo
```

## What it detects

| # | Threat | Category | MITRE | How it's found (analytics) |
|---|--------|----------|-------|----------------------------|
| 1 | **Port scan** | Reconnaissance | T1046 | SQL fan-out: distinct dst ports vs SYN-only count per source |
| 2 | **SYN flood** | Denial of Service | T1499.002 | SYN rate + distinct-source count to one service (SQL) |
| 3 | **ARP spoofing** | Man-in-the-Middle | T1557.002 | One IP mapped to ≥2 MACs (pandas group-by) |
| 4 | **DNS tunnelling** | Exfiltration / C2 | T1071.004 | Shannon entropy + name length + volume per domain (numpy) |
| 5 | **C2 beaconing** | Command & Control | T1071 | Session inter-arrival coefficient of variation (numpy) |
| 6 | **Data exfiltration** | Exfiltration | T1048 | Outbound/inbound byte asymmetry to external IPs (SQL) |
| 7 | **Brute force** | Credential Access | T1110 | Repeated attempts to auth ports (SSH/RDP/FTP…) (SQL) |
| 8 | **Cleartext credentials** | Exposure | T1040 | Unencrypted protocol usage (HTTP/FTP/Telnet) (SQL) |
| 9 | **Service sweep** | Reconnaissance | T1046 | SYN-only probes to one TCP port on ≥20 hosts in a rolling 60-second window |
| 10 | **DNS lookup failures** | Network Reliability | Not applicable | ≥30 NXDOMAIN/SERVFAIL/REFUSED responses and ≥50% failures per client in a rolling 300-second window |

Each detector returns a severity, key metrics, an **evidence table**, and a
recommended action. The synthetic benign fixture produces **zero findings**;
production thresholds still need tuning to the local network.

Service sweeps expose a gap in distinct-port scan rules: probing SMB port 445
on many machines uses only one port. DNS failure findings help investigate
applications that cannot resolve names, distinguishing nonexistent names,
resolver failures and policy refusals. Neither finding proves a compromise.
See [research, implementation choices and next priorities](docs/real-world-improvements.md).

## Pipeline

```
 capture (.pcap/.pcapng/.csv)
        │  ingest.py         → tshark fields / CSV → normalised DataFrame
        ▼
   SQLite database           → database.py: packets table + indexes + views
        │                       (conversations, host_traffic, port_activity)
        ▼
   detectors.py              → pandas + numpy + SQL  → Finding[]
        │
        ├── visualize.py      → 6 matplotlib PNG charts
        └── report.py         → Markdown report (MITRE + evidence + fixes)
```

## Install

Requires Python 3.9+.

```bash
pip install -r requirements.txt
```

`tshark` (bundled with [Wireshark](https://www.wireshark.org/)) is only needed
to read `.pcap`/`.pcapng` files directly. CSV captures need no extra tools — you
can also export one from Wireshark via *File → Export Packet Dissections → As
CSV*. Packet-list CSV includes only displayed columns, so it has reduced
detection coverage. Its `Time` column must contain numeric seconds (relative
or epoch). Import warnings are shown in the CLI and Markdown report; the
dashboard reminds CSV users to check coverage.

The importer also accepts canonical packet columns and **headered** comma-separated
`tshark -T fields` exports using field names such as `frame.time_epoch`,
`tcp.flags.syn`, `dns.flags.response` and `dns.flags.rcode`. IPv4 and IPv6
endpoints are supported. Missing TCP flags or DNS fields are left unknown;
they are not guessed from the human-readable Info column.

### Local dashboard

The optional Django dashboard requires Python 3.10+ (Django 6 requires 3.12+):

```bash
pip install -r requirements-web.txt
python manage.py migrate
python manage.py runserver 127.0.0.1:8000
```

The dashboard is intended for local, single-user use. New detectors run
automatically for both uploaded captures and the built-in demo. The demo now
includes an SMB sweep and mixed DNS failures.

## Usage

```bash
# 1) Analyse the built-in synthetic capture (with known attacks)
python analyze.py --demo

# 2) Analyse a real capture (needs tshark on PATH)
python analyze.py captures/session.pcapng

# 3) Analyse a CSV export, persist the DB, emit machine-readable findings
python analyze.py export.csv --db output/analysis.db --json output/findings.json

# equivalent module form
python -m netsec_analyzer --demo
```

Options:

| Flag | Purpose |
|------|---------|
| `--demo` | generate + analyse a synthetic capture with planted attacks |
| `-o, --outdir DIR` | where charts and the report are written (default `output/`) |
| `--db PATH` | also save the SQLite analysis database to a file |
| `--json PATH` | write findings (with evidence) as JSON |
| `--no-charts` | skip chart rendering |
| `--seed N` | RNG seed for the synthetic capture |

## Outputs

Running `--demo` produces:

```
output/
├── report.md                    # full Markdown security report
├── findings_by_severity.png     # severity histogram
├── protocols.png                # protocol mix
├── timeline.png                 # packets/s + KB/s over time
├── top_talkers.png              # busiest hosts (sent vs received)
├── syn_scatter.png              # dst-port vs time (scans & floods pop out)
└── dns_entropy.png              # query length vs entropy (tunnels top-right)
```

Console summary:

```
 ● [Critical] Man-in-the-Middle   ARP spoofing / IP conflict for 10.0.0.1
 ● [High    ] Reconnaissance      Port scan from 10.0.0.66
 ● [High    ] Denial of Service   SYN flood against 10.0.0.20:80
 ● [High    ] Exfiltration / C2   Possible DNS tunnelling to exfil-c2.net
 ● [High    ] Command & Control   C2 beaconing 10.0.0.108 -> 185.220.101.47
 ● [High    ] Exfiltration        Possible data exfiltration 10.0.0.108 -> 91.203.145.9
 ● [High    ] Credential Access   SSH brute force 10.0.0.77 -> 10.0.0.30
 ● [Medium  ] Credential Access   Credentials/data over unencrypted protocols
```

## Project layout

```
netsec_analyzer/
├── __init__.py        # package + canonical PACKET_COLUMNS schema
├── ingest.py          # pcap (tshark) / CSV → normalised DataFrame
├── database.py        # SQLite table, indexes, analytical views, helpers
├── detectors.py       # 10 security/reliability detectors (pandas + numpy + SQL)
├── visualize.py       # matplotlib charts
├── report.py          # Markdown report builder
├── sample_data.py     # synthetic capture generator (planted attacks)
└── cli.py             # argparse entry point wiring the pipeline
analyze.py             # thin `python analyze.py` runner
tests/test_detectors.py
```

## The data-analysis / SQL approach

The design deliberately uses **the right tool for each question**:

- **SQL (SQLite views)** answers set-based questions. `conversations`,
  `host_traffic` and `port_activity` pre-aggregate the capture so detectors like
  port-scan fan-out, top talkers, brute force and traffic asymmetry are simple,
  fast `GROUP BY`/`HAVING` queries with indexes behind them.
- **numpy** does the numerical heavy lifting: Shannon entropy of DNS names,
  coefficient-of-variation of beacon inter-arrival times, weighted throughput
  histograms.
- **pandas** handles reshaping, per-group feature engineering and evidence
  tables.

## Extending it

Add a detector by writing a function that returns `list[Finding]` and appending
it to `ALL_DETECTORS` in `detectors.py`:

```python
def detect_my_threat(conn) -> list[Finding]:
    df = pd.read_sql_query("SELECT ... FROM packets ...", conn)
    return [Finding(id=..., title=..., category=..., severity="High",
                    mitre="Txxxx - ...", description=..., recommendation=...,
                    metrics={...}, evidence=df)]
```

## Testing

```bash
pytest tests/            # if pytest is installed
python tests/test_detectors.py   # zero-dependency fallback runner
python -m unittest discover -s tests -p test_real_world.py  # new regression suite
python manage.py test dashboard  # dashboard integration tests, isolated DB
```

The suite asserts every planted attack is detected, that benign traffic yields
**no** findings, and covers ingestion, the SQL views and the helper maths.

## Notes & limitations

- Detections are **heuristic**; validate against full packet context before
  acting. Thresholds are function arguments you can tune.
- Sweep detection counts distinct targets, so retries to one server do not
  inflate host diversity. Approved scanners and management tools can still
  trigger it. Slow sweeps below the window threshold are not detected.
- DNS failure ratios count observed responses with known response codes,
  not unanswered requests. Capture duplication, packet loss, DNS filtering and
  resolver forwarding affect interpretation. Encrypted DNS payloads are not
  inspected. NXDOMAIN alone is not evidence of a domain-generation algorithm.
- The bundled capture is **synthetic** sample data for demonstration and tests,
  not a real recording.
- HTTPS/TLS payloads are encrypted — like Wireshark, this tool reasons over
  metadata (timing, volume, endpoints, SNI/DNS), not decrypted content.
