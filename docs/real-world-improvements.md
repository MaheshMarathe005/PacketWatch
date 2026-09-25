# Real-world improvements

Research checked on 2026-09-25. These changes extend the existing capture →
SQLite → detector → report pipeline; no capture data is sent to outside services.

## Problems and implemented solutions

| Problem | Evidence and rationale | Implementation |
| --- | --- | --- |
| One-port sweeps were invisible to the existing ≥100-distinct-ports detector. | [MITRE T1046](https://attack.mitre.org/techniques/T1046/) describes remote service discovery, including SMB/RDP scanning. [CISA's ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide) recommends restricting remote services and segmenting networks to limit lateral movement. | `detect_service_sweep`: group TCP SYN-only packets by source/service; track distinct targets in rolling windows. Report the highest-diversity qualifying window once per source/service, with per-target evidence. |
| DNS connectivity failures were collected but ignored. | [Wireshark's DNS field reference](https://www.wireshark.org/docs/dfref/d/dns.html) exposes response flags and codes. [MITRE T1568.002](https://attack.mitre.org/techniques/T1568/002/) identifies failed lookups as one signal to correlate with random-looking domains and endpoint activity. | `detect_dns_failures`: per-client response error rate, separate NXDOMAIN/SERVFAIL/REFUSED totals, resolver count and packet evidence. Findings are operational, not automatic malware diagnoses. |
| The documented Wireshark CSV upload path did not map ordinary display headers and could crash on missing transport fields. | [Wireshark's export documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html) distinguishes packet-list exports from richer packet data. [TShark documentation](https://www.wireshark.org/docs/man-pages/tshark.html) describes explicit field export and structured output. | Header mapping, safe optional-field handling, numeric time/length validation, detailed-field preservation, IPv6 endpoint fallback, structured TShark JSON output and reduced-coverage warnings. Relative timestamps beginning at zero now produce the correct duration. |

Thresholds are project defaults, not values prescribed by these sources:

| Function | Defaults | Important limits |
| --- | --- | --- |
| `detect_service_sweep(df, min_hosts=20, window_s=60)` | ≥20 distinct destinations for one source/port in 60 seconds, inclusive | Requires explicit TCP SYN/ACK flags, endpoints, destination port and timestamps. Approved scanners can trigger it. No proof of successful authentication or lateral movement. |
| `detect_dns_failures(df, min_failures=30, min_failure_ratio=0.5, window_s=300)` | ≥30 error responses and ≥50% failures within 300 seconds, inclusive | Requires DNS response flags, response codes, endpoints and timestamps. Destination is the observed client, which may be a forwarding resolver. Missing replies and encrypted DNS are outside coverage. |

Both use rolling windows rather than clock-aligned buckets so a burst crossing
a minute boundary is still detected. A single finding per client or source/service
contains the strongest observed qualifying window. DNS ratios describe captured
responses; without transaction identifiers, duplicate packets/replies are not
deduplicated. Other legacy detectors retain their existing whole-capture logic.

## Validation

- Known synthetic attacks and the benign-traffic regression fixture.
- Service sweep retries, source/service isolation, non-SYN packets, exact time
  boundaries, shuffled input and separated bursts.
- DNS response direction, each error code, successful-response denominator,
  small samples, missing fields, separated clients and slow background failures.
- Canonical, Wireshark display and dotted TShark CSV headers; IPv6,
  quoted separators, unknown optional fields and invalid input.
- CLI JSON/Markdown output and Django upload/demo report flows. PCAP reader
  JSON handling of quotes, separators and newlines is tested with mocked output;
  an optional integration test runs actual
  TShark against synthetic IPv4 TCP and IPv6 DNS packet bytes. This is not a
  production-PCAP benchmark.

## Next priorities (not implemented)

1. **Environment-specific configuration and allowlists.** Let analysts tune
   windows and thresholds, identify approved scanners/resolvers, and explain
   suppressed findings. This should precede broad production deployment.
2. **Persistent capture-coverage summary.** Show which detectors had sufficient
   fields, packet-drop indicators and capture-direction limits directly in every
   dashboard report. Current CSV warnings are a first step.
3. **Queued analysis and streaming ingestion.** The current dashboard runs work
   synchronously and the parser reads captures into memory. Background jobs,
   bounded uploads and chunked ingestion are needed for large captures.
4. **DNS transaction correlation.** Collect transaction identifiers and match
   requests/replies to distinguish timeouts, latency and duplicate observations.
