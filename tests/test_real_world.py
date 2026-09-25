"""Regression tests for real capture ingestion and time-bounded detections.

Also runnable without pytest: python -m unittest discover -s tests -p test_real_world.py
"""

import contextlib
import io
import json
import shutil
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from netsec_analyzer import database, detectors, ingest
from netsec_analyzer.cli import main
from netsec_analyzer.sample_data import generate_capture


def sweep_rows(count=20, **overrides):
    rows = []
    for i in range(count):
        row = dict(ts=50 + i, src_ip="10.0.0.8", dst_ip=f"10.0.1.{i + 1}",
                   protocol="TCP", transport="TCP", src_port=50000 + i,
                   dst_port=445, tcp_syn=1, tcp_ack=0, length=74)
        row.update(overrides)
        rows.append(row)
    return rows


def dns_rows(count=30, **overrides):
    rows = []
    for i in range(count):
        row = dict(ts=290 + i, src_ip="10.0.0.1", dst_ip="10.0.0.8",
                   protocol="DNS", transport="UDP", src_port=53, dst_port=50000 + i,
                   dns_response=1, dns_rcode=(2, 3, 5)[i % 3],
                   dns_qry_name=f"service{i}.example.invalid", length=90)
        row.update(overrides)
        rows.append(row)
    return rows


def frame(rows):
    return ingest._coerce_schema(pd.DataFrame(rows))


class DetectionTests(unittest.TestCase):
    def test_sweep_crosses_clock_boundary_and_ignores_long_capture(self):
        rows = sweep_rows() + sweep_rows(1, ts=5000, dst_ip="10.0.1.100")
        findings = detectors.detect_service_sweep(frame(rows[::-1]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metrics["distinct_hosts"], 20)
        self.assertEqual(len(findings[0].evidence), 20)
        self.assertNotIn("10.0.1.100", findings[0].evidence.dst_ip.tolist())

    def test_sweep_counts_targets_not_retransmissions(self):
        self.assertEqual(detectors.detect_service_sweep(
            frame(sweep_rows(100, dst_ip="10.0.1.1"))), [])

    def test_sweep_does_not_combine_sources_ports_or_acknowledgements(self):
        for field, value in (("src_ip", "10.0.0.9"), ("dst_port", 3389), ("tcp_ack", 1)):
            with self.subTest(field=field):
                rows = sweep_rows()
                for row in rows[10:]:
                    row[field] = value
                self.assertEqual(detectors.detect_service_sweep(frame(rows)), [])

    def test_sweep_window_boundary_and_slow_traffic(self):
        rows = sweep_rows(19, ts=0) + sweep_rows(1, ts=60, dst_ip="10.0.1.20")
        self.assertEqual(len(detectors.detect_service_sweep(frame(rows))), 1)
        rows[-1]["ts"] = 60.001
        self.assertEqual(detectors.detect_service_sweep(frame(rows)), [])

    def test_sweep_reports_only_peak_window_per_source_service(self):
        rows = sweep_rows(20) + [dict(row, ts=row["ts"] + 400) for row in sweep_rows(25)]
        findings = detectors.detect_service_sweep(frame(rows))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metrics["distinct_hosts"], 25)

    def test_dns_failure_types_client_attribution_and_evidence(self):
        findings = detectors.detect_dns_failures(frame(dns_rows()[::-1]))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.id, "dnsfail-10.0.0.8")
        self.assertEqual(finding.metrics["failure_ratio"], 1.0)
        for name in ("servfail", "nxdomain", "refused"):
            self.assertEqual(finding.metrics[name], 10)
        self.assertEqual(set(finding.evidence.response), {"SERVFAIL", "NXDOMAIN", "REFUSED"})
        self.assertEqual(finding.category, "Network Reliability")
        self.assertNotIn("T1568", finding.mitre)

    def test_dns_successes_in_denominator(self):
        rows = []
        for i, row in enumerate(dns_rows()):
            for j in range(3):
                rows.append(dict(row, ts=i * 4 + j, dns_rcode=0))
            rows.append(dict(row, ts=i * 4 + 3))
        self.assertEqual(detectors.detect_dns_failures(frame(rows)), [])

    def test_dns_queries_unknown_codes_and_small_samples_do_not_alert(self):
        for rows in (dns_rows(29), dns_rows(dns_response=0),
                     dns_rows(dns_rcode=None), dns_rows(dns_rcode=0),
                     dns_rows(dns_response=None)):
            with self.subTest(rows=rows[0]):
                self.assertEqual(detectors.detect_dns_failures(frame(rows)), [])

    def test_dns_clients_are_not_combined(self):
        rows = dns_rows(20) + dns_rows(20, dst_ip="10.0.0.9")
        self.assertEqual(detectors.detect_dns_failures(frame(rows)), [])

    def test_dns_window_is_bounded(self):
        rows = [dict(row, ts=i * 20) for i, row in enumerate(dns_rows())]
        self.assertEqual(detectors.detect_dns_failures(frame(rows)), [])

    def test_detectors_skip_missing_timestamps(self):
        for detector, rows in ((detectors.detect_service_sweep, sweep_rows(ts=None)),
                               (detectors.detect_dns_failures, dns_rows(ts=None))):
            self.assertEqual(detector(frame(rows)), [])

    def test_invalid_thresholds(self):
        df = frame([])
        for detector, kwargs in ((detectors.detect_service_sweep, {"window_s": 0}),
                                 (detectors.detect_service_sweep, {"min_hosts": 1}),
                                 (detectors.detect_dns_failures, {"window_s": float("nan")}),
                                 (detectors.detect_dns_failures, {"min_failure_ratio": 2})):
            with self.assertRaises(ValueError):
                detector(df, **kwargs)

    def test_demo_integrates_both_new_detectors(self):
        df = generate_capture()
        conn = database.build_database(df)
        try:
            ids = {f.id for f in detectors.run_all(df, conn)}
        finally:
            conn.close()
        self.assertIn("sweep-10.0.0.88-445", ids)
        self.assertIn("dnsfail-10.0.0.109", ids)


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def read(self, rows):
        path = self.root / "capture.csv"
        pd.DataFrame(rows).to_csv(path, index=False)
        return ingest.read_csv(str(path))

    def test_wireshark_summary_csv_and_zero_based_duration(self):
        df = self.read([
            {"No.": i + 1, "Time": i * 2, "Source": "10.0.0.8",
             "Destination": "10.0.0.1", "Protocol": "TCP", "Length": 74,
             "Info": '50000 → 445 [SYN], text with "quotes"'} for i in range(2)
        ])
        self.assertEqual(df.src_ip.tolist(), ["10.0.0.8"] * 2)
        self.assertEqual(df.transport.tolist(), ["TCP"] * 2)
        self.assertTrue(df.tcp_syn.isna().all())
        self.assertTrue(df.attrs["analysis_warnings"])
        conn = database.build_database(df)
        try:
            self.assertEqual(database.summary(conn)["duration_s"], 2.0)
        finally:
            conn.close()

    def test_dotted_tshark_headers_keep_ports_flags_and_dns_fields(self):
        df = self.read([
            {"frame.time_epoch": 0, "ip.src": "10.0.0.8", "ip.dst": "10.0.0.1",
             "_ws.col.Protocol": "TCP", "frame.len": 74,
             "tcp.srcport": 50000, "tcp.dstport": 445,
             "tcp.flags.syn": "True", "tcp.flags.ack": "False"},
            {"frame.time_epoch": 1, "ip.src": "10.0.0.1", "ip.dst": "10.0.0.8",
             "_ws.col.Protocol": "DNS", "frame.len": 90,
             "udp.srcport": 53, "udp.dstport": 50001,
             "dns.flags.response": 1, "dns.flags.rcode": 3, "dns.qry.name": "missing.invalid"},
        ])
        self.assertEqual(df.transport.tolist(), ["TCP", "UDP"])
        self.assertEqual(df.iloc[0].dst_port, 445)
        self.assertEqual(df.iloc[0].tcp_syn, 1)
        self.assertEqual(df.iloc[0].tcp_ack, 0)
        self.assertEqual(df.iloc[1].dns_rcode, 3)

    def test_ipv6_endpoints_and_transport_with_extension_header(self):
        df = self.read([{
            "frame.time_epoch": 0, "ipv6.src": "fd00::8", "ipv6.dst": "fd00::1",
            "ipv6.nxt": 0, "_ws.col.Protocol": "DNS", "frame.len": 100,
            "udp.srcport": 50000, "udp.dstport": 53,
        }])
        self.assertEqual(df.iloc[0].src_ip, "fd00::8")
        self.assertEqual(df.iloc[0].transport, "UDP")

    def test_canonical_ports_preserved_without_transport(self):
        df = self.read([dict(ts=0, src_ip="10.0.0.8", protocol="TCP", length=74,
                             src_port=50000, dst_port=445)])
        self.assertEqual(df.iloc[0].dst_port, 445)
        self.assertEqual(df.iloc[0].transport, "TCP")

    def test_missing_optional_fields_do_not_invent_transport(self):
        df = self.read([dict(ts=0, src_ip="10.0.0.8", protocol="DNS", length=74)])
        self.assertEqual(df.iloc[0].transport, "OTHER")
        self.assertTrue(df.src_port.isna().all())

    def test_invalid_input_has_actionable_error(self):
        for row, message in (({"unrelated": "data"}, "Unrecognised"),
                             (dict(ts="12:30:00", protocol="TCP", length=74), "timestamps"),
                             (dict(ts=float("inf"), protocol="TCP", length=74), "timestamps"),
                             (dict(ts=0, protocol="TCP", length=-1), "non-negative"),
                             (dict(ts=0, protocol="TCP", length="bad"), "whole numbers")):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, message):
                self.read([row])

    def test_partial_raw_export_missing_tcp_fields(self):
        df = self.read([dict(ts=0, protocol="DNS", length=90, ip_proto=17,
                             udp_srcport=53, udp_dstport=50000)])
        self.assertEqual(df.iloc[0].src_port, 53)
        self.assertEqual(df.iloc[0].transport, "UDP")

    def test_pcap_reader_preserves_quoted_separator_and_ipv6(self):
        import subprocess
        raw = {"frame_no": "1", "ts": "0", "ipv6_src": "fd00::1",
               "ipv6_dst": "fd00::8", "protocol": "TCP", "length": "74",
               "tcp_srcport": "50000", "tcp_dstport": "445", "tcp_syn": "1",
               "tcp_ack": "0", "info": 'quoted "text" | separator\nnext\tline \\path'}
        layers = {field.lower(): [raw[col]] for field, col in ingest._TSHARK_FIELDS if col in raw}
        layers["ipv6.src"].append("fd00::99")
        layers["dns.qry.name"] = []
        output = json.dumps([{"_source": {"layers": layers}}])
        with patch.object(ingest.shutil, "which", return_value="/usr/bin/tshark"), \
                patch.object(ingest.subprocess, "run", return_value=
                             subprocess.CompletedProcess([], 0, output, "")) as run:
            df = ingest.read_pcap("capture.pcapng")
        self.assertEqual(run.call_args.args[0][3:5], ["-T", "json"])
        self.assertEqual(df.iloc[0]["info"], raw["info"])
        self.assertEqual(df.iloc[0].src_ip, "fd00::1")
        self.assertEqual(df.iloc[0].protocol, "TCP")

    def test_pcap_reader_handles_empty_capture_and_invalid_output(self):
        import subprocess
        with patch.object(ingest.shutil, "which", return_value="/usr/bin/tshark"), \
                patch.object(ingest.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "[]", "")
            self.assertTrue(ingest.read_pcap("empty.pcap").empty)
            run.return_value = subprocess.CompletedProcess([], 0, "invalid JSON", "")
            with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                ingest.read_pcap("broken.pcap")

    @unittest.skipUnless(shutil.which("tshark"), "optional tshark binary unavailable")
    def test_actual_tshark_ipv4_sweep_and_ipv6_dns_failures(self):
        """Decode real synthetic packet bytes, including valid IP/transport checksums."""
        def checksum(data):
            data += b"\x00" * (len(data) % 2)
            total = sum(struct.unpack(f"!{len(data) // 2}H", data))
            while total >> 16:
                total = (total & 0xffff) + (total >> 16)
            return (~total) & 0xffff

        packets = []
        for i in range(20):
            src, dst = socket.inet_aton("10.0.0.8"), socket.inet_aton(f"10.0.1.{i + 1}")
            tcp = struct.pack("!HHIIHHHH", 50000 + i, 445, i, 0, 0x5002, 65535, 0, 0)
            pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
            tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, i, 0, 64, 6, 0, src, dst)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            packets.append(bytes(12) + b"\x08\x00" + ip + tcp)
        for i in range(30):
            src = socket.inet_pton(socket.AF_INET6, "fd00::1")
            dst = socket.inet_pton(socket.AF_INET6, "fd00::8")
            name = b"\x07missing\x07invalid\x00"
            dns = struct.pack("!HHHHHH", i, 0x8183, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
            udp = struct.pack("!HHHH", 53, 50000 + i, 8 + len(dns), 0) + dns
            pseudo = src + dst + struct.pack("!I3xB", len(udp), 17)
            udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xffff) + udp[8:]
            ip = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64, src, dst)
            packets.append(bytes(12) + b"\x86\xdd" + ip + udp)
        path = self.root / "network.pcap"
        with path.open("wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, packet in enumerate(packets):
                stream.write(struct.pack("<IIII", i, 0, len(packet), len(packet)))
                stream.write(packet)
        df = ingest.load(str(path))
        self.assertEqual(len(df), 50)
        self.assertEqual(detectors.detect_service_sweep(df)[0].metrics["distinct_hosts"], 20)
        finding = detectors.detect_dns_failures(df)[0]
        self.assertEqual(finding.id, "dnsfail-fd00::8")
        self.assertEqual(finding.metrics["nxdomain"], 30)

    def test_cli_exports_new_findings_and_summary_limitations(self):
        self.read(sweep_rows() + dns_rows())
        json_path = self.root / "findings.json"
        with contextlib.redirect_stdout(io.StringIO()):
            status = main([str(self.root / "capture.csv"), "--no-charts",
                           "-o", str(self.root), "--json", str(json_path)])
        self.assertEqual(status, 0)
        findings = json.loads(json_path.read_text())
        ids = {finding["id"] for finding in findings}
        self.assertIn("sweep-10.0.0.8-445", ids)
        self.assertIn("dnsfail-10.0.0.8", ids)
        self.assertIn("NXDOMAIN", (self.root / "report.md").read_text())
        self.read([{"Time": 0, "Source": "10.0.0.8", "Destination": "10.0.0.1",
                    "Protocol": "TCP", "Length": 74}])
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            self.assertEqual(main([str(self.root / "capture.csv"), "--no-charts",
                                   "-o", str(self.root)]), 0)
        self.assertIn("warning:", stderr.getvalue())
        self.assertIn("Capture limitation", (self.root / "report.md").read_text())


if __name__ == "__main__":
    unittest.main()
