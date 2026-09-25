"""Tests for NetThreat: detectors fire on known attacks and stay quiet on
benign traffic, plus ingest/database/helper coverage.

Runs under ``pytest`` when it is installed. If pytest is unavailable, the
file is still executable directly (``python tests/test_detectors.py``) via a
minimal built-in runner defined at the bottom.
"""

from __future__ import annotations

import inspect
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd

try:
    import pytest
    HAVE_PYTEST = True
except ModuleNotFoundError:  # pragma: no cover - offline fallback
    HAVE_PYTEST = False

    class _Approx:
        def __init__(self, exp, abs=None, rel=None):
            self.exp, self.abs, self.rel = exp, abs, rel

        def __eq__(self, other):
            tol = self.abs if self.abs is not None else max(
                abs(self.exp), abs(other)) * (self.rel or 1e-6)
            return abs(other - self.exp) <= tol

        def __repr__(self):
            return f"approx({self.exp}, abs={self.abs}, rel={self.rel})"

    class _PytestShim:
        @staticmethod
        def fixture(func=None, **_kw):
            def mark(fn):
                fn.__is_fixture__ = True
                return fn
            return mark(func) if callable(func) else mark

        approx = staticmethod(lambda exp, abs=None, rel=None: _Approx(exp, abs, rel))

    pytest = _PytestShim()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from netsec_analyzer import PACKET_COLUMNS, database as db, detectors, ingest
from netsec_analyzer.sample_data import generate_capture


@pytest.fixture(scope="module")
def capture():
    """Full synthetic capture + its SQLite connection (built once)."""
    df = generate_capture(seed=7)
    conn = db.build_database(df)
    findings = detectors.run_all(df, conn)
    by_id = {f.id.split("-")[0]: f for f in findings}
    return {"df": df, "conn": conn, "findings": findings, "by_kind": by_id}


def make_df(rows: list[dict], tmp_path) -> pd.DataFrame:
    """Round-trip rows through CSV ingestion to get a normalised frame."""
    df = pd.DataFrame(rows, columns=PACKET_COLUMNS)
    df["frame_no"] = range(1, len(df) + 1)
    path = tmp_path / "cap.csv"
    df.to_csv(path, index=False)
    return ingest.read_csv(str(path))


def _row(**kw) -> dict:
    base = {c: None for c in PACKET_COLUMNS}
    base.update(kw)
    return base

# --------------------------------------------------------------------------
# Attacks embedded in the synthetic capture must all be detected.
# --------------------------------------------------------------------------

def test_all_expected_categories_detected(capture):
    cats = {f.category for f in capture["findings"]}
    for expected in ["Reconnaissance", "Denial of Service", "Man-in-the-Middle",
                     "Command and Control", "Exfiltration"]:
        assert expected in cats, f"missing category {expected!r}"


def test_port_scan(capture):
    fs = detectors.detect_port_scan(capture["conn"])
    assert any("10.0.0.66" in f.title for f in fs)
    # The brute-force host (one port, many attempts) is NOT a port scan.
    assert not any("10.0.0.77" in f.title for f in fs)


def test_syn_flood(capture):
    fs = detectors.detect_syn_flood(capture["conn"])
    assert len(fs) == 1
    assert fs[0].metrics["sources"] >= 50


def test_arp_spoofing(capture):
    fs = detectors.detect_arp_spoofing(capture["df"])
    assert len(fs) == 1 and fs[0].severity == "Critical"
    assert fs[0].metrics["claimed_macs"] >= 2


def test_dns_tunneling(capture):
    fs = detectors.detect_dns_tunneling(capture["df"])
    assert any("exfil-c2.net" in f.title for f in fs)
    assert fs[0].metrics["mean_entropy"] >= 3.5


def test_beaconing_single_direction(capture):
    fs = detectors.detect_beaconing(capture["df"])
    # The beacon and its reply must collapse to one internal->external finding.
    assert len(fs) == 1
    assert fs[0].metrics["interval_s"] == pytest.approx(30, abs=3)
    assert fs[0].metrics["cv"] <= 0.15


def test_data_exfiltration(capture):
    fs = detectors.detect_data_exfiltration(capture["conn"])
    assert any("91.203.145.9" in f.title for f in fs)
    assert fs[0].metrics["ratio"] >= 5


def test_brute_force(capture):
    fs = detectors.detect_brute_force(capture["conn"])
    assert any(f.metrics["service"] == "SSH" for f in fs)


def test_cleartext(capture):
    fs = detectors.detect_cleartext_credentials(capture["conn"])
    assert len(fs) == 1 and fs[0].metrics["cleartext_packets"] >= 3

# --------------------------------------------------------------------------
# Benign traffic must not raise any findings (false-positive guard).
# --------------------------------------------------------------------------

def test_benign_traffic_is_clean(tmp_path):
    rows = []
    t = 1_700_000_000.0
    for i in range(30):
        c = f"10.0.0.{100 + (i % 5)}"
        rows.append(_row(ts=t + i, src_ip=c, dst_ip="10.0.0.1", protocol="DNS",
                         transport="UDP", src_port=50000 + i, dst_port=53,
                         length=75, dns_qry_name="google.com", dns_qry_type=1,
                         dns_response=0))
        rows.append(_row(ts=t + i + 0.5, src_ip=c, dst_ip="93.184.10.5",
                         protocol="TLS", transport="TCP", src_port=50000 + i,
                         dst_port=443, length=800, tcp_syn=0, tcp_ack=1,
                         tcp_fin=0, tcp_rst=0))
    # consistent, single-MAC ARP for the gateway
    for i in range(4):
        rows.append(_row(ts=t + i * 20, src_ip="10.0.0.1", dst_ip="10.0.0.100",
                         protocol="ARP", transport="ARP", length=42,
                         arp_src_ip="10.0.0.1", arp_src_mac="00:11:22:33:44:01",
                         arp_opcode=2))
    df = make_df(rows, tmp_path)
    conn = db.build_database(df)
    assert detectors.run_all(df, conn) == []


# --------------------------------------------------------------------------
# Helper functions.
# --------------------------------------------------------------------------

def test_entropy_ordering():
    assert detectors.shannon_entropy("aaaaaaaa") < detectors.shannon_entropy("a1b2c3d4")
    assert detectors.shannon_entropy("") == 0.0


def test_is_internal():
    assert detectors.is_internal("10.0.0.5")
    assert detectors.is_internal("192.168.1.1")
    assert not detectors.is_internal("8.8.8.8")
    assert not detectors.is_internal(None)


def test_registered_domain():
    assert detectors.registered_domain("a.b.evil.com") == "evil.com"
    assert detectors.registered_domain("localhost") == "localhost"


# --------------------------------------------------------------------------
# Ingest + database plumbing.
# --------------------------------------------------------------------------

def test_ingest_schema_and_dtypes(capture):
    df = capture["df"]
    assert set(PACKET_COLUMNS).issubset(df.columns)
    assert str(df["src_port"].dtype) == "Int64"
    assert str(df["length"].dtype) == "int64"


def test_database_views(capture):
    conn = capture["conn"]
    conv = db.query(conn, "SELECT COUNT(*) AS n FROM conversations")
    assert conv["n"].iloc[0] > 0
    s = db.summary(conn)
    assert s["packets"] == len(capture["df"]) and s["total_bytes"] > 0


def _run_standalone() -> int:
    """Minimal test runner used when pytest is not installed."""
    g = dict(globals())
    fixtures = {n: f for n, f in g.items() if getattr(f, "__is_fixture__", False)}
    cache: dict[str, object] = {}

    def resolve(name):
        if name == "tmp_path":
            return Path(tempfile.mkdtemp(prefix="netthreat-test-"))
        if name in fixtures:
            if name not in cache:
                cache[name] = fixtures[name]()
            return cache[name]
        raise KeyError(f"unknown fixture {name!r}")

    tests = sorted(n for n, f in g.items()
                   if n.startswith("test_") and callable(f))
    passed, failed = 0, []
    for name in tests:
        fn = g[name]
        kwargs = {p: resolve(p) for p in inspect.signature(fn).parameters}
        try:
            fn(**kwargs)
            passed += 1
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failed.append((name, exc))
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {len(failed)} failed (of {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__" and not HAVE_PYTEST:
    raise SystemExit(_run_standalone())



