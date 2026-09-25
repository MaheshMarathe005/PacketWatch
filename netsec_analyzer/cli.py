"""Command-line entry point that ties the pipeline together.

    ingest -> SQLite -> detectors -> charts -> Markdown report

Run ``python -m netsec_analyzer --help`` for options.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, database as db, detectors, ingest, report, visualize
from .sample_data import generate_capture, save_csv

_SEV_ICON = {"Critical": "\033[95m●\033[0m", "High": "\033[91m●\033[0m",
             "Medium": "\033[93m●\033[0m", "Low": "\033[94m●\033[0m",
             "Info": "\033[90m●\033[0m"}


def _load_capture(args) -> tuple:
    """Return (dataframe, display_name) from --demo or a capture path."""
    if args.demo or not args.capture:
        os.makedirs("sample_captures", exist_ok=True)
        path = "sample_captures/synthetic_capture.csv"
        df = generate_capture(seed=args.seed)
        save_csv(df, path)
        return ingest.read_csv(path), f"{path} (synthetic demo)"
    return ingest.load(args.capture), args.capture


def _print_console(summary: dict, findings: list, report_path: str,
                   charts: dict) -> None:
    print("\n" + "=" * 68)
    print(" PacketWatch — results")
    print("=" * 68)
    print(f" packets={summary['packets']:,}  duration={summary['duration_s']:.1f}s  "
          f"bytes={summary['total_bytes']:,}  hosts={summary['distinct_sources']}")
    print("-" * 68)
    if not findings:
        print(" No threats detected. ✅")
    else:
        for i, f in enumerate(findings, 1):
            icon = _SEV_ICON.get(f.severity, "●")
            print(f" {icon} [{f.severity:8}] {f.category:26} {f.title}")
    print("-" * 68)
    if charts:
        print(f" charts : {len(charts)} PNG(s) in {os.path.dirname(report_path) or '.'}/")
    print(f" report : {report_path}")
    print("=" * 68 + "\n")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsec_analyzer",
        description="Detect network-security threats in a Wireshark capture "
                    "using pandas/numpy analytics and a SQLite database.")
    p.add_argument("capture", nargs="?",
                   help="path to a .pcap/.pcapng or .csv capture "
                        "(omit, or use --demo, to analyse a synthetic sample)")
    p.add_argument("--demo", action="store_true",
                   help="generate and analyse a synthetic capture with known attacks")
    p.add_argument("-o", "--outdir", default="output",
                   help="directory for charts and report (default: output)")
    p.add_argument("--db", metavar="PATH",
                   help="also persist the SQLite analysis DB to this file")
    p.add_argument("--no-charts", action="store_true", help="skip chart rendering")
    p.add_argument("--json", metavar="PATH",
                   help="write machine-readable findings to this JSON file")
    p.add_argument("--seed", type=int, default=42,
                   help="RNG seed for the synthetic capture (default: 42)")
    p.add_argument("--version", action="version",
                   version=f"PacketWatch {__version__}")
    return p


def _findings_to_json(findings: list) -> list:
    out = []
    for f in findings:
        out.append({
            "id": f.id, "title": f.title, "category": f.category,
            "severity": f.severity, "mitre": f.mitre,
            "description": f.description, "recommendation": f.recommendation,
            "metrics": f.metrics,
            "evidence": f.evidence.head(20).to_dict(orient="records"),
        })
    return out


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        df, name = _load_capture(args)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if df.empty:
        print("error: capture contains no packets", file=sys.stderr)
        return 2

    for warning in df.attrs.get("analysis_warnings", []):
        print(f"warning: {warning}", file=sys.stderr)

    os.makedirs(args.outdir, exist_ok=True)
    conn = db.build_database(df, db_path=args.db or ":memory:")
    summary = db.summary(conn)
    summary["analysis_warnings"] = df.attrs.get("analysis_warnings", [])
    findings = detectors.run_all(df, conn)

    charts = {}
    if not args.no_charts:
        charts = visualize.generate_all(df, conn, findings, args.outdir)

    report_path = report.write_report(summary, findings, charts, name, args.outdir)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(_findings_to_json(findings), fh, indent=2)

    _print_console(summary, findings, report_path, charts)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
