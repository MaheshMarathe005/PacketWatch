"""Bridge between Django and the ``netsec_analyzer`` analysis pipeline."""

from __future__ import annotations

import json
import os
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from netsec_analyzer import database, detectors, ingest, report, visualize
from netsec_analyzer.sample_data import generate_capture

from .models import CaptureRun

_EVIDENCE_LIMIT = 15


def _serialize_evidence(df) -> dict:
    if df is None or getattr(df, "empty", True):
        return {"columns": [], "rows": [], "total": 0, "truncated": False}
    cols = [str(c) for c in df.columns]
    rows = [[report._fmt(v) for v in rec]
            for rec in df.head(_EVIDENCE_LIMIT).itertuples(index=False, name=None)]
    return {"columns": cols, "rows": rows, "total": int(len(df)),
            "truncated": len(df) > _EVIDENCE_LIMIT}


def _serialize_finding(f) -> dict:
    return {
        "id": f.id, "title": f.title, "category": f.category,
        "severity": f.severity, "mitre": f.mitre, "description": f.description,
        "recommendation": f.recommendation,
        "metrics": {str(k): (v if isinstance(v, (int, float, str, bool)) else str(v))
                    for k, v in (f.metrics or {}).items()},
        "evidence": _serialize_evidence(f.evidence),
    }


def analyze_dataframe(df, name: str, source: str) -> CaptureRun:
    """Run the full pipeline on a DataFrame and persist a CaptureRun."""
    conn = database.build_database(df)
    summary = database.summary(conn)
    summary["analysis_warnings"] = df.attrs.get("analysis_warnings", [])
    findings = detectors.run_all(df, conn)

    run_rel = timezone.now().strftime("runs/%Y%m%d-%H%M%S-%f")
    outdir = Path(settings.MEDIA_ROOT) / run_rel
    outdir.mkdir(parents=True, exist_ok=True)

    charts_abs = visualize.generate_all(df, conn, findings, str(outdir))
    charts_rel = {k: os.path.relpath(v, settings.MEDIA_ROOT)
                  for k, v in charts_abs.items()}

    report_path = report.write_report(summary, findings, charts_abs, name, str(outdir))
    serial = [_serialize_finding(f) for f in findings]
    json_path = outdir / "findings.json"
    json_path.write_text(json.dumps(serial, indent=2), encoding="utf-8")

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return CaptureRun.objects.create(
        name=name, source=source,
        packets=summary["packets"], duration_s=summary["duration_s"],
        total_bytes=summary["total_bytes"],
        distinct_sources=summary["distinct_sources"],
        distinct_destinations=summary["distinct_destinations"],
        findings=serial, charts=charts_rel, severity_counts=sev_counts,
        report_rel=os.path.relpath(report_path, settings.MEDIA_ROOT),
        json_rel=os.path.relpath(json_path, settings.MEDIA_ROOT),
    )


def run_demo(seed: int = 42) -> CaptureRun:
    df = generate_capture(seed=seed)
    return analyze_dataframe(df, name="Synthetic demo capture", source="demo")


def run_from_path(path: str, display_name: str) -> CaptureRun:
    df = ingest.load(path)
    if df.empty:
        raise ValueError("The capture contained no parseable packets.")
    return analyze_dataframe(df, name=display_name, source="upload")
