"""Persistence for analysis runs.

Each capture that gets analysed becomes a ``CaptureRun`` row so the dashboard
can show history and re-open past reports. The heavy per-packet analytics live
in an in-memory SQLite DB built by :mod:`netsec_analyzer.database`; this model
only stores the run summary, findings and chart locations via the Django ORM.
"""

from __future__ import annotations

from django.db import models


class CaptureRun(models.Model):
    SOURCE_CHOICES = [("demo", "Synthetic demo"), ("upload", "Uploaded capture")]

    name = models.CharField(max_length=255)
    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default="upload")
    created = models.DateTimeField(auto_now_add=True)

    # Capture summary (from database.summary()).
    packets = models.IntegerField(default=0)
    duration_s = models.FloatField(default=0.0)
    total_bytes = models.BigIntegerField(default=0)
    distinct_sources = models.IntegerField(default=0)
    distinct_destinations = models.IntegerField(default=0)

    # Results.
    findings = models.JSONField(default=list)          # serialized Finding list
    charts = models.JSONField(default=dict)            # name -> media-relative path
    severity_counts = models.JSONField(default=dict)   # {"Critical": 1, ...}
    report_rel = models.CharField(max_length=512, blank=True, default="")
    json_rel = models.CharField(max_length=512, blank=True, default="")

    class Meta:
        ordering = ["-created"]

    def __str__(self) -> str:
        return f"{self.name} ({self.created:%Y-%m-%d %H:%M})"

    @property
    def finding_count(self) -> int:
        return len(self.findings or [])

    @property
    def top_severity(self) -> str:
        order = ["Critical", "High", "Medium", "Low", "Info"]
        for sev in order:
            if (self.severity_counts or {}).get(sev):
                return sev
        return "None"

    @property
    def is_clean(self) -> bool:
        return self.finding_count == 0
