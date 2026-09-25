"""Views for the PacketWatch dashboard."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from . import services
from .models import CaptureRun

ALLOWED_EXT = {".pcap", ".pcapng", ".cap", ".csv"}


def index(request):
    runs = CaptureRun.objects.all()[:25]
    return render(request, "dashboard/index.html", {"runs": runs})


@require_POST
def analyze(request):
    # Demo button.
    if request.POST.get("mode") == "demo":
        try:
            run = services.run_demo()
        except Exception as exc:  # noqa: BLE001
            messages.error(request, f"Demo analysis failed: {exc}")
            return redirect("index")
        messages.success(request, "Analysed the synthetic demo capture.")
        return redirect("report_detail", pk=run.pk)

    upload = request.FILES.get("capture")
    if not upload:
        messages.error(request, "Please choose a capture file or run the demo.")
        return redirect("index")

    ext = os.path.splitext(upload.name)[1].lower()
    if ext not in ALLOWED_EXT:
        messages.error(request, f"Unsupported file type '{ext}'. "
                                "Use .pcap, .pcapng, .cap or .csv.")
        return redirect("index")

    # Stream the upload to disk under media/uploads/<timestamp>/.
    sub = timezone.now().strftime("uploads/%Y%m%d-%H%M%S-%f")
    dest_dir = Path(settings.MEDIA_ROOT) / sub
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / upload.name
    with open(dest, "wb") as fh:
        for chunk in upload.chunks():
            fh.write(chunk)

    try:
        run = services.run_from_path(str(dest), display_name=upload.name)
    except Exception as exc:  # noqa: BLE001
        messages.error(request, f"Could not analyse '{upload.name}': {exc}")
        return redirect("index")
    messages.success(request, f"Analysed {upload.name}.")
    if ext == ".csv":
        messages.info(request, "CSV analysis uses only exported fields. Check the "
                      "downloadable report for capture limitations; pcap/pcapng "
                      "provides the most complete detector coverage.")
    return redirect("report_detail", pk=run.pk)


def report_detail(request, pk):
    run = get_object_or_404(CaptureRun, pk=pk)
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    sev_summary = [(s, run.severity_counts.get(s, 0)) for s in sev_order
                   if run.severity_counts.get(s, 0)]
    chart_titles = [
        ("findings", "Findings by severity"),
        ("timeline", "Traffic rate over time"),
        ("protocols", "Protocol distribution"),
        ("top_talkers", "Top talkers"),
        ("syn_scatter", "SYN targets over time"),
        ("dns_entropy", "DNS length vs entropy"),
    ]
    charts = [(title, run.charts[key]) for key, title in chart_titles
              if key in run.charts]
    return render(request, "dashboard/report.html", {
        "run": run, "sev_summary": sev_summary, "charts": charts,
    })


@require_POST
def delete_run(request, pk):
    run = get_object_or_404(CaptureRun, pk=pk)
    # Remove the run's generated media directory (charts + report + json).
    rel = run.report_rel or run.json_rel
    if rel:
        run_dir = (Path(settings.MEDIA_ROOT) / rel).parent
        try:
            if run_dir.is_dir() and run_dir != Path(settings.MEDIA_ROOT):
                shutil.rmtree(run_dir)
        except OSError:
            pass
    run.delete()
    messages.success(request, "Deleted analysis run.")
    return redirect("index")
