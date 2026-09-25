"""Exercise upload/demo routes and persistence using an isolated test database."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import CaptureRun


class AnalysisFlowTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.media = Path(directory.name)
        override = override_settings(MEDIA_ROOT=directory.name)
        override.enable()
        self.addCleanup(override.disable)
        charts = patch("dashboard.services.visualize.generate_all", return_value={})
        charts.start()
        self.addCleanup(charts.stop)

    def test_demo_persists_and_renders_new_findings(self):
        response = self.client.post(reverse("analyze"), {"mode": "demo"}, follow=True)
        self.assertEqual(response.status_code, 200)
        run = CaptureRun.objects.get()
        ids = {finding["id"] for finding in run.findings}
        self.assertIn("sweep-10.0.0.88-445", ids)
        self.assertIn("dnsfail-10.0.0.109", ids)
        self.assertContains(response, "Possible SMB service sweep")
        self.assertContains(response, "DNS lookup failure burst")
        self.assertContains(response, "SERVFAIL")
        exported = json.loads((self.media / run.json_rel).read_text())
        self.assertEqual(len(exported), len(run.findings))

    def test_wireshark_csv_upload_explains_limited_coverage(self):
        upload = SimpleUploadedFile("packets.csv", (
            "No.,Time,Source,Destination,Protocol,Length,Info\n"
            "1,0,10.0.0.8,10.0.0.1,TCP,74,SYN\n"
            "2,2,10.0.0.8,10.0.0.1,TCP,74,SYN\n"
        ).encode(), content_type="text/csv")
        response = self.client.post(reverse("analyze"), {"capture": upload}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CSV analysis uses only exported fields")
        run = CaptureRun.objects.get()
        self.assertEqual(run.duration_s, 2)
        self.assertIn("Capture limitation", (self.media / run.report_rel).read_text())

    def test_invalid_csv_displays_error_without_creating_run(self):
        upload = SimpleUploadedFile("unrelated.csv", b"item,quantity\nbook,2\n")
        response = self.client.post(reverse("analyze"), {"capture": upload}, follow=True)
        self.assertContains(response, "Unrecognised capture CSV")
        self.assertFalse(CaptureRun.objects.exists())
