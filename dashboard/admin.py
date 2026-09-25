from django.contrib import admin

from .models import CaptureRun


@admin.register(CaptureRun)
class CaptureRunAdmin(admin.ModelAdmin):
    list_display = ("name", "source", "created", "packets", "finding_count",
                    "top_severity")
    list_filter = ("source", "created")
    search_fields = ("name",)
    readonly_fields = ("created",)
