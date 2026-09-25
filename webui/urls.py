"""Root URL configuration."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("dashboard.urls")),
]

# Serve generated charts / uploaded captures during local development.
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
