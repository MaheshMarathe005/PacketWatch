from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("analyze/", views.analyze, name="analyze"),
    path("run/<int:pk>/", views.report_detail, name="report_detail"),
    path("run/<int:pk>/delete/", views.delete_run, name="delete_run"),
]
