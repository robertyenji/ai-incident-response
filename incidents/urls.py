from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('incidents/<uuid:incident_id>/', views.incident_detail, name='incident_detail'),
    path('simulator/', views.simulator, name='simulator'),
    path('controls/', views.controls, name='controls'),
    path('compliance-report/', views.compliance_report, name='compliance_report'),
    # API
    path('api/scan/', views.api_scan, name='api_scan'),
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/incidents/<uuid:incident_id>/resolve/', views.resolve_incident, name='resolve_incident'),
    path('api/incidents/<uuid:incident_id>/false-positive/', views.false_positive, name='false_positive'),
]
