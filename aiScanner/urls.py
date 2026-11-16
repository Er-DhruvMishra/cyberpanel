from django.urls import path

from . import scheduled_views, views

urlpatterns = [
    path('', views.aiScannerHome, name='aiScannerHome'),
    path('start-scan/', views.startScan, name='aiScannerStartScan'),
    path('settings/', views.getSettings, name='aiScannerSettings'),
    path('settings/save/', views.saveSettings, name='aiScannerSaveSettings'),
    path('settings/test-key/', views.testKey, name='aiScannerTestKey'),

    path('scan-history/', views.getScanHistory, name='aiScannerHistory'),
    path('scan-details/<str:scan_id>/', views.getScanDetails, name='aiScannerDetails'),
    path('scan-status/<str:scan_id>/', views.getScanStatus, name='aiScannerScanStatus'),

    path('scheduled-scans/', scheduled_views.scheduledScans, name='aiScannerScheduledScans'),
    path('scheduled-scans/<int:scan_id>/', scheduled_views.scheduledScanDetail, name='aiScannerScheduledScanDetail'),
    path('scheduled-scans/<int:scan_id>/toggle/', scheduled_views.toggleScheduledScan, name='aiScannerToggleScheduledScan'),
    path('scheduled-scans/<int:scan_id>/executions/', scheduled_views.scheduledScanExecutions, name='aiScannerScheduledScanExecutions'),
]
