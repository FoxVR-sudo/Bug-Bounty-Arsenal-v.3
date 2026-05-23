"""
WebSocket URL routing configuration
"""
from django.urls import path
from scans import consumers

websocket_urlpatterns = [
    path('ws/scan/<str:scan_id>/', consumers.ScanProgressConsumer.as_asgi()),
]
