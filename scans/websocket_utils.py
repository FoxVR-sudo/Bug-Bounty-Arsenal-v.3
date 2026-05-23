"""
Utility functions for WebSocket communications
"""
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def send_scan_update(scan_id, data):
    """
    Send a scan update via WebSocket to all connected clients.

    Args:
        scan_id: The scan ID
        data: Dictionary with update data
    """
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return

    group_name = f'scan_{scan_id}'

    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            'type': 'scan_update',
            'data': data
        }
    )


def send_scan_complete(scan_id, data):
    """
    Send scan completion notification via WebSocket.

    Args:
        scan_id: The scan ID
        data: Dictionary with completion data
    """
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return

    group_name = f'scan_{scan_id}'

    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            'type': 'scan_complete',
            'data': data
        }
    )


def send_scan_error(scan_id, data):
    """
    Send scan error notification via WebSocket.

    Args:
        scan_id: The scan ID
        data: Dictionary with error data
    """
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return

    group_name = f'scan_{scan_id}'

    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            'type': 'scan_error',
            'data': data
        }
    )
