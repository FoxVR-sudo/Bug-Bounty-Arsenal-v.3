"""
WebSocket consumers for real-time scan progress updates
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time scan progress updates.

    Clients connect to ws://domain/ws/scan/<scan_id>/
    and receive real-time updates about scan progress.
    """

    async def connect(self):
        """Handle WebSocket connection"""
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.room_group_name = f'scan_{self.scan_id}'

        # Check if user is authenticated
        user = self.scope.get('user')
        if user is None or isinstance(user, AnonymousUser):
            await self.close()
            return

        # Verify user has access to this scan
        has_access = await self.check_scan_access(user, self.scan_id)
        if not has_access:
            await self.close()
            return

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        # Send initial scan status
        scan_data = await self.get_scan_status(self.scan_id)
        if scan_data:
            await self.send(text_data=json.dumps({
                'type': 'scan_status',
                'data': scan_data
            }))

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

    async def receive(self, text_data):
        """Handle messages from WebSocket client"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong'
                }))
            elif message_type == 'get_status':
                scan_data = await self.get_scan_status(self.scan_id)
                if scan_data:
                    await self.send(text_data=json.dumps({
                        'type': 'scan_status',
                        'data': scan_data
                    }))
        except json.JSONDecodeError:
            pass

    async def scan_update(self, event):
        """
        Handle scan update events from channel layer.
        Called when scan progress updates are sent to the group.
        """
        await self.send(text_data=json.dumps({
            'type': 'scan_update',
            'data': event['data']
        }))

    async def scan_complete(self, event):
        """Handle scan completion event"""
        await self.send(text_data=json.dumps({
            'type': 'scan_complete',
            'data': event['data']
        }))

    async def scan_error(self, event):
        """Handle scan error event"""
        await self.send(text_data=json.dumps({
            'type': 'scan_error',
            'data': event['data']
        }))

    @database_sync_to_async
    def check_scan_access(self, user, scan_id):
        """Check if user has access to this scan"""
        from scans.models import Scan
        try:
            scan = Scan.objects.get(id=scan_id)
            # User must own the scan or be admin
            return scan.user == user or user.is_staff
        except Scan.DoesNotExist:
            return False

    @database_sync_to_async
    def get_scan_status(self, scan_id):
        """Get current scan status from database"""
        from scans.models import Scan
        try:
            scan = Scan.objects.get(id=scan_id)
            return {
                'id': scan.id,
                'target': scan.target,
                'status': scan.status,
                'progress': getattr(scan, 'progress', 0),
                'current_step': getattr(scan, 'current_step', ''),
                'vulnerabilities_found': scan.vulnerabilities_found,
                'severity_counts': scan.severity_counts,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            }
        except Scan.DoesNotExist:
            return None
