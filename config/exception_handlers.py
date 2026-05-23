"""
Custom exception handlers for better error messages
"""
from rest_framework.views import exception_handler
from rest_framework import status


def custom_exception_handler(exc, context):
    """
    Custom exception handler that provides better throttle messages
    """
    response = exception_handler(exc, context)

    if response is not None and response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        # Get wait time from response
        wait_time = response.data.get('detail', '')

        # Extract seconds from the message
        if 'Expected available in' in str(wait_time):
            try:
                # Extract seconds
                seconds = int(''.join(filter(str.isdigit, str(wait_time))))

                # Convert to friendly format
                if seconds >= 3600:
                    hours = seconds // 3600
                    minutes = (seconds % 3600) // 60
                    friendly_time = f"{hours} hour{'s' if hours > 1 else ''}"
                    if minutes > 0:
                        friendly_time += f" and {minutes} minute{'s' if minutes > 1 else ''}"
                elif seconds >= 60:
                    minutes = seconds // 60
                    friendly_time = f"{minutes} minute{'s' if minutes > 1 else ''}"
                else:
                    friendly_time = f"{seconds} second{'s' if seconds > 1 else ''}"

                response.data = {
                    'error': f'Too many login attempts. Please try again in {friendly_time}.',
                    'wait_seconds': seconds,
                    'retry_after': friendly_time
                }
            except (ValueError, TypeError):
                response.data = {
                    'error': 'Too many login attempts. Please try again later.',
                }

    return response
