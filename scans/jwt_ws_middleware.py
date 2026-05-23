from __future__ import annotations

from urllib.parse import parse_qs

from channels.auth import AuthMiddlewareStack
from channels.db import database_sync_to_async


@database_sync_to_async
def _get_user_from_token(token: str):
    from rest_framework_simplejwt.authentication import JWTAuthentication

    jwt_auth = JWTAuthentication()
    validated = jwt_auth.get_validated_token(token)
    return jwt_auth.get_user(validated)


class JWTAuthMiddleware:
    """Authenticate Channels WebSocket connections using a JWT passed as querystring.

    Frontend connects to: ws(s)://<host>/ws/scan/<scan_id>/?token=<jwt>

    If token is missing/invalid, downstream middleware determines the user
    (e.g. session auth). This preserves compatibility with AuthMiddlewareStack.
    """

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        query_string = scope.get('query_string', b'')
        try:
            query_params = parse_qs(query_string.decode())
        except Exception:
            query_params = {}

        token_values = query_params.get('token') or []
        token = token_values[0] if token_values else None

        if token:
            try:
                scope['user'] = await _get_user_from_token(token)
            except Exception:
                # Keep whatever user is already set (likely AnonymousUser)
                pass

        return await self.inner(scope, receive, send)


def JWTAuthMiddlewareStack(inner):
    return JWTAuthMiddleware(AuthMiddlewareStack(inner))
