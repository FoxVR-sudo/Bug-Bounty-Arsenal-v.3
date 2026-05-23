# detectors/interactsh_client.py
"""Interactsh API client used for OOB validations (SSRF, RCE, etc.)."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
from typing import Optional, List, Dict

import aiohttp

logger = logging.getLogger(__name__)

INTERACTSH_SERVER = "interact.sh"  # Fallbacks: oast.pro, oast.live, oast.fun


class InteractshClient:
    """
    Full-featured interact.sh client with polling support.

    Usage:
        client = InteractshClient()
        await client.initialize()

        callback_url = client.generate_url("test123")
        # ... inject callback_url into target ...

        interactions = await client.poll_interactions()
        if interactions:
            print(f"Callbacks received: {interactions}")
    """

    def __init__(self, server: str = INTERACTSH_SERVER):
        # Allow specifying full host or host with protocol; default to https
        if server.startswith("http"):
            self.base_url = server.rstrip("/")
        else:
            self.base_url = f"https://{server.strip()}"
        self.session = None
        self.correlation_id = None
        self.base_domain = None
        self.secret = None
        self.polling_url = None
        self._interactions_cache = []

    async def initialize(self) -> bool:
        """Initialize interact.sh session"""
        try:
            self.correlation_id = secrets.token_hex(8)
            self.secret = secrets.token_hex(16)

            if not self.session:
                self.session = aiohttp.ClientSession()

            payload = {
                "secret": self.secret,
                "correlation-id": self.correlation_id,
            }

            register_url = f"{self.base_url}/register"
            async with self.session.post(register_url, json=payload, timeout=10) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"Interactsh register failed ({resp.status}): {text}")
                data = await resp.json(content_type=None)

            domain = data.get("domain") or data.get("success")
            if not domain:
                # API might return base64 encoded domain
                b64_domain = data.get("base64-domain")
                if b64_domain:
                    try:
                        domain = base64.b64decode(b64_domain).decode("utf-8").strip()
                    except Exception:
                        domain = None

            self.base_domain = domain or f"{self.correlation_id}.oast.pro"
            self.polling_url = f"{self.base_url}/poll?id={self.correlation_id}&secret={self.secret}"

            logger.info("✅ Interactsh initialized: %s", self.base_domain)
            return True

        except Exception as e:
            logger.warning("Failed to initialize Interactsh: %s", e)
            return False

    def generate_url(self, marker: str, protocol: str = "http") -> str:
        """
        Generate callback URL with marker.

        Args:
            marker: Unique identifier for this callback
            protocol: http, https, dns (DNS is subdomain only)

        Returns:
            Callback URL like http://marker.correlation_id.oast.pro
        """
        if not self.base_domain:
            raise RuntimeError("Client not initialized")

        subdomain = f"{marker}.{self.base_domain}"

        if protocol == "dns":
            return subdomain
        else:
            return f"{protocol}://{subdomain}"

    async def poll_interactions(self, timeout: int = 5) -> List[Dict]:
        """
        Poll interact.sh for interactions (DNS queries, HTTP requests).

        Returns:
            List of interaction dictionaries containing:
            - protocol: "dns" or "http"
            - full_id: Full domain that was queried
            - raw_request: Raw HTTP request (for HTTP interactions)
            - timestamp: When interaction occurred
        """
        try:
            if not self.polling_url or not self.session:
                return []

            poll_url = f"{self.polling_url}&_={secrets.token_hex(4)}"
            async with self.session.get(poll_url, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.debug("Interactsh poll failed with status %s", resp.status)
                    return []
                payload = await resp.json(content_type=None)

            interactions: List[Dict] = []
            for encoded in payload.get("data", []) or []:
                try:
                    decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                    json_data = json.loads(decoded)
                    interactions.append(json_data)
                except Exception as decode_err:
                    logger.debug("Failed to decode interaction: %s", decode_err)

            if interactions:
                self._interactions_cache.extend(interactions)
            return interactions

        except Exception as e:
            logger.debug("Interaction polling failed: %s", e)
            return []

    async def check_callback(self, marker: str, timeout: int = 5, max_retries: int = 3) -> Optional[Dict]:
        """
        Check if callback was triggered for specific marker.

        Args:
            marker: The unique marker used in callback URL
            timeout: How long to wait for callback (seconds)
            max_retries: Number of polling attempts

        Returns:
            Interaction dict if found, None otherwise
        """
        expected_subdomain = f"{marker}.{self.base_domain}"

        for attempt in range(max_retries):
            interactions = await self.poll_interactions(timeout=timeout)

            for interaction in interactions:
                full_id = interaction.get("full-id") or interaction.get("full_id", "")
                if marker in full_id or expected_subdomain in full_id:
                    logger.info("✅ Callback received: %s", full_id)
                    return interaction

            if attempt < max_retries - 1:
                await asyncio.sleep(1)

        return None

    async def get_http_details(self, marker: str) -> Optional[Dict]:
        """
        Get HTTP request details for a specific marker.

        Returns:
            Dict containing:
            - method: HTTP method (GET, POST, etc.)
            - headers: Request headers
            - body: Request body
            - remote_addr: Client IP address
        """
        interaction = await self.check_callback(marker)

        if interaction and (interaction.get("protocol") or interaction.get("protocol-type")) == "http":
            raw_request = interaction.get("raw-request") or interaction.get("raw_request", "")

            # Parse HTTP request
            lines = raw_request.split("\r\n")
            if lines:
                # First line: GET /path HTTP/1.1
                first_line = lines[0].split()
                method = first_line[0] if first_line else "UNKNOWN"

                # Headers
                headers = {}
                body = ""
                in_body = False

                for line in lines[1:]:
                    if not line and not in_body:
                        in_body = True
                        continue

                    if in_body:
                        body += line + "\n"
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.strip()] = value.strip()

                return {
                    "method": method,
                    "headers": headers,
                    "body": body.strip(),
                    "remote_addr": interaction.get("remote_address", "unknown"),
                    "timestamp": interaction.get("timestamp"),
                }

        return None

    async def cleanup(self):
        """Cleanup and close session"""
        if self.session:
            try:
                deregister_url = f"{self.base_url}/deregister"
                payload = {
                    "secret": self.secret,
                    "correlation-id": self.correlation_id,
                }
                async with self.session.post(deregister_url, json=payload, timeout=5):
                    pass
            except Exception:
                pass
            await self.session.close()
            self.session = None


# Global client instance (reused)
_global_client = None
_client_lock = asyncio.Lock()


async def get_interactsh_client() -> Optional[InteractshClient]:
    """Get or create global interact.sh client.

    Returns None if initialization fails (no internet, server down, etc.).
    The global client is only stored after *successful* initialization so that
    a failed attempt does not permanently poison the cache.
    """
    global _global_client

    async with _client_lock:
        if _global_client is None:
            client = InteractshClient()
            ok = await client.initialize()
            if not ok:
                # Do NOT store the failed client — allow retry on next call
                logger.warning("Interactsh initialization failed; OOB detectors will be skipped")
                return None
            _global_client = client

        return _global_client


# Manual verification helper
def generate_manual_verification_payload(target_url: str) -> str:
    """
    Generate payload for manual verification with Burp Collaborator.

    Returns formatted payload string for manual testing.
    """
    return f"""
=== MANUAL SSRF VERIFICATION ===

Target: {target_url}

Test with Burp Collaborator:
1. Start Burp Suite and open Collaborator client
2. Click "Copy to clipboard" to get your unique domain (e.g., abc123.burpcollaborator.net)
3. Inject the domain into target URL parameters:

   Examples:
   - {target_url}?url=http://YOUR_COLLABORATOR_DOMAIN
   - {target_url}?redirect=http://YOUR_COLLABORATOR_DOMAIN
   - {target_url}?dest=http://YOUR_COLLABORATOR_DOMAIN

4. Click "Poll now" in Burp Collaborator to check for interactions
5. Look for DNS or HTTP interactions - these confirm SSRF!

Recommended Collaborator domains to test:
- http://YOUR_DOMAIN (basic HTTP)
- https://YOUR_DOMAIN (HTTPS)
- YOUR_DOMAIN (DNS only)
- ftp://YOUR_DOMAIN (FTP)
- file:///etc/passwd (local file - dangerous!)
- http://169.254.169.254/latest/meta-data/ (AWS metadata - high severity!)

If ANY interaction appears in Collaborator = CONFIRMED SSRF!
"""
