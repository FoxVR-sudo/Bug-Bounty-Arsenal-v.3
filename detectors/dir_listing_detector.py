# detectors/dir_listing_detector.py
# Active detector: checks for directory listing (safe, non-destructive).
import logging
import os
from urllib.parse import urlparse

from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


@register_active
async def dir_listing_detector(session, url, context):
    findings = []
    if not url:
        return findings

    per_host_rate = context.get("per_host_rate", None)
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path or "/"
        # request the parent directory to detect an index/listing
        parent = os.path.dirname(path.rstrip("/")) + "/"
        test_url = parsed._replace(path=parent, query="").geturl()

        await await_host_token(host, per_host_rate)
        try:
            async with session.get(test_url, allow_redirects=True) as resp:
                try:
                    body = await resp.text()
                except Exception:
                    body = ""
                status = resp.status
                headers = dict(resp.headers)
        except Exception as e:
            logger.debug("Dir listing request failed for %s: %s", test_url, e)
            return findings

        if "Index of" in (body or "") or "<title>Index of" in (body or ""):
            findings.append({
                "type": "Directory Listing",
                "evidence": f"Directory listing detected at {test_url}",
                "how_found": "Requested parent directory and observed listing page",
                "severity": "low",
                "payload": None,
                "evidence_url": test_url,
                "evidence_body": body,
                "evidence_headers": headers,
                "evidence_status": status,
            })
    except Exception:
        pass

    return findings
