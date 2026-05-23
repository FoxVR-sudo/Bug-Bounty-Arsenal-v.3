"""
Minimal crawler module for parameter discovery
"""
from typing import Dict, List
from urllib.parse import urlparse, parse_qsl


async def discover_params(session, url: str) -> Dict:
    """
    Discover parameters and forms from a URL
    Returns dict with 'forms' key containing list of discovered forms
    """
    try:
        async with session.get(url) as response:
            html = await response.text()

            # Simple form detection - look for input fields
            forms = []

            # Extract query parameters from URL
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qsl(parsed.query)
                if params:
                    # Create a form dict from query params
                    inputs = [param[0] for param in params]
                    forms.append({
                        "action": url,
                        "method": "get",
                        "inputs": inputs
                    })

            # Simple HTML form detection (basic regex)
            import re
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\']'
            inputs = re.findall(input_pattern, html, re.IGNORECASE)

            if inputs:
                forms.append({
                    "action": url,
                    "method": "post",
                    "inputs": list(set(inputs))  # Remove duplicates
                })

            return {"forms": forms}

    except Exception:
        return {"forms": []}


async def crawl_site(session, start_url: str, max_depth: int = 2) -> List[str]:
    """
    Basic site crawler - returns list of discovered URLs
    """
    discovered_urls = set([start_url])

    try:
        async with session.get(start_url) as response:
            html = await response.text()

            # Simple link extraction
            import re
            link_pattern = r'href=["\']([^"\']+)["\']'
            links = re.findall(link_pattern, html, re.IGNORECASE)

            for link in links:
                if link.startswith('http'):
                    discovered_urls.add(link)
                elif link.startswith('/'):
                    parsed = urlparse(start_url)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{link}"
                    discovered_urls.add(full_url)

    except Exception:
        pass

    return list(discovered_urls)
