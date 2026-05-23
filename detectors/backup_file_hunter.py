"""
Backup & Old File Hunter for 0-Day Discovery
Discovers exposed backup files, old systems, and sensitive file leaks
"""
import asyncio
import time
from urllib.parse import urljoin
from typing import Dict, List, Any

import requests

from detectors.registry import register_active, DetectorSkip


_FRONTEND_SHELL_MARKERS = (
    '<!doctype html',
    '<html',
    '<div id="root"></div>',
    'you need to enable javascript to run this app',
    'bugbounty arsenal - automated vulnerability scanner',
    '/static/js/main.',
)


def _looks_like_frontend_shell(content_type: str, content_disposition: str, sample: bytes) -> bool:
    content_type_l = str(content_type or '').lower()
    content_disposition_l = str(content_disposition or '').lower()

    # If the server explicitly serves an attachment or a non-index filename,
    # do not treat it as the SPA shell.
    if 'attachment' in content_disposition_l:
        return False
    if 'filename=' in content_disposition_l and 'index.html' not in content_disposition_l:
        return False

    sample_text = sample.decode('utf-8', errors='ignore').lower()
    if any(marker in sample_text for marker in _FRONTEND_SHELL_MARKERS):
        return True

    return 'text/html' in content_type_l or 'application/xhtml+xml' in content_type_l


class BackupFileHunter:
    """
    Hunts for exposed backup files and old versions:
    - Database backups (.sql, .bak, .dump)
    - Source code archives (.zip, .tar.gz, .rar)
    - Configuration backups (.old, .bak, .backup)
    - Temporary files (.tmp, .swp, ~)
    """

    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []

        # Common backup file patterns
        self.backup_files = [
            # Database backups
            'backup.sql',
            'database.sql',
            'db.sql',
            'dump.sql',
            'backup.bak',
            'database.bak',
            'db.dump',
            'mysql.sql',
            'postgres.sql',

            # Source code archives
            'backup.zip',
            'site.zip',
            'www.zip',
            'source.zip',
            'code.zip',
            'backup.tar.gz',
            'site.tar.gz',
            'backup.rar',

            # Configuration backups
            'config.old',
            'config.bak',
            '.env.old',
            '.env.backup',
            'settings.old',
            'web.config.old',

            # Old/backup directories
            'backup/',
            'backups/',
            'old/',
            '.backup/',
            '_backup/',

            # Common file names
            'site.bak',
            'index.old',
            'admin.old',
            'login.bak',

            # Git/SVN exposures
            '.git/config',
            '.svn/entries',
            '.env',
            '.DS_Store',

            # Temp files
            'temp.zip',
            'tmp.zip',
            '.swp',
            '~',
        ]

        # Common paths to prepend
        self.paths = [
            '',
            'admin/',
            'backup/',
            'backups/',
            'old/',
            'temp/',
            'files/',
            'data/',
        ]

    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            exposed_files = []

            # Check each backup file pattern
            for path in self.paths:
                for backup_file in self.backup_files[:20]:  # Limit to prevent too many requests
                    url = urljoin(self.target, path + backup_file)

                    if self.check_file_exists(url):
                        file_info = self.analyze_backup_file(url)
                        exposed_files.append(file_info)

                        self.findings.append({
                            'type': 'exposed_backup',
                            'severity': file_info['severity'],
                            'url': url,
                            'file_type': file_info['file_type'],
                            'size': file_info.get('size', 'unknown'),
                            'description': f"Exposed {file_info['file_type']} file: {backup_file}"
                        })

                    # Rate limiting
                    time.sleep(0.1)

            return {
                'vulnerable': len(exposed_files) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'exposed_count': len(exposed_files),
                'details': {
                    'database_backups': [f for f in self.findings if 'sql' in f['url'] or 'dump' in f['url']],
                    'source_archives': [f for f in self.findings if any(ext in f['url'] for ext in ['.zip', '.tar', '.rar'])],
                    'config_files': [f for f in self.findings if any(ext in f['url'] for ext in ['.env', 'config', 'settings'])],
                    'git_svn': [f for f in self.findings if any(d in f['url'] for d in ['.git', '.svn'])],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }

    def check_file_exists(self, url: str) -> bool:
        """Check if a backup-like file is actually downloadable at the URL."""
        try:
            response = requests.head(url, timeout=5, verify=False, allow_redirects=False)

            if response.status_code == 200:
                return self._confirm_downloadable_candidate(url)

            # Sometimes HEAD doesn't work, try GET
            if response.status_code == 405:
                return self._confirm_downloadable_candidate(url)

            return False
        except Exception:
            return False

    def _confirm_downloadable_candidate(self, url: str) -> bool:
        try:
            with requests.get(url, timeout=5, verify=False, stream=True, allow_redirects=False) as response:
                if response.status_code != 200:
                    return False

                sample = response.raw.read(512, decode_content=True)
                return not _looks_like_frontend_shell(
                    response.headers.get('content-type', ''),
                    response.headers.get('content-disposition', ''),
                    sample,
                )
        except Exception:
            return False

    def analyze_backup_file(self, url: str) -> Dict[str, Any]:
        """Analyze the type and severity of backup file"""
        file_info = {
            'url': url,
            'file_type': 'unknown',
            'severity': 'medium'
        }

        # Determine file type and severity
        if any(ext in url for ext in ['.sql', '.dump', '.bak', 'database']):
            file_info['file_type'] = 'database_backup'
            file_info['severity'] = 'critical'
        elif any(ext in url for ext in ['.zip', '.tar.gz', '.rar']):
            file_info['file_type'] = 'source_code_archive'
            file_info['severity'] = 'high'
        elif '.env' in url or 'config' in url:
            file_info['file_type'] = 'configuration_file'
            file_info['severity'] = 'high'
        elif '.git' in url or '.svn' in url:
            file_info['file_type'] = 'version_control'
            file_info['severity'] = 'critical'
        elif any(ext in url for ext in ['.old', '.backup']):
            file_info['file_type'] = 'old_version'
            file_info['severity'] = 'medium'

        # Try to get file size
        try:
            response = requests.head(url, timeout=5, verify=False)
            if 'content-length' in response.headers:
                size_bytes = int(response.headers['content-length'])
                file_info['size'] = self.format_file_size(size_bytes)
        except:
            pass

        return file_info

    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    def calculate_severity(self) -> str:
        """Calculate overall severity"""
        if not self.findings:
            return 'info'

        severities = [f.get('severity', 'info') for f in self.findings]

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function"""
    hunter = BackupFileHunter(target)
    return hunter.run()


class AsyncBackupFileHunter:
    def __init__(self, session, target: str, *, verify_tls: bool = True):
        self.session = session
        self.target = target.rstrip("/")
        self.verify_tls = bool(verify_tls)
        self.findings: List[Dict[str, Any]] = []

        self.backup_files = BackupFileHunter(target).backup_files
        self.paths = BackupFileHunter(target).paths

    def _analyze_backup_file(self, url: str, *, content_length: int | None) -> Dict[str, Any]:
        file_info: Dict[str, Any] = {
            "url": url,
            "file_type": "unknown",
            "severity": "medium",
        }
        url_l = url.lower()
        if any(ext in url_l for ext in [".sql", ".dump", ".bak", "database"]):
            file_info["file_type"] = "database_backup"
            file_info["severity"] = "critical"
        elif any(ext in url_l for ext in [".zip", ".tar.gz", ".rar"]):
            file_info["file_type"] = "source_code_archive"
            file_info["severity"] = "high"
        elif ".env" in url_l or "config" in url_l or "settings" in url_l:
            file_info["file_type"] = "configuration_file"
            file_info["severity"] = "high"
        elif ".git" in url_l or ".svn" in url_l:
            file_info["file_type"] = "version_control"
            file_info["severity"] = "critical"
        elif any(ext in url_l for ext in [".old", ".backup"]):
            file_info["file_type"] = "old_version"
            file_info["severity"] = "medium"

        if isinstance(content_length, int) and content_length >= 0:
            file_info["size"] = self._format_file_size(content_length)
        return file_info

    def _format_file_size(self, size_bytes: int) -> str:
        size = float(size_bytes)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def _calculate_severity(self) -> str:
        if not self.findings:
            return "info"
        severities = [f.get("severity", "info") for f in self.findings]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    async def _probe(self, url: str) -> Dict[str, Any] | None:
        ssl_opt = None if self.verify_tls else False
        try:
            async with self.session.head(url, allow_redirects=False, ssl=ssl_opt) as resp:
                status = resp.status
                cl = resp.headers.get("content-length")
                content_length = int(cl) if cl and cl.isdigit() else None

                if status == 200:
                    return await self._confirm_downloadable_candidate(url, ssl=ssl_opt)

                if status == 405:
                    return await self._confirm_downloadable_candidate(url, ssl=ssl_opt)

                return None
        except Exception:
            return None

    async def _confirm_downloadable_candidate(self, url: str, *, ssl) -> Dict[str, Any] | None:
        try:
            async with self.session.get(url, allow_redirects=False, ssl=ssl) as resp:
                if resp.status != 200:
                    return None

                cl = resp.headers.get("content-length")
                content_length = int(cl) if cl and cl.isdigit() else None
                sample = await resp.content.read(512)
                if _looks_like_frontend_shell(
                    resp.headers.get("content-type", ""),
                    resp.headers.get("content-disposition", ""),
                    sample,
                ):
                    return None

                return {"status": resp.status, "content_length": content_length, "confirmed": True}
        except Exception:
            return None

    async def run(self, *, files_limit: int = 20, request_delay: float = 0.1) -> Dict[str, Any]:
        exposed_files: List[Dict[str, Any]] = []
        for path in self.paths:
            for backup_file in self.backup_files[: max(0, int(files_limit))]:
                url = urljoin(self.target, path + backup_file)
                probe = await self._probe(url)
                if probe:
                    file_info = self._analyze_backup_file(url, content_length=probe.get("content_length"))
                    exposed_files.append(file_info)
                    description = f"Exposed {file_info.get('file_type', 'backup')} file: {backup_file}"
                    self.findings.append(
                        {
                            "type": "exposed_backup",
                            "severity": file_info.get("severity", "medium"),
                            "url": url,
                            "file_type": file_info.get("file_type", "unknown"),
                            "size": file_info.get("size", "unknown"),
                            "description": description,
                            "confirmed": True,
                        }
                    )

                if request_delay:
                    await asyncio.sleep(float(request_delay))

        return {
            "vulnerable": len(exposed_files) > 0,
            "severity": self._calculate_severity(),
            "findings": self.findings,
            "exposed_count": len(exposed_files),
            "details": {
                "database_backups": [f for f in self.findings if "sql" in f.get("url", "") or "dump" in f.get("url", "")],
                "source_archives": [
                    f
                    for f in self.findings
                    if any(ext in f.get("url", "") for ext in [".zip", ".tar", ".rar"])
                ],
                "config_files": [
                    f
                    for f in self.findings
                    if any(ext in f.get("url", "") for ext in [".env", "config", "settings"])
                ],
                "git_svn": [f for f in self.findings if any(d in f.get("url", "") for d in [".git", ".svn"])],
            },
        }


@register_active
async def backup_file_hunter(session, url: str, context: Dict[str, Any]):
    """Async wrapper for BackupFileHunter.

    This is brute-forcey (many URL probes), so gate behind allow_destructive.
    """
    if not bool(context.get("allow_destructive", False)):
        raise DetectorSkip("backup_file_hunter requires allow_destructive")

    verify_tls = context.get("verify_tls", True)
    hunter = AsyncBackupFileHunter(session, url, verify_tls=bool(verify_tls))
    result = await hunter.run(
        files_limit=int(context.get("backup_file_hunter_files_limit", 20)),
        request_delay=float(context.get("backup_file_hunter_request_delay", 0.1)),
    )
    findings = []
    for f in (result or {}).get("findings", []) or []:
        findings.append(
            {
                "url": f.get("url", url),
                "type": "Exposed Backup/Old File",
                "severity": f.get("severity", "medium"),
                "description": f.get("description", "Exposed backup file detected"),
                "evidence": f.get("url") or f.get("description") or "backup file exposed",
                "how_found": "backup_file_hunter",
                "detector": "backup_file_hunter",
            }
        )
    return findings
