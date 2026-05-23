"""
utils/auto_update.py
────────────────────
Central manager for keeping vulnerability data sources current.

Managed resources:
  - Nuclei templates   → `nuclei -update-templates`
  - CVE list V5        → `git pull` (or `git clone --depth=1`) from GitHub

State file: ~/.bugbounty_arsenal/update_state.json
  Tracks last-successful-update timestamp per resource.
  Auto-update is skipped if the resource is newer than max_age_hours.

Usage:
    from utils.auto_update import auto_update_all, update_nuclei_templates, update_cve_database

    # At scan startup, fire-and-forget if stale:
    results = await auto_update_all()
    # Or individually:
    result = await update_nuclei_templates()
    result = await update_cve_database("/path/to/cvelistV5")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── State persistence ──────────────────────────────────────────────────────────

_STATE_DIR = Path.home() / ".bugbounty_arsenal"
_STATE_FILE = _STATE_DIR / "update_state.json"


def _load_state() -> dict:
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_state(state: dict) -> None:
    try:
        _STATE_DIR.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.debug("auto_update: could not save state: %s", exc)


def _mark_updated(resource: str) -> None:
    state = _load_state()
    state[resource] = datetime.now(timezone.utc).isoformat()
    _save_state(state)


def is_stale(resource: str, max_age_hours: int = 24) -> bool:
    """Return True if *resource* was not updated within *max_age_hours*."""
    state = _load_state()
    ts_str = state.get(resource)
    if not ts_str:
        return True
    try:
        ts = datetime.fromisoformat(ts_str)
        # Make sure both are timezone-aware
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
        return age_hours >= max_age_hours
    except Exception:
        return True


def last_updated(resource: str) -> Optional[str]:
    """Return ISO timestamp of last successful update, or None."""
    return _load_state().get(resource)


# ── Nuclei template auto-update ───────────────────────────────────────────────

async def update_nuclei_templates(
    nuclei_path: Optional[str] = None,
    *,
    force: bool = False,
    max_age_hours: int = 24,
) -> dict:
    """
    Update Nuclei templates via `nuclei -update-templates`.

    Returns:
        {status: 'ok' | 'skipped' | 'error', message: str}
    """
    if not force and not is_stale("nuclei_templates", max_age_hours):
        return {"status": "skipped", "reason": "templates updated within last 24h",
                "last_updated": last_updated("nuclei_templates")}

    path = nuclei_path or shutil.which("nuclei")
    if not path:
        return {"status": "error", "reason": (
            "`nuclei` binary not found in PATH "
            "— install from https://nuclei.projectdiscovery.io"
        )}

    logger.info("auto_update: updating Nuclei templates…")
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"status": "error", "reason": "nuclei -update-templates timed out after 120s"}

        out = (stdout or b"").decode("utf-8", errors="replace").strip()
        err = (stderr or b"").decode("utf-8", errors="replace").strip()

        if proc.returncode == 0:
            _mark_updated("nuclei_templates")
            logger.info("auto_update: Nuclei templates updated successfully")
            return {"status": "ok", "message": out[:300] or "Templates updated"}
        else:
            msg = err[:300] or out[:300] or f"exit code {proc.returncode}"
            logger.warning("auto_update: Nuclei template update failed: %s", msg)
            return {"status": "error", "reason": msg}

    except FileNotFoundError:
        return {"status": "error", "reason": f"`nuclei` not executable at {path}"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


# ── CVE database auto-update ──────────────────────────────────────────────────

_DEFAULT_CVE_REPO = "https://github.com/CVEProject/cvelistV5.git"
_DEFAULT_CVE_PATH = str(Path.home() / "cvelistV5")


async def update_cve_database(
    db_path: Optional[str] = None,
    *,
    force: bool = False,
    max_age_hours: int = 168,  # Weekly by default — DB is large
) -> dict:
    """
    Keep the local cvelistV5 CVE database current via Git.

    - If the path has a `.git` dir: runs `git -C <path> pull --ff-only --quiet`
    - If path does not exist: runs `git clone --depth=1 <repo> <path>`

    Returns:
        {status: 'ok' | 'skipped' | 'error', message: str}
    """
    path = db_path or os.environ.get("CVE_DB_PATH") or _DEFAULT_CVE_PATH

    if not force and not is_stale("cve_database", max_age_hours):
        return {"status": "skipped", "reason": "CVE database updated within last 7 days",
                "last_updated": last_updated("cve_database")}

    git = shutil.which("git")
    if not git:
        return {"status": "error", "reason": "`git` not found in PATH — cannot update CVE database"}

    path_obj = Path(path)
    if path_obj.is_dir() and (path_obj / ".git").is_dir():
        cmd = [git, "-C", path, "pull", "--ff-only", "--quiet"]
        action = "pull"
    elif not path_obj.exists():
        logger.info("auto_update: CVE database not found at %s — cloning (this may take a few minutes)…", path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        cmd = [git, "clone", "--depth=1", "--quiet", _DEFAULT_CVE_REPO, path]
        action = "clone"
    else:
        return {"status": "error",
                "reason": f"{path} exists but is not a git repo. Remove it or set CVE_DB_PATH to a different location."}

    logger.info("auto_update: CVE database %s at %s…", action, path)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            # clone can take a few minutes for a shallow clone of a large repo
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"status": "error", "reason": f"git {action} timed out after 600s"}

        out = (stdout or b"").decode("utf-8", errors="replace").strip()
        err = (stderr or b"").decode("utf-8", errors="replace").strip()

        if proc.returncode == 0:
            _mark_updated("cve_database")
            # Invalidate the CVE SQLite index so it gets rebuilt on next scan
            _invalidate_cve_index()
            logger.info("auto_update: CVE database %s completed", action)
            return {"status": "ok", "message": out[:300] or f"CVE database {action} completed"}
        else:
            msg = err[:300] or f"git exit code {proc.returncode}"
            logger.warning("auto_update: CVE database %s failed: %s", action, msg)
            return {"status": "error", "reason": msg}

    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def _invalidate_cve_index() -> None:
    """Remove the SQLite CVE index so it gets rebuilt after a DB update."""
    try:
        index_path = _STATE_DIR / "cve_index.db"
        if index_path.exists():
            index_path.unlink()
            logger.debug("auto_update: CVE index invalidated")
    except Exception as exc:
        logger.debug("auto_update: could not remove CVE index: %s", exc)


# ── Combined entry point ──────────────────────────────────────────────────────

async def auto_update_all(
    nuclei_path: Optional[str] = None,
    cve_db_path: Optional[str] = None,
    *,
    force: bool = False,
) -> dict:
    """
    Run all auto-updates concurrently.  Safe to call at scanner startup.

    Returns:
        {
            "nuclei_templates": {status, ...},
            "cve_database":     {status, ...},
        }
    """
    nuclei_result, cve_result = await asyncio.gather(
        update_nuclei_templates(nuclei_path, force=force),
        update_cve_database(cve_db_path, force=force),
        return_exceptions=False,
    )
    results = {"nuclei_templates": nuclei_result, "cve_database": cve_result}

    for name, r in results.items():
        if r.get("status") == "ok":
            logger.info("auto_update: %s → OK", name)
        elif r.get("status") == "skipped":
            logger.debug("auto_update: %s → skipped (%s)", name, r.get("reason", ""))
        else:
            logger.warning("auto_update: %s → error: %s", name, r.get("reason", "unknown"))

    return results
