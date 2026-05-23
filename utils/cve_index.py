"""
utils/cve_index.py
──────────────────
SQLite index over the cvelistV5 CVE database for fast product lookups.

Problem:  cvelistV5 ships ~250,000 JSON files.  Scanning them all on every
          request is O(250k) file reads ≈ 30–120s.

Solution: Build a compact SQLite index once (3–7 min first run), then every
          product lookup is a single indexed SQL query (< 1ms).

Index location: ~/.bugbounty_arsenal/cve_index.db

Index schema:
  cve_meta     — one row per CVE  (cve_id, year, cvss_score, severity, file_path)
  cve_products — many rows per CVE, one per product keyword
  index_meta   — build metadata (db_root, build_ts, row_count)

Usage:
    from utils.cve_index import get_cves_for_product, ensure_index

    ensure_index("/path/to/cvelistV5")           # builds if missing/stale
    cves = get_cves_for_product("wordpress", db_path="/path/to/cvelistV5")
    # returns list of dicts: {cve_id, cvss_score, severity, file_path}
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Generator, List, Optional

logger = logging.getLogger(__name__)

_STATE_DIR = Path.home() / ".bugbounty_arsenal"
_INDEX_PATH = _STATE_DIR / "cve_index.db"
_BUILD_LOCK = threading.Lock()  # prevent concurrent index builds

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_meta (
    cve_id      TEXT    PRIMARY KEY,
    year        INTEGER,
    cvss_score  REAL    DEFAULT 0.0,
    severity    TEXT    DEFAULT 'unknown',
    file_path   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_products (
    product_key TEXT NOT NULL,
    cve_id      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_product_cve
    ON cve_products(product_key, cve_id);

CREATE INDEX IF NOT EXISTS idx_product
    ON cve_products(product_key);

CREATE TABLE IF NOT EXISTS index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _open_index(index_path: Path = _INDEX_PATH) -> sqlite3.Connection:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(index_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _iter_cve_files(db_root: Path) -> Generator[Path, None, None]:
    """Yield all *.json CVE files under *db_root*, sorted newest-first by year."""
    cves_dir = db_root / "cves"
    if not cves_dir.is_dir():
        cves_dir = db_root  # fallback if root IS the cves dir
    for year_dir in sorted(cves_dir.iterdir(), reverse=True):
        if not year_dir.is_dir():
            continue
        for chunk_dir in year_dir.iterdir():
            if not chunk_dir.is_dir():
                continue
            for f in chunk_dir.iterdir():
                if f.suffix == ".json" and f.stem.startswith("CVE-"):
                    yield f


def _extract_index_rows(file_path: Path) -> Optional[tuple]:
    """
    Parse a CVE JSON file and return:
        (cve_id, year, cvss_score, severity, file_path_str, product_keys: list[str])
    Returns None on error or no useful data.
    """
    try:
        data = json.loads(file_path.read_bytes())
    except Exception:
        return None

    meta = data.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    if not cve_id.startswith("CVE-"):
        return None

    try:
        year = int(cve_id.split("-")[1])
    except Exception:
        year = 0

    cna = data.get("containers", {}).get("cna", {})

    # CVSS
    cvss_score = 0.0
    severity = "unknown"
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                cvss_score = float(metric[key].get("baseScore", 0.0))
                severity = metric[key].get("baseSeverity", "unknown").lower()
                break
        if cvss_score:
            break

    # Product keywords from affected[] section
    product_keys: set[str] = set()
    for item in cna.get("affected", []):
        vendor = str(item.get("vendor", "") or "").lower().strip()
        product = str(item.get("product", "") or "").lower().strip()
        for kw in (vendor, product):
            # Normalize: remove common noise, keep alphanumeric+dash
            kw_clean = kw.replace(" ", "_")[:64]
            if kw_clean and kw_clean not in ("n/a", "unknown", "-", ""):
                product_keys.add(kw_clean)

    if not product_keys:
        return None  # nothing useful to index

    return cve_id, year, cvss_score, severity, str(file_path), list(product_keys)


# ── Index build ───────────────────────────────────────────────────────────────

def build_index(
    db_path: str,
    *,
    index_path: Path = _INDEX_PATH,
    progress_every: int = 5000,
) -> int:
    """
    Build (or rebuild) the SQLite index from scratch.

    Returns the number of CVEs indexed.
    """
    db_root = Path(db_path)
    logger.info("cve_index: building index from %s → %s", db_root, index_path)

    conn = _open_index(index_path)
    # Clear old data
    conn.execute("DELETE FROM cve_products")
    conn.execute("DELETE FROM cve_meta")
    conn.commit()

    meta_rows: list[tuple] = []
    product_rows: list[tuple] = []
    count = 0

    for file_path in _iter_cve_files(db_root):
        row = _extract_index_rows(file_path)
        if row is None:
            continue
        cve_id, year, cvss, sev, fpath, prod_keys = row
        meta_rows.append((cve_id, year, cvss, sev, fpath))
        for pk in prod_keys:
            product_rows.append((pk, cve_id))
        count += 1

        if count % progress_every == 0:
            logger.info("cve_index: indexed %d CVEs…", count)
            conn.executemany(
                "INSERT OR REPLACE INTO cve_meta VALUES (?,?,?,?,?)", meta_rows
            )
            conn.executemany(
                "INSERT OR IGNORE INTO cve_products VALUES (?,?)", product_rows
            )
            conn.commit()
            meta_rows.clear()
            product_rows.clear()

    # Final batch
    if meta_rows:
        conn.executemany("INSERT OR REPLACE INTO cve_meta VALUES (?,?,?,?,?)", meta_rows)
    if product_rows:
        conn.executemany("INSERT OR IGNORE INTO cve_products VALUES (?,?)", product_rows)

    conn.execute(
        "INSERT OR REPLACE INTO index_meta VALUES (?,?)",
        ("db_root", str(db_root)),
    )
    conn.execute(
        "INSERT OR REPLACE INTO index_meta VALUES (?,?)",
        ("row_count", str(count)),
    )
    import datetime
    conn.execute(
        "INSERT OR REPLACE INTO index_meta VALUES (?,?)",
        ("build_ts", datetime.datetime.now(datetime.timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()
    logger.info("cve_index: index complete — %d CVEs", count)
    return count


def _index_is_valid(db_path: str, index_path: Path = _INDEX_PATH) -> bool:
    """True if index exists and was built from the same db_root."""
    if not index_path.exists():
        return False
    try:
        conn = sqlite3.connect(str(index_path))
        row = conn.execute(
            "SELECT value FROM index_meta WHERE key='db_root'"
        ).fetchone()
        conn.close()
        if row and row[0] == str(Path(db_path)):
            return True
    except Exception:
        pass
    return False


def ensure_index(
    db_path: str,
    *,
    index_path: Path = _INDEX_PATH,
    force: bool = False,
) -> None:
    """
    Build the index if it doesn't exist or was built from a different db_root.
    Thread-safe: concurrent callers will wait for the first build to finish.
    """
    if not force and _index_is_valid(db_path, index_path):
        return

    with _BUILD_LOCK:
        # Double-check after acquiring lock
        if not force and _index_is_valid(db_path, index_path):
            return
        try:
            build_index(db_path, index_path=index_path)
        except Exception as exc:
            logger.error("cve_index: build failed: %s", exc)


# ── Query API ─────────────────────────────────────────────────────────────────

def get_cves_for_product(
    product_keyword: str,
    *,
    db_path: str,
    index_path: Path = _INDEX_PATH,
    limit: int = 20,
    min_cvss: float = 0.0,
) -> List[dict]:
    """
    Return up to *limit* CVEs matching *product_keyword*, sorted by CVSS desc.

    Each result:
        {cve_id, year, cvss_score, severity, file_path}
    """
    ensure_index(db_path, index_path=index_path)
    try:
        conn = _open_index(index_path)
        rows = conn.execute(
            """
            SELECT m.cve_id, m.year, m.cvss_score, m.severity, m.file_path
            FROM cve_products p
            JOIN cve_meta m ON m.cve_id = p.cve_id
            WHERE p.product_key = ?
              AND m.cvss_score >= ?
            ORDER BY m.cvss_score DESC
            LIMIT ?
            """,
            (product_keyword.lower().strip(), min_cvss, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("cve_index: query failed for %s: %s", product_keyword, exc)
        return []


def get_index_stats(index_path: Path = _INDEX_PATH) -> dict:
    """Return build metadata from the index."""
    if not index_path.exists():
        return {"built": False}
    try:
        conn = sqlite3.connect(str(index_path))
        rows = conn.execute("SELECT key, value FROM index_meta").fetchall()
        conn.close()
        meta = {r[0]: r[1] for r in rows}
        meta["built"] = True
        return meta
    except Exception:
        return {"built": False}
