# credsift/enricher.py
"""
HIBP (HaveIBeenPwned) k-anonymity enrichment for CredRecords.

Privacy model
-------------
Only the first 5 hex characters of the SHA1 password hash are transmitted.
The full hash and the plaintext password never leave the local machine.
Results are cached in SQLite to avoid redundant API calls across sessions.

API reference: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
"""

import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from credsift.parsers import CredRecord
from credsift.db import DEFAULT_DB, _connect


# ── Constants ─────────────────────────────────────────────────────────────────

HIBP_URL      = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_DELAY = 0.1   # seconds between requests — respect HIBP rate limits
CACHE_TABLE   = "hibp_cache"


# ── Cache setup ───────────────────────────────────────────────────────────────

def init_hibp_cache(db_path: Path = DEFAULT_DB) -> None:
    """Create the HIBP result cache table if it does not exist."""
    with _connect(db_path) as conn:
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {CACHE_TABLE} (
                prefix      TEXT PRIMARY KEY,
                response    TEXT NOT NULL,
                fetched_at  TEXT NOT NULL
            )
        """)
        conn.commit()


def _cache_get(prefix: str, db_path: Path) -> Optional[str]:
    """Return cached HIBP response for a prefix, or None if not cached."""
    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT response FROM {CACHE_TABLE} WHERE prefix = ?",
            (prefix.upper(),)
        ).fetchone()
    return row["response"] if row else None


def _cache_set(prefix: str, response: str, db_path: Path) -> None:
    """Store a HIBP response in the cache."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            f"INSERT OR REPLACE INTO {CACHE_TABLE} (prefix, response, fetched_at) "
            f"VALUES (?, ?, ?)",
            (prefix.upper(), response, now)
        )
        conn.commit()


# ── Core logic ────────────────────────────────────────────────────────────────

def _sha1(plaintext: str) -> str:
    """Return uppercase SHA1 hex digest of a plaintext string."""
    return hashlib.sha1(plaintext.encode("utf-8")).hexdigest().upper()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
)
def _fetch_range(prefix: str) -> str:
    """
    Fetch all SHA1 hash suffixes from HIBP for a given 5-char prefix.
    Retries up to 3 times with exponential backoff on failure.
    """
    url = HIBP_URL.format(prefix=prefix.upper())
    response = httpx.get(url, timeout=10)
    response.raise_for_status()
    return response.text


def check_password(
    plaintext: str,
    db_path: Path = DEFAULT_DB,
) -> Optional[int]:
    """
    Check whether a plaintext password appears in HIBP breach data.

    Returns the breach count if found, 0 if not found, None on API error.
    Uses local SHA1 + k-anonymity — plaintext never leaves this machine.

    Args:
        plaintext: The plaintext password to check.
        db_path:   Path to SQLite DB used for response caching.
    """
    sha1      = _sha1(plaintext)
    prefix    = sha1[:5]
    suffix    = sha1[5:]

    # Check cache first
    cached = _cache_get(prefix, db_path)
    if cached is None:
        try:
            time.sleep(REQUEST_DELAY)
            cached = _fetch_range(prefix)
            _cache_set(prefix, cached, db_path)
        except Exception:
            return None  # API unavailable — enrich gracefully degrades

    # Search the returned suffix list for our hash
    for line in cached.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        returned_suffix, count = parts
        if returned_suffix.upper() == suffix.upper():
            return int(count)

    return 0  # prefix matched, suffix not found — password not in dataset


# ── Public API ────────────────────────────────────────────────────────────────

def enrich(
    record: CredRecord,
    db_path: Path = DEFAULT_DB,
) -> dict:
    """
    Enrich a CredRecord with HIBP breach data.

    Only enriches records with a plaintext password (is_hash=False).
    Hash records are tagged as 'hibp:skipped-hash' — cracking is out of scope.

    Returns a dict with enrichment results:
        {
            "checked":      bool,
            "pwned":        bool,
            "breach_count": int or None,
            "tag":          str,
        }
    """
    result = {
        "checked":      False,
        "pwned":        False,
        "breach_count": None,
        "tag":          None,
    }

    if not record.secret:
        result["tag"] = "hibp:no-secret"
        return result

    if record.is_hash:
        result["tag"] = "hibp:skipped-hash"
        return result

    count = check_password(record.secret, db_path)

    if count is None:
        result["tag"] = "hibp:api-error"
        return result

    result["checked"]      = True
    result["breach_count"] = count

    if count > 0:
        result["pwned"] = True
        result["tag"]   = f"hibp:pwned:{count}"
        if "hibp:pwned" not in record.tags:
            record.tags.append(f"hibp:pwned:{count}")
    else:
        result["tag"] = "hibp:clean"
        if "hibp:clean" not in record.tags:
            record.tags.append("hibp:clean")

    return result


def enrich_batch(
    records: list[CredRecord],
    db_path: Path = DEFAULT_DB,
    verbose: bool = False,
) -> list[dict]:
    """
    Enrich a list of CredRecords, returning one result dict per record.
    Skips hash records automatically. Respects REQUEST_DELAY between calls.
    """
    results = []
    for i, record in enumerate(records):
        result = enrich(record, db_path)
        results.append(result)
        if verbose:
            status = result["tag"] or "unknown"
            print(f"  [{i+1}/{len(records)}] {status}")
    return results