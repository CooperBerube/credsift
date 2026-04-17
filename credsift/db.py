# credsift/db.py
"""
SQLite session store for ingested and scored CredRecords.

Schema
------
records
  id          INTEGER  PRIMARY KEY
  raw_hash    TEXT     UNIQUE  — SHA256 of the raw line (dedup key)
  fmt         TEXT
  email       TEXT
  username    TEXT
  domain      TEXT
  secret      TEXT
  is_hash     INTEGER  (0/1)
  hash_type   TEXT
  source      TEXT
  risk_score  REAL
  tags        TEXT     — JSON array
  ingested_at TEXT     — ISO8601 timestamp
"""

import sqlite3
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from credsift.parsers import CredRecord


DEFAULT_DB = Path("credsift.db")


def _connect(db_path: Path = DEFAULT_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DEFAULT_DB) -> None:
    """Create tables and indexes if they do not exist."""
    with _connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_hash    TEXT    NOT NULL UNIQUE,
                fmt         TEXT    NOT NULL,
                email       TEXT,
                username    TEXT,
                domain      TEXT,
                secret      TEXT,
                is_hash     INTEGER NOT NULL DEFAULT 0,
                hash_type   TEXT,
                source      TEXT,
                risk_score  REAL    NOT NULL DEFAULT 0.0,
                tags        TEXT    NOT NULL DEFAULT '[]',
                ingested_at TEXT    NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain     ON records(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_score ON records(risk_score)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_hash   ON records(raw_hash)")
        conn.commit()


def record_hash(raw: str) -> str:
    """Return a SHA256 hex digest of the raw line — used as the dedup key."""
    return hashlib.sha256(raw.encode()).hexdigest()


def insert_record(record: CredRecord, db_path: Path = DEFAULT_DB) -> bool:
    """
    Insert a CredRecord into the database.
    Returns True if inserted, False if it was a duplicate (raw_hash conflict).
    """
    rh = record_hash(record.raw)
    now = datetime.now(timezone.utc).isoformat()

    try:
        with _connect(db_path) as conn:
            conn.execute("""
                INSERT INTO records
                    (raw_hash, fmt, email, username, domain, secret,
                     is_hash, hash_type, source, risk_score, tags, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rh,
                record.fmt.value,
                record.email,
                record.username,
                record.domain,
                record.secret,
                int(record.is_hash),
                record.hash_type.value if record.hash_type else None,
                record.source,
                record.risk_score,
                json.dumps(record.tags),
                now,
            ))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False  # duplicate raw_hash


def exists(raw: str, db_path: Path = DEFAULT_DB) -> bool:
    """Return True if this raw line is already in the database."""
    rh = record_hash(raw)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM records WHERE raw_hash = ?", (rh,)
        ).fetchone()
    return row is not None


def query_by_domain(domain: str, db_path: Path = DEFAULT_DB) -> list[sqlite3.Row]:
    """Return all records matching a domain, ordered by risk_score descending."""
    with _connect(db_path) as conn:
        return conn.execute("""
            SELECT * FROM records
            WHERE domain = ?
            ORDER BY risk_score DESC
        """, (domain,)).fetchall()


def query_top(n: int = 20, db_path: Path = DEFAULT_DB) -> list[sqlite3.Row]:
    """Return the top N records by risk_score."""
    with _connect(db_path) as conn:
        return conn.execute("""
            SELECT * FROM records
            ORDER BY risk_score DESC
            LIMIT ?
        """, (n,)).fetchall()


def record_count(db_path: Path = DEFAULT_DB) -> int:
    """Return total number of records in the database."""
    with _connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]