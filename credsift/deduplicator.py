# credsift/deduplicator.py
"""
Two-layer deduplication for CredRecord streams.

Layer 1 — Bloom filter (pybloom-live)
    Fast probabilistic check. No DB hit needed for ~99% of duplicates.
    Small false-positive rate (~0.1%) means occasional unnecessary DB
    lookups — never missed duplicates.

Layer 2 — SQLite raw_hash lookup
    Authoritative check for anything the bloom filter passes through.
    Only fires when the bloom filter says "not seen" — rare after warmup.
"""

from pybloom_live import BloomFilter
from pathlib import Path
from credsift.parsers import CredRecord
from credsift.db import record_hash, exists, insert_record, DEFAULT_DB


class Deduplicator:
    """
    Stateful deduplicator for a single credsift session.

    Usage
    -----
        dedup = Deduplicator(expected=1_000_000)
        for record in stream:
            if dedup.is_new(record):
                # process and store
    """

    def __init__(
        self,
        expected: int = 1_000_000,
        error_rate: float = 0.001,
        db_path: Path = DEFAULT_DB,
    ):
        """
        Args:
            expected:   Approximate number of records to be processed.
                        The bloom filter sizes itself to this number.
            error_rate: Acceptable false-positive rate (default 0.1%).
            db_path:    Path to the SQLite database for authoritative checks.
        """
        self.bloom    = BloomFilter(capacity=expected, error_rate=error_rate)
        self.db_path  = db_path
        self._seen    = 0
        self._dupes   = 0

    def is_new(self, record: CredRecord) -> bool:
        """
        Return True if this record has not been seen before.
        Side effect: adds the record's hash to the bloom filter if new.
        """
        rh = record_hash(record.raw)

        # Layer 1: bloom filter — fast path
        if rh in self.bloom:
            self._dupes += 1
            return False

        # Layer 2: authoritative DB check (rare after warmup)
        if exists(record.raw, self.db_path):
            self.bloom.add(rh)   # backfill bloom so we don't hit DB again
            self._dupes += 1
            return False

        # Genuinely new — add to bloom filter
        self.bloom.add(rh)
        self._seen += 1
        return True

    @property
    def stats(self) -> dict:
        """Return deduplication statistics for the current session."""
        total = self._seen + self._dupes
        return {
            "total_processed": total,
            "unique":          self._seen,
            "duplicates":      self._dupes,
            "dupe_rate":       round(self._dupes / total, 4) if total else 0.0,
        }