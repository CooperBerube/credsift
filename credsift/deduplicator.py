# credsift/deduplicator.py
"""Bloom filter + SQLite-backed deduplication for CredRecord streams."""

def is_duplicate(record) -> bool:
    raise NotImplementedError