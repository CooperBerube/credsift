# tests/test_enricher.py
"""
Tests for enricher.py.

The HIBP API is never called in tests. _fetch_range is monkeypatched
to return controlled responses so tests are fast, offline, and deterministic.
"""
import pytest
from pathlib import Path
from credsift.parsers import parse_line, CredRecord, FormatType
from credsift.db import init_db
from credsift.enricher import (
    init_hibp_cache, check_password, enrich, enrich_batch,
    _sha1, _cache_get, _cache_set,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    init_hibp_cache(db)
    return db


def make_record(raw="bob@example.com:hunter2"):
    return parse_line(raw)


def fake_hibp_response(plaintext: str, count: int = 10) -> str:
    """
    Build a fake HIBP range response containing the given plaintext's
    SHA1 suffix with the given breach count.
    """
    sha1   = _sha1(plaintext)
    suffix = sha1[5:]
    # HIBP returns suffix:count, one per line, uppercase
    return f"{suffix.upper()}:{count}\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"


# ── _sha1 ─────────────────────────────────────────────────────────────────────

def test_sha1_returns_uppercase_hex():
    result = _sha1("hunter2")
    assert result == result.upper()
    assert len(result) == 40


def test_sha1_known_value():
    # SHA1("password") is well known
    assert _sha1("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_sha1_deterministic():
    assert _sha1("test") == _sha1("test")


# ── Cache ─────────────────────────────────────────────────────────────────────

def test_cache_miss_returns_none(tmp_db):
    assert _cache_get("AAAAA", tmp_db) is None


def test_cache_set_and_get(tmp_db):
    _cache_set("AAAAA", "BBBBB:5", tmp_db)
    assert _cache_get("AAAAA", tmp_db) == "BBBBB:5"


def test_cache_is_case_insensitive(tmp_db):
    _cache_set("aaaaa", "BBBBB:5", tmp_db)
    assert _cache_get("AAAAA", tmp_db) == "BBBBB:5"


def test_cache_overwrite(tmp_db):
    _cache_set("AAAAA", "first", tmp_db)
    _cache_set("AAAAA", "second", tmp_db)
    assert _cache_get("AAAAA", tmp_db) == "second"


# ── check_password ────────────────────────────────────────────────────────────

def test_check_password_found(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: fake_hibp_response("hunter2", count=9834)
    )
    count = check_password("hunter2", tmp_db)
    assert count == 9834


def test_check_password_not_found(monkeypatch, tmp_db):
    # Return a response that does NOT contain hunter2's suffix
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
    )
    count = check_password("hunter2", tmp_db)
    assert count == 0


def test_check_password_uses_cache(monkeypatch, tmp_db):
    calls = {"n": 0}

    def fake_fetch(prefix):
        calls["n"] += 1
        return fake_hibp_response("hunter2", count=5)

    monkeypatch.setattr("credsift.enricher._fetch_range", fake_fetch)

    check_password("hunter2", tmp_db)  # first call — hits API
    check_password("hunter2", tmp_db)  # second call — should hit cache

    assert calls["n"] == 1  # API called exactly once


def test_check_password_api_error_returns_none(monkeypatch, tmp_db):
    def bad_fetch(prefix):
        raise Exception("network error")

    monkeypatch.setattr("credsift.enricher._fetch_range", bad_fetch)
    result = check_password("hunter2", tmp_db)
    assert result is None


# ── enrich ────────────────────────────────────────────────────────────────────

def test_enrich_pwned_record(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: fake_hibp_response("hunter2", count=9834)
    )
    r = make_record("bob@example.com:hunter2")
    result = enrich(r, tmp_db)
    assert result["checked"] is True
    assert result["pwned"] is True
    assert result["breach_count"] == 9834
    assert "hibp:pwned" in result["tag"]


def test_enrich_clean_record(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
    )
    r = make_record("bob@example.com:hunter2")
    result = enrich(r, tmp_db)
    assert result["checked"] is True
    assert result["pwned"] is False
    assert result["breach_count"] == 0
    assert result["tag"] == "hibp:clean"


def test_enrich_skips_hash_records(tmp_db):
    r = make_record("bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99")
    result = enrich(r, tmp_db)
    assert result["checked"] is False
    assert result["tag"] == "hibp:skipped-hash"


def test_enrich_skips_record_with_no_secret(tmp_db):
    r = CredRecord(raw="empty", fmt=FormatType.UNKNOWN)
    result = enrich(r, tmp_db)
    assert result["tag"] == "hibp:no-secret"


def test_enrich_tags_record_when_pwned(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: fake_hibp_response("hunter2", count=5)
    )
    r = make_record("bob@example.com:hunter2")
    enrich(r, tmp_db)
    assert any("hibp:pwned" in tag for tag in r.tags)


def test_enrich_tags_record_when_clean(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
    )
    r = make_record("bob@example.com:hunter2")
    enrich(r, tmp_db)
    assert "hibp:clean" in r.tags


def test_enrich_api_error_gracefully_degrades(monkeypatch, tmp_db):
    def bad_fetch(prefix):
        raise Exception("network error")

    monkeypatch.setattr("credsift.enricher._fetch_range", bad_fetch)
    r = make_record("bob@example.com:hunter2")
    result = enrich(r, tmp_db)
    assert result["tag"] == "hibp:api-error"
    assert result["checked"] is False


# ── enrich_batch ──────────────────────────────────────────────────────────────

def test_enrich_batch_returns_one_result_per_record(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: fake_hibp_response("hunter2", count=1)
    )
    records = [
        make_record("a@example.com:hunter2"),
        make_record("b@example.com:hunter2"),
        make_record("c@example.com:5f4dcc3b5aa765d61d8327deb882cf99"),
    ]
    results = enrich_batch(records, tmp_db)
    assert len(results) == 3


def test_enrich_batch_skips_hashes(monkeypatch, tmp_db):
    monkeypatch.setattr(
        "credsift.enricher._fetch_range",
        lambda prefix: fake_hibp_response("hunter2", count=1)
    )
    records = [
        make_record("a@example.com:hunter2"),
        make_record("b@example.com:5f4dcc3b5aa765d61d8327deb882cf99"),
    ]
    results = enrich_batch(records, tmp_db)
    assert results[0]["checked"] is True
    assert results[1]["checked"] is False