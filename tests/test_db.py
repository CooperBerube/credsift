# tests/test_db.py
import pytest
from pathlib import Path
from credsift.parsers import parse_line, FormatType
from credsift.db import (
    init_db, insert_record, exists, record_hash,
    query_by_domain, query_top, record_count,
)


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a fresh temporary database for each test."""
    db = tmp_path / "test.db"
    init_db(db)
    return db


def make_record(raw="bob@example.com:hunter2"):
    return parse_line(raw)


def test_init_creates_db(tmp_db):
    assert tmp_db.exists()


def test_insert_returns_true_for_new_record(tmp_db):
    r = make_record()
    assert insert_record(r, tmp_db) is True


def test_insert_returns_false_for_duplicate(tmp_db):
    r = make_record()
    insert_record(r, tmp_db)
    assert insert_record(r, tmp_db) is False


def test_exists_true_after_insert(tmp_db):
    r = make_record()
    insert_record(r, tmp_db)
    assert exists(r.raw, tmp_db) is True


def test_exists_false_before_insert(tmp_db):
    assert exists("nobody@nowhere.com:pass", tmp_db) is False


def test_record_count(tmp_db):
    insert_record(make_record("a@example.com:pass1"), tmp_db)
    insert_record(make_record("b@example.com:pass2"), tmp_db)
    assert record_count(tmp_db) == 2


def test_query_by_domain(tmp_db):
    insert_record(make_record("alice@target.com:pass1"), tmp_db)
    insert_record(make_record("bob@target.com:pass2"), tmp_db)
    insert_record(make_record("carol@other.com:pass3"), tmp_db)
    rows = query_by_domain("target.com", tmp_db)
    assert len(rows) == 2
    assert all(r["domain"] == "target.com" for r in rows)


def test_query_top(tmp_db):
    insert_record(make_record("a@example.com:pass1"), tmp_db)
    insert_record(make_record("b@example.com:pass2"), tmp_db)
    insert_record(make_record("c@example.com:pass3"), tmp_db)
    rows = query_top(2, tmp_db)
    assert len(rows) == 2


def test_record_hash_is_deterministic():
    assert record_hash("test") == record_hash("test")


def test_record_hash_differs_for_different_input():
    assert record_hash("test1") != record_hash("test2")