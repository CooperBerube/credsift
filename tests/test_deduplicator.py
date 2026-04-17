# tests/test_deduplicator.py
import pytest
from pathlib import Path
from credsift.parsers import parse_line
from credsift.db import init_db, insert_record
from credsift.deduplicator import Deduplicator


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    return db


def make_record(raw="bob@example.com:hunter2"):
    return parse_line(raw)


def test_new_record_is_new(tmp_db):
    dedup = Deduplicator(db_path=tmp_db)
    r = make_record()
    assert dedup.is_new(r) is True


def test_same_record_twice_is_not_new(tmp_db):
    dedup = Deduplicator(db_path=tmp_db)
    r = make_record()
    dedup.is_new(r)
    assert dedup.is_new(r) is False


def test_different_records_are_both_new(tmp_db):
    dedup = Deduplicator(db_path=tmp_db)
    assert dedup.is_new(make_record("a@example.com:pass1")) is True
    assert dedup.is_new(make_record("b@example.com:pass2")) is True


def test_stats_track_correctly(tmp_db):
    dedup = Deduplicator(db_path=tmp_db)
    r = make_record()
    dedup.is_new(r)
    dedup.is_new(r)   # duplicate
    assert dedup.stats["unique"]     == 1
    assert dedup.stats["duplicates"] == 1
    assert dedup.stats["dupe_rate"]  == 0.5


def test_bloom_catches_db_existing_record(tmp_db):
    """Record already in DB from a previous session should be caught."""
    r = make_record()
    insert_record(r, tmp_db)       # simulate a previous session
    dedup = Deduplicator(db_path=tmp_db)
    assert dedup.is_new(r) is False


def test_stats_empty_session(tmp_db):
    dedup = Deduplicator(db_path=tmp_db)
    assert dedup.stats["dupe_rate"] == 0.0