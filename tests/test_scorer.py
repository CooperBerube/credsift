# tests/test_scorer.py
import pytest
from credsift.parsers import parse_line, CredRecord, FormatType, HashType
from credsift.scorer import (
    score, score_and_update, ScoringWeights,
    _score_credential_type, _score_domain_match,
    _score_format_quality, _score_source_trust,
    DEFAULT_WEIGHTS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make(raw: str, source: str = None) -> CredRecord:
    r = parse_line(raw)
    r.source = source
    return r


# ── ScoringWeights ────────────────────────────────────────────────────────────

def test_default_weights_sum_to_one():
    w = DEFAULT_WEIGHTS
    total = w.credential_type + w.domain_match + w.format_quality + w.source_trust
    assert abs(total - 1.0) < 1e-6


def test_custom_weights_valid():
    w = ScoringWeights(
        credential_type=0.4,
        domain_match=0.3,
        format_quality=0.2,
        source_trust=0.1,
    )
    assert w.credential_type == 0.4


def test_invalid_weights_raise():
    with pytest.raises(ValueError):
        ScoringWeights(
            credential_type=0.5,
            domain_match=0.5,
            format_quality=0.5,
            source_trust=0.5,
        )


# ── Credential type scoring ───────────────────────────────────────────────────

def test_plaintext_scores_highest():
    r = make("bob@example.com:hunter2")
    assert _score_credential_type(r) == 1.0


def test_md5_scores_higher_than_bcrypt():
    md5    = make("bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99")
    bcrypt = make("bob@example.com:$2b$12$" + "a" * 53)
    assert _score_credential_type(md5) > _score_credential_type(bcrypt)


def test_no_secret_scores_low():
    r = CredRecord(raw="garbage", fmt=FormatType.UNKNOWN)
    assert _score_credential_type(r) == 0.1


# ── Domain match scoring ──────────────────────────────────────────────────────

def test_exact_domain_match():
    r = make("bob@example.com:pass")
    assert _score_domain_match(r, "example.com") == 1.0


def test_subdomain_match():
    r = make("bob@mail.example.com:pass")
    assert _score_domain_match(r, "example.com") == 0.7


def test_no_domain_match():
    r = make("bob@other.com:pass")
    assert _score_domain_match(r, "example.com") == 0.1


def test_no_target_domain_is_neutral():
    r = make("bob@example.com:pass")
    assert _score_domain_match(r, None) == 0.5


def test_record_without_domain():
    r = make("bobsmith:hunter2")
    assert _score_domain_match(r, "example.com") == 0.2


# ── Format quality scoring ────────────────────────────────────────────────────

def test_email_pass_highest_format():
    r = make("bob@example.com:hunter2")
    assert _score_format_quality(r) == 1.0


def test_hash_only_lowest_format():
    r = make("5f4dcc3b5aa765d61d8327deb882cf99")
    assert _score_format_quality(r) == 0.3


def test_email_hash_higher_than_user_pass():
    eh = make("bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99")
    up = make("bobsmith:hunter2")
    assert _score_format_quality(eh) > _score_format_quality(up)


# ── Source trust scoring ──────────────────────────────────────────────────────

def test_known_source_scores_highest():
    r = make("bob@example.com:pass", source="hibp")
    assert _score_source_trust(r) == 1.0


def test_unknown_source_scores_mid():
    r = make("bob@example.com:pass", source="some_random_paste")
    assert _score_source_trust(r) == 0.5


def test_no_source_scores_lowest():
    r = make("bob@example.com:pass", source=None)
    assert _score_source_trust(r) == 0.3


def test_source_match_is_case_insensitive():
    r = make("bob@example.com:pass", source="HIBP")
    assert _score_source_trust(r) == 1.0


def test_source_match_partial():
    r = make("bob@example.com:pass", source="haveibeenpwned-2023")
    assert _score_source_trust(r) == 1.0


# ── Full score() ──────────────────────────────────────────────────────────────

def test_score_returns_float_between_0_and_1():
    r = make("bob@example.com:hunter2")
    s = score(r, target_domain="example.com")
    assert 0.0 <= s <= 1.0


def test_high_value_record_scores_above_0_8():
    """Plaintext password, exact domain match, trusted source."""
    r = make("bob@example.com:hunter2", source="hibp")
    s = score(r, target_domain="example.com")
    assert s >= 0.8


def test_low_value_record_scores_below_0_5():
    """Hash-only record, no domain, no source — should score below 0.5."""
    r = make("5f4dcc3b5aa765d61d8327deb882cf99")
    s = score(r, target_domain="example.com")
    assert s < 0.5


def test_score_without_target_domain():
    r = make("bob@example.com:hunter2")
    s = score(r)
    assert 0.0 <= s <= 1.0


def test_score_and_update_mutates_record():
    r = make("bob@example.com:hunter2")
    assert r.risk_score == 0.0
    score_and_update(r, target_domain="example.com")
    assert r.risk_score > 0.0


def test_score_and_update_returns_record():
    r = make("bob@example.com:hunter2")
    result = score_and_update(r)
    assert result is r


def test_custom_weights_change_score():
    """A record with mixed sub-scores should change when weights shift."""
    # MD5 hash (not plaintext), exact domain match, trusted source
    # credential_type sub-score is 0.85 not 1.0 — so weights matter
    r = make("bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99", source="hibp")
    default_score = score(r, target_domain="example.com")
    w = ScoringWeights(
        credential_type=0.1,
        domain_match=0.1,
        format_quality=0.1,
        source_trust=0.7,
    )
    custom_score = score(r, target_domain="example.com", weights=w)
    assert default_score != custom_score