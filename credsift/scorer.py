# credsift/scorer.py
"""
Weighted risk scoring for CredRecord objects.

Each record receives a risk_score between 0.0 (lowest) and 1.0 (highest).
The score is a weighted sum of four sub-scores:

    credential_type  — plaintext passwords score highest
    domain_match     — exact target domain match scores highest
    format_quality   — structured formats score higher than bare hashes
    source_trust     — known breach sources score higher than unknown

Weights must sum to 1.0. Defaults reflect typical triage priority.
"""

from dataclasses import dataclass
from typing import Optional
from credsift.parsers import CredRecord, FormatType, HashType


# ── Weight configuration ───────────────────────────────────────────────────────

@dataclass
class ScoringWeights:
    """
    Relative importance of each scoring factor.
    All four weights must sum to 1.0.
    """
    credential_type: float = 0.35
    domain_match:    float = 0.35
    format_quality:  float = 0.15
    source_trust:    float = 0.15

    def __post_init__(self):
        total = (
            self.credential_type
            + self.domain_match
            + self.format_quality
            + self.source_trust
        )
        if not abs(total - 1.0) < 1e-6:
            raise ValueError(
                f"ScoringWeights must sum to 1.0, got {total:.4f}"
            )


DEFAULT_WEIGHTS = ScoringWeights()


# ── Trusted source registry ────────────────────────────────────────────────────

# Known reputable breach dataset identifiers.
# Analysts can extend this list as they add sources.
TRUSTED_SOURCES = {
    "hibp",
    "haveibeenpwned",
    "rockyou",
    "collection1",
    "antipublic",
    "breachcompilation",
    "comb",           # Combination Of Many Breaches (2021)
    "linkedin",
    "adobe",
    "myspace",
    "dropbox",
}


# ── Sub-scorers ────────────────────────────────────────────────────────────────

def _score_credential_type(record: CredRecord) -> float:
    """
    Score based on how exploitable the credential is.

    Plaintext password  → 1.0  (immediately usable for login)
    Unknown / no secret → 0.1  (minimal signal)
    Hash scores by crackability:
        MD5             → 0.85 (trivially crackable)
        SHA1            → 0.75 (easily crackable)
        SHA256          → 0.5  (crackable with resources)
        bcrypt          → 0.2  (computationally expensive)
    """
    if not record.secret:
        return 0.1

    if not record.is_hash:
        return 1.0  # plaintext password

    hash_scores = {
        HashType.MD5:    0.85,
        HashType.SHA1:   0.75,
        HashType.SHA256: 0.5,
        HashType.BCRYPT: 0.2,
        HashType.UNKNOWN: 0.4,
    }
    return hash_scores.get(record.hash_type, 0.4)


def _score_domain_match(record: CredRecord, target_domain: Optional[str]) -> float:
    """
    Score based on how closely the record matches the target domain.

    No target specified    → 0.5  (neutral — no context to score against)
    Exact domain match     → 1.0
    Subdomain match        → 0.7  (e.g. mail.example.com vs example.com)
    No match               → 0.1
    Record has no domain   → 0.2
    """
    if target_domain is None:
        return 0.5

    if not record.domain:
        return 0.2

    record_domain  = record.domain.lower().strip()
    target_domain  = target_domain.lower().strip()

    if record_domain == target_domain:
        return 1.0

    # Subdomain: record is mail.example.com, target is example.com
    if record_domain.endswith('.' + target_domain):
        return 0.7

    # Parent domain: record is example.com, target is mail.example.com
    if target_domain.endswith('.' + record_domain):
        return 0.6

    return 0.1


def _score_format_quality(record: CredRecord) -> float:
    """
    Score based on how structured and actionable the record format is.

    EMAIL_PASS   → 1.0  (email + plaintext — most actionable)
    EMAIL_HASH   → 0.8  (email + hash — actionable with cracking)
    USER_PASS    → 0.6  (username only — harder to attribute)
    JSON_EXPORT  → 0.7  (structured but variable field quality)
    HASH_ONLY    → 0.3  (no identity information)
    UNKNOWN      → 0.1
    """
    format_scores = {
        FormatType.EMAIL_PASS:  1.0,
        FormatType.EMAIL_HASH:  0.8,
        FormatType.JSON_EXPORT: 0.7,
        FormatType.USER_PASS:   0.6,
        FormatType.HASH_ONLY:   0.3,
        FormatType.UNKNOWN:     0.1,
    }
    return format_scores.get(record.fmt, 0.1)


def _score_source_trust(record: CredRecord) -> float:
    """
    Score based on the credibility of the data source.

    Known trusted source  → 1.0
    Unknown source        → 0.5
    No source recorded    → 0.3
    """
    if not record.source:
        return 0.3

    source_lower = record.source.lower().strip()

    for trusted in TRUSTED_SOURCES:
        if trusted in source_lower:
            return 1.0

    return 0.5


# ── Public API ─────────────────────────────────────────────────────────────────

def score(
    record: CredRecord,
    target_domain: Optional[str] = None,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> float:
    """
    Compute and return a risk score between 0.0 and 1.0 for a CredRecord.

    Args:
        record:        The CredRecord to score.
        target_domain: The domain being assessed (e.g. "example.com").
                       Pass None to score without domain context.
        weights:       ScoringWeights instance. Defaults to DEFAULT_WEIGHTS.

    Returns:
        Float between 0.0 and 1.0. Higher = higher priority.
    """
    s_cred   = _score_credential_type(record)
    s_domain = _score_domain_match(record, target_domain)
    s_format = _score_format_quality(record)
    s_source = _score_source_trust(record)

    raw_score = (
        weights.credential_type * s_cred
        + weights.domain_match  * s_domain
        + weights.format_quality * s_format
        + weights.source_trust  * s_source
    )

    return round(min(max(raw_score, 0.0), 1.0), 4)


def score_and_update(
    record: CredRecord,
    target_domain: Optional[str] = None,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> CredRecord:
    """
    Score a record and mutate its risk_score field in place.
    Returns the same record for convenient chaining.

    Example
    -------
        record = score_and_update(parse_line(line), target_domain="example.com")
    """
    record.risk_score = score(record, target_domain, weights)
    return record