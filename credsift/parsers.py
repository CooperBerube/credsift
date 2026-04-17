# credsift/parsers.py
"""
Format detection and field extraction for credential dump lines.

Supported formats (to be implemented in Milestone 2):
  - email:password
  - email:hash  (MD5 / SHA1 / bcrypt inferred by length/prefix)
  - user:password (no domain)
  - hash-only wordlists
  - JSON breach exports
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FormatType(Enum):
    EMAIL_PASS   = "email:password"
    EMAIL_HASH   = "email:hash"
    USER_PASS    = "user:password"
    HASH_ONLY    = "hash_only"
    JSON_EXPORT  = "json_export"
    UNKNOWN      = "unknown"


@dataclass
class CredRecord:
    raw:        str
    fmt:        FormatType
    email:      Optional[str] = None
    username:   Optional[str] = None
    domain:     Optional[str] = None
    secret:     Optional[str] = None   # password or hash
    is_hash:    bool = False
    source:     Optional[str] = None
    risk_score: float = 0.0
    tags:       list[str] = field(default_factory=list)


def detect_format(line: str) -> FormatType:
    """Inspect a single line and return its FormatType."""
    raise NotImplementedError


def parse_line(line: str, fmt: FormatType) -> Optional[CredRecord]:
    """Parse a line into a CredRecord given a known FormatType."""
    raise NotImplementedError