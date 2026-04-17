import re
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# Format examples (reference):
# email:password       →  bob@example.com:hunter2
# email:hash (MD5)     →  bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99
# email:hash (SHA1)    →  bob@example.com:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# email:hash (bcrypt)  →  bob@example.com:$2b$12$KIXHrMCwqBQRJmMaRBZOku...
# user:password        →  bobsmith:hunter2
# hash only            →  5f4dcc3b5aa765d61d8327deb882cf99
# json export          →  {"email": "bob@example.com", "password": "hunter2"}


# ── Enums ────────────────────────────────────────────────────────────────────

class HashType(Enum):
    MD5     = "md5"
    SHA1    = "sha1"
    SHA256  = "sha256"
    BCRYPT  = "bcrypt"
    UNKNOWN = "unknown"


class FormatType(Enum):
    EMAIL_PASS  = "email:password"
    EMAIL_HASH  = "email:hash"
    USER_PASS   = "user:password"
    HASH_ONLY   = "hash_only"
    JSON_EXPORT = "json_export"
    UNKNOWN     = "unknown"


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class CredRecord:
    raw:        str
    fmt:        FormatType
    email:      Optional[str]      = None
    username:   Optional[str]      = None
    domain:     Optional[str]      = None
    secret:     Optional[str]      = None   # password or hash string
    hash_type:  Optional[HashType] = None
    is_hash:    bool               = False
    source:     Optional[str]      = None
    risk_score: float              = 0.0
    tags:       list[str]          = field(default_factory=list)


# ── Regex ─────────────────────────────────────────────────────────────────────

HEX_RE   = re.compile(r'^[a-fA-F0-9]+$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


# ── Helpers ───────────────────────────────────────────────────────────────────

def detect_hash_type(value: str) -> Optional[HashType]:
    """Return HashType if value looks like a hash, else None."""
    v = value.strip()
    if not v:
        return None
    if v.startswith(('$2b$', '$2a$')) and len(v) == 60:
        return HashType.BCRYPT
    if HEX_RE.match(v):
        if len(v) == 32:
            return HashType.MD5
        if len(v) == 40:
            return HashType.SHA1
        if len(v) == 64:
            return HashType.SHA256
    return None


def _split_email(email: str) -> tuple[str, str]:
    """Return (local, domain) from an email string."""
    local, _, domain = email.partition('@')
    return local, domain


# ── Core functions ────────────────────────────────────────────────────────────

def detect_format(line: str) -> FormatType:
    """Inspect a single line and return its FormatType."""
    line = line.strip()
    if not line:
        return FormatType.UNKNOWN

    # 1. JSON — try parse first, unambiguous
    if line.startswith('{'):
        try:
            json.loads(line)
            return FormatType.JSON_EXPORT
        except json.JSONDecodeError:
            pass

    # 2. Colon-separated — the most common case
    if ':' in line:
        left, _, right = line.partition(':')
        left  = left.strip()
        right = right.strip()

        if EMAIL_RE.match(left):
            if detect_hash_type(right):
                return FormatType.EMAIL_HASH
            return FormatType.EMAIL_PASS

        if left and right:
            return FormatType.USER_PASS

    # 3. Hash only — no colon, matches a known hash pattern
    if detect_hash_type(line):
        return FormatType.HASH_ONLY

    return FormatType.UNKNOWN


def parse_line(line: str, fmt: Optional[FormatType] = None) -> Optional[CredRecord]:
    """
    Parse a raw line into a CredRecord.
    If fmt is None, detect_format() is called automatically.
    Returns None if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    if fmt is None:
        fmt = detect_format(line)

    if fmt == FormatType.EMAIL_PASS:
        left, _, right = line.partition(':')
        _, domain = _split_email(left.strip())
        return CredRecord(
            raw=line, fmt=fmt,
            email=left.strip(), domain=domain,
            secret=right.strip(),
        )

    if fmt == FormatType.EMAIL_HASH:
        left, _, right = line.partition(':')
        _, domain = _split_email(left.strip())
        ht = detect_hash_type(right.strip())
        return CredRecord(
            raw=line, fmt=fmt,
            email=left.strip(), domain=domain,
            secret=right.strip(),
            hash_type=ht, is_hash=True,
        )

    if fmt == FormatType.USER_PASS:
        left, _, right = line.partition(':')
        return CredRecord(
            raw=line, fmt=fmt,
            username=left.strip(),
            secret=right.strip(),
        )

    if fmt == FormatType.HASH_ONLY:
        ht = detect_hash_type(line)
        return CredRecord(
            raw=line, fmt=fmt,
            secret=line,
            hash_type=ht, is_hash=True,
        )

    if fmt == FormatType.JSON_EXPORT:
        try:
            data   = json.loads(line)
            email  = data.get('email') or data.get('Email')
            secret = data.get('password') or data.get('Password') or data.get('hash')
            domain = _split_email(email)[1] if email else None
            return CredRecord(
                raw=line, fmt=fmt,
                email=email, domain=domain,
                secret=secret,
            )
        except (json.JSONDecodeError, AttributeError):
            return None

    return None  # UNKNOWN