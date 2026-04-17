import pytest
from credsift.parsers import (
    detect_format, detect_hash_type, parse_line,
    FormatType, HashType, CredRecord,
)

# --- detect_hash_type ---

def test_hash_md5():
    assert detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99") == HashType.MD5

def test_hash_sha1():
    assert detect_hash_type("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8") == HashType.SHA1

def test_hash_sha256():
    h = "a" * 64
    assert detect_hash_type(h) == HashType.SHA256

def test_hash_bcrypt():
    assert detect_hash_type("$2b$12$" + "a" * 53) == HashType.BCRYPT

def test_hash_plaintext_returns_none():
    assert detect_hash_type("hunter2") is None

def test_hash_empty_returns_none():
    assert detect_hash_type("") is None


# --- detect_format ---

def test_format_email_pass():
    assert detect_format("bob@example.com:hunter2") == FormatType.EMAIL_PASS

def test_format_email_hash_md5():
    assert detect_format("bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99") == FormatType.EMAIL_HASH

def test_format_email_hash_bcrypt():
    line = "bob@example.com:$2b$12$" + "a" * 53
    assert detect_format(line) == FormatType.EMAIL_HASH

def test_format_user_pass():
    assert detect_format("bobsmith:hunter2") == FormatType.USER_PASS

def test_format_hash_only():
    assert detect_format("5f4dcc3b5aa765d61d8327deb882cf99") == FormatType.HASH_ONLY

def test_format_json():
    assert detect_format('{"email":"bob@example.com","password":"hunter2"}') == FormatType.JSON_EXPORT

def test_format_empty_is_unknown():
    assert detect_format("") == FormatType.UNKNOWN

def test_format_garbage_is_unknown():
    assert detect_format("%%%notarecord%%%") == FormatType.UNKNOWN


# --- parse_line ---

def test_parse_email_pass():
    r = parse_line("bob@example.com:hunter2")
    assert r.email == "bob@example.com"
    assert r.domain == "example.com"
    assert r.secret == "hunter2"
    assert r.is_hash is False

def test_parse_email_hash():
    r = parse_line("bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99")
    assert r.email == "bob@example.com"
    assert r.hash_type == HashType.MD5
    assert r.is_hash is True

def test_parse_user_pass():
    r = parse_line("bobsmith:hunter2")
    assert r.username == "bobsmith"
    assert r.secret == "hunter2"
    assert r.email is None

def test_parse_hash_only():
    r = parse_line("5f4dcc3b5aa765d61d8327deb882cf99")
    assert r.is_hash is True
    assert r.hash_type == HashType.MD5

def test_parse_json():
    r = parse_line('{"email":"bob@example.com","password":"hunter2"}')
    assert r.email == "bob@example.com"
    assert r.secret == "hunter2"

def test_parse_empty_returns_none():
    assert parse_line("") is None

def test_parse_unknown_returns_none():
    assert parse_line("%%%notarecord%%%") is None

def test_domain_extracted_correctly():
    r = parse_line("alice@corp.co.uk:password123")
    assert r.domain == "corp.co.uk"