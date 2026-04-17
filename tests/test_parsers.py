# tests/test_parsers.py
from credsift.parsers import FormatType, CredRecord

def test_credrecord_instantiation():
    record = CredRecord(raw="test@example.com:hunter2", fmt=FormatType.EMAIL_PASS)
    assert record.fmt == FormatType.EMAIL_PASS
    assert record.risk_score == 0.0