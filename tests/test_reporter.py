# tests/test_reporter.py
import json
from io import StringIO
from credsift.parsers import parse_line
from credsift.scorer import score_and_update
from credsift.reporter import (
    report_csv, report_json, report_table,
    report, print_summary, _risk_color, _truncate,
)


def make_records():
    raws = [
        "alice@example.com:password123",
        "bob@example.com:hunter2",
        "carol@example.com:5f4dcc3b5aa765d61d8327deb882cf99",
        "dave@other.com:letmein",
    ]
    records = [parse_line(r) for r in raws]
    for r in records:
        score_and_update(r, target_domain="example.com")
    return records


def test_risk_color_high():
    assert _risk_color(0.9) == "bold red"


def test_risk_color_medium():
    assert _risk_color(0.7) == "orange3"


def test_risk_color_low():
    assert _risk_color(0.2) == "dim"


def test_truncate_short_string():
    assert _truncate("hello") == "hello"


def test_truncate_long_string():
    result = _truncate("a" * 50, max_len=10)
    assert len(result) == 10
    assert result.endswith("…")


def test_truncate_none():
    assert _truncate(None) == "—"


def test_report_csv_headers(capsys):
    records = make_records()
    report_csv(records)
    captured = capsys.readouterr()
    assert "email" in captured.out
    assert "risk_score" in captured.out


def test_report_csv_row_count():
    records = make_records()
    out = StringIO()
    report_csv(records, output=out)
    lines = out.getvalue().strip().split("\n")
    assert len(lines) == len(records) + 1  # +1 for header


def test_report_csv_top():
    records = make_records()
    out = StringIO()
    report_csv(records, top=2, output=out)
    lines = out.getvalue().strip().split("\n")
    assert len(lines) == 3  # header + 2 records


def test_report_json_valid():
    records = make_records()
    out = StringIO()
    report_json(records, output=out)
    lines = out.getvalue().strip().split("\n")
    assert len(lines) == len(records)
    for line in lines:
        obj = json.loads(line)
        assert "email" in obj
        assert "risk_score" in obj


def test_report_json_sorted_by_score():
    records = make_records()
    out = StringIO()
    report_json(records, output=out)
    lines = out.getvalue().strip().split("\n")
    scores = [json.loads(l)["risk_score"] for l in lines]
    assert scores == sorted(scores, reverse=True)


def test_report_json_top():
    records = make_records()
    out = StringIO()
    report_json(records, top=2, output=out)
    lines = out.getvalue().strip().split("\n")
    assert len(lines) == 2


def test_report_dispatcher_unknown_format(capsys):
    records = make_records()
    report(records, fmt="xml")
    captured = capsys.readouterr()
    assert "Unknown format" in captured.out