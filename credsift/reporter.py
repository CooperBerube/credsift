# credsift/reporter.py
"""Output formatters: rich terminal table, CSV, JSON."""

def report(records, fmt: str = "table") -> None:
    raise NotImplementedError