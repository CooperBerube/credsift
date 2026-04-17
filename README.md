# credsift

> CLI tool for credential dump triage and domain-targeted analysis.
[![CI](https://github.com/cooperberube/credsift/actions/workflows/ci.yml/badge.svg)](https://github.com/cooperberube/credsift/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Status: active development — v0.1.0 coming soon**

## What it does

Ingests credential dump files, normalizes formats, deduplicates,
enriches via HaveIBeenPwned (using k-anonymity), and outputs prioritized
hits filtered to a target domain.

## Installation

````bash
pip install credsift   # once published to PyPI
# or from source:
git clone https://github.com/YOUR_USERNAME/credsift
cd credsift && pip install -e .
\```

## Usage

```bash
credsift --input dump.txt --domain example.com --format table
\```

## Usage notes

**Re-running against the same file** — credsift remembers every record it
has processed in its session database (`credsift.db`). Running against the
same file twice will show no results on the second run because all records
are correctly identified as duplicates. Use `--dry-run` for repeated testing,
or `--db engagement_name.db` to isolate sessions per engagement. 