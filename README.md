# credsift

> CLI tool for credential dump triage and domain-targeted analysis.

[![CI](https://github.com/cooperberube/credsift/actions/workflows/ci.yml/badge.svg)](https://github.com/cooperberube/credsift/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/credsift)](https://pypi.org/project/credsift/)

credsift ingests credential dump files, normalizes them across seven
formats, deduplicates across sessions, scores each record by risk, and
outputs a prioritized hit list filtered to a target domain. Built for
authorized security testing and incident response.

## Example output

credsift --input tests/fixtures/large_dump.txt \
>          --domain example.com \
>          --no-enrich \
>          --dry-run \
>          --top 10 \
>          --source rockyou

credsift  starting run


───────────────────────────────────────────────────────────────────────────────────────────── run summary ──────────────────────────────────────────────────────────────────────────────────────────────
  target domain : example.com
  processed     : 1,200
  unique        : 1,000
  duplicates    : 200

  high risk   (≥0.8) : 152
  medium risk (≥0.6) : 0
  low risk    (<0.6) : 0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


                                                       credsift results — example.com                                                       
                                                                                                                                            
    score   email / user                       domain                 secret                     type             tags                      
 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 
     1.00   carol868@example.com               example.com            correct-horse              email            —                         
     1.00   dave505@example.com                example.com            correct-horse              email            —                         
     1.00   grace446@example.com               example.com            monkey                     email            —                         
     1.00   bob983@example.com                 example.com            monkey                     email            —                         
     1.00   grace279@example.com               example.com            correct-horse              email            —                         
     1.00   bob747@example.com                 example.com            hunter2                    email            —                         
     1.00   frank719@example.com               example.com            hunter2                    email            —                         
     1.00   dave277@example.com                example.com            monkey                     email            —                         
     1.00   bob733@example.com                 example.com            password123                email            —                         
     1.00   alice874@example.com               example.com            password123                email            —                         
                                                                                                                                            
  showing 10 of 152 records

---

## Features

- Auto-detects seven credential formats — `email:password`, `email:MD5`,
  `email:SHA1`, `email:SHA256`, `email:bcrypt`, `user:password`,
  hash-only wordlists, and JSON breach exports
- Two-layer deduplication — bloom filter + SQLite, persistent across sessions
- Weighted risk scoring across credential type, domain match, format
  quality, and source trust
- HIBP enrichment via k-anonymity — plaintext passwords never leave
  your machine
- Three output formats — rich terminal table, CSV, newline-delimited JSON
- Session isolation via `--db` — one database file per engagement

---

## Installation

```bash
pip install credsift
```

Or from source:

```bash
git clone https://github.com/cooperberube/credsift
cd credsift
pip install -e .
```

---

## Usage

```bash
# Basic run — table output
credsift --input dump.txt --domain example.com

# Skip HIBP enrichment (faster, offline-safe)
credsift --input dump.txt --domain example.com --no-enrich

# Top 10 highest-risk hits only
credsift --input dump.txt --domain example.com --no-enrich --top 10

# Label the source for trust scoring
credsift --input dump.txt --domain example.com --source rockyou

# CSV output
credsift --input dump.txt --domain example.com --format csv > results.csv

# JSON output — pipe to jq for filtering
credsift --input dump.txt --domain example.com --format json \
  | jq 'select(.risk_score >= 0.7)'

# High risk records only
credsift --input dump.txt --domain example.com --min-score 0.8

# Dry run — process but do not write to database
credsift --input dump.txt --domain example.com --dry-run

# Isolate sessions per engagement
credsift --input dump.txt --domain example.com --db engagement_acme.db
```

---

## All flags

| Flag | Default | Description |
|---|---|---|
| `--input / -i` | required | Path to credential dump file |
| `--domain / -d` | none | Target domain to prioritize |
| `--format / -f` | `table` | Output format: `table`, `csv`, `json` |
| `--top` | all | Show only top N results by risk score |
| `--min-score` | `0.0` | Filter results below this score |
| `--source` | none | Label for this data source |
| `--no-enrich` | off | Skip HIBP enrichment |
| `--dry-run` | off | Process without writing to database |
| `--db` | `credsift.db` | Path to SQLite session database |

---

## Supported input formats

| Format | Example |
|---|---|
| `email:password` | `bob@example.com:hunter2` |
| `email:MD5` | `bob@example.com:5f4dcc3b5aa765d61d8327deb882cf99` |
| `email:SHA1` | `bob@example.com:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| `email:SHA256` | `bob@example.com:a665a45920422f...` |
| `email:bcrypt` | `bob@example.com:$2b$12$...` |
| `user:password` | `bobsmith:hunter2` |
| `hash only` | `5f4dcc3b5aa765d61d8327deb882cf99` |
| `JSON export` | `{"email":"bob@example.com","password":"hunter2"}` |

---

## Risk scoring

Each record receives a score between 0.0 and 1.0 based on four factors:

| Factor | Weight | High score | Low score |
|---|---|---|---|
| Credential type | 35% | Plaintext password | bcrypt hash |
| Domain match | 35% | Exact target domain | No match |
| Format quality | 15% | `email:password` | Hash only |
| Source trust | 15% | Known breach dataset | No source |

Scores are color-coded in table output — red (≥0.8), orange (≥0.6), yellow (≥0.4).

---

## HIBP enrichment and k-anonymity

When checking passwords against HaveIBeenPwned, credsift never transmits
the plaintext password or its full hash. Only the first 5 characters of
the SHA1 hash are sent. The full suffix is checked locally against the
returned dataset. This is the k-anonymity model described in the
[HIBP API documentation](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange).

Hash records are skipped automatically — cracking is out of scope.
API failures degrade gracefully — the run continues without enrichment.
Results are cached in SQLite so each unique password is only checked once
across all sessions.

---

## Session management

credsift remembers every record it processes in its session database.
Running the same dump twice correctly produces no output on the second
run — all records are identified as duplicates. This is intentional
for production use where you ingest multiple related dumps over time
and want to see only what is new.

For repeated testing, use `--dry-run`. For separate engagements,
use `--db engagement_name.db`.

---

## Legal and ethics

This tool is for authorized security testing, incident response, and
threat intelligence work only. Use against systems or data you do not
have explicit written permission to analyze is prohibited.

See [docs/ETHICS.md](docs/ETHICS.md) for the full policy.

---

## Development

```bash
git clone https://github.com/cooperberube/credsift
cd credsift
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE) for details.