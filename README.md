# credsift

> CLI tool for credential dump triage and domain-targeted analysis.

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