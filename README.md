# CC-REG-01: Open Claim-Checker

[![DOI](https://zenodo.org/badge/1410810221.svg)](https://doi.org/10.5281/zenodo.23246073)

A free, open tool that checks software-backed claims **by examining the evidence itself**, not by trusting labels.
Python 3.10+, standard library only, no external API.

## What it catches today

**Module 1, static scan (`ccreg_scan.py`)**
- `HARDCODED_PASS`: a status such as `"VERIFIED"` or `"PASS"` written as a literal, or chosen only by
  which command ran, instead of being derived from results.
- `PATTERNED_HASH`: a "SHA-256" that is a hand-typed sequence (e.g. `3f2e1d0c9b8a…`, two interleaved
  countdowns) rather than a real digest. 0 false alarms on 1,000,000 genuine SHA-256 values.

**Module 2, receipt recompute (`ccreg_receipts.py`)**
- Finds every declared file hash and `manifest_root` in a project and recomputes them from the bytes on disk.
  Reports MATCH, MISMATCH, MISSING or ESCAPES_ROOT for each file.

```
python ccreg_scan.py path/to/project
python ccreg_receipts.py path/to/project
```
Exit code 0 means nothing found or all receipts verified; 1 means findings to review.

## Results on real packages

| Package | Module 2 result |
|---|---|
| Coherent Accounting 51.0 | 19/19 files and root match → VERIFIED |
| Coherent Accounting 50.0 (from its PDF) | 11 listed `.pyc` files missing → BROKEN |
| GODNODE Ω²-APEX v7.8 | 27/27 → VERIFIED |
| FM-REG-01 v2 | 3/3 → VERIFIED |
| CA 51.0 with one planted line in `keys.py` | MISMATCH → BROKEN |

Module 1 flagged two literal "VERIFIED" statuses in a genesis-engine script, a command-name-only PASS in
GODNODE v7.7's CLI, and two invented receipts. It reported zero findings on the repaired GODNODE v7.8.

## Self-verification
- `python tests/test_ccreg.py`: 10/10 tests pass.
- `python tests/mutation_test.py`: removes each detection rule in turn; 8/8 removals are caught by the tests.
- Run on its own folder, module 1 flags exactly the two deliberately fake receipts kept as test fixtures.

## Status (HMCR evidence contract)
| Module | Status |
|---|---|
| 1. Static scan | Demonstrated |
| 2. Receipt recompute | Demonstrated |
| 3. Sandboxed test run | Specified |
| 4. Mutation check | Specified |
| 5. Evidence classification | Specified |
| 6. schema.org ClaimReview output | Specified |

**Limits:** findings are evidence for human review, never automatic verdicts. Module 1 is a heuristic: it finds
the two patterns above and cannot prove code is honest.

Author: Brian Scott Politzer. License: MIT.

## How to cite

Politzer, B. S. (2026). *CC-REG-01: Open Claim-Checker* (v0.2.0) [Software]. Zenodo. https://doi.org/10.5281/zenodo.23246074

To cite the project across all versions, use https://doi.org/10.5281/zenodo.23246073
