# SBOM Reachability Pruning (Python)

**Author:** [Ashay Kushwaha](https://github.com/AshayK003) ([CypherLabs](https://github.com/AshayK003))
**Report:** [internals/report.pdf](internals/report.pdf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)] [![Report](https://img.shields.io/badge/report-PDF-red.svg)](internals/report.pdf)

**Keywords:** SBOM, supply-chain security, vulnerability triage, OSV, reachability analysis, govulncheck for Python

> **Status: measured on CPython 3.12.10 (Windows), `python report.py`
> regenerates every number.** Article follows numbers, never precedes them.

---

## Gap

Vulnerability scanners (Grype, Trivy, DepScan, pip-audit) match CVEs by
package version and drown teams in findings for code that is never called
--- pairwise agreement sits under 0.7 Jaccard, and OSV records from
different sources openly conflict. The gold-standard fix, Go's
govulncheck, narrows version matches to actually-called code with call
stacks --- but it is Go-only. The official Python attempt (osv-scanner PR
\#2131) is experimental, poetry.lock-only, written in Go, and parses
Python with regexes. **No Python-native tool maps version matches to
module-level reachability with measured precision.** This repo is that
tool.

## What it will do

SBOM from pip-freeze/requirements, CVE mapping via the free OSV API
(per-source records, never silently merged), and stdlib-`ast` import +
usage analysis to verdict each finding `reachable`, `imported-unused`,
or `unimported` --- then measure precision before/after pruning on a
fixed 8-repo corpus, with ground truth from manual audit. No floating
percentages cited; our own numbers or nothing.

## Results (`python report.py`, frozen OSV snapshot 2026-09-22)

162 version-match findings across 8 roots prune to 143 reachable-only
(19 pruned). Manual audit of all 11 finding-bearing verdicts against
actual import lines: precision **0.88 before → 1.00 after**, zero
reachable findings dropped.

| Root | Findings | Kept | Pruned | Note |
|---|---|---|---|---|
| requests 2.28.2 | 20 | 20 | 0 | urllib3/idna/certifi all used |
| flask 2.0.3 | 30 | 30 | 0 | Werkzeug/Jinja2/click all used |
| httpie 3.2.2 | 31 | 12 | 19 | dev-Werkzeug never imported |
| black 23.12.1+jupyter | 81 | 81 | 0 | aiohttp via optional blackd daemon (documented nuance, not silent) |
| pydantic, jinja2, redos-harness, pyyaml | 0 | 0 | 0 | clean controls |

Two predictions overturned by evidence, both documented: aiohttp is
imported by shipped `blackd` (verdict reachable per spec; prune story
rests on Werkzeug-dev), and the empty-summary click record is a real
advisory (CVE-2026-7246, range verified to include 8.0.4).

Accept-rule for every verdict: imports read from shipped wheels, benign
ground truth from manual audit (`internals/AUDIT.json`, not committed) —
never inferred, never cited from elsewhere.

## References

- OSV API (`v1/query`): https://google.github.io/osv.dev/post-v1-query/
- govulncheck tutorial (the model): https://tip.golang.org/doc/tutorial/govulncheck
- osv-scanner Python reachability PR: https://github.com/google/osv-scanner/pull/2131
- Scanner-consistency study: https://arxiv.org/html/2503.14388v3
- pip-audit (reference OSV client): https://github.com/pypa/pip-audit

## Limitations (honest, updated as numbers land)

- Module level only: symbol-level pruning waits on per-symbol OSV data that
  mostly doesn't exist for PyPI.
- Dynamic imports (`__import__`, `importlib`), console-script-only deps, and
  namespace packages are documented blind spots, not handled cases.
