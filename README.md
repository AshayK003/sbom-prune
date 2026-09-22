# SBOM Reachability Pruning (Python)

**Author:** [Ashay Kushwaha](https://github.com/AshayK003) ([CypherLabs](https://github.com/AshayK003))

> **Status: corpus recon in progress — no numbers yet.** Nothing below is
> claimed until one command reproduces it. Article follows numbers, never
> precedes them.

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
