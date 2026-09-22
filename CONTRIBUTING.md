# Contributing

## One command reproduces everything

```bash
python -m pytest tests -q   # suite green on CPython >= 3.10, hermetic (recorded fixtures)
python report.py            # regenerates every README number (needs PyPI + OSV network)
```

## Corpus policy (frozen v1)

`corpus.json` v1 (8 roots, pins + OSV snapshot 2026-09-22) is **frozen**.
Predictions in it are audit inputs, not ground truth — the audit
(`internals/AUDIT.json`, never committed) decides. Additions bump the
version and re-run everything.

## Reachability rules

Verdict enum is `reachable` / `imported-unused` / `unimported`, computed
from shipped code with test/doc trees excluded. New signals (usage
heuristics, extra mappings) must keep the fixture suite green and be
re-audited. Blind spots stay documented, never silently absorbed.

## Open issues (stretch, in order)

1. **Symbol-level pruning** — needs per-symbol OSV data that mostly
   doesn't exist for PyPI; entry-point awareness (the blackd nuance) rides
   along here.
2. VEX-statement output for existing triage pipelines.
3. Offline DB mode (cached OSV snapshot instead of live API).
4. Lockfile support beyond requirements/pip-freeze (poetry, uv).
