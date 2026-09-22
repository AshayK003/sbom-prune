"""The one runnable check (SPEC): vulnerable-but-unimported pruned,
vulnerable-and-used kept, clean stays clean. Hermetic: recorded OSV
fixture, no live API."""

import json
from pathlib import Path

from osv import parse_response
from reach import compute
from sbom import pins_from_requirements

FIX = Path(__file__).parent / "fixtures" / "demo"

DIST_MAP = {
    "vulnlib": ["vulnlib"],
    "unusedlib": ["unusedlib"],
    "cleanlib": ["cleanlib"],
}


def test_verdicts():
    verdicts, unknown = compute(FIX, DIST_MAP)
    assert verdicts["vulnlib"] == "reachable"
    assert verdicts["unusedlib"] == "imported-unused"
    assert verdicts["cleanlib"] == "reachable"
    assert unknown == {}, unknown


def test_sbom_parse():
    pins, _ = pins_from_requirements(FIX / "requirements.txt")
    assert pins == {"vulnlib": "1.0", "unusedlib": "2.0", "cleanlib": "3.0"}


def test_osv_fixture_replay():
    payload = json.loads((FIX / "osv_demo.json").read_text(encoding="utf-8"))
    recs = {pkg: parse_response({"vulns": v}) for pkg, v in payload.items()}
    assert [r["id"] for r in recs["vulnlib"]] == ["CVE-20XX-0001"]
    assert [r["id"] for r in recs["unusedlib"]] == ["CVE-20XX-0002"]
    assert recs["cleanlib"] == []
