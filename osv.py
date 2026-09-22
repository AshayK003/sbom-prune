"""Minimal OSV v1/query client over stdlib urllib (no requests).

Per-source records are returned as-is and never merged: conflicting ranges
across GHSA/PYSEC/CVE records are the caller's to report, not ours to hide.
"""

import json
import urllib.request

API = "https://api.osv.dev/v1/query"


def parse_response(payload):
    """Extract [{id, summary, aliases, affected}] from a v1/query payload."""
    out = []
    for v in payload.get("vulns") or []:
        out.append(
            {
                "id": v.get("id"),
                "summary": v.get("summary") or "",
                "aliases": v.get("aliases") or [],
                "affected": v.get("affected") or [],
            }
        )
    return out


def query(package, version, timeout=30):
    """Live query. Returns record list. Raises on network/HTTP failure."""
    body = json.dumps(
        {"package": {"name": package, "ecosystem": "PyPI"}, "version": version}
    ).encode()
    req = urllib.request.Request(API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return parse_response(json.load(resp))


def snapshot(pins, timeout=30):
    """{package: [records]} for pinned {package: version}. Unpinned skipped."""
    out = {}
    for package, version in pins.items():
        if not version:
            out[package] = {"unpinned": True, "records": []}
        else:
            out[package] = {"unpinned": False, "records": query(package, version, timeout)}
    return out


def save_fixture(data, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def load_fixture(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
