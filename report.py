"""One-command precision report (stdlib only).

Reads frozen corpus.json, fetches each root's sdist from PyPI (small,
KBs), computes module-level verdicts, and prints the before/after table.
If internals/AUDIT.json exists (manual ground-truth labels), precision
is computed; otherwise the verdict table prints with audit pending.

Scope rule: test/doc/example trees are EXCLUDED -- reachability means
production-code reachability. Test-only usage is a different claim.
"""

import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from reach import compute  # noqa: E402
from sbom import canonical  # noqa: E402

EXCLUDE = ("tests", "test", "testing", "docs", "examples", "example")


def pruned_tree(src):
    """Copy src minus test/doc trees into a temp dir. Returns temp path."""
    import shutil

    dst = tempfile.mkdtemp(prefix="sbomprune_")
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(
            d for d in dirnames if d not in EXCLUDE and not d.startswith(".")
        )
        rel = os.path.relpath(dirpath, src)
        target = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for f in filenames:
            if f.endswith(".py") and not f.startswith("test_") and f != "conftest.py":
                shutil.copy2(os.path.join(dirpath, f), os.path.join(target, f))
    return dst


ROOTS = {  # id -> (pypi-name, version) | ("local", relpath) | None
    "requests": ("requests", "2.28.2"),
    "flask": ("flask", "2.0.3"),
    "httpie": ("httpie", "3.2.2"),
    "black": ("black", "23.12.1"),
    "pydantic": ("pydantic", "1.10.13"),
    "jinja2": ("jinja2", "3.0.3"),
    "redos-harness": ("local", os.path.join(HERE, "..", "redos-harness")),
    "pyyaml": None,
}

DIST_MAPS = {  # id -> {canonical-dist: [top-level modules]}
    "requests": {"urllib3": ["urllib3"], "idna": ["idna"], "certifi": ["certifi"], "charset-normalizer": ["charset_normalizer"]},
    "flask": {"werkzeug": ["werkzeug"], "jinja2": ["jinja2"], "itsdangerous": ["itsdangerous"], "click": ["click"]},
    "httpie": {"requests": ["requests"], "pygments": ["pygments"], "rich": ["rich"], "multidict": ["multidict"], "defusedxml": ["defusedxml"], "requests-toolbelt": ["requests_toolbelt"], "werkzeug": ["werkzeug"]},
    "black": {"click": ["click"], "packaging": ["packaging"], "pathspec": ["pathspec"], "platformdirs": ["platformdirs"], "mypy-extensions": ["mypy_extensions"], "aiohttp": ["aiohttp"], "ipython": ["IPython"]},
    "pydantic": {"typing-extensions": ["typing_extensions"]},
    "jinja2": {"markupsafe": ["markupsafe"]},
    "redos-harness": {},
    "pyyaml": {},
}


def get_source(rid, workdir):
    spec = ROOTS[rid]
    if spec is None:
        return None
    if spec[0] == "local":
        path = os.path.normpath(spec[1])
        return pruned_tree(path) if os.path.isdir(path) else None
    pkg, ver = spec
    # Isolated subdir per root: a shared dir lets archives[0] grab another
    # root's file (measured wrong once — never again).
    subdir = os.path.join(workdir, rid)
    os.makedirs(subdir, exist_ok=True)
    subprocess.run(
        [sys.executable, "-m", "pip", "download", "--no-deps", "--no-binary", ":all",
         "-d", subdir, f"{pkg}=={ver}"],
        check=True, capture_output=True,
    )
    prefix = pkg.replace("-", "_").lower()
    archives = sorted(
        f for f in os.listdir(subdir)
        if f.endswith((".tar.gz", ".zip", ".whl")) and f.lower().startswith(prefix)
    )
    if not archives:
        raise RuntimeError(f"no distribution fetched for {pkg}=={ver}")
    arc = os.path.join(subdir, archives[0])
    out = os.path.join(workdir, f"src_{rid}")
    os.makedirs(out, exist_ok=True)
    if arc.endswith(".tar.gz"):
        with tarfile.open(arc) as tf:
            tf.extractall(out, filter="data")
    else:
        import zipfile

        with zipfile.ZipFile(arc) as zf:
            zf.extractall(out)
    inner = [os.path.join(out, d) for d in os.listdir(out) if os.path.isdir(os.path.join(out, d))]
    base = inner[0] if len(inner) == 1 else out
    return pruned_tree(base)


def main():
    corpus = json.load(open(os.path.join(HERE, "corpus.json")))["entries"]
    audit_path = os.path.join(HERE, "internals", "AUDIT.json")
    audit = {}
    if os.path.exists(audit_path):
        audit = json.load(open(audit_path))
    workdir = tempfile.mkdtemp(prefix="sbomprune_dl_")
    print(f"{'root':<14} {'package':<20} {'vulns':<6} {'verdict':<16} audit")
    print("-" * 90)
    before, after = 0, 0
    audit_tp_b, audit_n_b, audit_tp_a, audit_n_a = 0, 0, 0, 0
    for entry in corpus:
        rid = entry["id"]
        src = get_source(rid, workdir)
        verdicts, unknown = compute(src, DIST_MAPS[rid]) if src else ({}, {})
        if unknown:
            print(f"  !! {rid}: unmapped imports (audit visibility): {sorted(unknown)}")
        for pkg, records in entry.get("vulns", {}).items():
            key = canonical(pkg)
            verdict = verdicts.get(key, "unimported")
            n = len(records)
            before += n
            kept = verdict == "reachable"
            if kept:
                after += n
            mark = "-"
            pa = audit.get("packages", {}).get(f"{rid}|{pkg}")
            if pa is not None:
                truly = pa["truly_reachable"]
                mark = "T" if truly else "F"
                audit_n_b += n
                audit_tp_b += n if truly else 0
                if kept:
                    audit_n_a += n
                    audit_tp_a += n if truly else 0
            print(f"{rid:<14} {pkg:<20} {n:<6} {verdict:<16} {mark}")
    print("-" * 90)
    print(f"findings before: {before}   after (reachable-only): {after}   pruned: {before - after}")
    if audit_n_b:
        print(f"precision before: {audit_tp_b}/{audit_n_b} = {audit_tp_b / audit_n_b:.2f}")
    if audit_n_a:
        print(f"precision after:  {audit_tp_a}/{audit_n_a} = {audit_tp_a / audit_n_a:.2f}")
    if not audit_n_b:
        print("audit pending: fill internals/AUDIT.json, rerun for precision")


if __name__ == "__main__":
    main()
