"""SBOM pins from requirements.txt / pip freeze (stdlib only).

V1 scope: `name==version` pins and bare names. Markers and extras are
stripped (extras recorded in the note field, not resolved). Anything fancier
(-r includes, URLs, editable installs) is reported, not parsed.
"""

import re

_CANON = re.compile(r"[-_.]+")


def canonical(name):
    return _CANON.sub("-", name).strip().lower()


def parse_requirement(line):
    """Parse one requirements line -> (canonical-name, version-or-None, note).

    Returns None for blank lines, comments, options (-r, -e, URLs).
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("-", "http://", "https://", "git+", "file:")):
        return None, None, f"unsupported: {line}"
    line = line.split("#", 1)[0].strip()
    line = line.split(";", 1)[0].strip()  # drop environment markers
    extras = ""
    if "[" in line:
        base, rest = line.split("[", 1)
        extras, line = rest.split("]", 1)[0], base + line.split("]", 1)[1]
    if "==" in line:
        name, version = line.split("==", 1)
        name, version = name.strip(), version.strip().split(",")[0].strip()
    else:
        name, version = re.split(r"[<>=!~\s]", line, 1)[0].strip(), None
    if not name:
        return None
    note = f"extras: {extras}" if extras else ""
    return canonical(name), (version or None), note


def pins_from_requirements(path):
    """{canonical-name: version-or-None}. Unpinned names map to None."""
    pins, notes = {}, {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parsed = parse_requirement(line)
            if not parsed:
                continue
            if len(parsed) == 3:
                name, version, note = parsed
                pins[name] = version
                if note:
                    notes[name] = note
    return pins, notes


def pins_from_freeze(path):
    """pip freeze output is always name==version."""
    pins = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "==" not in line:
                continue
            name, version = line.split("==", 1)
            pins[canonical(name)] = version.strip()
    return pins, {}
