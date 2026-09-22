"""Module-level reachability via stdlib ast (no dependencies).

For each third-party distribution: is it imported, and are any imported
names actually used? Verdicts: reachable | imported-unused | unimported.

Documented blind spots (not handled, reported): relative imports are
skipped (they never name third-party code); dynamic imports
(__import__/importlib), star-imports (names unknowable statically), and
console-script-only deps are invisible to this analysis by construction.
"""

import ast
from pathlib import Path


def file_imports(tree):
    """{top_module: set(names)} from absolute imports. Star imports record
    the module with a None marker (usage unknowable -> treated as used)."""
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                imports.setdefault(top, set()).add(a.asname or top.split(".")[-1])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative: never third-party, skip (documented)
            top = (node.module or "").split(".")[0]
            if not top:
                continue
            if any(a.name == "*" for a in node.names):
                imports.setdefault(top, set()).add(None)  # unknowable -> used
            else:
                imports.setdefault(top, set()).update(a.asname or a.name for a in node.names)
    return imports


def used_names(tree):
    """Set of loaded root names (Name Load ids + Attribute value roots)."""
    used = set()

    class V(ast.NodeVisitor):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                used.add(node.id)

        def visit_Attribute(self, node):
            n = node
            while isinstance(n, ast.Attribute):
                n = n.value
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                used.add(n.id)

    V().visit(tree)
    return used


def compute(root, dist_map):
    """Verdicts per distribution.

    root: directory of first-party source. dist_map: {dist: [top_modules]}.
    Returns ({dist: verdict}, {unknown_top_module: files}).
    Unknown = imported third-party-looking modules absent from dist_map
    (reported for audit visibility, never silently dropped).
    """
    imports, used, files = {}, set(), {}
    for path in sorted(Path(root).rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue  # unparseable file: reported via unknown? no -> skip, documented
        for mod, names in file_imports(tree).items():
            imports.setdefault(mod, set()).update(names)
            files.setdefault(mod, set()).add(str(path))
        used.update(used_names(tree))

    verdicts, unknown = {}, {}
    wanted = {}  # top_module -> dist
    for dist, mods in dist_map.items():
        for m in mods:
            wanted[m] = dist
    for dist, mods in dist_map.items():
        hits = [(m, imports.get(m, set())) for m in mods if m in imports]
        if not hits:
            verdicts[dist] = "unimported"
            continue
        names = set().union(*[names for _, names in hits])
        if None in names or (names & used):
            verdicts[dist] = "reachable"
        else:
            verdicts[dist] = "imported-unused"
    for mod in imports:
        if mod not in wanted:
            unknown[mod] = sorted(files[mod])
    return verdicts, unknown
