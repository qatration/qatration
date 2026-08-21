"""Every name this code loads must be reachable — no model, no network.

`compile()` accepts a NameError; it is a runtime event, raised only when the line runs. So a
call site reached ONLY on a branch no test walks can ship broken while the whole suite stays
green. That is not hypothetical here: `run_redteam.py` and `run_adaptive.py` both called
`safe_target_name(...)` — the rule that keeps a config's `name:` from becoming a path — without
importing it. That line runs only when a config carries a `name:`, so the tool worked on every
config that did not, and exited 1 with a traceback on the ones that did.

The same shape guards `_auth_gate`. A crash at an authorization gate fails closed, so it is not
a hole, but a traceback is not the answer a security tool should give to a valid config, and no
suite can see it while no suite loads one.

WHAT THIS DOES NOT CATCH, stated rather than implied. It is deliberately conservative and
reports a load only when the name is in NO scope at all:

  * a module-level name bound after the line that reads it counts as bound
  * a class attribute counts as visible inside that class's methods, which Python does not do
  * a module using `from x import *` is skipped entirely and named in the output

Guessing at a star import would produce noise, and noise in a gate is how a gate stops being
read. Every one of those is a false NEGATIVE — this reports less than the truth, never more.

The scan is worth nothing until it has been shown failing, so it runs on a planted bug first, in
this process, every time.

    python test_names.py           # exits 1 on any failure (CI gate)
"""
import ast, builtins, io, os, sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# `__file__` and its neighbours are not in `dir(builtins)` but exist in every module.
BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__spec__", "__package__"}

# Where the tool's own code lives. `out/` holds artifacts, never source.
SCANNED = ("redteam", "tools")
SKIP_DIRS = {".git", "out", "__pycache__", ".venv", "node_modules"}


def bound_by(node):
    """Every name bound anywhere under `node`, not descending into a nested function body.

    A nested `def` contributes its own name and nothing else, because its body is a separate
    scope: the names it binds are not visible out here.
    """
    out, stack = set(), [node]
    while stack:
        n = stack.pop()
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(c.name)
                continue
            if isinstance(c, ast.Lambda):
                continue
            if isinstance(c, ast.Name) and isinstance(c.ctx, (ast.Store, ast.Del)):
                out.add(c.id)
            elif isinstance(c, (ast.Import, ast.ImportFrom)):
                for a in c.names:
                    out.add((a.asname or a.name).split(".")[0])
            elif isinstance(c, ast.ExceptHandler) and c.name:
                out.add(c.name)
            elif isinstance(c, (ast.Global, ast.Nonlocal)):
                out.update(c.names)
            stack.append(c)
    return out


def declared(node, kind):
    """Names declared `global` (or `nonlocal`) ANYWHERE below `node`, nested bodies included.

    `bound_by` stops at a nested function because its bindings are its own. `global` is the
    exception: it reaches past every scope between the statement and the module, so the binding
    belongs out here even though the statement is in there. Reading such a name from module
    level was the one false positive this scan produced, and a false positive in a gate is how
    a gate stops being read.
    """
    return {n for d in ast.walk(node) if isinstance(d, kind) for n in d.names}


def _params(fn):
    a = fn.args
    out = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs}
    if a.vararg:
        out.add(a.vararg.arg)
    if a.kwarg:
        out.add(a.kwarg.arg)
    return out


def _walk(node, visible, path, hits):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        for d in getattr(node, "decorator_list", []):
            _walk(d, visible, path, hits)
        # Defaults are evaluated in the ENCLOSING scope, not in the body's.
        for d in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            _walk(d, visible, path, hits)
        inner = visible | _params(node) | bound_by(node) | declared(node, ast.Nonlocal)
        for c in (node.body if isinstance(node.body, list) else [node.body]):
            _walk(c, inner, path, hits)
        return
    if isinstance(node, ast.ClassDef):
        for d in node.decorator_list + list(node.bases):
            _walk(d, visible, path, hits)
        inner = visible | bound_by(node)
        for c in node.body:
            _walk(c, inner, path, hits)
        return
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        inner = visible | bound_by(node)
        for c in ast.iter_child_nodes(node):
            _walk(c, inner, path, hits)
        return
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        if node.id not in visible and node.id not in BUILTINS:
            hits.append((path, node.lineno, node.id))
        return
    for c in ast.iter_child_nodes(node):
        _walk(c, visible, path, hits)


def undefined_loads(src, path):
    """-> [(path, line, name)], or None when the module star-imports and was not read."""
    tree = ast.parse(src, path)
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
            return None
    hits, top = [], bound_by(tree) | declared(tree, ast.Global)
    for c in tree.body:
        _walk(c, top, path, hits)
    return hits


def main():
    checks, fails = 0, []

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- THE SCAN IS SHOWN FAILING FIRST -------------------------------------------------
    #
    # The real bug, reduced: an import that lost a name, and a call to it on a branch that only
    # runs for some configs. If the repository scan below reports clean, it has to have reported
    # this dirty in the same process, or "clean" only means the scan is broken.
    PLANTED = (
        "from workspace import OUT as WORKSPACE_OUT   # one place decides where output goes\n"
        "def main(tcfg, target):\n"
        "    if tcfg.get('name'):\n"
        "        target.name = safe_target_name(tcfg['name'], 'target config')\n"
    )
    planted = undefined_loads(PLANTED, "<planted>")
    check("the scan reports a name that is called but never imported",
          [h[2] for h in (planted or [])] == ["safe_target_name"], planted)

    fixed = PLANTED.replace("WORKSPACE_OUT   #", "WORKSPACE_OUT, safe_target_name   #")
    check("...and reports nothing once the import carries it",
          undefined_loads(fixed, "<fixed>") == [], undefined_loads(fixed, "<fixed>"))

    # The shapes that would make it noisy if the scope rules were wrong. A gate people re-run
    # instead of read is worse than no gate, and false positives are how that starts.
    QUIET = [
        ("a comprehension target", "xs = [i for i in range(3)]\ny = [i * 2 for i in xs]\n"),
        ("a walrus", "def f(s):\n    if (n := len(s)) > 2:\n        return n\n"),
        ("an except alias", "try:\n    pass\nexcept ValueError as e:\n    print(e)\n"),
        ("a with target", "import io\nwith io.StringIO() as fh:\n    fh.write('x')\n"),
        ("a global declared in a function",
         "def set_it():\n    global LATER\n    LATER = 1\ndef read_it():\n    return LATER\n"),
        ("a name bound only inside a try",
         "try:\n    import tomllib\nexcept ImportError:\n    tomllib = None\nprint(tomllib)\n"),
        ("a closure over an enclosing local",
         "def outer(a):\n    def inner():\n        return a\n    return inner\n"),
        ("a default evaluated in the enclosing scope", "LIMIT = 5\ndef f(n=LIMIT):\n    return n\n"),
        ("a class attribute read by its own method",
         "class C:\n    N = 1\n    def f(self):\n        return C.N\n"),
        ("a decorator", "import functools\n@functools.cache\ndef f():\n    return 1\n"),
        ("a nonlocal declared in a nested function",
         "def outer():\n    def inner():\n        nonlocal seen\n        seen = 1\n"
         "    seen = 0\n    inner()\n    return seen\n"),
    ]
    noisy = []
    for label, src in QUIET:
        r = undefined_loads(src, f"<{label}>")
        if r:
            noisy.append(f"{label} -> {r}")
    check("...and stays quiet on the shapes that would make it noise", not noisy, "; ".join(noisy))
    check("a module with `from x import *` is skipped rather than guessed at",
          undefined_loads("from os.path import *\nprint(join('a', 'b'))\n", "<star>") is None)

    # --- THE REPOSITORY ------------------------------------------------------------------
    hits, skipped, files = [], [], 0
    for top in SCANNED:
        for dirpath, dirs, names in os.walk(os.path.join(ROOT, top)):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in sorted(names):
                if not n.endswith(".py"):
                    continue
                p = os.path.join(dirpath, n)
                rel = os.path.relpath(p, ROOT).replace("\\", "/")
                files += 1
                try:
                    r = undefined_loads(io.open(p, encoding="utf-8").read(), rel)
                except SyntaxError as e:
                    hits.append((rel, e.lineno or 0, f"does not parse: {e.msg}"))
                    continue
                if r is None:
                    skipped.append(rel)
                else:
                    hits += r

    check(f"every name loaded across {files} files in {'/'.join(SCANNED)} resolves somewhere",
          not hits, "; ".join(f"{p}:{ln}: {nm}" for p, ln, nm in hits[:12]))
    if skipped:
        print(f"      (skipped for `import *`: {', '.join(skipped)})")
    # An empty walk reports every file clean. That is the failure this whole suite is about,
    # arriving through the suite itself.
    check("...and there was source to scan at all", files > 40,
          f"only {files} .py files found under {SCANNED} — the walk found nothing to check")

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — no call site is one branch away from a NameError.")


if __name__ == "__main__":
    main()
