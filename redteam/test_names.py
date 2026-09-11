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
import ast, builtins, glob, io, os, sys
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

    # --- NO ASSERTION MAY BE TRUE NO MATTER WHAT THE CODE DOES -------------------------
    #
    # THE TAUTOLOGY GATE. This suite exists because a property the compiler accepts can still
    # be one no run reaches; an assertion that cannot fail is the same defect from the other
    # side, and it is worse, because it reports itself as a pass.
    #
    # Not hypothetical, and not only in old code. Two gates written the same day this was
    # added passed under mutation -- one because the delivery family it needed was never
    # exercised in its fixture, one because the longest attack id in its fixture was ten
    # characters and the constant it was checking was twenty-two. Two more in the shipped
    # suite were `... or True`: a detector-throws check whose fixture had stopped making
    # anything throw, and a per-target-key check whose author hedged on data that in fact
    # supports the stronger claim.
    #
    # The two-armed idiom is exempt, and the exemption is derived rather than listed:
    #
    #     try:
    #         thing_that_should_raise()
    #         check("X is refused", False, "it was accepted")
    #     except ValueError:
    #         check("X is refused", True)
    #
    # That `True` fails whenever the wrong arm runs, so a label carrying BOTH a constant-true
    # and a constant-false assertion is one assertion with two arms. A lone `or True` has no
    # such partner and cannot borrow one.
    #
    # It cannot see a fixture too small to reach a property -- only mutation shows that -- so
    # passing here is not proof of anything. Failing is proof of the opposite.
    def _fixed_truth(node):
        """-> True/False if this expression's value is fixed, else None."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.BoolOp):
            vals = [_fixed_truth(v) for v in node.values]
            if isinstance(node.op, ast.Or):
                return True if any(v is True for v in vals) else (
                    False if all(v is False for v in vals) else None)
            return False if any(v is False for v in vals) else (
                True if all(v is True for v in vals) else None)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = _fixed_truth(node.operand)
            return None if inner is None else (not inner)
        if (isinstance(node, ast.Compare) and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Eq, ast.Is))
                and ast.dump(node.left) == ast.dump(node.comparators[0])):
            return True                      # `x == x`
        return None

    _by_label, _n_checks, _unparsed = {}, 0, []
    _suites = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    for _sp in _suites:
        try:
            _tree = ast.parse(io.open(_sp, encoding="utf-8").read())
        except SyntaxError as e:
            _unparsed.append(f"{os.path.basename(_sp)}: {e}")
            continue
        for _n in ast.walk(_tree):
            # A BARE ASSERT COUNTS TOO. The suites carry 42 of them, and a gate that reads
            # one assertion form and not the other is the defect it exists to catch. There
            # is no two-armed exemption here: that idiom pairs on a label and an assert has
            # none, so it is keyed by its own line and stands alone.
            if isinstance(_n, ast.Assert):
                _n_checks += 1
                _by_label[(os.path.basename(_sp), f"<assert line {_n.lineno}>")] = [
                    (_n.lineno, _fixed_truth(_n.test))]
                continue
            if not (isinstance(_n, ast.Call) and isinstance(_n.func, ast.Name)
                    and _n.func.id == "check" and len(_n.args) >= 2):
                continue
            _n_checks += 1
            _lab = _n.args[0]
            _key = (os.path.basename(_sp),
                    _lab.value if isinstance(_lab, ast.Constant) else ast.dump(_lab))
            _by_label.setdefault(_key, []).append((_n.lineno, _fixed_truth(_n.args[1])))

    _tauto = []
    for (_f, _label), _calls in sorted(_by_label.items()):
        _vals = {v for _, v in _calls}
        if True in _vals and False in _vals:
            continue                          # the two-armed idiom
        _tauto += [f"{_f}:{ln}  {str(_label)[:70]}" for ln, v in _calls if v is True]

    check("every suite in this directory parses", not _unparsed, "; ".join(_unparsed))
    check(f"none of the {_n_checks} assertions across {len(_suites)} suites is true no matter "
          f"what the code does — `check(...)` calls and bare asserts alike",
          not _tauto, "; ".join(_tauto[:4]))
    # A scan that found nothing because it walked nothing is the failure this whole file is
    # about, so the reach is asserted rather than assumed -- same as the line above about
    # having source to scan at all.
    check("...and there were assertions to scan", _n_checks > 500 and len(_suites) > 20,
          f"{_n_checks} check() calls in {len(_suites)} suites")

    # --- AND ONE WRITTEN IN THE OTHER SUITE'S DIALECT -----------------------------------
    #
    # These suites carry two `check` signatures. Most are `check(label, ok, detail)`, where
    # the second argument is the assertion; a few are `check(label, got, want)`, where the
    # comparison happens inside. Write the second form in a file that defines the first and
    # nothing complains: the expected value lands in `detail`, the VALUE lands in `ok`, and
    # the assertion silently weakens to `is it truthy`.
    #
    # Found in this repository, twice, in the two lines that gate what the CI exit code is:
    # `check("...cannot answer rather than failing the build", regression_verdict(d)[0], 3)`
    # passes on 1, 2, 3 and 4 alike -- and 1 is `fail the build`, the exact outcome the
    # label says must not happen.
    #
    # The tautology scan above cannot see this: the expression is a call, its value is not
    # fixed, and it does fail when the code returns zero. It asserts less than its label
    # says rather than nothing at all, which is why it needs its own question: in a file
    # whose `check` takes a `detail`, a bare NUMBER in that slot is the other dialect.
    def _detail_form(fn):
        """Does THIS function define `check` with a `detail` slot rather than a `want` one?

        PER FUNCTION, NOT PER FILE. `test_workspace` defines both signatures -- `main` takes a
        `detail`, `check_every_command_refuses` takes a `want` -- so asking the question of the
        file flagged thirty-four calls that were written in the dialect of the `check` actually
        in scope. A scan that cries wolf is a scan somebody switches off.
        """
        for n in fn.body:
            if isinstance(n, ast.FunctionDef) and n.name == "check":
                names = [a.arg for a in n.args.args]
                return len(names) >= 3 and names[2] in ("detail", "why", "note")
        return False

    def _wrong_dialect(tree):
        """-> line numbers of `check(label, value, <number>)` in a detail-form scope."""
        out = []
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            if not _detail_form(fn):
                continue
            out += _constants_in_detail(fn)
        return sorted(out)

    def _constants_in_detail(fn):
        out = []
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "check" and len(n.args) == 3):
                continue
            third = n.args[2]
            # A BARE `True` OR `False` COUNTS TOO, and excluding it was a guess:
            # `detail` is what gets printed beside a failure, and a lone `False`
            # there tells a reader nothing. It is the `want` of the other dialect
            # and weakens the assertion exactly as a number does -- written by hand
            # here three times in one block, the hour this scan was written.
            if (isinstance(third, ast.Constant)
                    and isinstance(third.value, (int, float, bool))):
                out.append(n.lineno)
        return out

    # THE SCAN IS PROVED ON A PLANTED ONE, in this process, like the name scan above it:
    # a detector for a shape nobody currently writes is a detector nobody has seen work.
    # WRAPPED IN A FUNCTION, because that is the shape every suite here has: `main` defines
    # its own `check` and the calls live beside it. A module-level fixture would prove the
    # scan on a shape the scan is not looking at.
    _NL = chr(10)
    _plant = ast.parse(_NL.join([
        "def main():",
        "    def check(label, ok, detail=''):",
        "        pass",
        "    check('x', f(), 3)",
        "    check('y', g() == 3, 'd')",
        "    check('z', h(), False)",
    ]) + _NL)
    check("the dialect scan finds a planted one, number or bool alike",
          _wrong_dialect(_plant) == [4, 6], str(_wrong_dialect(_plant)))
    _plant2 = ast.parse(_NL.join([
        "def main():",
        "    def check(label, got, want):",
        "        pass",
        "    check('x', f(), 3)",
    ]) + _NL)
    check("...and leaves the scopes that really take a `want` alone",
          _wrong_dialect(_plant2) == [], str(_wrong_dialect(_plant2)))

    _dialect = []
    for _sp in _suites:
        try:
            _tree = ast.parse(io.open(_sp, encoding="utf-8").read())
        except SyntaxError:
            continue
        _dialect += ["%s:%d" % (os.path.basename(_sp), ln)
                     for ln in _wrong_dialect(_tree)]
    check("no assertion passes its expected value where the detail goes, which would "
          "weaken it to `is it truthy`", not _dialect, "; ".join(_dialect[:6]))

    # --- THE NUMBER A SUITE PRINTS IS THE NUMBER IT RAN ---------------------------------
    #
    # `test_isolation` counts its checks as they run, with the reason written above the
    # counter: "Counted as they run, not declared. A hardcoded total is a coverage claim."
    # It then snapshots that counter into `total` before the last few checks, and prints
    # the snapshot. Two checks added after that line ran, passed, and were invisible: the
    # suite said 63/63 both before and after they existed.
    #
    # A snapshot taken before the end IS a hardcoded total, arrived at by a different
    # route. Failures still turn the suite red -- `fails` is read at print time -- so this
    # is a coverage claim that understates itself, which is the direction that makes
    # somebody stop adding checks to a file that never seems to grow.
    import glob as _g9, re as _r9
    _snapped = []
    for _p9 in sorted(_g9.glob(os.path.join(HERE, "test_*.py"))):
        _lines = io.open(_p9, encoding="utf-8").read().splitlines()
        _snaps = [i for i, l in enumerate(_lines) if _r9.match(r"\s*total\s*=\s*checks\s*$", l)]
        if not _snaps:
            continue
        _after = [i for i, l in enumerate(_lines) if i > _snaps[-1] and _r9.match(r"\s*check\(", l)]
        if _after:
            _snapped.append("%s: %d check(s) after line %d"
                            % (os.path.basename(_p9), len(_after), _snaps[-1] + 1))
    check("no suite keeps checking after it has counted its checks",
          not _snapped, "; ".join(_snapped))

    # --- TWO `check` SIGNATURES, AND THE WRONG ONE PASSES QUIETLY ----------------------
    #
    # Most suites here define `check(label, ok, detail="")` and a few define
    # `check(label, got, want)`. Writing the second shape in a file that has the first
    # gives `check("...", sorted(x), ["a"])`: the expected value lands in `detail`, and
    # the ASSERTION becomes `bool(sorted(x))` -- true for any non-empty result and false
    # for every empty one, whatever the values are.
    #
    # Both failure modes are live. A check that should compare `[] == []` FAILS, which is
    # loud and gets fixed; a check that should compare `["8.8.8.8"] == ["a"]` PASSES,
    # which is a green check asserting nothing. Both happened repeatedly while writing
    # this suite's neighbours, in both directions, and nothing could see them.
    #
    # A CONTAINER IS THE TELL. Nobody writes `check(label, ["a"], ...)` meaning "the truth
    # value of this list"; they mean "equals". The rule is narrow on purpose: only files
    # whose own `check` names its second parameter `ok`, and only a second argument that
    # constructs a container.
    import ast as _ast_s
    _CONTAINERS = (_ast_s.List, _ast_s.Dict, _ast_s.Set, _ast_s.ListComp,
                   _ast_s.DictComp, _ast_s.SetComp)
    _MAKERS = {"sorted", "list", "set", "dict"}
    _wrong = []
    for _sp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        try:
            _tree = _ast_s.parse(io.open(_sp, encoding="utf-8").read())
        except SyntaxError:
            continue
        _styles = set()
        for _n in _ast_s.walk(_tree):
            if isinstance(_n, _ast_s.FunctionDef) and _n.name == "check":
                _a = [_x.arg for _x in _n.args.args]
                if len(_a) >= 2:
                    _styles.add(_a[1])
        # A file with BOTH shapes is its own hazard and is not judged here: `test_workspace`
        # defines `check` six times across six functions, and which one a call reaches
        # depends on where it sits.
        if _styles != {"ok"}:
            continue
        for _n in _ast_s.walk(_tree):
            if not (isinstance(_n, _ast_s.Call) and isinstance(_n.func, _ast_s.Name)
                    and _n.func.id == "check" and len(_n.args) >= 2):
                continue
            _second = _n.args[1]
            if isinstance(_second, _CONTAINERS) or (
                    isinstance(_second, _ast_s.Call)
                    and isinstance(_second.func, _ast_s.Name)
                    and _second.func.id in _MAKERS):
                _wrong.append("%s:%d" % (os.path.basename(_sp), _n.lineno))
    check("no check asserts the truth value of a container it meant to compare",
          not _wrong, "; ".join(_wrong[:8]))
    # AND THE SCAN CAN SEE THE FILES IT IS ABOUT, or the claim above is about nothing.
    _ok_files = 0
    for _sp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        try:
            _tree = _ast_s.parse(io.open(_sp, encoding="utf-8").read())
        except SyntaxError:
            continue
        for _n in _ast_s.walk(_tree):
            if (isinstance(_n, _ast_s.FunctionDef) and _n.name == "check"
                    and [_x.arg for _x in _n.args.args][1:2] == ["ok"]):
                _ok_files += 1
                break
    check("...over the suites that use that signature", _ok_files >= 20, str(_ok_files))

    # --- A SUITE THAT PASSED EVERY CHECK AND EXITED 1 WHILE TIDYING UP -------------------
    #
    # `test_fleet_limits` started a server whose script lived inside a
    # `with TemporaryDirectory()`, killed it with `os.kill(pid, SIGTERM)` and left the block.
    # On Windows that signal is `TerminateProcess`, which returns before the process releases
    # its handles, so the rmtree hit `WinError 32 ... being used by another process`, the
    # exception escaped `main`, and the suite exited 1 having printed eight PASS lines and no
    # tally at all. One run in twelve.
    #
    # It is the mirror of the rule this file already keeps -- a suite that exits 0 while
    # printing FAIL -- and its cost was not theoretical: `tools/unguarded.py` refuses to
    # sweep a module whose suites are not green, and skipped `runner.py` for this.
    #
    # `TemporaryDirectory` RAISES OUT OF ITS OWN CLEANUP, so the rule is about the context
    # manager rather than about temp directories: `mkdtemp` with `rmtree(ignore_errors=True)`
    # says the same thing and cannot fail a run that has already answered its question.
    # `Popen` AND `kill`, NOT `run`. `subprocess.run` waits, so whatever it started is gone
    # before the block ends; these two are the shapes that leave a process alive -- a Popen
    # nobody waited for, and a pid signalled rather than reaped, which is what this suite did.
    _SPAWNS = {"Popen", "kill"}
    def _live_teardowns(src, name):
        """-> the lines where a `with TemporaryDirectory()` holds a process that outlives it."""
        try:
            _tree = _ast_s.parse(src)
        except SyntaxError:
            return []
        _out = []
        for _n in _ast_s.walk(_tree):
            if not isinstance(_n, _ast_s.With):
                continue
            if not any(isinstance(_i.context_expr, _ast_s.Call)
                       and getattr(_i.context_expr.func, "attr", None) == "TemporaryDirectory"
                       for _i in _n.items):
                continue
            for _c in _ast_s.walk(_n):
                if (isinstance(_c, _ast_s.Call)
                        and getattr(_c.func, "attr", None) in _SPAWNS):
                    _out.append("%s:%d" % (name, _n.lineno))
                    break
        return _out

    # ON A PLANTED ONE FIRST, in this process, every time -- the rule this file opens with.
    # With the tree clean there is nothing for this scan to find, so weakening it changes no
    # answer: `_SPAWNS = set()` and `_is_tmpdir = False` both stayed green until the planted
    # case existed. A check that passes because it found nothing to look at is the defect
    # this whole file is about.
    _PLANTED = ("import subprocess, tempfile, os\n"
                "def go():\n"
                "    with tempfile.TemporaryDirectory() as d:\n"
                "        p = subprocess.Popen(['sleep', '1'], cwd=d)\n"
                "        os.kill(p.pid, 15)\n")
    check("the teardown scan finds a directory deleted under a live process",
          _live_teardowns(_PLANTED, "planted.py") == ["planted.py:3"],
          str(_live_teardowns(_PLANTED, "planted.py")))
    _OK_SRC = ("import subprocess, tempfile\n"
               "def go():\n"
               "    with tempfile.TemporaryDirectory() as d:\n"
               "        subprocess.run(['ls', d])\n")
    check("...and does not flag one that only ran a command to completion",
          not _live_teardowns(_OK_SRC, "ok.py"), str(_live_teardowns(_OK_SRC, "ok.py")))
    _teardown = []
    for _sp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        _teardown += _live_teardowns(io.open(_sp, encoding="utf-8").read(),
                                     os.path.basename(_sp))
    check("no suite deletes a directory a process it started may still be in",
          not _teardown, "; ".join(sorted(set(_teardown))[:8]))
    # AND THE SCAN CAN SEE THE SHAPE IT IS ABOUT, or the claim above is about nothing: the
    # suites DO use `TemporaryDirectory`, just not around a process.
    _tmp_users = sum(
        1 for _sp in sorted(glob.glob(os.path.join(HERE, "test_*.py")))
        if "TemporaryDirectory" in io.open(_sp, encoding="utf-8").read())
    check("...over the suites that use one at all", _tmp_users >= 5, str(_tmp_users))

    # --- A CONSTANT `workspace` OWNS, WRITTEN OUT AGAIN SOMEWHERE ELSE -----------------
    #
    # `workspace.BROKE` carries the comment that predicted this: the tuple `("EXPLOITED",
    # "PARTIAL")` had been written out in `history`, `discrimination` and `build_index`,
    # a fourth was caught arriving, and they were collapsed into one definition -- "three
    # copies of a rule agree until the day somebody decides a fourth verdict counts as a
    # breach, and then two reports disagree about what a finding is".
    #
    # THE GREP THAT FOUND THOSE THREE MISSED A FIFTH. `model_matrix.py` line 23 was its own
    # `BROKE = ("EXPLOITED", "PARTIAL")`, identical and unimported, in the command that
    # prints "model choice MATTERS here" off exactly that tuple. A rule enforced by a grep
    # somebody ran once is a rule for as long as nobody adds a file.
    #
    # The scan is narrow on purpose: a module-level assignment of a LITERAL whose name
    # `workspace` also binds to a module-level literal. An alias (`OUT = WORKSPACE_OUT`) is
    # not a literal and is not a copy; a local constant nothing else owns is not touched.
    import ast as _ast_w
    _LITS = (_ast_w.Constant, _ast_w.Tuple, _ast_w.List, _ast_w.Set, _ast_w.Dict)

    def _top_literals(path):
        try:
            _tree = _ast_w.parse(io.open(path, encoding="utf-8").read())
        except (SyntaxError, OSError):
            return {}
        out = {}
        for _n in _tree.body:
            if (isinstance(_n, _ast_w.Assign) and len(_n.targets) == 1
                    and isinstance(_n.targets[0], _ast_w.Name)
                    and isinstance(_n.value, _LITS)):
                out[_n.targets[0].id] = _ast_w.dump(_n.value)
        return out

    _ws = _top_literals(os.path.join(HERE, "workspace.py"))
    # NAMED, NOT COUNTED. A floor on how MANY literals workspace holds is satisfied by any
    # five of them, so a mutation that stops it owning the one this rule is about leaves the
    # scan green with nothing to find -- an empty set satisfying the claim made about it.
    # `BROKE` is the constant whose five copies motivated the rule, and it is checked by name.
    # `OUT` is deliberately not on this list: it is `out_dir()`, a CALL, so it is not a
    # literal and this scan cannot see it either way -- naming it here would be a check that
    # fails for a reason unrelated to the rule.
    _want_owned = ("BROKE", "NOT_MEASURED")
    _unowned = [k for k in _want_owned if k not in _ws]
    check("workspace owns the constants other modules share", not _unowned,
          "not module-level literals in workspace.py: %s" % _unowned)
    check("...and there are more than those to protect", len(_ws) >= 5,
          "%d module-level literals" % len(_ws))
    _copies = []
    for _sp in sorted(glob.glob(os.path.join(HERE, "*.py"))
                      + glob.glob(os.path.join(ROOT, "tools", "*.py"))):
        _b = os.path.basename(_sp)
        if _b.startswith("test_") or _b == "workspace.py":
            continue
        for _k, _v in _top_literals(_sp).items():
            if _k in _ws:
                _copies.append("%s:%s%s" % (_b, _k,
                                            "" if _v == _ws[_k] else " (and DIFFERS)"))
    check("no module writes out a constant workspace already owns", not _copies,
          "; ".join(_copies))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — no call site is one branch away from a NameError.")


if __name__ == "__main__":
    main()
