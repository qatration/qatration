"""The instrument that says which guards are untested was itself untested — no model, no network.

`tools/unguarded.py` deletes each documented guard in a module and reports the ones no suite
missed. Its whole subject is a silence mistaken for a result, and it had two of its own.

The first guard sweep ever pointed at `tools/` found the second one. It also found that
nothing imports this file: four suites matched a grep for `unguarded`, and every one of them
matched a LOCAL VARIABLE called `_unguarded`. A suite map built by looking for a name in a
file is a set that cannot see the difference, which is the mistake this whole family of
sweeps exists to find, committed by the sweep.

What is checked here:

  * a guard with no comment above it is COUNTED, not dropped. `workspace.py` has twenty-one
    branches of that shape and one carries a comment, so the sweep tested one and the
    summary read `0 survived` — a verdict on the file, from one twenty-first of it.
  * a module nothing imports is reported rather than passed over, since a guard no suite
    can reach is the strongest form of the thing this looks for.
  * `--only` naming a module that does not exist is refused, because sweeping nothing and
    saying it was clean is the same defect one level up.

    python test_unguarded.py     # exits 1 on any failure (CI gate)
"""
import io
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import unguarded  # noqa: E402

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS  " + label)
    else:
        FAIL += 1
        print("FAIL  " + label + (("  " + detail) if detail else ""))


DOCUMENTED = '''"""A module with one guard of each kind."""


def kept(x):
    # A COMMENT MEANS SOMEBODY PAID FOR THIS BRANCH ONCE, which is the scope.
    if x is None:
        return "none"
    return x


def silent(x):
    if x == 0:
        return "zero"
    return x
'''


def sweep_in(source, only=()):
    """Run the sweep over a throwaway package directory holding one module.

    `RT` is module-level in the tool, so this is where it is pointed. Nothing here imports
    the fixture module, which is deliberate: it makes the `NO SUITE IMPORTS IT` arm the one
    under test and costs no suite runs.
    """
    d = tempfile.mkdtemp()
    io.open(os.path.join(d, "fixture_mod.py"), "w", encoding="utf-8",
            newline="").write(source)
    old = unguarded.RT
    try:
        unguarded.RT = d
        return unguarded.sweep_guards(only)
    finally:
        unguarded.RT = old


def main():
    # --- the counter that keeps the denominator honest ------------------------------------
    tested, survivors, undocumented = sweep_in(DOCUMENTED)
    check("a guard with no comment above it is counted, not dropped",
          undocumented == 1, "counted %d" % undocumented)
    # AND THE DOCUMENTED ONE IS NOT counted there, or the number above is `every branch` and
    # says nothing about which kind was skipped.
    check("...and a guard that has one is not counted with it",
          undocumented == 1 and len(survivors) == 1,
          "%d undocumented, %d survivor(s)" % (undocumented, len(survivors)))

    # --- a module nothing imports ----------------------------------------------------------
    #
    # The strongest form of what this looks for: not a guard whose suite missed it, a guard
    # no suite could reach. It is a SURVIVOR rather than a skip, and it says why.
    check("a module no suite imports is reported, not passed over",
          survivors and survivors[0][0] == "fixture_mod.py", str(survivors[:1]))
    check("...saying that is the reason, rather than naming a suite that failed to catch it",
          survivors and "nothing imports it" in survivors[0][3], str(survivors[:1]))
    check("...and it is the documented guard that is named",
          survivors and "if x is None:" in survivors[0][2], str(survivors[:1]))
    # NOTHING WAS DELETED, because there was no suite to run against. `tested` counts
    # deletions that were actually judged, and a survivor from this arm is not one of them.
    check("...and nothing was counted as tested, since nothing could judge it",
          tested == 0, "tested %d" % tested)

    # --- a module with no guard of this shape at all ----------------------------------------
    #
    # An empty answer from a file that HAS branches would be the same silence one level in.
    _plain, _plain_s, _plain_u = sweep_in('def f(x):\n    return x\n')
    check("a module with no guard of this shape reports nothing and claims nothing",
          (_plain, _plain_s, _plain_u) == (0, [], 0),
          str((_plain, _plain_s, _plain_u)))

    # --- `--only` naming something that is not there ---------------------------------------
    #
    # Sweeping nothing and reporting it clean is this tool's own subject, so a name that
    # matches no module is refused rather than quietly narrowed to the empty set.
    why = ""
    try:
        sweep_in(DOCUMENTED, only=("no_such_module",))
    except SystemExit as e:
        why = str(e)
    except Exception as e:
        why = "%s: %s" % (type(e).__name__, e)
    check("a --only that matches no module is refused", "no such module" in why,
          why or "it swept nothing and said nothing")
    check("...and the refusal names what it could not find",
          "no_such_module" in why, why)
    # AND A NAME THAT DOES MATCH STILL RUNS, or the refusal above is a filter that refuses
    # everything and the check passes for the wrong reason.
    _t2, _s2, _u2 = sweep_in(DOCUMENTED, only=("fixture_mod",))
    check("...while a name that matches one still sweeps it",
          _u2 == 1 and len(_s2) == 1, "%d undocumented, %d survivor(s)" % (_u2, len(_s2)))

    # --- THE ROUTE A SUITE MAP BUILT ON `import <name>` CANNOT SEE --------------------
    #
    # `workspace` globs `targets_*.py` and calls `import_module` on each name, so every
    # suite that reaches `workspace` reaches all eleven practice adapters. Asked only
    # about literal imports, this tool answered `NO SUITE IMPORTS IT` for every one of
    # them and listed their guards as survivors: eleven false findings of exactly the
    # shape it exists to report, enough to bury a real one.
    #
    # DERIVED, NOT LISTED. A pattern counts as a route only when one function both globs
    # it and calls `import_module`, so a glob that merely reads files is not mistaken
    # for one.
    routes = unguarded._dynamic_routes()
    check("the engine's own dynamic import route is derived from its source",
          routes.get("targets_*.py") == "workspace", str(routes))
    _adapters = [_m for _m in sorted(os.listdir(unguarded.RT))
                 if _m.startswith("targets_") and _m.endswith(".py")]
    _unreached = [_m for _m in _adapters if not unguarded._suites_touching(_m)]
    check("...so no practice adapter is reported as reached by nothing",
          _unreached == [], str(_unreached))
    check("...and there were adapters to reach", len(_adapters) >= 8,
          str(len(_adapters)))
    # AND THE FIRST ROUTE STILL WORKS ON ITS OWN, or the widening replaced it.
    check("...while a module imported by name is still found by its own name",
          "test_workspace.py" in unguarded._suites_touching("workspace.py"),
          str(unguarded._suites_touching("workspace.py")[:3]))

    # A GLOB THAT ONLY READS IS NOT A ROUTE. Both halves have to be in one function, or
    # every module that lists a directory would make every file in it reachable.
    _d = tempfile.mkdtemp()
    io.open(os.path.join(_d, "loader.py"), "w", encoding="utf-8", newline="").write(
        "import glob, importlib" + chr(10)
        + "def load():" + chr(10)
        + "    for f in glob.glob('plug_*.py'):" + chr(10)
        + "        importlib.import_module(f[:-3])" + chr(10))
    # BOTH IN ONE FILE, which is the case a file-level scan cannot tell apart. `reader.py`
    # loads `plugb_*.py` and, in a different function, merely reads `data_*.py`.
    io.open(os.path.join(_d, "reader.py"), "w", encoding="utf-8", newline="").write(
        "import glob, importlib" + chr(10)
        + "def load():" + chr(10)
        + "    for f in glob.glob('plugb_*.py'):" + chr(10)
        + "        importlib.import_module(f[:-3])" + chr(10)
        + chr(10)
        + "def read():" + chr(10)
        + "    return [open(f).read() for f in glob.glob('data_*.py')]" + chr(10))
    _old_rt = unguarded.RT
    try:
        unguarded.RT = _d
        _r = unguarded._dynamic_routes()
    finally:
        unguarded.RT = _old_rt
    check("a glob whose function also imports is a route",
          _r.get("plug_*.py") == "loader", str(_r))
    check("...and a glob that only reads files is not",
          "data_*.py" not in _r, str(_r))
    check("...even when the same file also has one that imports",
          _r.get("plugb_*.py") == "reader" and "data_*.py" not in _r, str(_r))

    # --- A SWEEP THAT DELETED NOTHING IS NOT A CLEAN BILL ---------------------------
    #
    # Pointed at three modules with no guard of this shape, the command printed `Nothing
    # this sweep deleted went unnoticed` — a verdict over an empty sweep, which is
    # the sentence this whole tool exists to refuse. It already refuses `--only` naming a
    # module that is not there, for the same reason; this is the same silence reached
    # through modules that do exist and hold nothing to test.
    #
    # Driven as a command, because the verdict is printed there and nowhere else.
    import subprocess as _sp_u
    _tool = os.path.join(ROOT, "tools", "unguarded.py")
    _env_u = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")

    def _run_tool(*a):
        _r = _sp_u.run([sys.executable, _tool] + list(a), capture_output=True, text=True,
                       timeout=900, env=_env_u, cwd=HERE)
        return (_r.stdout or "") + (_r.stderr or "")

    _empty = _run_tool("--guards", "--only", "mint", "run_all", "run_recon")
    check("a sweep that deleted nothing does not report a clean bill",
          "went unnoticed" not in _empty, _empty[-300:])
    check("...and says so, rather than printing a zero and stopping",
          "NOTHING WAS DELETED" in _empty, _empty[-300:])
    # AND THE THREE MODULES ARE REALLY THERE, or this passes because `--only` refused
    # them and the command never swept at all.
    check("...over modules that exist, not a refusal in disguise",
          "no such module" not in _empty, _empty[-300:])

    # AND EVERY ARM COUNTS. The first version of that verdict counted deletions from the
    # guards arm alone, so `--refusals` deleted fifty early refusals and the summary read
    # `NOTHING WAS DELETED` — the same defect it was written to fix, pointed the other
    # way, and it shipped for as long as it took to run the other arm once.
    #
    # This is the source, not a run: the refusals arm re-scores the whole stored fleet and
    # takes minutes, which is too long to spend inside a suite. What is asserted is that
    # each arm feeds the counter the verdict reads.
    _tool_src = io.open(_tool, encoding="utf-8").read()
    _main_src = _tool_src[_tool_src.index("def main("):]
    _arms = [_a for _a in ("sweep_guards(", "sweep_rules()", "sweep_refusals()",
                           "sweep_patterns()")
             if _a in _main_src]
    check("every arm of the sweep exists to be counted", len(_arms) == 4, str(_arms))
    _uncounted = []
    for _a in _arms:
        _at = _main_src.index(_a)
        _next = min([_p for _p in
                     [_main_src.find(_o, _at + 1) for _o in ("if both or", "\n    #")]
                     if _p > 0] or [len(_main_src)])
        if "swept +=" not in _main_src[_at:_next]:
            _uncounted.append(_a)
    check("...and each one adds what it deleted to the number the verdict reads",
          _uncounted == [], str(_uncounted))

    # --- WHICH HALF OF AN ENTRY IS THE RULE ----------------------------------------
    #
    # `sweep_rules` reads `return True`, so a rule that lives as an ELEMENT of a pattern
    # list is invisible to it: the oracle keeps eighty-two of those and the first sweep
    # of them found forty-one with no case. `sweep_patterns` is that arm.
    #
    # An entry is a bare pattern or a tuple, and the tuple is not always the same way
    # round: `_SECRETS` is (pattern, label) and `_INSECURE_CODE` is (label, pattern).
    # Taking element zero from both reported five of `_INSECURE_CODE`'s rules as
    # uncovered when what had been neutralised was their prose — a finding about
    # nothing, in the tool whose subject is exactly that.
    #
    # The position is READ FROM THE DETECTOR: it unpacks the entry and passes one of the
    # names to `re.search`. Driven over source rather than the real oracle, so the case
    # is a fixture and not a fact about today's file.
    import ast as _ast_p

    def _pos(src, det, name):
        return unguarded._pattern_position(_ast_p.parse(src), src, det, name)

    _first = J_SRC = (
        "import re" + chr(10)
        + "L = [('a', 'x')]" + chr(10)
        + "def d_one(p, c):" + chr(10)
        + "    for pat, label in L:" + chr(10)
        + "        if re.search(pat, p):" + chr(10)
        + "            return True" + chr(10))
    check("the rule is the element the detector searches with",
          _pos(J_SRC, "d_one", "L") == 0, str(_pos(J_SRC, "d_one", "L")))
    _SECOND = (
        "import re" + chr(10)
        + "L = [('a', 'x')]" + chr(10)
        + "def d_two(p, c):" + chr(10)
        + "    for label, pat in L:" + chr(10)
        + "        if re.search(pat, p):" + chr(10)
        + "            return True" + chr(10))
    check("...and it is not assumed to be the first",
          _pos(_SECOND, "d_two", "L") == 1, str(_pos(_SECOND, "d_two", "L")))
    # AND WHERE IT CANNOT BE READ, NOTHING IS CLAIMED. Guessing here reports the other
    # half's prose as a rule with no case, which is a finding about nothing.
    _OPAQUE = (
        "L = [('a', 'x')]" + chr(10)
        + "def d_three(p, c):" + chr(10)
        + "    for a, b in L:" + chr(10)
        + "        if a in p:" + chr(10)
        + "            return True" + chr(10))
    check("...and where neither half reaches a regex, no position is claimed",
          _pos(_OPAQUE, "d_three", "L") is None, str(_pos(_OPAQUE, "d_three", "L")))

    # AND THE ARM, DRIVEN. The three checks above read `_pattern_position` on its own,
    # and a rule with a fixture is not a caller with one: putting `pos = 0` back inside
    # `sweep_patterns` left every one of them green. So a whole little oracle, with a
    # suite of its own, swept for real.
    import shutil as _sh_p
    _pw = tempfile.mkdtemp()
    _old_rt2 = unguarded.RT
    try:
        unguarded.RT = _pw
        io.open(os.path.join(_pw, "oracle.py"), "w", encoding="utf-8",
                newline="").write(
            "import re" + chr(10)
            # (label, pattern): the way round that made element zero the wrong guess.
            + "L = [('the label', 'zzcovered'), ('other label', 'zzfree')]" + chr(10)
            + "def d_fix(p, c):" + chr(10)
            + "    for label, pat in L:" + chr(10)
            + "        if re.search(pat, p):" + chr(10)
            + "            return True" + chr(10)
            + "    return False" + chr(10)
            # A LIST WHOSE HALVES NEITHER REACH A REGEX. The position cannot be read, so
            # the arm has to say nothing about it: guessing reports the other half's prose
            # as a rule with no case, and crashing takes the whole sweep with it.
            + chr(10)
            + "M = [('alpha', 'beta')]" + chr(10)
            + "def d_opaque(p, c):" + chr(10)
            + "    for a, b in M:" + chr(10)
            + "        if a in p:" + chr(10)
            + "            return True" + chr(10)
            + "    return False" + chr(10))
        # One of the two rules has a case and the other does not, so the arm has to come
        # back with exactly one name and it has to be the right one.
        io.open(os.path.join(_pw, "test_oracle.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import oracle" + chr(10)
            + "assert oracle.d_fix('a zzcovered reply', {})" + chr(10)
            + "print('ok')" + chr(10))
        _n_p, _free_p = unguarded.sweep_patterns()
    finally:
        unguarded.RT = _old_rt2
        _sh_p.rmtree(_pw, ignore_errors=True)
    check("the pattern arm sweeps both rules of a two-rule list",
          _n_p == 2, str(_n_p))
    check("...and says nothing at all about a list whose halves it cannot read",
          not any(f[0] == "M" for f in _free_p), str(_free_p))
    check("...and names the one with no case",
          [f[2] for f in _free_p] == ["zzfree"], str(_free_p))

    # AND IT IS REACHABLE FROM THE COMMAND.
    _tool_src2 = io.open(_tool, encoding="utf-8").read()
    check("the pattern arm has a flag of its own",
          "--patterns" in _tool_src2, "no --patterns flag")
    if FAIL:
        return 1
    print("\nOK — the instrument that names untested guards is not one of them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
