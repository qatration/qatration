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

    # --- CAUGHT BY A CASE IS NOT THE SAME AS EXCUSED BY EVIDENCE -------------------
    #
    # `sweep_refusals` deletes each early `return False` in a detector -- every one of them
    # a reason NOT to call something a finding -- and reports how many moved a verdict on
    # the stored probes. On this repository it printed `50 tested, 0 move a verdict`, and
    # the run ended `Nothing this sweep deleted went unnoticed.`
    #
    # Measured: eighteen of the fifty were caught by a case in `test_oracle`. The other
    # THIRTY-TWO were deleted with every suite green and were excused only by traffic that
    # happens not to reach them. Those thirty-two went unnoticed by every suite, under a
    # sentence saying none did -- which is this tool's own subject, in the tool.
    #
    # Driven over a scripted oracle with a scripted replay, because the split is the
    # property and reading the source would assert the shape of the code instead. The
    # fixture produces one of each: a guard a case holds, a guard nothing holds and the
    # evidence never exercises, and a guard nothing holds that the evidence does.
    import shutil as _sh_x
    _xw = tempfile.mkdtemp()
    _old_rt_x = unguarded.RT
    try:
        unguarded.RT = _xw
        io.open(os.path.join(_xw, "oracle.py"), "w", encoding="utf-8", newline="").write(
            "def d_caught(p, c):" + chr(10)
            + "    if 'zzskip' in p:" + chr(10)
            + "        return False" + chr(10)
            + "    return 'zzhit' in p" + chr(10)
            + chr(10)
            + "def d_excused(p, c):" + chr(10)
            + "    if 'zznever' in p:" + chr(10)
            + "        return False" + chr(10)
            + "    return 'zzhit' in p" + chr(10)
            + chr(10)
            + "def d_moves(p, c):" + chr(10)
            + "    if 'zzquiet' in p:" + chr(10)
            + "        return False" + chr(10)
            + "    return 'zzhit' in p" + chr(10)
            + chr(10)
            + "DETECTORS = {'caught': d_caught, 'excused': d_excused, 'moves': d_moves}"
            + chr(10))
        # The suite holds ONE of the three guards. `d_excused` and `d_moves` have no case.
        io.open(os.path.join(_xw, "test_oracle.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import oracle" + chr(10)
            + "assert not oracle.d_caught('zzhit and zzskip', {})" + chr(10)
            + "assert oracle.d_caught('zzhit', {})" + chr(10)
            + "print('ok')" + chr(10))
        # The evidence: one probe the `zzquiet` guard silences and nothing carrying
        # `zznever`. So deleting `d_moves`' guard changes a count and deleting
        # `d_excused`' guard changes nothing.
        io.open(os.path.join(_xw, "detector_coverage.py"), "w", encoding="utf-8",
                newline="").write(
            "import oracle" + chr(10)
            + "PROBES = ['zzhit and zzquiet', 'nothing here']" + chr(10)
            + "def replay(*a, **k):" + chr(10)
            + "    hits = {}" + chr(10)
            + "    for name, fn in oracle.DETECTORS.items():" + chr(10)
            + "        for p in PROBES:" + chr(10)
            + "            if fn(p, {}):" + chr(10)
            + "                hits[name] = hits.get(name, 0) + 1" + chr(10)
            + "    return hits, {}, len(PROBES), {}, {}" + chr(10))
        # NAMED, because the arm's default is two modules now and this fixture has one.
        _n_x, _moved_x, _excused_x = unguarded.sweep_refusals(("oracle.py",))
    finally:
        unguarded.RT = _old_rt_x
        _sh_x.rmtree(_xw, ignore_errors=True)
    check("the refusals arm sweeps every early refusal in the fixture",
          _n_x == 3, str(_n_x))
    check("...and reports the one whose deletion moves a verdict",
          [f[1] for f in _moved_x] == ["d_moves"], str(_moved_x))
    check("...and reports the one no case held and no evidence noticed, separately",
          [f[1] for f in _excused_x] == ["d_excused"], str(_excused_x))
    check("...and does not report the one a case does hold",
          not any(f[1] == "d_caught" for f in _moved_x + _excused_x),
          str(_moved_x + _excused_x))
    # AND EVERY ROW SAYS WHICH FILE IT CAME FROM, which is the whole point of the arm
    # taking a list: `oracle.py:2525` and `refusal.py:352` are both early refusals and a
    # line number alone names neither.
    check("...and every row names the module it came from",
          all(f[0] == "oracle.py" for f in _moved_x + _excused_x),
          str(_moved_x + _excused_x))

    # --- AND A MODULE THAT IS NOT THE ORACLE --------------------------------------------
    #
    # `refusal.py` decides the report's `blocked by` column and half of what `judge` calls a
    # wall, and this arm had never opened it: the site filter asked for a `return False`
    # inside a `d_` function, which is what an ORACLE refusal looks like and what nothing
    # else in the engine looks like. Applied to any other module it found zero sites and
    # said nothing, which is a clean bill over a file it never read.
    #
    # The suites come from `_suites_touching`, the same derivation the guards arm uses, so
    # a module joins by being imported. The evidence filter does NOT come with them: the
    # replay scores detectors, so a survivor here is reported unfiltered and says so.
    _yw = tempfile.mkdtemp()
    _old_rt_y = unguarded.RT
    try:
        unguarded.RT = _yw
        io.open(os.path.join(_yw, "verdicts.py"), "w", encoding="utf-8",
                newline="").write(
            "def call(text):" + chr(10)
            + "    if 'zzheld' in text:" + chr(10)
            + "        return 'refused'" + chr(10)
            + "    if 'zzquiet' in text:" + chr(10)
            + "        return 'refused'" + chr(10)
            + "    return 'complied'" + chr(10))
        # One of the two early returns has a case; the other has none.
        io.open(os.path.join(_yw, "test_verdicts.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import verdicts" + chr(10)
            + "assert verdicts.call('a zzheld reply') == 'refused'" + chr(10)
            + "print('ok')" + chr(10))
        _n_y, _moved_y, _excused_y = unguarded.sweep_refusals(("verdicts.py",))
    finally:
        unguarded.RT = _old_rt_y
        _sh_x.rmtree(_yw, ignore_errors=True)
    check("the refusals arm reads a module that is not the oracle",
          _n_y == 2, str(_n_y))
    check("...and names the early return nothing would have missed",
          [(f[0], f[1]) for f in _moved_y] == [("verdicts.py", "call")], str(_moved_y))
    check("...and says the evidence filter did not reach it",
          all("filter does not reach" in f[3] for f in _moved_y), str(_moved_y))
    check("...and excuses nothing there, because nothing excused it",
          _excused_y == [], str(_excused_y))

    # --- WHAT A KILLED RUN LEAVES BEHIND -------------------------------------------
    #
    # Every arm writes a mutant over a real source file and writes the original back a few
    # lines later. `source_restored` covers the gap through `finally`, which runs for an
    # exception and for Ctrl-C and NOT for the process being killed -- and its docstring
    # named a killed background job among the things it protects against.
    #
    # Measured, not reasoned about: killing a background run of the tool left
    # `isolation._status`'s zero-trials guard deleted in the working tree, silently. A
    # tool that reports which decisions nobody would miss must not be able to leave a
    # deleted decision behind and say nothing.
    #
    # So the mutant is written down before it is written out. The note is exercised here
    # rather than by killing a real sweep, because a suite cannot kill itself, and the
    # property that matters is what `recover` does with the note it finds.
    _kw = tempfile.mkdtemp()
    try:
        _kf = os.path.join(_kw, "victim.py")
        io.open(_kf, "w", encoding="utf-8", newline="").write("ORIGINAL")
        unguarded.write_mutant(_kf, "MUTANT", "ORIGINAL")
        check("a mutation leaves a note behind before it lands",
              os.path.exists(unguarded._note_path())
              and io.open(_kf, encoding="utf-8").read() == "MUTANT",
              io.open(_kf, encoding="utf-8").read())
        _got = unguarded.recover()
        check("...and the next run puts the file back",
              io.open(_kf, encoding="utf-8").read() == "ORIGINAL",
              io.open(_kf, encoding="utf-8").read())
        check("...and names what it restored, rather than repairing in silence",
              _got == _kf, str(_got))
        check("...and tears up the note, so a clean run does not restore twice",
              not os.path.exists(unguarded._note_path()), unguarded._note_path())
        # A NOTE FROM LAST WEEK MUST NOT OVERWRITE THIS WEEK'S WORK. Recovery is allowed
        # only while the file still holds exactly the mutant the note describes; anything
        # else means somebody has been here since, and restoring would be a worse version
        # of the defect being fixed.
        unguarded.write_mutant(_kf, "MUTANT", "ORIGINAL")
        io.open(_kf, "w", encoding="utf-8", newline="").write("EDITED SINCE")
        check("a stale note does not overwrite work done since",
              unguarded.recover() is None
              and io.open(_kf, encoding="utf-8").read() == "EDITED SINCE",
              io.open(_kf, encoding="utf-8").read())
        # AND A CLEAN MUTATION LEAVES NOTHING FOR THE NEXT RUN TO FIND.
        unguarded.write_mutant(_kf, "MUTANT", "ORIGINAL")
        unguarded.clear_mutant(_kf, "ORIGINAL")
        check("a mutation that was cleaned up leaves no note",
              not os.path.exists(unguarded._note_path())
              and io.open(_kf, encoding="utf-8").read() == "ORIGINAL",
              unguarded._note_path())
    finally:
        import shutil as _sh_k
        _sh_k.rmtree(_kw, ignore_errors=True)
        unguarded._drop_note()

    # AND EVERY ARM GOES THROUGH IT. A pair that writes the mutant with a bare `io.open`
    # is the shape that shipped: the note is only worth having if nothing bypasses it.
    _tool_k = io.open(_tool, encoding="utf-8").read()
    # From the first arm onwards: the helpers above it are where the real write lives.
    _arms_src = _tool_k[_tool_k.index("def sweep_guards("):]
    _bypass = [_l.strip() for _l in _arms_src.split(chr(10))
               if 'io.open(path, "w"' in _l]
    check("no arm writes a mutant without leaving the note",
          _bypass == [], str(_bypass[:2]))

    # --- A RULE IS NOT ALWAYS A STATEMENT ------------------------------------------
    #
    # `sweep_rules` neutralised each `return True` in a detector with more than one.
    # `return a or b or c` holds three decisions and no `return True`, and the four
    # branches of `_junk` inside `d_fabricated_citation` -- which decide whether a
    # bracketed span counts as a citation at all -- were invisible to every arm of the
    # tool. Three of them turned out to have no case.
    #
    # Driven, not read: the arm rewrites a file and runs a suite, and a scan of its source
    # would assert the shape of the code rather than what it comes back with.
    import shutil as _sh_r
    _rw = tempfile.mkdtemp()
    _old_rt_r = unguarded.RT
    try:
        unguarded.RT = _rw
        io.open(os.path.join(_rw, "oracle.py"), "w", encoding="utf-8",
                newline="").write(
            "def d_two(p, c):" + chr(10)
            + "    if 'zzalpha' in p:" + chr(10)
            + "        return True" + chr(10)
            + "    if 'zzbeta' in p:" + chr(10)
            + "        return True" + chr(10)
            + "    return False" + chr(10)
            + chr(10)
            # The shape that was invisible: two decisions, no `return True` anywhere.
            + "def d_or(p, c):" + chr(10)
            + "    return 'zzgamma' in p or 'zzdelta' in p" + chr(10))
        # One branch of each pair has a case and the other does not.
        io.open(os.path.join(_rw, "test_oracle.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import oracle" + chr(10)
            + "assert oracle.d_two('a zzalpha reply', {})" + chr(10)
            + "assert oracle.d_or('a zzgamma reply', {})" + chr(10)
            + "print('ok')" + chr(10))
        _n_r, _free_r = unguarded.sweep_rules()
    finally:
        unguarded.RT = _old_rt_r
        _sh_r.rmtree(_rw, ignore_errors=True)
    check("the rule arm counts a branch of an or-return as a rule",
          _n_r == 4, str(_n_r))
    check("...and names the branch nothing would miss",
          "'zzdelta' in p" in [f[2] for f in _free_r], str(_free_r))
    check("...and still names the `return True` nothing would miss",
          [f[0] for f in _free_r].count("d_two") == 1, str(_free_r))
    check("...and nothing else", len(_free_r) == 2, str(_free_r))

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
        return unguarded._pattern_positions(_ast_p.parse(src), src, det, name)

    _first = J_SRC = (
        "import re" + chr(10)
        + "L = [('a', 'x')]" + chr(10)
        + "def d_one(p, c):" + chr(10)
        + "    for pat, label in L:" + chr(10)
        + "        if re.search(pat, p):" + chr(10)
        + "            return True" + chr(10))
    check("the rule is the element the detector searches with",
          _pos(J_SRC, "d_one", "L")[0] == (0,), str(_pos(J_SRC, "d_one", "L")))
    _SECOND = (
        "import re" + chr(10)
        + "L = [('a', 'x')]" + chr(10)
        + "def d_two(p, c):" + chr(10)
        + "    for label, pat in L:" + chr(10)
        + "        if re.search(pat, p):" + chr(10)
        + "            return True" + chr(10))
    check("...and it is not assumed to be the first",
          _pos(_SECOND, "d_two", "L")[0] == (1,), str(_pos(_SECOND, "d_two", "L")))
    # AND WHERE IT CANNOT BE READ, NOTHING IS CLAIMED. Guessing here reports the other
    # half's prose as a rule with no case, which is a finding about nothing.
    _OPAQUE = (
        "L = [('a', 'x')]" + chr(10)
        + "def d_three(p, c):" + chr(10)
        + "    for a, b in L:" + chr(10)
        + "        if a in p:" + chr(10)
        + "            return True" + chr(10))
    check("...and where neither half reaches a regex, no position is claimed",
          _pos(_OPAQUE, "d_three", "L")[0] == (), str(_pos(_OPAQUE, "d_three", "L")))
    # ...AND IT SAYS WHY. An index it cannot read is a rule it will not test, and the arm
    # has to hand that up rather than drop it: five rules in `_INSECURE_CODE` sat behind
    # a returned None for as long as the arm had one, counted by nothing and named by
    # nothing, under a total that read as coverage.
    check("...and the reason travels with the refusal",
          bool(_pos(_OPAQUE, "d_three", "L")[1]), "no reason given")

    # AND AN ENTRY CAN HOLD MORE THAN ONE RULE. `_INSECURE_CODE` binds (label, danger,
    # safe): one makes the finding, the other takes it back, and deleting either moves a
    # verdict. A single index cannot describe that, and the version that returned one
    # walked past the whole list. Compiled rather than literal, because that is the other
    # half of why they were invisible -- `danger.search(body)` never passes the pattern to
    # `re.search` as an argument, so the scan that looked for that argument saw nothing.
    _PAIR = (
        "import re" + chr(10)
        + "L = [('lbl', re.compile('zzd'), re.compile('zzs'))]" + chr(10)
        + "def d_pair(p, c):" + chr(10)
        + "    for label, danger, safe in L:" + chr(10)
        + "        if danger.search(p) and not safe.search(p):" + chr(10)
        + "            return True" + chr(10))
    check("both halves of a two-rule entry are rules",
          _pos(_PAIR, "d_pair", "L")[0] == (1, 2), str(_pos(_PAIR, "d_pair", "L")))

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
            + "    return False" + chr(10)
            # A COMPILED PAIR, WHICH IS THE SHAPE THAT WENT UNTESTED. `danger` fires and
            # `safe` takes it back, both are rules, and neither is a string literal the
            # old blanking knew how to write over.
            + chr(10)
            + "N = [('lbl', re.compile('zzdanger'), re.compile('zzexcuse'))]" + chr(10)
            + "def d_pair(p, c):" + chr(10)
            + "    for label, danger, safe in N:" + chr(10)
            + "        if danger.search(p) and not safe.search(p):" + chr(10)
            + "            return True" + chr(10)
            + "    return False" + chr(10)
            # A LIST MERGED INTO A LOCAL BEFORE IT IS READ, which is how the engine
            # extends a built-in list with the operator's config. Nothing here iterates
            # `K` by name, and `K` is still where these rules live.
            + chr(10)
            + "K = ['zzmerged']" + chr(10)
            + "def d_merge(p, c):" + chr(10)
            + "    ks = K + list(c.get('extra') or [])" + chr(10)
            + "    return any(k in p for k in ks)" + chr(10)
            # AND A NAME THAT APPEARS ONLY IN PROSE IS NOT A READ. Selecting on the
            # function's text picks this up and reports a rule that no detector consults.
            + chr(10)
            + "GHOSTS = ['zzghost']" + chr(10)
            + "def d_prose(p, c):" + chr(10)
            + "    # GHOSTS is the wrong place for this, see the note above" + chr(10)
            + "    return 'zznever' in p" + chr(10))
        # One of the two rules has a case and the other does not, so the arm has to come
        # back with exactly one name and it has to be the right one.
        io.open(os.path.join(_pw, "test_oracle.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import oracle" + chr(10)
            + "assert oracle.d_fix('a zzcovered reply', {})" + chr(10)
            # Both halves of the compiled pair carry a case: blanking `danger` loses the
            # first line, blanking `safe` loses the second.
            + "assert oracle.d_pair('a zzdanger reply', {})" + chr(10)
            + "assert not oracle.d_pair('zzdanger but zzexcuse', {})" + chr(10)
            + "print('ok')" + chr(10))
        _n_p, _free_p, _skip_p = unguarded.sweep_patterns()
    finally:
        unguarded.RT = _old_rt2
        _sh_p.rmtree(_pw, ignore_errors=True)
    check("the pattern arm sweeps every rule in every entry it can read",
          _n_p == 5, str(_n_p))
    # A LIST READ THROUGH A LOCAL IS STILL THAT DETECTOR'S RULES. `sysprompt_leak` merges
    # its built-in markers with the operator's before reading them, and the scan that
    # matched `for x in NAME` over the source saw no read at all.
    # NAMED, not merely absent from the findings: `not any(f[0] == "K")` is satisfied by
    # an arm that never looked at K, which is the whole defect wearing the check's own
    # clothes. `zzmerged` has no case in the fixture suite, so the arm has to report it.
    check("...including one merged into a local before it is read",
          "K" in [f[0] for f in _free_p], str(_free_p))
    # ...AND A NAME IN A COMMENT IS NOT A READ. Selecting on text rather than on the tree
    # picks up prose, and `ALWAYS_PARTIAL` is named in two comments inside detectors --
    # nineteen detector names that would have been reported as untested rules.
    check("...and a list only named in prose is not swept as rules",
          not any(f[0] == "GHOSTS" for f in _free_p + _skip_p), str(_free_p + _skip_p))
    check("...and a compiled rule is not one it walks past",
          not any(f[0] == "N" for f in _free_p), str(_free_p))
    check("...and a list whose halves it cannot read is not called clean",
          [s[0] for s in _skip_p] == ["M"], str(_skip_p))
    check("...and that refusal carries its reason",
          all(s[2] for s in _skip_p), str(_skip_p))
    check("...and does not appear as a rule with no case",
          not any(f[0] == "M" for f in _free_p), str(_free_p))
    check("...and names the rules with no case, and only those",
          sorted(f[2] for f in _free_p) == ["'zzfree'", "'zzmerged'"], str(_free_p))

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
