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

import json as _json_k  # noqa: E402
import shutil as _sh_k  # noqa: E402
import subprocess as _sp_k  # noqa: E402
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


def sweep_in(source, only=(), suite=None):
    """Run the sweep over a throwaway package directory holding one module.

    `RT` is module-level in the tool, so this is where it is pointed. Nothing here imports
    the fixture module by default, which is deliberate: it makes the `NO SUITE IMPORTS IT`
    arm the one under test and costs no suite runs.

    `suite` writes a `test_fixture.py` beside it, which is how the other two arms are
    reached: a suite that imports the module is what the sweep derives, and whether it is
    GREEN is what decides between sweeping the module and holding it back.
    """
    d = tempfile.mkdtemp()
    io.open(os.path.join(d, "fixture_mod.py"), "w", encoding="utf-8",
            newline="").write(source)
    if suite is not None:
        io.open(os.path.join(d, "test_fixture.py"), "w", encoding="utf-8",
                newline="").write(suite)
    old = unguarded.RT
    try:
        unguarded.RT = d
        return unguarded.sweep_guards(only)
    finally:
        unguarded.RT = old


def main():
    # THE WHOLE SUITE GETS ITS OWN NOTE, first thing, because the whole suite exercises the
    # mechanism: `sweep_in` below runs the tool's own sweep functions in this process, and
    # each of them ends in `clear_mutant` -> `_drop_note`. With no override that is the
    # CHECKOUT's note, and `unguarded._run` runs this file as a suite for every module it
    # sweeps -- so a sweep would write a note, launch this suite, and have its own record
    # torn up by the child, leaving a mutant nothing could recover from.
    #
    # Measured, and it is how this was found: a mutant left by a killed sweep of
    # `targets_memorybot.py` could not be recovered, and the note was gone. Setting this at
    # the top rather than around each block is the version that cannot be outflanked by the
    # next arm somebody adds.
    _note_here = tempfile.mkdtemp(prefix="unguarded-suite-note-")
    os.environ["QATRATION_UNGUARDED_NOTE"] = os.path.join(_note_here, "note.json")
    # --- the counter that keeps the denominator honest ------------------------------------
    tested, survivors, undocumented, held, _empty = sweep_in(DOCUMENTED)
    check("a guard with no comment above it is counted, not dropped",
          undocumented == 1, "counted %d" % undocumented)
    check("...and a module nothing held back holds nothing back", not held, str(held))


    # --- A MODULE SOMEBODY NAMED AND GOT SILENCE ABOUT ----------------------------------
    #
    # Package-wide, a file with no guard of this shape is passed over quietly, and that is
    # right: most hold none and listing them is the noise that stops a report being read.
    # Under `--only` it is not. The reader typed the name. `init_config.py`, `history.py`
    # and `worker.py` were asked for in one run and produced no line at all, which is
    # indistinguishable from not having been looked at -- the distinction this arm already
    # draws for a module whose suites are red.
    _bare = 'def f(x):\n    return x\n'
    _t5, _s5, _u5, _h5, _e5 = sweep_in(_bare, only=("fixture_mod",))
    check("a named module with no guard of this shape is named back",
          _e5 == ["fixture_mod.py"], str(_e5))
    check("...and nothing was deleted from it", (_t5, _s5) == (0, []),
          "%d tested, %d survivor(s)" % (_t5, len(_s5)))
    # AND NOT PACKAGE-WIDE, where it would be a list of forty files nobody reads.
    check("...while a sweep nobody narrowed says nothing about them",
          not sweep_in(_bare)[4], str(sweep_in(_bare)[4]))

    # --- A MODULE THE SWEEP NEVER OPENED DID NOT REPORT CLEAN -----------------------------
    #
    # The sweep refuses to judge a module whose suites are red to begin with, which is right:
    # a deletion that cannot make a green suite red proves nothing when the suite was already
    # red. It printed one line and returned nothing, so the summary closed with `Nothing this
    # sweep deleted went unnoticed` over a module nothing was deleted from.
    #
    # It happened: `test_fleet_limits` exited 1 one run in twelve from its own teardown,
    # `runner.py` imports into it, and its documented guards went unswept behind that
    # sentence -- which is the same discipline the undocumented count already gets, missing
    # for the case where a whole module is skipped.
    _RED = ("import sys\nimport fixture_mod\nprint('FAIL  planted')\nsys.exit(1)\n")
    _GREEN = ("import fixture_mod\nprint('PASS  planted')\n")
    _t3, _s3, _u3, _h3, _e3 = sweep_in(DOCUMENTED, suite=_RED)
    check("a module whose suite is red is held back, not reported on",
          _h3 == [("fixture_mod.py", 1)], str(_h3))
    check("...and nothing was deleted from it", _t3 == 0 and not _s3,
          "%d tested, %d survivor(s)" % (_t3, len(_s3)))
    # AND A GREEN ONE IS SWEPT, or the check above is satisfied by a harness that cannot
    # reach the other arm at all.
    _t4, _s4, _u4, _h4, _e4 = sweep_in(DOCUMENTED, suite=_GREEN)
    check("...while a module whose suite is green is swept", _t4 == 1 and not _h4,
          "%d tested, held %s" % (_t4, _h4))
    # AND THE GUARD IT SWEPT IS A SURVIVOR HERE, because the planted suite asserts nothing:
    # deleting the guard cannot make it red, which is exactly what this tool reports.
    check("...and a guard no case keeps is still reported from it",
          len(_s4) == 1 and "if x is None:" in _s4[0][2], str(_s4[:1]))

    # --- `break` AND `continue` ARE GUARDS ------------------------------------------------
    #
    # The body pattern read `return`, `raise` and `sys.exit`, and a branch that skips an
    # item reads `continue`. `if not isinstance(doc, dict): continue` is the shape this
    # repository found eight times in one day, and deleting it means the item is processed.
    # Measured across the engine when this was widened: 41 documented guards were in scope
    # and TEN were not -- and for `benign`, `compare_targets`, `defense_report` and
    # `lint_arsenal`, the one documented guard each of them has was among the ten, so the
    # sweep answered "no guard of this shape here" about a module that had one. The first
    # run after widening found a survivor in `lint_arsenal`.
    _LOOPS = ('"""A module whose guards skip and stop rather than return."""' + chr(10)
              + chr(10) + chr(10)
              + "def each(rows):" + chr(10)
              + "    out = []" + chr(10)
              + "    for r in rows:" + chr(10)
              + "        # A ROW THAT IS NOT A MAPPING IS SKIPPED, and somebody paid for"
              + " that." + chr(10)
              + "        if not isinstance(r, dict):" + chr(10)
              + "            continue" + chr(10)
              + "        # AND THE LIST IS BOUNDED, which is also a branch." + chr(10)
              + "        if len(out) >= 3:" + chr(10)
              + "            break" + chr(10)
              + "        out.append(r)" + chr(10)
              + "    return out" + chr(10))
    _tl, _sl, _ul, _hl, _el = sweep_in(_LOOPS, suite=_GREEN)
    check("a documented guard whose body is `continue` or `break` is in scope",
          _tl == 2, "tested %d" % _tl)
    check("...and neither is counted as undocumented instead",
          _ul == 0, "counted %d undocumented" % _ul)
    check("...and both survive deletion here, since the fixture suite never calls them",
          len(_sl) == 2, str(_sl))
    # AND THE THREE THAT WERE ALWAYS IN SCOPE STILL ARE, or widening replaced them.
    _tr, _sr, _ur, _hr, _er = sweep_in(DOCUMENTED, suite=_GREEN)
    check("...while a guard whose body is `return` is still in scope too",
          _tr == 1, "tested %d" % _tr)

    # AND THE SENTENCE THE TOOL CLOSES WITH, which is the one a reader takes for the
    # verdict. `main` is driven rather than read: a rule that only the returned tuple knows
    # is a rule the summary can go on contradicting.
    import contextlib as _ctx, io as _io_u

    def _closing(files, only):
        """files: {module stem: (source, suite source or None)}."""
        d = tempfile.mkdtemp()
        for _stem, (_src, _suite) in files.items():
            io.open(os.path.join(d, _stem + ".py"), "w", encoding="utf-8",
                    newline="").write(_src)
            if _suite is not None:
                io.open(os.path.join(d, "test_" + _stem + ".py"), "w", encoding="utf-8",
                        newline="").write(_suite)
        old, buf = unguarded.RT, _io_u.StringIO()
        try:
            unguarded.RT = d
            with _ctx.redirect_stdout(buf):
                unguarded.main(["--guards", "--only"] + list(only))
        finally:
            unguarded.RT = old
        return buf.getvalue()

    _said_red = _closing({"fixture_mod": (DOCUMENTED, _RED)}, ["fixture_mod"])
    check("a run that swept nothing does not close as a run that found nothing",
          "went unnoticed" not in _said_red, _said_red[-200:])
    check("...it names the module it never opened",
          "fixture_mod.py" in _said_red and "NEVER SWEPT" in _said_red, _said_red[-300:])
    check("...and says the suite is why, not the module",
          "not green" in _said_red, _said_red[-300:])
    # AND DOES NOT BLAME THE SHAPE OF THE CODE. `Every branch this sweep looked at was
    # either undocumented or not of the shape it takes` is a statement about the module and
    # it is false here: the branch was documented and of exactly that shape, and the sweep
    # never looked at it.
    check("...and not the shape of the code it never read",
          "not of the shape it takes" not in _said_red, _said_red[-300:])
    # AND A RUN THAT DID SWEEP STILL CLOSES THE WAY IT DID, or the caveat lands on every
    # honest sweep, which is the failure mode on the other side of this.
    _said_ok = _closing({"fixture_mod": ("def f(x):\n    return x\n", _GREEN)},
                        ["fixture_mod"])
    check("...while a sweep with nothing held back carries no such caveat",
          "NEVER SWEPT" not in _said_ok, _said_ok[-300:])
    # AND THE MODULE SOMEBODY NAMED THAT HOLDS NOTHING OF THIS SHAPE. The returned tuple
    # knowing it is not the same as the reader being told: this whole file is about a
    # summary that did not carry what the sweep did not do.
    _said_bare = _closing({"fixture_mod": ("def f(x):\n    return x\n", _GREEN)},
                          ["fixture_mod"])
    check("a named module with no guard of this shape is named in the summary",
          "hold no documented guard of this shape" in _said_bare
          and "fixture_mod.py" in _said_bare, _said_bare[-400:])
    check("...and the run does not close as though it had swept it",
          "went unnoticed" not in _said_bare, _said_bare[-300:])

    # AND THE CASE THAT ACTUALLY HAPPENED: one module swept, another held. The closing line
    # there was `Nothing this sweep deleted went unnoticed` -- true of the module it opened
    # and a clean bill over the one it did not. Two modules, because with only a held one
    # the run sweeps nothing and takes a different sentence entirely.
    _said_both = _closing({"fixture_mod": (DOCUMENTED, _GREEN.replace("fixture_mod",
                                                                      "fixture_mod")),
                           "othermod": (DOCUMENTED,
                                        _RED.replace("fixture_mod", "othermod"))},
                          ["fixture_mod", "othermod"])
    check("a sweep that opened one module and not the other says so",
          "NEVER SWEPT" in _said_both, _said_both[-300:])
    # AFTER THE CLOSING SENTENCE, WHATEVER IT WAS. This run has a survivor, so it ends with
    # `N decision(s) to look at` rather than a clean bill -- and the module nobody opened
    # qualifies that line exactly as much as it qualifies the clean one.
    check("...after the sentence it qualifies, not inside one branch of it",
          "decision(s) to look at" in _said_both
          and _said_both.index("decision(s) to look at")
          < _said_both.index("NEVER SWEPT"), _said_both[-300:])
    check("...naming the one it did not open, and not the one it did",
          "othermod" in _said_both.split("NEVER SWEPT")[-1]
          and "fixture_mod" not in _said_both.split("NEVER SWEPT")[-1],
          _said_both[-300:])
    # AND THE SECTION SAYS IT TOO, beside the count it qualifies, which is where a reader
    # looking at the module list is already looking.
    check("...and the guards section names it beside its own count",
          "were not swept at all" in _said_both and "othermod.py (1 guard(s))"
          in _said_both, _said_both[:600])
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
    _plain, _plain_s, _plain_u, _plain_h, _plain_e = sweep_in(
        'def f(x):\n    return x\n')
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
    _t2, _s2, _u2, _h2, _e2 = sweep_in(DOCUMENTED, only=("fixture_mod",))
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
    # AND ITS OWN NOTE, because RUNNING this tool is touching the note: `main` opens with
    # `recover()`, which reads the record of a killed sweep and tears it up when the file no
    # longer holds that mutant. A child launched from here inherits the parent's
    # environment, so without this every invocation below destroys the recovery note of
    # whatever sweep is running in the checkout -- and `unguarded._run` runs THIS FILE as a
    # suite for every module it sweeps.
    #
    # Measured: with this line absent, writing a note and running this suite as a subprocess
    # leaves no note behind. That is a mutant nothing can recover from, caused by the suite
    # that tests the recovery.
    _env_u = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1",
                  QATRATION_UNGUARDED_NOTE=os.path.join(
                      tempfile.mkdtemp(prefix="unguarded-suite-note-"), "note.json"))

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
    # --- A SUITE THAT RAN OUT OF TIME DID NOT CATCH ANYTHING ---------------------------
    #
    # `_run` returns 99 for a timeout, and every loop here asked `any(_run(s) for s in
    # suites)`. 99 is truthy, so a suite that hit the ceiling counted as one that caught the
    # mutant: a guard nothing measured came back defended, and the summary closed over it.
    # The absence of a verdict published as a verdict, by the tool written to find that.
    #
    # It cost a wrong sentence rather than staying hypothetical. Re-checking a survivor
    # against the suites that reach it, `test_benign` hit the 420-second ceiling under load
    # and was named as the suite driving `authorization`'s no-host guard; run on its own
    # afterwards it passes with the guard deleted. The guard really was undriven, and the
    # instrument said otherwise because it could not tell `failed` from `never finished`.
    check("a suite that failed caught the mutant", unguarded._caught(1) is True, "1")
    check("...and one that passed did not", unguarded._caught(0) is False, "0")
    check("...and one that never finished is neither",
          unguarded._caught(unguarded.TIMED_OUT) is None, str(unguarded.TIMED_OUT))
    # AND THE LOOP OVER A SET OF SUITES SAYS WHICH ONES IT COULD NOT ASK, rather than
    # folding them into either answer.
    _seen_q = []

    def _fake_run(code_by_suite):
        def _r(s, timeout=420):
            _seen_q.append(s)
            return code_by_suite[s]
        return _r

    _real_run_q = unguarded._run
    try:
        unguarded._run = _fake_run({"a": 0, "b": unguarded.TIMED_OUT, "c": 0})
        _red_q, _slow_q = unguarded._any_caught(["a", "b", "c"])
        check("a mutant no suite caught is not caught", _red_q is False, str(_red_q))
        check("...and the suite that never finished is named",
              _slow_q == ["b"], str(_slow_q))
        # AND A REAL FAILURE STILL WINS, or the rule above turns every red suite into a
        # shrug. `b` times out and `c` fails: the mutant was caught.
        _seen_q.clear()
        unguarded._run = _fake_run({"a": 0, "b": unguarded.TIMED_OUT, "c": 1})
        _red2_q, _slow2_q = unguarded._any_caught(["a", "b", "c"])
        check("...while a suite that really failed still catches it", _red2_q is True,
              str(_red2_q))
        # AND IT STOPS THERE, because running the rest proves nothing and costs minutes.
        _seen_q.clear()
        unguarded._run = _fake_run({"a": 1, "b": 0, "c": 0})
        unguarded._any_caught(["a", "b", "c"])
        check("...and stops at the first suite that caught it", _seen_q == ["a"],
              str(_seen_q))
    finally:
        unguarded._run = _real_run_q

    # --- AND THE ASSERTIONS READ THAT THIRD STATE TOO ----------------------------------
    #
    # `_caught` was added for the sweep loops and seven ASSERTS kept the old reading:
    # `assert _run(s) == 0` is false for a timeout exactly as it is for a failure. So a
    # suite that ran long at the end of a module sweep aborted the run with
    #
    #     workspace.py was not restored
    #
    # which accuses this tool of damaging a working tree it restored correctly, and is the
    # one sentence that would make an operator stop and check their git status. A run that
    # measured nothing, published as a verdict about their files.
    #
    # `_still_green` answers the three states in words, and every assert now carries the
    # reason rather than an equality.
    _real_run_g = unguarded._run
    try:
        unguarded._run = lambda s, timeout=420: {"green.py": 0, "red.py": 1,
                                                 "slow.py": unguarded.TIMED_OUT}[s]
        check("a suite that passed is green and says nothing",
              unguarded._still_green("green.py") == "", unguarded._still_green("green.py"))
        check("...one that failed is named as red",
              "is red" in unguarded._still_green("red.py"),
              unguarded._still_green("red.py"))
        check("...and one that never finished says THAT, not that it failed",
              "never finished" in unguarded._still_green("slow.py")
              and "red" not in unguarded._still_green("slow.py"),
              unguarded._still_green("slow.py"))
    finally:
        unguarded._run = _real_run_g
    # AND NO ARM STILL COMPARES AN EXIT CODE TO ZERO, which is the form that cannot tell
    # the third state from the second. Asked of the source, because the arms that do it are
    # in sweeps too slow to drive here.
    _tool_g = io.open(os.path.join(ROOT, "tools", "unguarded.py"),
                      encoding="utf-8").read()
    _old_form = [_l.strip() for _l in _tool_g.split(chr(10))
                 if _l.lstrip().startswith("assert ")
                 and ("_run(s)" in _l or "_run(suite)" in _l)]
    check("no assertion in the tool reads an exit code directly",
          _old_form == [], str(_old_form[:2]))

    # --- A SUITE THAT REACHES A MODULE THROUGH ANOTHER ONE STILL REACHES IT ------------
    #
    # `_suites_touching` matches a direct import and nothing else, and its docstring claims
    # to return "every suite that reaches this module". It does not. `test_verify` reaches
    # `workspace` through `verify` and `test_matrix` through `model_matrix`; neither imports
    # `workspace` itself, so a guard either of them drives is deleted, the direct importers
    # stay green, and the sweep prints SURVIVED about a decision something would have
    # missed. A gap reported as a measurement, by the tool named after that failure.
    #
    # Measured over this package: 44 of the 63 modules have an incomplete set.
    # `authorization.py` was swept against 3 suites where 49 reach it.
    #
    # The closure is not what the bulk sweep runs -- it is nearly every suite for nearly
    # every module. It is what a SURVIVOR is checked against, and survivors are few.
    _direct_w = set(unguarded._suites_touching("workspace.py"))
    _reach_w = set(unguarded._suites_reaching("workspace.py"))
    check("the reaching set contains everything the direct set does",
          _direct_w <= _reach_w, str(sorted(_direct_w - _reach_w)))
    check("...and a suite that reaches workspace through verify is in it",
          "test_verify.py" in _reach_w, "test_verify.py drives workspace.clipped")
    check("...and one that reaches it through model_matrix is too",
          "test_matrix.py" in _reach_w, "test_matrix.py drives workspace.say_unreadable")
    check("...neither of which the direct set names",
          not ({"test_verify.py", "test_matrix.py"} & _direct_w), str(sorted(_direct_w)))
    # AND IT IS NOT SIMPLY EVERY SUITE THERE IS, or the two above are satisfied by a
    # function that returns the directory listing. A module nothing reaches has no suites.
    _all_suites = {f for f in os.listdir(unguarded.RT)
                   if f.startswith("test_") and f.endswith(".py")}
    check("...while the reaching set is still derived, not the whole directory",
          _reach_w < _all_suites or len(_reach_w) < len(_all_suites),
          "%d of %d" % (len(_reach_w), len(_all_suites)))
    # AND THE GRAPH IS THE PACKAGE'S OWN IMPORTS, asserted on a pair this repository has:
    # `verify` imports `workspace`, so anything reaching `verify` reaches `workspace`.
    _graph = unguarded._package_imports()
    check("the import graph sees that verify imports workspace",
          "workspace" in _graph.get("verify", set()), str(sorted(_graph.get("verify", []))[:6]))

    # --- AND THE MUTANT WRITES SOMEWHERE TOO -------------------------------------------
    #
    # This tool is careful with the source it breaks and said nothing about the directory
    # the broken engine writes into. `workspace.refuse_overwrite` stops a run REPLACING a
    # tracked artifact -- "a tracked artifact is evidence something else recounts: in this
    # project the README, the site and `qatration coverage` all read these files" -- and
    # nothing stops one ADDING one. `results_files()` globs the directory, so a file a
    # mutant writes joins the fleet and is counted by every page and every recount.
    #
    # Measured: a sweep of `workspace.py` left two `run_*.json` records in `out/` beside the
    # twenty-five real ones.
    #
    # IT REPORTS AND REMOVES NOTHING, and that is the whole design. A cleanup that deletes
    # is the most dangerous shape this fix could take against the one directory here whose
    # contents are evidence -- and the first version of it deleted all 237 tracked files,
    # because it diffed two snapshots taken against DIFFERENT roots. Hence the root travels
    # with the snapshot, and a mismatch says nothing rather than saying everything.
    import shutil as _sh_a2
    _aw = tempfile.mkdtemp()
    try:
        _kept = os.path.join(_aw, "results_kept.json")
        io.open(_kept, "w", encoding="utf-8").write("{}")
        _before_a = (_aw, {os.path.join(dp, fn)
                           for dp, _d, fns in os.walk(_aw) for fn in fns})
        _added_a = os.path.join(_aw, "run_mutant.json")
        io.open(_added_a, "w", encoding="utf-8").write("{}")
        os.makedirs(os.path.join(_aw, "history"), exist_ok=True)
        _added_n = os.path.join(_aw, "history", "ghost.jsonl")
        io.open(_added_n, "w", encoding="utf-8").write("{}")

        # THROUGH THE REAL `_workspace_snapshot`, not a lambda standing in for it. A stub
        # that returns the root by hand cannot fail when the root stops being captured,
        # which is precisely the line that turned this fix into a workspace delete. So
        # `workspace.OUT` is moved instead, which is what a suite reloading it does.
        import workspace as _ws_q
        _real_out_q = _ws_q.OUT
        try:
            _ws_q.OUT = _aw
            _left = unguarded._say_what_was_left(_before_a)
            # AND THE SAME CALL AGAIN WITH THE WORKSPACE MOVED. Two readings of two
            # different directories are not a list of new files.
            _elsewhere = tempfile.mkdtemp()
            try:
                # WITH EVIDENCE IN IT, or this case cannot fail: an empty directory has
                # nothing to name whether the roots are compared or not, and the version of
                # this fix that deleted 237 tracked files is exactly the one that names
                # every file in a workspace it never snapshotted.
                io.open(os.path.join(_elsewhere, "results_other.json"), "w",
                        encoding="utf-8").write("{}")
                _ws_q.OUT = _elsewhere
                _mismatch = unguarded._say_what_was_left(_before_a)
            finally:
                _sh_a2.rmtree(_elsewhere, ignore_errors=True)
        finally:
            _ws_q.OUT = _real_out_q

        check("what a mutant wrote into the workspace is named",
              _added_a in _left, str(_left))
        check("...including one it wrote in a subdirectory",
              _added_n in _left, str(_left))
        check("...and NOTHING is removed, because this directory holds the evidence",
              os.path.exists(_added_a) and os.path.exists(_added_n)
              and os.path.exists(_kept), _aw)
        # AND THE ARTIFACT THAT WAS ALREADY THERE IS NOT NAMED. Without this the report may
        # name the whole workspace and still pass the two checks above -- which is exactly
        # what the version of this fix that deleted 237 tracked files did.
        check("...while the artifact that was already there is not named",
              _kept not in _left, str(_left))
        # AND A SNAPSHOT OF A DIFFERENT ROOT SAYS NOTHING. `workspace.OUT` is resolved at
        # import and a suite can reload it under its own `QATRATION_OUT`, so two readings
        # are not always two readings of the same directory. Calling that difference "what
        # the mutant added" names every file in the real workspace.
        check("a snapshot taken against a different root is not a list of new files",
              _mismatch == [], str(_mismatch))
        check("a snapshot that could not be taken names nothing",
              unguarded._say_what_was_left(None) == [], "it named something")
    finally:
        _sh_a2.rmtree(_aw, ignore_errors=True)

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
        # NAMED, because the arm's default is two modules now and this fixture has one.
        _n_r, _free_r, _un_r = unguarded.sweep_rules(("oracle.py",))
    finally:
        unguarded.RT = _old_rt_r
        _sh_r.rmtree(_rw, ignore_errors=True)
    check("the rule arm counts a branch of an or-return as a rule",
          _n_r == 4, str(_n_r))
    check("...and names the branch nothing would miss",
          "'zzdelta' in p" in [f[3] for f in _free_r], str(_free_r))
    check("...and still names the `return True` nothing would miss",
          [f[1] for f in _free_r].count("d_two") == 1, str(_free_r))
    check("...and nothing else", len(_free_r) == 2, str(_free_r))
    check("...and every row names the module it came from",
          all(f[0] == "oracle.py" for f in _free_r), str(_free_r))

    # --- AND A RULE IN A MODULE THAT IS NOT THE ORACLE ---------------------------------
    #
    # `return True` is an ORACLE shape: one independent way for a detector to fire.
    # `refusal.declined` ends on `return bool(a or b or c)` and `classify` returns a dict,
    # so the arm pointed anywhere else found no sites and said nothing -- and one of
    # `declined`'s three ors, the handoff rule its own comment says cost 108 misread
    # replies, had no case.
    #
    # Through `bool(...)` as well as bare, because that is how the real one is written and
    # the first version of the branch reader asked only for a bare `BoolOp`.
    _qw = tempfile.mkdtemp()
    _old_rt_q = unguarded.RT
    try:
        unguarded.RT = _qw
        io.open(os.path.join(_qw, "verdict2.py"), "w", encoding="utf-8",
                newline="").write(
            "def declined(text):" + chr(10)
            + "    return bool('zzno' in text or 'zznever' in text)" + chr(10))
        io.open(os.path.join(_qw, "test_verdict2.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import verdict2" + chr(10)
            + "assert verdict2.declined('a zzno reply')" + chr(10)
            + "print('ok')" + chr(10))
        _n_q, _free_q, _un_q = unguarded.sweep_rules(("verdict2.py",))
    finally:
        unguarded.RT = _old_rt_q
        _sh_r.rmtree(_qw, ignore_errors=True)
    check("the rule arm reads an or-chain wrapped in bool(), in a module that is not the oracle",
          _n_q == 2, str(_n_q))
    check("...and names the branch of it that nothing would miss",
          [(f[0], f[3]) for f in _free_q] == [("verdict2.py", "'zznever' in text")],
          str(_free_q))

    # --- WHICH HALF OF AN ENTRY IS THE RULE ----------------------------------------
    #
    # --- AND THE ARM SAYS WHAT IT WALKED PAST ------------------------------------------
    #
    # It printed "31 rule site(s) tested, 0 with no case of their own" over an oracle of
    # SIXTY-SIX detectors, with rules swept in twelve of them, and named neither number.
    # `sweep_guards` names the guards that carry no comment and `sweep_patterns` names the
    # lists where it cannot tell which half is the rule; this arm was the one of the three
    # that still counted what it touched and said nothing about the rest.
    #
    # TWO REASONS, kept apart because they are different facts: a detector with exactly one
    # `return True` has one way to fire, so that statement IS the detector and deleting it
    # asks a different question; a detector with none fires by a shape this arm cannot read.
    _shapes = (
        "def d_one(p, c):" + chr(10)
        + "    if 'zz1' in p:" + chr(10)
        + "        return True" + chr(10)
        + "    return False" + chr(10)
        + chr(10)
        + "def d_two(p, c):" + chr(10)
        + "    if 'zz2' in p:" + chr(10)
        + "        return True" + chr(10)
        + "    if 'zz3' in p:" + chr(10)
        + "        return True" + chr(10)
        + "    return False" + chr(10)
        + chr(10)
        + "def d_none(p, c):" + chr(10)
        + "    return 'zz4' in p" + chr(10))
    _out = unguarded._rules_out_of_scope(_shapes, "oracle.py")
    _named = {_n: _w for _m, _n, _w in _out}
    check("a detector with one way to fire is named as out of scope",
          "d_one" in _named and "one way to fire" in _named["d_one"], str(_named))
    check("...and one this arm cannot read at all is named separately",
          "d_none" in _named and "does not read" in _named["d_none"], str(_named))
    check("...while the detector it DOES sweep is not in the remainder",
          "d_two" not in _named, str(_named))
    # AND THE TWO REASONS ARE NOT COLLAPSED INTO ONE SENTENCE, which is what makes the
    # line worth printing: `not covered` and `not reachable from here` send a reader to
    # different places.
    check("...and the two reasons are different sentences",
          _named.get("d_one") != _named.get("d_none"), str(_named))
    # ON THE REAL ORACLE, because a fixture proves the rule and this proves the debt: the
    # arm reports on rules in a minority of the detectors that exist.
    _real = unguarded._rules_out_of_scope(
        io.open(os.path.join(HERE, "oracle.py"), encoding="utf-8").read(), "oracle.py")
    check("the real oracle has detectors this arm cannot report on", len(_real) > 20,
          "%d" % len(_real))
    # AND ONLY `oracle.py` HAS THIS SHAPE. `refusal.py` answers with an or-chain and is
    # swept whole by the branch arm, so a remainder there would be an invented number.
    check("...and the arm claims no remainder for a module it sweeps whole",
          unguarded._rules_out_of_scope(
              io.open(os.path.join(HERE, "refusal.py"), encoding="utf-8").read(),
              "refusal.py") == [],
          "refusal.py reported a remainder")
    # ASKED WITH A MODULE THAT HAS THE SHAPE, because `refusal.py` has no `d_` function at
    # all: it would answer empty whether or not the rule looked. `return True` means one way
    # for a DETECTOR to fire and that is an `oracle.py` shape -- anywhere else the same
    # statement is an ordinary early return, and counting it would invent a debt.
    check("...even when that module is full of functions named like detectors",
          unguarded._rules_out_of_scope(_shapes, "verdict2.py") == [],
          str(unguarded._rules_out_of_scope(_shapes, "verdict2.py")))

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
        # NAMED, because the arm's default is two modules now and this fixture has one.
        _n_p, _free_p, _skip_p = unguarded.sweep_patterns(("oracle.py",))
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
          "K" in [f[1] for f in _free_p], str(_free_p))
    # ...AND A NAME IN A COMMENT IS NOT A READ. Selecting on text rather than on the tree
    # picks up prose, and `ALWAYS_PARTIAL` is named in two comments inside detectors --
    # nineteen detector names that would have been reported as untested rules.
    check("...and a list only named in prose is not swept as rules",
          not any(f[1] == "GHOSTS" for f in _free_p + _skip_p), str(_free_p + _skip_p))
    check("...and a compiled rule is not one it walks past",
          not any(f[1] == "N" for f in _free_p), str(_free_p))
    check("...and a list whose halves it cannot read is not called clean",
          [s[1] for s in _skip_p] == ["M"], str(_skip_p))
    check("...and that refusal carries its reason",
          all(s[3] for s in _skip_p), str(_skip_p))
    check("...and does not appear as a rule with no case",
          not any(f[1] == "M" for f in _free_p), str(_free_p))
    check("...and names the rules with no case, and only those",
          sorted(f[3] for f in _free_p) == ["'zzfree'", "'zzmerged'"], str(_free_p))
    check("...and every row names the module it came from",
          all(f[0] == "oracle.py" for f in _free_p + _skip_p), str(_free_p + _skip_p))

    # --- A MODULE THAT NEVER UNPACKS ITS PAIRS AT THE CALL SITE ------------------------
    #
    # Which half of an entry is the rule was read from the loop that binds the two names.
    # `refusal.py` binds neither: six lists are read as `_hits(out, _rules(DECLINE))`, and
    # `_rules` is `[p for p, _ in pairs]` one function away. With nothing to look at, every
    # list in that module came back `cannot tell which half is the rule` -- twenty-six
    # rules reported as unreadable rather than swept.
    #
    # Derived from the helper, not assumed to be the first half: the comprehension names
    # one of the targets it binds, and which one is the answer.
    _hw = tempfile.mkdtemp()
    _old_rt3 = unguarded.RT
    try:
        unguarded.RT = _hw
        io.open(os.path.join(_hw, "locks.py"), "w", encoding="utf-8", newline="").write(
            "import re" + chr(10)
            # (specimen, pattern): the way round that makes "the first half" the wrong guess.
            + "L = [('a zzcovered reply', 'zzcovered'),"
              " ('a zzfree reply', 'zzfree')]" + chr(10)
            + "def _rules(pairs):" + chr(10)
            + "    return [p for _s, p in pairs]" + chr(10)
            + "def named(text):" + chr(10)
            + "    return [p for p in _rules(L) if re.search(p, text)]" + chr(10))
        io.open(os.path.join(_hw, "test_locks.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import locks" + chr(10)
            + "assert locks.named('a zzcovered reply')" + chr(10)
            + "print('ok')" + chr(10))
        _n_h, _free_h, _skip_h = unguarded.sweep_patterns(("locks.py",))
    finally:
        unguarded.RT = _old_rt3
        _sh_p.rmtree(_hw, ignore_errors=True)
    check("the pattern arm reads a list whose pairs are unpacked by a helper",
          _n_h == 2, "%s  skipped=%s" % (_n_h, _skip_h))
    check("...and takes the half the helper keeps, not the first one",
          [f[3] for f in _free_h] == ["'zzfree'"], str(_free_h))
    check("...and claims nothing it could not read",
          _skip_h == [], str(_skip_h))

    # --- AN ENTRY THAT HOLDS A LIST OF RULES -------------------------------------------
    #
    # `CLASSES` in `refusal.py` is five `(class, rules)` entries and the rules are the
    # nested half, read as `_hits(out, [p for p, _ in rules])`. Neither name the loop
    # binds ever reaches a regex, so the arm could read no index, skipped all five, and
    # printed `5 more rule(s)` over THIRTY-TWO patterns -- a remainder named in entries
    # and counted in rules, which is this tool's own subject arrived at from the inside.
    #
    # Three things are being asked here, and the fixture is built so that each one can
    # be got wrong on its own:
    #
    #   * the nested pair is (specimen, pattern), so an arm that assumes the rule is the
    #     first half neutralises the specimen and reports the wrong name;
    #   * `class_names` reads `C` and reads no rule out of it, and it is written FIRST --
    #     which is exactly why the real one was skipped, since the arm derived the
    #     position from `pattern_classes` and never asked `classify`;
    #   * `D` is read by a loop that asks no regex question at all, so the arm still
    #     cannot read it -- and what it says about it has to be counted in rules.
    _nw = tempfile.mkdtemp()
    _old_rt4 = unguarded.RT
    try:
        unguarded.RT = _nw
        io.open(os.path.join(_nw, "locks.py"), "w", encoding="utf-8", newline="").write(
            "import re" + chr(10)
            + "C = [('one', [('a zzcovered specimen', 'zzcovered'),"
              " ('a zzfree specimen', 'zzfree')])]" + chr(10)
            + "D = [('two', [('alpha', 'x'), ('beta', 'y')])]" + chr(10)
            + "def class_names():" + chr(10)
            + "    return {c for c, _r in C}" + chr(10)
            # (patterns, text), the way round that punishes an arm taking argument
            # one because argument one is usually the rules.
            + "def _hits(patterns, text):" + chr(10)
            + "    return [p for p in patterns if re.search(p, text)]" + chr(10)
            + "def classify(text):" + chr(10)
            + "    for cls, rules in C:" + chr(10)
            + "        if _hits([p for _s, p in rules], text):" + chr(10)
            + "            return cls" + chr(10)
            + "    for cls, rules in D:" + chr(10)
            + "        if any(a in text for a, _b in rules):" + chr(10)
            + "            return cls" + chr(10)
            + "    return 'none'" + chr(10))
        io.open(os.path.join(_nw, "test_locks.py"), "w", encoding="utf-8",
                newline="").write(
            "import sys, os" + chr(10)
            + "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" + chr(10)
            + "import locks" + chr(10)
            + "assert locks.classify('a zzcovered reply') == 'one'" + chr(10)
            + "assert locks.classify('a quiet reply') == 'none'" + chr(10)
            + "assert locks.class_names() == {'one'}" + chr(10)
            + "print('ok')" + chr(10))
        _n_n, _free_n, _skip_n = unguarded.sweep_patterns(("locks.py",))
    finally:
        unguarded.RT = _old_rt4
        _sh_p.rmtree(_nw, ignore_errors=True)
    check("a rule nested inside an entry is swept, not skipped",
          _n_n == 2, "%d tested, skipped %s" % (_n_n, _skip_n))
    # AND THE HALF THE COMPREHENSION KEEPS, which here is the second one: taking the
    # first would neutralise `'a zzfree specimen'` and name a specimen as an untested
    # rule, a finding about nothing.
    check("...and it is the half the comprehension keeps, not the first one",
          [f[3] for f in _free_n] == ["'zzfree'"], str(_free_n))
    # AND THE READER IT ASKS IS THE ONE THAT READS THEM AS RULES. `class_names` comes
    # first in the file and reads no pattern out of `C`; the arm that took the first
    # function mentioning a list derived from it and skipped the list.
    check("...and the reader it asks is the one that reads them as rules",
          [f[2] for f in _free_n] == ["classify"], str(_free_n))
    # AND THE ONE IT STILL CANNOT READ IS COUNTED IN RULES. `len(skipped)` is what the
    # summary prints as `N more rule(s)`, and one entry there is two patterns.
    check("...while a nested list it cannot read is counted in rules, not entries",
          len([s for s in _skip_n if s[1] == "D"]) == 2,
          str([s for s in _skip_n if s[1] == "D"]))
    check("...and the readable one is not among them",
          not any(s[1] == "C" for s in _skip_n), str(_skip_n))

    # AND IT IS REACHABLE FROM THE COMMAND.
    _tool_src2 = io.open(_tool, encoding="utf-8").read()
    check("the pattern arm has a flag of its own",
          "--patterns" in _tool_src2, "no --patterns flag")

    # ------------------------------------------------------------------------------
    # THE NOTE A KILLED RUN LEAVES, AND WHO READS IT.
    #
    # `write_mutant` writes a note before it writes the mutant, so that a run killed in
    # the gap can be undone -- and for as long as that note existed, ONE program opened
    # it: the next run of this same tool. Nobody starts it twice in a row; it takes
    # minutes. What runs next is `tools/check.py` and `tools/guard.py`, and a killed
    # sweep left a tree that both of them called clean. Measured, not reasoned about: a
    # documented guard deleted out of `oracle.py` with the note live, and
    # `guard.py --tree` printed `ok  guard: the tree`.
    #
    # And the deletion nothing else catches is the likeliest one to be sitting there --
    # the whole point of this sweep is the guards no suite can see, so `check.py` being
    # green over it is the designed behaviour of `check.py`, not a gap in it.
    _kw = tempfile.mkdtemp()
    # ITS OWN NOTE, NOT THE CHECKOUT'S. Writing the real one would mean `tools/check.py`
    # destroying the recovery record of a sweep somebody killed an hour earlier.
    # THE CHECKOUT'S NOTE IS THE ONE THIS SUITE MUST NEVER RESOLVE TO, and it is computed
    # by asking what `_note_path` would answer with the override taken away -- because
    # `main` now sets that override once, for the whole file, rather than each block
    # setting and popping its own. A block that popped it left every later arm writing the
    # real note again, which is how this suite went on destroying the record of a live
    # sweep after four narrower fixes.
    _saved_note = os.environ.pop("QATRATION_UNGUARDED_NOTE", None)
    _real_note = unguarded._note_path()
    if _saved_note is not None:
        os.environ["QATRATION_UNGUARDED_NOTE"] = _saved_note
    _note = unguarded._note_path()
    _gate = [sys.executable, os.path.join(ROOT, "tools", "guard.py"), "--tree"]

    def _guard_says():
        _p = _sp_k.run(_gate, capture_output=True, text=True, cwd=ROOT,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                PYTHONIOENCODING="utf-8"))
        return _p.returncode, ((_p.stdout or "") + (_p.stderr or ""))

    try:
        check("a suite gets a note of its own, away from this checkout's",
              _note != _real_note, "%s == %s" % (_note, _real_note))
        check("...and the checkout's own note is what it would answer without the override",
              _real_note.startswith(tempfile.gettempdir())
              and "unguarded-recovery-" in _real_note, _real_note)
        _victim = os.path.join(_kw, "subject.py")
        _orig_v = "def f():" + chr(10) + "    return 1" + chr(10)
        io.open(_victim, "w", encoding="utf-8", newline="").write(_orig_v)

        check("with no note at all, nothing is live",
              unguarded.live_mutation() is None, str(unguarded.live_mutation()))
        _rc0, _out0 = _guard_says()
        check("...and the gate that runs before every commit is happy",
              _rc0 == 0, "rc=%s %s" % (_rc0, _out0[-90:]))

        unguarded.write_mutant(_victim, "MUTANT" + chr(10), _orig_v)
        check("a killed run leaves the mutant on disk",
              io.open(_victim, encoding="utf-8").read() == "MUTANT" + chr(10),
              repr(io.open(_victim, encoding="utf-8").read()))
        _live = unguarded.live_mutation()
        check("...and the note says which file and what was in it",
              _live == (_victim, _orig_v), str(_live))
        # THE ONE THAT MATTERS. Before this, the answer here was `rc=0  ok  guard: the
        # tree`, with a deleted decision on disk.
        _rc1, _out1 = _guard_says()
        check("...and the pre-commit gate now refuses instead of saying ok",
              _rc1 == 1, "rc=%s %s" % (_rc1, _out1[-120:]))
        check("...naming the file it will not commit around",
              "subject.py" in _out1, _out1[-160:])
        check("...and naming a fix that does not throw away uncommitted work",
              "--recover" in _out1 and "git checkout" in _out1, _out1[-200:])

        # A STALE NOTE IS NOT A LIVE ONE. The file was rewritten since -- by hand, by a
        # branch switch, by the person who noticed -- and a gate that keeps refusing over
        # a file that no longer holds the mutant is a worse version of this defect.
        io.open(_victim, "w", encoding="utf-8", newline="").write(_orig_v)
        check("a note whose file no longer holds the mutant is not live",
              unguarded.live_mutation() is None, str(unguarded.live_mutation()))
        _rc2, _out2 = _guard_says()
        check("...so the gate does not refuse forever over a note nobody can find",
              _rc2 == 0, "rc=%s %s" % (_rc2, _out2[-90:]))

        # A NOTE THAT PARSES IS NOT YET A NOTE. It is written by a process that was
        # killed once already.
        for _junk, _what in ((["a", "b"], "a list"), ('"hello"', "a string"),
                             ('{"path": 7}', "a path that is not a path"),
                             ('{"path": ["a"]}', "a path that is a list"),
                             ('{"path": "%s"}' % _victim.replace(chr(92), chr(92) * 2),
                              "no mutant and no original"),
                             ("{not json", "not JSON at all")):
            io.open(_note, "w", encoding="utf-8", newline="").write(
                _junk if isinstance(_junk, str) else _json_k.dumps(_junk))
            check("a note holding %s is not read as a live mutation" % _what,
                  unguarded.live_mutation() is None, str(unguarded.live_mutation()))

        # AND THE FLAG THE REFUSAL NAMES EXISTS AND WORKS.
        io.open(_victim, "w", encoding="utf-8", newline="").write(_orig_v)
        unguarded.write_mutant(_victim, "MUTANT" + chr(10), _orig_v)
        _rec_out, _rec_ran_on = "", False
        try:
            _p_rec = _sp_k.run([sys.executable, _tool, "--recover"], capture_output=True,
                               text=True, timeout=120, cwd=ROOT,
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                        PYTHONIOENCODING="utf-8"))
            _rec_out = _p_rec.stdout or ""
        except _sp_k.TimeoutExpired:
            _rec_ran_on = True
        check("`--recover` puts the file back",
              io.open(_victim, encoding="utf-8").read() == _orig_v,
              repr(io.open(_victim, encoding="utf-8").read()))
        check("...and says which file it touched, rather than repairing in silence",
              "subject.py" in _rec_out, _rec_out[-120:])
        check("...and stops there rather than starting a sweep of minutes",
              not _rec_ran_on and "documented guards" not in _rec_out,
              "still running after 120s" if _rec_ran_on else _rec_out[:120])
        check("...and clears the note, so the next commit is not refused",
              unguarded.live_mutation() is None and not os.path.exists(_note),
              str(unguarded.live_mutation()))
        _rc3, _out3 = _guard_says()
        check("...which the gate agrees with",
              _rc3 == 0, "rc=%s %s" % (_rc3, _out3[-90:]))
    finally:
        _sh_k.rmtree(_kw, ignore_errors=True)

    # AND EVERY OTHER SUITE THAT TOUCHES THE MECHANISM, asked of the tree rather than
    # remembered. The rule is not "test_unguarded is careful"; it is that no suite may
    # write the note of the checkout it runs in, and the next suite to reach for
    # `write_mutant` will not have read this comment.
    # EVERY WAY A SUITE CAN REACH THE NOTE, in one place: a direct call, a sweep entry
    # point that ends in one, or a launch of the tool whose `main` opens with `recover()`.
    _CALLS = ("write_mutant(", "clear_mutant(", "_drop_note(", "source_restored(",
              "_run_tool(", "sweep_in(", "sweep_guards(", "sweep_rules(")

    def _scan_for_careless(_where):
        """-> (suites that touch the note, the ones that touch it unprotected).

        A FUNCTION SO THE GATE CAN BE MADE TO FAIL. Written inline, it scanned the real
        directory and nothing else -- and with the tree clean there is nothing for it to
        catch, so disarming it entirely changed no answer. A gate nobody has watched fail
        is a gate nobody has tested, and this one guards a mechanism whose failure costs a
        mutant that cannot be recovered.
        """
        _touchers, _careless = [], []
        for _f in sorted(os.listdir(_where)):
            if not _f.startswith("test_") or not _f.endswith(".py"):
                continue
            _src_n = io.open(os.path.join(_where, _f), encoding="utf-8").read()
            # RUNNING THE TOOL COUNTS. A suite that never names one of those functions can
            # still destroy the note by launching `tools/unguarded.py`, whose `main` opens with
            # `recover()`. That is how this file went on tearing up the checkout's note after
            # every direct call had been put inside an override.
            # A PATH TO THE TOOL, not a mention of its name. Twenty-seven files here name
            # `unguarded.py` in prose or in a directory scan and touch nothing; two BUILD a
            # path to it and run it, and those two are the ones whose children call `recover`.
            _launches = [_l for _l in _src_n.split(chr(10))
                         if "unguarded.py" in _l and ("join(" in _l or "sys.executable" in _l)]
            # ONE SET FOR BOTH QUESTIONS. "does this file touch the note" and "where does
            # it first touch it" were asked of two different lists, so a suite whose only
            # contact is `sweep_in` was not a toucher at all and skipped the rule entirely.
            # Found by the planted fixtures below, which is what they are for.
            if not (_launches or any(_w in _src_n for _w in _CALLS)):
                continue
            _touchers.append(_f)
            # BY LINE ORDER, NOT BY PRESENCE. This asked whether the file MENTIONS the override
            # anywhere, which is a file-level answer to a block-level question -- and this very
            # file passed it while calling `_drop_note` six hundred lines above the line that
            # sets the override. The gate could not see the block it was written for.
            #
            # What has to hold is that the override is set BEFORE the first call that can reach
            # the note, so every such call runs inside it.
            # THE FIRST CALL THAT CAN REACH THE NOTE, by LINE, and a definition is not a call.
            # Four narrower versions of this rule were wrong in four different ways and each is
            # worth naming, because the next reader will reach for the same shortcuts:
            #
            #   * "does the file mention the override" -- a file-level answer to a block-level
            #     question, which this very file passed while dropping the note six hundred
            #     lines above the line that set one.
            #   * "does the file name unguarded.py" -- twenty-seven files do, in prose and in
            #     directory scans, and touch nothing.
            #   * "where does the path to the tool get built" -- building a path does nothing;
            #     what matters is the call.
            #   * substring search for `sweep_in(` -- which matches `def sweep_in(`, so a file
            #     was careless for DEFINING the function it also guards.
            #
            # So: the first LINE that is not a definition and not a comment and calls one of
            # the entry points, against the first line that puts the override anywhere -- in
            # this process or in a child's environment, both of which count.

            # FROM `main` ONWARD, because a call inside a helper DEFINED above `main` runs when
            # `main` calls it, not where it is written. Line order is a statement about time
            # only inside the body that executes top to bottom, and that body is `main`.
            _body_n = _src_n[_src_n.index("def main():"):] if "def main():" in _src_n else _src_n
            _lines_n = _body_n.split(chr(10))
            _first_touch = next(
                (_i for _i, _l in enumerate(_lines_n)
                 if not _l.lstrip().startswith(("#", "def ", "from ", "import "))
                 and any(_w in _l for _w in _CALLS)), None)
            _set_at = next((_i for _i, _l in enumerate(_lines_n)
                            if "QATRATION_UNGUARDED_NOTE" in _l
                            and not _l.lstrip().startswith("#")), None)
            if _set_at is None or (_first_touch is not None and _set_at > _first_touch):
                _careless.append(_f)
        return _touchers, _careless

    _touchers, _careless = _scan_for_careless(HERE)
    check("the suites that write a mutation note were found at all",
          len(_touchers) >= 2, str(_touchers))
    check("...and not one of them writes the note belonging to this checkout",
          _careless == [], str(_careless))
    # AND THE GATE HAS BEEN WATCHED FAILING, over suites written to fail it. With the tree
    # clean there is nothing here for it to catch, so `if False` in its place changed no
    # answer -- a gate nobody has seen fail is a gate nobody has tested, and this one
    # guards the mechanism whose failure costs a mutant that cannot be recovered.
    _fake = tempfile.mkdtemp(prefix="careless-suites-")
    try:
        _CARELESS_SRC = (
            "def main():" + chr(10)
            + "    unguarded.sweep_in(X)" + chr(10)
            + '    os.environ["QATRATION_UNGUARDED_NOTE"] = "too late"' + chr(10))
        _CAREFUL_SRC = (
            "def main():" + chr(10)
            + '    os.environ["QATRATION_UNGUARDED_NOTE"] = "first"' + chr(10)
            + "    unguarded.sweep_in(X)" + chr(10))
        # A BARE SUBPROCESS, not the helper: a suite that spells the launch out itself
        # names none of the functions in `_CALLS`, so the path scan is the only thing that
        # can see it. Written with `_run_tool(` this fixture proved nothing about that.
        _LAUNCHER_SRC = (
            "def main():" + chr(10)
            + '    _tool = os.path.join(ROOT, "tools", "unguarded.py")' + chr(10)
            + "    subprocess.run([sys.executable, _tool])" + chr(10))
        _INNOCENT_SRC = (
            "# this one only mentions unguarded.py in a sentence" + chr(10)
            + "def main():" + chr(10)
            + "    return 0" + chr(10))
        for _name, _src_f in (("test_careless.py", _CARELESS_SRC),
                              ("test_careful.py", _CAREFUL_SRC),
                              ("test_launcher.py", _LAUNCHER_SRC),
                              ("test_innocent.py", _INNOCENT_SRC)):
            io.open(os.path.join(_fake, _name), "w", encoding="utf-8",
                    newline="").write(_src_f)
        _t_f, _c_f = _scan_for_careless(_fake)
        check("a suite that sweeps before taking its own note is named",
              "test_careless.py" in _c_f, str(_c_f))
        check("...and one that takes it first is not",
              "test_careful.py" not in _c_f, str(_c_f))
        check("...and one that launches the tool with no note at all is named",
              "test_launcher.py" in _c_f, str(_c_f))
        check("...while a suite that only mentions the tool is not even a toucher",
              "test_innocent.py" not in _t_f, str(_t_f))
        check("...and the three that do touch it were all found",
              sorted(_t_f) == ["test_careful.py", "test_careless.py",
                               "test_launcher.py"], str(_t_f))
    finally:
        _sh_k.rmtree(_fake, ignore_errors=True)
    # AND THE GATE CAN SEE A BLOCK THAT RUNS OUTSIDE THE OVERRIDE, which the version that
    # asked only whether the file mentions it could not. Planted, because a gate nobody has
    # watched fail is a gate nobody has tested.
    _planted = ("import os\n"
                "unguarded.write_mutant(f, 'm', 'o')\n"
                'os.environ["QATRATION_UNGUARDED_NOTE"] = "later"\n')
    _first_p = min((_planted.index(_w) for _w in
                    ("write_mutant(", "clear_mutant(", "_drop_note(", "source_restored(")
                    if _w in _planted), default=None)
    _set_p = _planted.index('os.environ["QATRATION_UNGUARDED_NOTE"]')
    check("a suite that sets the override AFTER its first note call is careless",
          _set_p > _first_p, "%r vs %r" % (_set_p, _first_p))
    _ordered = ('os.environ["QATRATION_UNGUARDED_NOTE"] = "first"\n'
                "unguarded.write_mutant(f, 'm', 'o')\n")
    check("...while one that sets it first is not",
          _ordered.index('os.environ["QATRATION_UNGUARDED_NOTE"]')
          < _ordered.index("write_mutant("), _ordered)
    if FAIL:
        return 1
    print("\nOK — the instrument that names untested guards is not one of them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
