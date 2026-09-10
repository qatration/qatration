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

    print("\n%d/%d passed" % (PASS, PASS + FAIL))
    if FAIL:
        return 1
    print("\nOK — the instrument that names untested guards is not one of them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
