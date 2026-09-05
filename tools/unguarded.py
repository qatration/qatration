# -*- coding: utf-8 -*-
"""Which decisions in this engine can be deleted without a single suite noticing?

Mutation asks whether a check can fail. This asks the reverse, and it is the question that
found most of the defects of 2026-09-04: **a rule nothing keeps**. Delete it, run the suites
that could see it, and read the exit code. Three sweeps, because a decision hides in three
shapes -- and the third carries the filter that makes any of this readable:

  * A DOCUMENTED GUARD -- `if <cond>: return/raise/sys.exit` with a comment above it. The
    comment means somebody paid for that branch once, usually by shipping the defect it now
    prevents. `isolation._status`'s third door into HARDENED could be removed with all
    forty-eight suites green; so could `sarif`'s config lookup and `run_generate`'s refusal.

  * A RULE INSIDE A DETECTOR -- every `return True` in a `d_*` function is an independent way
    for that detector to fire. A detector with two rules and one fixture that trips both has a
    rule nothing keeps: `command_injection`'s baseline branch was deleted in silence because
    every positive fixture also carried a shell metacharacter, and `exfil_via_url` had three
    rules and one input that satisfied all of them.

  * A GUARD AGAINST A FALSE POSITIVE -- every early `return False` in a `d_*` function is a
    reason NOT to call something a finding: echo subtraction, an unarmed config, the caller's
    own id, a value the user supplied rather than the target. Delete one and a false positive
    should appear. `verbatim_replay` was calling the user's own quoted text a replay by the
    target, and `sysprompt_paraphrase`'s length floor was the only thing between a two-word
    reply and a leak verdict; neither had a fixture.

AND THE THIRD SWEEP FILTERS ITSELF, which is the part worth stealing. Forty-nine such guards,
thirty-two removable with `test_oracle` green -- a list nobody reads, because most are
empty-input exits whose removal changes nothing (the code below them returns False anyway).
Replay the stored probes in `out/` with each guard removed and the list sorts itself: thirty
moved no verdict across 6,882 probes, two moved one. A sweep is only as useful as the number
it reports, and evidence is what takes that number from thirty-two to two. Where `out/` holds
nothing, the sweep says so and reports the unfiltered list rather than pretending to have
filtered it.

NOT PART OF `tools/check.py`, deliberately. It rewrites source files and runs the suites
dozens of times over -- minutes rather than seconds -- and a check that edits the tree is not
something to have running on every push. Run it after a stretch of work, the way you would run
a profiler.

    python tools/unguarded.py            # all three sweeps
    python tools/unguarded.py --guards   # documented guards only
    python tools/unguarded.py --rules    # detector rules only
    python tools/unguarded.py --refusals # the guards that PREVENT a finding
    python tools/unguarded.py --guards --only oracle.py refusal.py    # just what changed

Every mutation is reverted immediately after its run, and the tree is verified green at the
end. `PYTHONDONTWRITEBYTECODE=1` is set for every child: a same-length edit written in the
same second is invisible to Python's bytecode cache, which has produced a mutation reported
against the wrong check before now.
"""
import argparse
import ast
import contextlib
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RT = os.path.join(os.path.dirname(HERE), "redteam")


@contextlib.contextmanager
def source_restored(path):
    """Hold a file's original text and put it back, whatever happens in between.

    THE ONE FAILURE THIS TOOL CAN CAUSE. Every sweep here writes a mutant over a real source
    file and writes the original back a few lines later, and each of those pairs was a bare
    sequence: interrupt it in the gap -- Ctrl-C, a killed background job, a suite that hangs
    past a deadline someone else is enforcing -- and the mutant is what stays on disk. A tool
    that reports which decisions nobody would miss should not be able to leave a deleted
    decision behind and say nothing.

    Found by killing a run of this file and then checking `git status` out of habit. It was
    clean, which was luck about where the signal landed rather than a property of the code.
    """
    orig = io.open(path, encoding="utf-8").read()
    try:
        yield orig
    finally:
        if io.open(path, encoding="utf-8").read() != orig:
            io.open(path, "w", encoding="utf-8", newline="").write(orig)

GUARD = re.compile(r"^(\s+)if\s+.+:\s*$")
BODY = re.compile(r"^\s+(return\b.*|raise\b.*|sys\.exit\(.*\))\s*$")


def _run(suite, timeout=420):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run([sys.executable, suite], cwd=RT, env=env, capture_output=True,
                           text=True, errors="replace", timeout=timeout)
        return p.returncode
    except subprocess.TimeoutExpired:
        return 99


def _suites_touching(mod):
    """Every suite whose source imports this module -- derived, so a new suite joins itself."""
    stem = mod[:-3]
    pat = re.compile(r"^\s*(?:import\s+%s\b|from\s+%s\s+import)" % (stem, stem), re.M)
    return [t for t in sorted(os.listdir(RT))
            if t.startswith("test_") and t.endswith(".py")
            and pat.search(io.open(os.path.join(RT, t), encoding="utf-8").read())]


def sweep_guards(only=()):
    """Delete each documented single-statement guard; report the ones nothing missed.

    `only` narrows it to named modules, which is the difference between an instrument that
    gets run and one that does not. Package-wide this deletes several hundred guards and runs
    every importing suite for each, which is hours: it was started twice today and killed
    twice, having reported on one module. Pointed at the three files a change touched it is
    minutes, and that is the version somebody runs before pushing.
    """
    survivors, tested = [], 0
    mods = sorted(f for f in os.listdir(RT)
                  if f.endswith(".py") and not f.startswith("test_"))
    if only:
        want = {m if m.endswith(".py") else m + ".py" for m in only}
        missing = sorted(want - set(mods))
        if missing:
            # A NAME THAT MATCHES NOTHING WOULD SWEEP NOTHING AND SAY IT WAS CLEAN, which is
            # this tool's own subject.
            raise SystemExit("unguarded: no such module in %s: %s"
                             % (RT, ", ".join(missing)))
        mods = [m for m in mods if m in want]
    for mod in mods:
        path = os.path.join(RT, mod)
        orig = io.open(path, encoding="utf-8").read()
        lines = orig.split("\n")
        hits = []
        for i, line in enumerate(lines[:-1]):
            g = GUARD.match(line)
            if not g or not BODY.match(lines[i + 1]):
                continue
            if len(lines[i + 1]) - len(lines[i + 1].lstrip()) <= len(g.group(1)):
                continue
            if i and lines[i - 1].strip().startswith("#"):
                hits.append(i)
        if not hits:
            continue
        suites = _suites_touching(mod)
        if not suites:
            print("%-24s %d guard(s), NO SUITE IMPORTS IT" % (mod, len(hits)))
            survivors += [(mod, i + 1, lines[i].strip(), "(nothing imports it)") for i in hits]
            continue
        if any(_run(s) for s in suites):
            print("%-24s SKIPPED (its suites are not green to begin with)" % mod)
            continue
        caught = 0
        with source_restored(path):
            for i in hits:
                tested += 1
                io.open(path, "w", encoding="utf-8", newline="").write(
                    "\n".join(lines[:i] + lines[i + 2:]))
                red = any(_run(s) for s in suites)
                io.open(path, "w", encoding="utf-8", newline="").write(orig)
                if red:
                    caught += 1
                else:
                    survivors.append((mod, i + 1, lines[i].strip(), ",".join(suites)))
        assert not any(_run(s) for s in suites), "%s was not restored" % mod
        print("%-24s %d/%-2d defended   (%s)" % (mod, caught, len(hits), ",".join(suites)))
    return tested, survivors


def sweep_rules():
    """Neutralise each `return True` in a multi-rule detector; report the free ones."""
    path = os.path.join(RT, "oracle.py")
    orig = io.open(path, encoding="utf-8").read()
    sites = []
    for node in ast.walk(ast.parse(orig)):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("d_"):
            rets = [c for c in ast.walk(node)
                    if isinstance(c, ast.Return) and isinstance(c.value, ast.Constant)
                    and c.value.value is True]
            if len(rets) > 1:
                sites += [(node.name, r.lineno) for r in rets]
    assert _run("test_oracle.py") == 0, "test_oracle is not green to begin with"
    lines = orig.split("\n")
    free = []
    with source_restored(path):
        for name, lineno in sites:
            idx = lineno - 1
            stmt = lines[idx]
            mutant = list(lines)
            mutant[idx] = " " * (len(stmt) - len(stmt.lstrip())) + "pass"
            io.open(path, "w", encoding="utf-8", newline="").write("\n".join(mutant))
            red = _run("test_oracle.py")
            io.open(path, "w", encoding="utf-8", newline="").write(orig)
            print("  %-28s line %-5d %s"
                  % (name, lineno, "kept" if red else "NO CASE OF ITS OWN"))
            if not red:
                free.append((name, lineno, stmt.strip()))
    assert _run("test_oracle.py") == 0, "oracle.py was not restored"
    return len(sites), free


_REPLAY = r"""
import sys, os, json
sys.path.insert(0, %r)
os.environ.setdefault("QATRATION_OUT", %r)
import detector_coverage as dc
hits, where, n, broke, sources = dc.replay()
print(json.dumps({"n": n, "hits": dict(hits), "broke": dict(broke)}))
"""


def _replay():
    """Every stored probe through every detector -> {detector: fires}. None if it raised."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    code = _REPLAY % (RT, os.path.join(os.path.dirname(RT), "out"))
    p = subprocess.run([sys.executable, "-c", code], cwd=RT, env=env,
                       capture_output=True, text=True, errors="replace", timeout=900)
    if p.returncode:
        return None
    import json as _json
    return _json.loads(p.stdout.strip().split("\n")[-1])


def sweep_refusals():
    """Neutralise each early `return False` in a detector; report the ones that matter.

    THE MIRROR OF `sweep_rules`. Every early `return False` is a reason NOT to call something
    a finding -- echo subtraction, an unarmed config, the caller's own id, a value the user
    supplied -- and deleting one should produce a false positive somewhere.

    AND ITS OWN NOISE FILTER, which is why this sweep is worth running at all. Forty-nine
    such guards, thirty-two of which can be removed with `test_oracle` green; that number
    alone is a list nobody reads, because most are empty-input exits whose removal changes
    nothing (the code after them returns False anyway). Replaying the stored evidence with
    each one removed separates them: thirty changed no verdict across 6,882 probes, and two
    moved one -- `verbatim_replay` 42 fires to 44, `sysprompt_paraphrase` 9 to 11. Those two
    were rules doing real work with no fixture behind them.

    Needs `out/` to hold evidence. With an empty workspace it reports every survivor, which
    is the unfiltered list and is said rather than silently skipped.
    """
    path = os.path.join(RT, "oracle.py")
    orig = io.open(path, encoding="utf-8").read()
    sites = []
    for node in ast.walk(ast.parse(orig)):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("d_"):
            last = node.body[-1]
            for c in ast.walk(node):
                if (isinstance(c, ast.Return) and isinstance(c.value, ast.Constant)
                        and c.value.value is False and c is not last):
                    sites.append((node.name, c.lineno))
    assert _run("test_oracle.py") == 0, "test_oracle is not green to begin with"
    base = _replay()
    if base is None or not base.get("n"):
        print("  ! no stored evidence in out/, so every survivor below is unfiltered")
    lines = orig.split("\n")
    moved = []
    with source_restored(path):
        for name, lineno in sites:
            idx = lineno - 1
            stmt = lines[idx]
            mutant = list(lines)
            mutant[idx] = " " * (len(stmt) - len(stmt.lstrip())) + "pass"
            io.open(path, "w", encoding="utf-8", newline="").write("\n".join(mutant))
            red = _run("test_oracle.py")
            got = None if red else _replay()
            io.open(path, "w", encoding="utf-8", newline="").write(orig)
            if red:
                continue
            if base is None or got is None:
                moved.append((name, lineno, "the replay could not answer"))
                continue
            diff = {k: (base["hits"].get(k, 0), got["hits"].get(k, 0))
                    for k in set(base["hits"]) | set(got["hits"])
                    if base["hits"].get(k, 0) != got["hits"].get(k, 0)}
            if diff:
                moved.append((name, lineno, "; ".join(
                    "%s %d->%d" % (k, a, b) for k, (a, b) in sorted(diff.items()))))
    assert _run("test_oracle.py") == 0, "oracle.py was not restored"
    return len(sites), moved


def main(argv):
    ap = argparse.ArgumentParser(prog="unguarded",
                                 description="decisions no suite would miss")
    ap.add_argument("--guards", action="store_true", help="documented guards only")
    ap.add_argument("--rules", action="store_true", help="detector rules only")
    ap.add_argument("--refusals", action="store_true",
                    help="guards against false positives only (needs evidence in out/)")
    ap.add_argument("--only", metavar="MODULE", nargs="+", default=(),
                    help="restrict the documented-guard sweep to these modules")
    args = ap.parse_args(argv)
    both = not (args.guards or args.rules or args.refusals)
    bad = 0
    if both or args.guards:
        print("=== documented guards ===")
        tested, survivors = sweep_guards(args.only)
        print("\n%d documented guard(s) tested, %d survived deletion" % (tested, len(survivors)))
        for mod, ln, src, who in survivors:
            print("  %s:%d  %s   [%s]" % (mod, ln, src[:70], who))
        bad += len(survivors)
    if both or args.rules:
        print("\n=== rules inside multi-rule detectors ===")
        n, free = sweep_rules()
        print("\n%d rule site(s) tested, %d with no case of their own" % (n, len(free)))
        for name, ln, src in free:
            print("  oracle.py:%d  %s  %s" % (ln, name, src[:60]))
        bad += len(free)
    if both or args.refusals:
        print("\n=== guards against false positives ===")
        n, moved = sweep_refusals()
        print("\n%d early refusal(s) tested, %d move a verdict on the stored evidence"
              % (n, len(moved)))
        for name, ln, what in moved:
            print("  oracle.py:%-6d %-26s %s" % (ln, name, what[:80]))
        bad += len(moved)

    # NOT AN EXIT CODE THAT FAILS A BUILD. Some survivors are equivalent mutations -- a guard
    # whose fallback reaches the same answer, an input bound whose effect is time rather than
    # a verdict -- and this tool cannot tell those from a real gap. It reports; a person reads.
    print("\n%d decision(s) to look at." % bad if bad else "\nEvery decision here is kept.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
