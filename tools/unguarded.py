# -*- coding: utf-8 -*-
"""Which decisions in this engine can be deleted without a single suite noticing?

Mutation asks whether a check can fail. This asks the reverse, and it is the question that
found most of the defects of 2026-09-04: **a rule nothing keeps**. Delete it, run the suites
that could see it, and read the exit code. Two sweeps, because a decision hides in two shapes:

  * A DOCUMENTED GUARD -- `if <cond>: return/raise/sys.exit` with a comment above it. The
    comment means somebody paid for that branch once, usually by shipping the defect it now
    prevents. `isolation._status`'s third door into HARDENED could be removed with all
    forty-eight suites green; so could `sarif`'s config lookup and `run_generate`'s refusal.

  * A RULE INSIDE A DETECTOR -- every `return True` in a `d_*` function is an independent way
    for that detector to fire. A detector with two rules and one fixture that trips both has a
    rule nothing keeps: `command_injection`'s baseline branch was deleted in silence because
    every positive fixture also carried a shell metacharacter, and `exfil_via_url` had three
    rules and one input that satisfied all of them.

NOT PART OF `tools/check.py`, deliberately. It rewrites source files and runs the suites
dozens of times over -- minutes rather than seconds -- and a check that edits the tree is not
something to have running on every push. Run it after a stretch of work, the way you would run
a profiler.

    python tools/unguarded.py            # both sweeps
    python tools/unguarded.py --guards   # documented guards only
    python tools/unguarded.py --rules    # detector rules only

Every mutation is reverted immediately after its run, and the tree is verified green at the
end. `PYTHONDONTWRITEBYTECODE=1` is set for every child: a same-length edit written in the
same second is invisible to Python's bytecode cache, which has produced a mutation reported
against the wrong check before now.
"""
import argparse
import ast
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RT = os.path.join(os.path.dirname(HERE), "redteam")

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


def sweep_guards():
    """Delete each documented single-statement guard; report the ones nothing missed."""
    survivors, tested = [], 0
    for mod in sorted(f for f in os.listdir(RT)
                      if f.endswith(".py") and not f.startswith("test_")):
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
    for name, lineno in sites:
        idx = lineno - 1
        stmt = lines[idx]
        mutant = list(lines)
        mutant[idx] = " " * (len(stmt) - len(stmt.lstrip())) + "pass"
        io.open(path, "w", encoding="utf-8", newline="").write("\n".join(mutant))
        red = _run("test_oracle.py")
        io.open(path, "w", encoding="utf-8", newline="").write(orig)
        print("  %-28s line %-5d %s" % (name, lineno, "kept" if red else "NO CASE OF ITS OWN"))
        if not red:
            free.append((name, lineno, stmt.strip()))
    assert _run("test_oracle.py") == 0, "oracle.py was not restored"
    return len(sites), free


def main(argv):
    ap = argparse.ArgumentParser(prog="unguarded",
                                 description="decisions no suite would miss")
    ap.add_argument("--guards", action="store_true", help="documented guards only")
    ap.add_argument("--rules", action="store_true", help="detector rules only")
    args = ap.parse_args(argv)
    both = not (args.guards or args.rules)
    bad = 0
    if both or args.guards:
        print("=== documented guards ===")
        tested, survivors = sweep_guards()
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
    # NOT AN EXIT CODE THAT FAILS A BUILD. Some survivors are equivalent mutations -- a guard
    # whose fallback reaches the same answer, an input bound whose effect is time rather than
    # a verdict -- and this tool cannot tell those from a real gap. It reports; a person reads.
    print("\n%d decision(s) to look at." % bad if bad else "\nEvery decision here is kept.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
