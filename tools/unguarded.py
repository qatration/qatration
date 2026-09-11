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
import fnmatch
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RT = os.path.join(os.path.dirname(HERE), "redteam")

# THE MODULES THAT DECIDE A VERDICT. `oracle.py` says what a finding is and `refusal.py`
# says what a wall is, and for most of this tool's life only the first was swept: the
# rules and refusals arms both asked for a shape that exists nowhere else, so every other
# file came back with no sites and no sentence saying so.
SWEPT_MODULES = ("oracle.py", "refusal.py")


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

    AND `finally` DOES NOT COVER A KILL, which this docstring used to claim it did. A
    `finally` block runs for an exception and for Ctrl-C; the process being killed —
    a background job stopped, a runner reclaiming a machine — skips it entirely.
    Killing a background run of this file left `isolation._status`'s zero-trials guard
    deleted in the working tree, silently, which is the one failure this tool must not
    be able to cause. `write_mutant` leaves a note for the next run to read.
    """
    orig = io.open(path, encoding="utf-8").read()
    try:
        yield orig
    finally:
        if io.open(path, encoding="utf-8").read() != orig:
            io.open(path, "w", encoding="utf-8", newline="").write(orig)
        _drop_note()


def _note_path():
    """Where the note lives: outside the tree, keyed to this checkout.

    Not inside the repository, because a file that appears there mid-sweep is one more
    thing for `guard.py`, the suites and `git status` to trip over — and this note
    exists precisely for the runs that never get to clean up after themselves.
    """
    key = hashlib.sha1(os.path.abspath(HERE).encode("utf-8")).hexdigest()[:12]
    return os.path.join(tempfile.gettempdir(), "unguarded-recovery-%s.json" % key)


def _drop_note():
    try:
        os.remove(_note_path())
    except OSError:
        pass


def write_mutant(path, mutant, orig):
    """Put a mutant on disk, having first written down how to undo it.

    The note records the MUTANT as well as the original, and `recover` puts a file back
    only while it still holds exactly that mutant. A note left by a run killed last
    week must not overwrite work somebody has done since, and a tool that restores from
    a stale note is a worse version of the problem it is fixing.
    """
    try:
        io.open(_note_path(), "w", encoding="utf-8").write(json.dumps(
            {"path": os.path.abspath(path), "mutant": mutant, "orig": orig}))
    except OSError:
        pass          # a note that cannot be written is not a reason to skip the sweep
    io.open(path, "w", encoding="utf-8", newline="").write(mutant)


def clear_mutant(path, orig):
    """Put the original back, then tear up the note. In that order."""
    io.open(path, "w", encoding="utf-8", newline="").write(orig)
    _drop_note()


def recover():
    """-> the file a killed run left mutated, put back, or None.

    Called before anything else is touched. Returns the path so the caller can SAY so:
    a tool that quietly repairs the tree teaches its user that the tree can be trusted
    without looking, which is the habit that found this in the first place.
    """
    p = _note_path()
    try:
        note = json.loads(io.open(p, encoding="utf-8").read())
    except (OSError, ValueError):
        return None
    restored = None
    try:
        now = io.open(note["path"], encoding="utf-8").read()
    except (OSError, KeyError):
        now = None
    if now is not None and now == note.get("mutant"):
        io.open(note["path"], "w", encoding="utf-8", newline="").write(note["orig"])
        restored = note["path"]
    _drop_note()
    return restored

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


def _dynamic_routes():
    """-> {glob pattern: the module that imports every file matching it}.

    DERIVED FROM THE ENGINE, not listed here. `workspace` globs `targets_*.py` and calls
    `import_module` on each name, so every suite that reaches `workspace` reaches all
    eleven practice adapters — and a suite map built on `import <name>` reports every
    one of them as `NO SUITE IMPORTS IT`. That is a false finding of exactly the shape
    this tool exists to report, and eleven of them would bury a real one.

    A pattern counts only when one function both globs it and calls `import_module`, so
    a glob that merely reads files is not mistaken for a route.
    """
    routes = {}
    for f in sorted(os.listdir(RT)):
        if not f.endswith(".py") or f.startswith("test_"):
            continue
        src = io.open(os.path.join(RT, f), encoding="utf-8").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for fn in [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            body = ast.get_source_segment(src, fn) or ""
            if "import_module(" not in body:
                continue
            for m in re.finditer(r'glob\(\s*[^)]*?["\']([^"\']*\*[^"\']*\.py)["\']',
                                 body):
                routes[m.group(1)] = f[:-3]
    return routes


def _suites_touching(mod):
    """Every suite that reaches this module, by import or by the engine's own glob.

    Derived, so a new suite joins itself. The second route is derived too: see
    `_dynamic_routes`. Without it this returns nothing for a practice adapter and the
    sweep reports one for every documented guard in it.
    """
    stem = mod[:-3]
    pat = re.compile(r"^\s*(?:import\s+%s\b|from\s+%s\s+import)" % (stem, stem), re.M)
    stems = {stem}
    for glob_pat, router in _dynamic_routes().items():
        if fnmatch.fnmatch(mod, glob_pat) and router != stem:
            stems.add(router)
    if len(stems) > 1:
        pat = re.compile("|".join(
            r"^\s*(?:import\s+%s\b|from\s+%s\s+import)" % (s, s)
            for s in sorted(stems)), re.M)
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
    survivors, tested, undocumented, held = [], 0, 0, []
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
            # A GUARD WITH NO COMMENT IS SKIPPED, and skipping it silently is this tool's
            # own subject. `workspace.py` has 21 branches of this shape and one of them
            # carries a comment, so the sweep tested one and the summary said `Every
            # decision here is kept`. Counted so the denominator reaches the reader.
            if not (i and lines[i - 1].strip().startswith("#")):
                undocumented += 1
                continue
            hits.append(i)
        if not hits:
            continue
        suites = _suites_touching(mod)
        if not suites:
            print("%-24s %d guard(s), NO SUITE IMPORTS IT" % (mod, len(hits)))
            survivors += [(mod, i + 1, lines[i].strip(), "(nothing imports it)") for i in hits]
            continue
        if any(_run(s) for s in suites):
            # AND CARRIED, not only printed. This line scrolled past and the summary below
            # closed with `Nothing this sweep deleted went unnoticed` -- a clean verdict over
            # a module nothing was deleted from. It happened: `test_fleet_limits` exited 1
            # one run in twelve from its own teardown, `runner.py` imports into it, and
            # twenty-nine documented guards went unswept behind that sentence.
            #
            # The same discipline the undocumented count already gets one screen down: what
            # was NOT looked at belongs in the summary, because a reader takes the closing
            # line for a verdict on what they asked about.
            print("%-24s SKIPPED (its suites are not green to begin with)" % mod)
            held.append((mod, len(hits)))
            continue
        caught = 0
        with source_restored(path):
            for i in hits:
                tested += 1
                write_mutant(path, "\n".join(lines[:i] + lines[i + 2:]), orig)
                red = any(_run(s) for s in suites)
                clear_mutant(path, orig)
                if red:
                    caught += 1
                else:
                    survivors.append((mod, i + 1, lines[i].strip(), ",".join(suites)))
        assert not any(_run(s) for s in suites), "%s was not restored" % mod
        print("%-24s %d/%-2d defended   (%s)" % (mod, caught, len(hits), ",".join(suites)))
    return tested, survivors, undocumented, held


def _or_branches(node):
    """-> the branches of `return a or b`, including through `bool(...)`.

    `refusal.declined` ends on `return bool(a or b or c)` and the first version of this
    asked only for a bare `BoolOp`, so the three rules that decide whether a reply is a
    refusal at all were not rules to it.
    """
    if not isinstance(node, ast.Return):
        return []
    v = node.value
    if (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "bool"
            and v.args):
        v = v.args[0]
    if isinstance(v, ast.BoolOp) and isinstance(v.op, ast.Or) and len(v.values) > 1:
        return list(v.values)
    return []


def _rule_sites(src, mod):
    """-> [(function, lineno, kind, node)] for the rules this module fires by.

    `return True` IS AN ORACLE SHAPE. It means one independent way for a DETECTOR to
    fire, and outside `oracle.py` nothing is written that way: `refusal.declined`
    answers with an or-chain and `classify` returns a dict. The branch arm is the half
    that generalises, so it is asked of every module and the statement arm only of the
    one where it means something.
    """
    sites = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.FunctionDef):
            continue
        if mod == "oracle.py":
            if not node.name.startswith("d_"):
                continue
            rets = [c for c in ast.walk(node)
                    if isinstance(c, ast.Return) and isinstance(c.value, ast.Constant)
                    and c.value.value is True]
            if len(rets) > 1:
                sites += [(node.name, r.lineno, "stmt", r) for r in rets]
        # `ast.walk` reaches the nested helpers too, which is where the missing four
        # were: a detector's junk test is a def inside the detector.
        for c in ast.walk(node):
            sites += [(node.name, v.lineno, "branch", v) for v in _or_branches(c)]
    return sites


def sweep_rules(modules=SWEPT_MODULES):
    """Neutralise each rule; report the ones nothing missed.

    TWO SHAPES, BECAUSE A RULE IS NOT ALWAYS A STATEMENT. `return True` inside a `d_`
    is one independent way for that detector to fire, and so is each branch of
    `return a or b or c`. This read only the first, and `_junk` inside
    `d_fabricated_citation` — four branches deciding whether a bracketed span counts
    as a citation at all — was invisible to every arm of this tool.

    THE TWO POINT IN OPPOSITE DIRECTIONS, and that is the right thing here. Deleting a
    `return True` makes a detector fire less; deleting a branch of a junk test makes it
    fire more. Both are a decision nothing in the suite would miss, which is the only
    question this file asks.

    AND TWO MODULES, for the reason the refusals arm has two: `refusal.declined` decides
    whether a reply counts as a refusal at all, on three ors, and one of the three had no
    case — the handoff rule its own comment says cost 108 misread replies before it was
    bounded. A tool that reads `oracle.py` and calls the answer a sweep is measuring one
    file and naming the engine.
    """
    total, free = 0, []
    for mod in modules:
        path = os.path.join(RT, mod)
        orig = io.open(path, encoding="utf-8").read()
        sites = _rule_sites(orig, mod)
        total += len(sites)
        suites = ["test_oracle.py"] if mod == "oracle.py" else _suites_touching(mod)
        if not suites:
            print("  ! nothing imports %s, so its silence here is not a result" % mod)
            continue
        for s in suites:
            assert _run(s) == 0, "%s is not green to begin with" % s
        with source_restored(path):
            for name, lineno, kind, node in sites:
                lines = orig.split("\n")
                if kind == "stmt":
                    stmt = lines[lineno - 1]
                    lines[lineno - 1] = " " * (len(stmt) - len(stmt.lstrip())) + "pass"
                else:
                    ln = node.lineno - 1
                    if node.lineno == node.end_lineno:
                        lines[ln] = (lines[ln][:node.col_offset] + "False"
                                     + lines[ln][node.end_col_offset:])
                    else:
                        head = lines[ln][:node.col_offset] + "False"
                        lines[ln:node.end_lineno] = [
                            head + lines[node.end_lineno - 1][node.end_col_offset:]]
                write_mutant(path, "\n".join(lines), orig)
                red = any(_run(s) for s in suites)
                clear_mutant(path, orig)
                shown = " ".join((ast.get_source_segment(orig, node) or "").split())
                print("  %-14s %-20s line %-5d %-18s %s"
                      % (mod, name, lineno, "kept" if red else "NO CASE OF ITS OWN",
                         shown[:36]))
                if not red:
                    free.append((mod, name, lineno, shown))
        for s in suites:
            assert _run(s) == 0, "%s was not restored" % mod
    return total, free


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


def _pattern_positions(tree, src, det, list_name):
    """-> (indices in a tuple entry the detector reads as regexes, why there are none).

    Derived from the loop that reads the list: `for pat, _what in _SECRET_AT_REST`
    binds two names and only one of them reaches a regex. Guessing which half is the
    rule reports the other half's prose as an uncovered rule, which is a finding about
    nothing, so an unreadable loop yields no index — and NAMES WHY, because the arm
    that skips in silence is the thing this tool exists to refuse.

    PLURAL, AND IT USED TO BE SINGULAR. `_INSECURE_CODE` binds (label, danger, safe)
    and the last two are both rules: one makes the finding and the other takes it
    back, so deleting either changes a verdict. Returning one index dropped five.

    AND A RULE NEED NOT REACH `re.search` AS AN ARGUMENT. A pre-compiled one is read
    as `danger.search(body)` — the same rule through a different surface, and those
    same five were invisible for that reason as well as the first.
    """
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == det), None)
    if fn is None:
        return (), "there is no %s to read" % det
    # THE LIST HANDED WHOLE TO A HELPER THAT UNPACKS IT. `_hits(out, _rules(DECLINE))`
    # binds nothing here, so the loop below has nothing to read; the helper says which
    # half it keeps and that is the same answer one call further out.
    unpack = _unpackers(tree)
    for call in ast.walk(fn):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id in unpack and call.args
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == list_name):
            return (unpack[call.func.id],), ""
    for node in ast.walk(fn):
        if not isinstance(node, (ast.For, ast.comprehension)):
            continue
        it = getattr(node, "iter", None)
        if not (isinstance(it, ast.Name) and it.id == list_name):
            continue
        target = getattr(node, "target", None)
        if not isinstance(target, (ast.Tuple, ast.List)):
            return (), "%s binds one name per entry" % det
        names = [e.id if isinstance(e, ast.Name) else None for e in target.elts]
        used_as_pattern = set()
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call):
                continue
            f = call.func
            if not isinstance(f, ast.Attribute) or f.attr not in _RE_METHODS:
                continue
            # `re.search(pat, text)` names the rule in the first argument;
            # `pat.search(text)` names it in the receiver. Both are the same read.
            if isinstance(f.value, ast.Name) and f.value.id == "re":
                if call.args and isinstance(call.args[0], ast.Name):
                    used_as_pattern.add(call.args[0].id)
            elif isinstance(f.value, ast.Name):
                used_as_pattern.add(f.value.id)
        found = tuple(i for i, nm in enumerate(names) if nm and nm in used_as_pattern)
        return found, "" if found else "no name %s binds reaches a regex" % det
    return (), "%s does not read %s in a loop" % (det, list_name)


# EVERY WAY A COMPILED OR LITERAL PATTERN GETS ASKED A QUESTION.
_RE_METHODS = ("search", "match", "fullmatch", "finditer", "findall", "sub", "split")


def _unpackers(tree):
    """-> {helper: which index of a pair it returns}.

    A THIRD WAY TO SAY WHICH HALF IS THE RULE. `refusal.py` does not unpack its pairs at
    the call site at all — six lists are read as `_hits(out, _rules(DECLINE))`, and
    `_rules` is `[p for p, _ in pairs]`. Nothing in the reading function binds the two
    names, so the loop-based derivation has nothing to look at and the whole module
    comes back as `cannot tell which half is the rule`.

    Derived from the helper rather than assumed: the comprehension names one of the
    targets it binds, and which one is the answer. A helper that returns something else
    is not an unpacker and is not listed.
    """
    out = {}
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        rets = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
        if len(rets) != 1 or not isinstance(rets[0].value, ast.ListComp):
            continue
        comp = rets[0].value
        if len(comp.generators) != 1:
            continue
        tgt = comp.generators[0].target
        if not isinstance(tgt, (ast.Tuple, ast.List)):
            continue
        names = [e.id if isinstance(e, ast.Name) else None for e in tgt.elts]
        if not isinstance(comp.elt, ast.Name) or comp.elt.id not in names:
            continue
        out[fn.name] = names.index(comp.elt.id)
    return out


def _never_matches(node):
    """-> source that matches nothing, in the shape the rule is written in, or None.

    A rule is a string literal or a `re.compile(...)` beside it, and the second shape
    is why five rules went untested: the sweep only knew how to blank a literal, and
    said nothing about the rest rather than admitting it could not.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return '"ZZ-MATCHES-NOTHING"'
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "compile"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"):
        return 're.compile("ZZ-MATCHES-NOTHING")'
    return None

def sweep_patterns(modules=SWEPT_MODULES):
    """Neutralise each pattern in a detector's rule list; report the ones nothing missed.

    `sweep_rules` reads `return True`, so a rule that lives as an ELEMENT of a pattern
    list is invisible to it. This oracle keeps fifty-one of those across nine lists, and
    the first sweep of them found forty-one with no case: three quarters of the rules in
    ten detectors could have been deleted with the suite still green.

    A list qualifies when a `d_` detector names it at all. Entries may be a bare
    pattern or a `(pattern, specimen)` pair — the pair is what the fix for those
    forty-one looks like, and this has to read both or it stops covering the lists that
    took it.

    AND IT RETURNS WHAT IT DID NOT TOUCH. The version that could read only one index per
    entry, and only a string literal, walked past `_INSECURE_CODE` entirely: five rules
    in a shipped detector, tested by nothing, and the summary line counted eighty-two and
    mentioned no absence. A number that reads as coverage over a set nobody named is the
    defect this whole tool is pointed at, arrived at from the inside.
    """
    total, free, skipped = 0, [], []
    for mod in modules:
        total_here, free_here, skipped_here = _sweep_patterns_in(mod)
        total += total_here
        free += free_here
        skipped += skipped_here
    return total, free, skipped


def _sweep_patterns_in(mod):
    """One module's pattern rules, neutralised one at a time."""
    path = os.path.join(RT, mod)
    orig = io.open(path, encoding="utf-8").read()
    tree = ast.parse(orig)
    lists = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, (ast.List, ast.Tuple)) and node.value.elts):
            lists[node.targets[0].id] = node.value
    # A LIST THE DETECTOR NAMES, not one it happens to iterate in a shape this
    # recognises. The first version matched `for x in NAME` and `x in NAME` over the
    # function's text, and the engine's commonest shape is neither:
    #
    #     markers = SYSLEAK_MARKERS + [m.lower() for m in ctx.get(...) or []]
    #     return any(m in o for m in markers)
    #
    # The list is extended by the operator's config and read through the local, so the
    # scan saw nothing and `sysprompt_leak`'s two built-in markers were swept by
    # nothing. `_RESERVED_TLD` went the same way through `host.endswith(...)`. Six
    # rules, in a total that read as every rule in a pattern list; the sweep that could
    # finally see them found no case for four, and one of the four was the same test
    # written twice and is gone, which is why the tuple is three long now.
    #
    # Read off the tree rather than the text, because the text says `ALWAYS_PARTIAL`
    # inside two comments and a scan over source selects a list of detector names as
    # a list of rules, then reports nineteen of them as untested.
    used = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        # A DETECTOR IN `oracle.py`, ANY FUNCTION ANYWHERE ELSE. `d_` is what a rule
        # list's reader is called there and nowhere else; asking for it in another
        # module selects nothing and reports the file clean.
        if mod == "oracle.py" and not node.name.startswith("d_"):
            continue
        for ref in ast.walk(node):
            if (isinstance(ref, ast.Name) and ref.id in lists
                    and isinstance(ref.ctx, ast.Load)):
                used.setdefault(ref.id, node.name)
    # THE PATTERN, NOT THE PAIR. A tuple entry carries a label or a specimen beside the
    # rule, and that is the case: replacing the whole tuple deletes the case with the
    # rule and every one of them comes back green.
    #
    # WHICH ELEMENT IS THE RULE IS READ FROM THE DETECTOR, not assumed to be the first.
    # `_SECRETS` is (pattern, label) and `_INSECURE_CODE` is (label, pattern): taking
    # element zero from both reported five of `_INSECURE_CODE`'s rules as uncovered when
    # what had been neutralised was their prose. The detector unpacks the entry and
    # passes one of the names to `re.search`; that name's position is the answer.
    sites, skipped = [], []
    for name, det in sorted(used.items()):
        pos, why = _pattern_positions(tree, orig, det, name)
        for i, el in enumerate(lists[name].elts):
            if isinstance(el, (ast.Tuple, ast.List)):
                here = [p for p in pos if p < len(el.elts)]
                if not here:
                    # CANNOT TELL WHICH HALF IS THE RULE, and that is a result of its
                    # own: guessing invents findings, and staying quiet about it is
                    # how five rules went untested behind a number that read clean.
                    skipped.append((mod, name, det,
                                    why or "no index inside this entry"))
                    continue
                targets = [el.elts[p] for p in here]
            else:
                targets = [el]
            for target in targets:
                if _never_matches(target):
                    sites.append((name, det, i, target))
                else:
                    skipped.append((mod, name, det,
                                    "the rule is not a literal or a compile"))
    suites = ["test_oracle.py"] if mod == "oracle.py" else _suites_touching(mod)
    if not suites:
        print("  ! nothing imports %s, so its silence here is not a result" % mod)
        return 0, [], []
    for s in suites:
        assert _run(s) == 0, "%s is not green to begin with" % s
    free = []
    with source_restored(path):
        for name, det, i, node in sites:
            blank = _never_matches(node)
            lines = orig.split("\n")
            ln = node.lineno - 1
            if node.lineno == node.end_lineno:
                lines[ln] = (lines[ln][:node.col_offset]
                             + blank + lines[ln][node.end_col_offset:])
            else:
                head = lines[ln][:node.col_offset] + blank
                lines[ln:node.end_lineno] = [
                    head + lines[node.end_lineno - 1][node.end_col_offset:]]
            write_mutant(path, "\n".join(lines), orig)
            red = any(_run(s) for s in suites)
            clear_mutant(path, orig)
            # WHICH RULE, not which entry: an entry can hold two, and `danger` with a
            # case beside `safe` without one is the difference between a detector that
            # is tested and one that is half tested.
            shown = " ".join((ast.get_source_segment(orig, node) or "").split())
            print("  %-20s %-26s %s  %s"
                  % (name, det, "kept" if red else "NO CASE OF ITS OWN", shown[:44]))
            if not red:
                free.append((mod, name, det, shown))
    for s in suites:
        assert _run(s) == 0, "%s was not restored" % mod
    return len(sites), free, skipped


def _refusal_sites(src, mod):
    """-> [(function, lineno)] for the early returns this module decides with.

    IN `oracle.py` A REFUSAL IS A `return False` IN A DETECTOR, because that is what a
    detector refusing to call something a finding looks like. Nowhere else is that the
    shape: `refusal.declined` answers True to refuse and `classify` returns a dict, so
    the same filter applied there finds nothing at all — which is exactly what this
    arm did, silently, for as long as it existed.
    """
    sites = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.FunctionDef):
            continue
        if mod == "oracle.py" and not node.name.startswith("d_"):
            continue
        last = node.body[-1]
        for c in ast.walk(node):
            if not isinstance(c, ast.Return) or c is last:
                continue
            if mod == "oracle.py" and not (isinstance(c.value, ast.Constant)
                                           and c.value.value is False):
                continue
            sites.append((node.name, c.lineno))
    return sites


def sweep_refusals(modules=SWEPT_MODULES):
    """Neutralise each early refusal; report the ones that matter.

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

    AND THE FILTER IS NOT THE SAME AS A FIXTURE, which this arm used to leave the reader
    to work out. `50 tested, 0 move a verdict` was true and read as `all fifty are
    tested`; the split behind it was EIGHTEEN caught by a case in `test_oracle` and
    THIRTY-TWO deleted with every suite green, excused only by the stored evidence not
    happening to exercise them. Those thirty-two are unmeasured on any workspace whose
    traffic differs from this one, and the summary said nothing about them at all.

    So the count comes back in three parts. A guard the suite catches is tested; a guard
    only the evidence excuses is not, and saying so is the same debt the documented-guard
    arm pays with `their silence here is not a result`.

    AND IT READ ONE FILE. `refusal.py` decides the report's `blocked by` column and half
    of what `judge` calls a wall — `declined` feeds `refusal_bypass`, `classify` names
    the lock in every row — and no arm of this tool had ever opened it. Swept by hand,
    ten of its thirteen early returns were caught and three were not: `declined(None)`
    raised instead of answering, a failed send after the model had already complied read
    as compliance, and `_minus` quietly dropped every blank line.

    The evidence filter belongs to `oracle.py` alone: the replay scores DETECTORS, so it
    has nothing to say about a function that names a lock. For every other module a
    survivor is reported unfiltered, and the summary says which half it is.
    """
    total, moved, excused = 0, [], []
    for mod in modules:
        path = os.path.join(RT, mod)
        orig = io.open(path, encoding="utf-8").read()
        sites = _refusal_sites(orig, mod)
        total += len(sites)
        # THE SUITES THAT CAN SEE IT, derived the way the guards arm derives them. On
        # `oracle.py` that is one file and running the rest would multiply the sweep by
        # its length for no answer; anywhere else the set is whatever imports it.
        suites = ["test_oracle.py"] if mod == "oracle.py" else _suites_touching(mod)
        if not suites:
            print("  ! nothing imports %s, so its silence here is not a result" % mod)
            continue
        for s in suites:
            assert _run(s) == 0, "%s is not green to begin with" % s
        base = _replay() if mod == "oracle.py" else None
        if mod == "oracle.py" and (base is None or not base.get("n")):
            print("  ! no stored evidence in out/, so every survivor below is unfiltered")
        lines = orig.split("\n")
        with source_restored(path):
            for name, lineno in sites:
                idx = lineno - 1
                stmt = lines[idx]
                mutant = list(lines)
                mutant[idx] = " " * (len(stmt) - len(stmt.lstrip())) + "pass"
                write_mutant(path, "\n".join(mutant), orig)
                red = any(_run(s) for s in suites)
                got = None if (red or mod != "oracle.py") else _replay()
                clear_mutant(path, orig)
                if red:
                    continue
                if mod != "oracle.py":
                    # NO EVIDENCE FILTER HERE, and that is a property of the replay
                    # rather than of the module: it scores detectors and this is not
                    # one. Reported as a survivor, which is the unfiltered answer.
                    moved.append((mod, name, lineno,
                                  "no case; the evidence filter does not reach this module"))
                    continue
                if base is None or got is None:
                    moved.append((mod, name, lineno, "the replay could not answer"))
                    continue
                diff = {k: (base["hits"].get(k, 0), got["hits"].get(k, 0))
                        for k in set(base["hits"]) | set(got["hits"])
                        if base["hits"].get(k, 0) != got["hits"].get(k, 0)}
                if diff:
                    moved.append((mod, name, lineno, "; ".join(
                        "%s %d->%d" % (k, a, b) for k, (a, b) in sorted(diff.items()))))
                else:
                    # DELETED WITH EVERY SUITE GREEN, and the evidence happened not to
                    # notice. That is not the same as tested, and it is the whole
                    # difference between this arm's number and its meaning.
                    excused.append((mod, name, lineno))
        for s in suites:
            assert _run(s) == 0, "%s was not restored" % mod
    return total, moved, excused


def main(argv):
    ap = argparse.ArgumentParser(prog="unguarded",
                                 description="decisions no suite would miss")
    ap.add_argument("--guards", action="store_true", help="documented guards only")
    ap.add_argument("--rules", action="store_true", help="detector rules only")
    ap.add_argument("--patterns", action="store_true",
                    help="rules that live as elements of a pattern list")
    ap.add_argument("--refusals", action="store_true",
                    help="guards against false positives only (needs evidence in out/)")
    ap.add_argument("--only", metavar="MODULE", nargs="+", default=(),
                    help="restrict the documented-guard sweep to these modules")
    args = ap.parse_args(argv)
    # BEFORE ANYTHING IS TOUCHED, and out loud. A run of this file killed in the gap
    # between the mutant and the original leaves a deleted decision in the tree, and
    # the only thing worse than finding one is a tool that fixes it without saying so.
    _back = recover()
    if _back:
        print("A previous run was killed mid-mutation. Restored %s." % _back)
    both = not (args.guards or args.rules or args.refusals or args.patterns)
    # WHAT WAS ACTUALLY DELETED, ACROSS EVERY ARM, which is a different number from what
    # was found. The closing verdict rests on this rather than on `bad`, because zero
    # survivors out of zero deletions is not a clean bill.
    #
    # EVERY ARM, and the first version of this counted one. `--refusals` deleted fifty and
    # the summary read `NOTHING WAS DELETED`: the same defect as the one it was written to
    # fix, pointed the other way, and it shipped for as long as it took to run the other
    # arm once.
    bad = swept = excused = 0
    unswept = []
    if both or args.guards:
        print("=== documented guards ===")
        tested, survivors, undocumented, held = sweep_guards(args.only)
        swept += tested
        print("\n%d documented guard(s) tested, %d survived deletion" % (tested, len(survivors)))
        if undocumented:
            # SAY WHAT WAS NOT LOOKED AT. The scope is deliberate -- a comment means
            # somebody paid for that branch once -- but a reader takes "0 survived" for a
            # verdict on the file, and on `workspace.py` that was one branch of twenty-one.
            print("  %d more guard(s) of the same shape carry no comment and were not "
                  "touched. Their silence here is not a result." % undocumented)
        if held:
            # WHICH SUITE, because the reader's next move is to run it. A module is held
            # back by a suite that is red HERE -- a flake, a missing practice fleet, a
            # platform this machine is not -- and none of those is a fact about the module.
            print("  %d module(s) were not swept at all, because a suite that can see "
                  "them is not green on this machine: %s.\n  Nothing below is a "
                  "verdict about them."
                  % (len(held), ", ".join("%s (%d guard(s))" % (m, n) for m, n in held)))
        for mod, ln, src, who in survivors:
            print("  %s:%d  %s   [%s]" % (mod, ln, src[:70], who))
        bad += len(survivors)
        unswept += held
    if both or args.rules:
        print("\n=== rules inside multi-rule detectors ===")
        n, free = sweep_rules()
        swept += n
        print("\n%d rule site(s) tested, %d with no case of their own" % (n, len(free)))
        for mod, name, ln, src in free:
            print("  %s:%d  %s  %s" % (mod, ln, name, src[:60]))
        bad += len(free)
    if both or args.patterns:
        print("\n=== rules that live in a pattern list ===")
        n, free, skipped = sweep_patterns()
        swept += n
        print("\n%d pattern rule(s) tested, %d with no case of their own"
              % (n, len(free)))
        for mod, name, det, pat in free:
            print("  %-12s %-18s %-24s %s" % (mod, name, det, pat[:48]))
        # SAY WHAT WAS NOT LOOKED AT, the same debt the guard arm above pays. This arm
        # ran for a week counting eighty-two and never mentioning the five it walked
        # past, which is a number that reads as coverage of a set nobody named.
        if skipped:
            print("  %d more rule(s) sit where this sweep cannot tell which half is the rule.\n"
                  "  They were not touched, and their silence here is not a result."
                  % len(skipped))
            for _k in sorted(set(skipped)):
                print("    %-12s %-18s %-24s %s" % _k)
        bad += len(free)
    if both or args.refusals:
        print("\n=== guards against false positives ===")
        n, moved, excused_here = sweep_refusals()
        swept += n
        print("\n%d early refusal(s) tested, %d move a verdict on the stored evidence"
              % (n, len(moved)))
        for mod, name, ln, what in moved:
            print("  %s:%-6d %-26s %s" % (mod, ln, name, what[:80]))
        # AND HOW MANY WERE EXCUSED RATHER THAN TESTED. `0 move a verdict` reads as
        # `all of them are covered`; on this fleet eighteen were caught by a case and
        # thirty-two by traffic that happened not to reach them.
        if excused_here:
            print("  %d of those were deleted with every suite green and changed no"
                  "\n  verdict on the stored evidence. The evidence excused them; no case"
                  "\n  tested them, and on a workspace with different traffic they are"
                  "\n  unmeasured." % len(excused_here))
            for mod, name, ln in excused_here:
                print("    %s:%-6d %s" % (mod, ln, name))
        excused += len(excused_here)
        bad += len(moved)

    # NOT AN EXIT CODE THAT FAILS A BUILD. Some survivors are equivalent mutations -- a guard
    # whose fallback reaches the same answer, an input bound whose effect is time rather than
    # a verdict -- and this tool cannot tell those from a real gap. It reports; a person reads.
    # AND A SWEEP THAT DELETED NOTHING HAS SHOWN NOTHING. Pointed at three modules with
    # no guard of this shape, this printed `Nothing this sweep deleted went unnoticed`—
    # a clean verdict over an empty sweep, which is the sentence this whole tool exists
    # to refuse. `--only` naming a module that does not exist is already refused for the
    # same reason; this is the same silence reached through a module that does exist and
    # holds nothing to test.
    if bad:
        print("\n%d decision(s) to look at." % bad)
    elif excused:
        # NOT THE SAME SENTENCE. Nothing is a finding, and %d of what was deleted was
        # missed by every suite and excused by traffic instead. `Nothing went unnoticed`
        # over that is the shape this whole file exists to refuse.
        print("\nNothing this sweep deleted moved a verdict, and %d of it went\n"
              "unnoticed by every suite, excused by the stored evidence rather\n"
              "than tested by a case." % excused)
    elif swept:
        print("\nNothing this sweep deleted went unnoticed.")
    elif unswept:
        # NOT `every branch was undocumented`, which is a statement about the CODE. Nothing
        # was deleted because a suite that watches these modules is red on this machine,
        # which is a statement about the machine, and the two send a reader to different
        # places -- one to the module, one to the suite.
        print("\nNOTHING WAS DELETED: every module named was held back.")
    else:
        print("\nNOTHING WAS DELETED, so nothing here is a verdict. Every branch this "
              "sweep\nlooked at was either undocumented or not of the shape it takes.")
    # AFTER THE SENTENCE, WHATEVER THE SENTENCE WAS. A module nobody opened qualifies a
    # clean bill, a list of findings and an empty sweep alike, and putting it inside one
    # branch is how it went missing from the other three. `Nothing this sweep deleted went
    # unnoticed` over a module nothing was deleted from is the shape this whole file exists
    # to refuse, and it is the shape that hid a suite failing one run in twelve.
    if unswept:
        print("%d module(s) were NEVER SWEPT (%s), because a suite that can see them is not "
              "green\nhere. Nothing above is a verdict about them."
              % (len(unswept), ", ".join(m for m, _n in unswept)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
