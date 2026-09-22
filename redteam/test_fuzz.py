"""
A seeded random walk over the readers a stranger's YAML reaches — no model, no network.

Mutation asks whether a rule somebody already wrote can fail. `tools/unguarded.py` asks
whether a rule is kept by anything. Neither can find a rule NOBODY WROTE, and that is what
this is for: build attack entries out of the shapes real corpora use and the shapes real
files get wrong, hand them to the functions that read an arsenal, and assert only what has
to hold whatever the input was.

It paid on the first run. `payload_text` had just been fixed by hand for one of its five
deliveries -- `[ask] ` with nothing under it -- and four thousand random entries found the
same shape still shipping from three branches along, plus two failures nobody had named:

  * `steps: hello` -- one missing pair of brackets -- rendered `[turn 1] h`, `[turn 2] e`,
    five turns of one character each, handed to a client as the conversation that breached
    their bot. A string is iterable, so this one never raised.
  * `history: "x"` did raise, `AttributeError` out of `(h or {}).get`, and took the report
    build with it at the point the findings were being written up.

IN THE GATE RATHER THAN IN `tools/`, deliberately, and that is the opposite of the choice
`unguarded` makes. That one rewrites source and runs the suites dozens of times over; this
one is arithmetic over dictionaries and finishes in seconds, so there is no reason for it to
be a thing somebody remembers to run.

SEEDED, for the same reason. A suite whose input changes every run is one that goes red on
somebody else's commit and green on the retry, and a gate nobody trusts is a gate nobody
reads. The seed is fixed here; pass another on the command line to walk somewhere else, and
put what it finds in a case rather than in the seed.

THE INVARIANTS ARE DRIVEN OVER PLANTED RENDERERS FIRST. A walk over correct code cannot
fail, so on its own it would be four thousand entries of nothing, reported as four thousand
entries of proof.

    python test_fuzz.py            # exits 1 on any failure (CI gate)
    python test_fuzz.py 12345      # the same walk from another seed
"""
import random
import re
import sys
import traceback

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import lint_arsenal as lint
import runner
import workspace as ws

SEED = 20260922
ENTRIES = 4000

# NON-ASCII BUT NOT CYRILLIC. `tools/guard.py` refuses a Cyrillic run anywhere outside a
# recorded reply, and the first version of this file carried a Cyrillic word among the
# pieces -- caught by the guard on the first full run, which is what a guard is for. What
# the piece is here for is a codepoint outside ASCII, and this still is one.
# The shapes a hand-written corpus actually contains, and the ones it gets wrong: blank
# strings and whitespace (the label with nothing under it), a marker nobody escaped, a
# string where a list belongs, and a value of the wrong type entirely.
PIECES = ["ignore", "", "  ", "system", "\n", "\t\t", "<|im_start|>", "A" * 300, "0",
          "drop table", "{{x}}", "%s", "-", "null", "café中"]
FIELDS = ["id", "text", "category", "delivery", "steps", "history", "seed", "user_prompt",
          "encode", "detectors", "objective", "notes", "severity"]


# EVERY LABEL `payload_text` WRITES, named rather than guessed at -- see `render_faults`.
# A label this does not know is one this suite cannot hold to anything, so a new one belongs
# here on the day it is written.
LABEL = re.compile(r"\[(?:ask|user prompt|planted in .*?|turn \d+|session \d+|forged .*?"
                   r"|steps|history)\]")


def _value(rnd, depth=0):
    r = rnd.random()
    if r < 0.30:
        return rnd.choice(PIECES)
    if r < 0.40:
        return rnd.choice([None, True, False, 0, -1, 3.5])
    if r < 0.55 and depth < 2:
        return [_value(rnd, depth + 1) for _ in range(rnd.randint(0, 3))]
    if r < 0.65 and depth < 2:
        return {rnd.choice(FIELDS): _value(rnd, depth + 1) for _ in range(rnd.randint(0, 3))}
    if r < 0.80:
        return rnd.choice(list(runner.DELIVERIES))
    return "".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 3)))


def entries(seed, n):
    """n attack entries, the same n for the same seed on any machine."""
    rnd = random.Random(seed)
    out = []
    for _ in range(n):
        a = {f: _value(rnd) for f in FIELDS if rnd.random() < 0.55}
        if rnd.random() < 0.6:
            a["delivery"] = rnd.choice(list(runner.DELIVERIES) + ["", None, "made-up"])
        out.append(a)
    return out


def render_faults(render, rows):
    """Every way `render` failed to produce a readable evidence block. -> [(kind, detail)].

    THE INVARIANT IS "THERE IS SOMETHING AFTER A LABEL", and the labels are named rather
    than guessed at. Two weaker versions were tried first and both were wrong the same way:
    they described the SHAPE of the output instead of the property.

      * "a line starting with `[` and ending with `]`" reported 191 findings in one run,
        every one of them a list that `str()` had rendered. `['nullsystem']` is not a label.
      * "a line holding `] ` with nothing after it" misses `[ask]` written with no trailing
        space at all.

    An invariant that guesses at its own subject is a finding generator, and a run full of
    findings nobody will read is worse than no run at all.
    """
    out = []
    for a in rows:
        try:
            s = render(a)
        except Exception:
            out.append(("raised", traceback.format_exc().strip().split("\n")[-1]))
            continue
        if not isinstance(s, str):
            out.append(("not a string", type(s).__name__))
            continue
        for line in s.split("\n"):
            m = LABEL.match(line)
            if m and not line[m.end():].strip():
                out.append(("a label with nothing under it", repr(line)))
                break
    return out


# --- the planted renderers, each with one of the defects this has actually found ---------
def _always_labels(a):
    return "[ask] %s" % (a.get("text") or "")


def _iterates_a_string(a):
    return "\n".join("[turn %d] %s" % (i + 1, s)
                     for i, s in enumerate(a.get("steps") or []))


def _returns_whatever(a):
    return a.get("text")


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else SEED
    checks, fails = 0, []

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    rows = entries(seed, ENTRIES)

    # --- THE WALK HAS TO REACH THE SHAPES IT CLAIMS TO TEST ------------------------------
    #
    # A generator that produced four thousand plain `direct` attacks would find nothing and
    # say so in the same words as a clean run. The denominator is asserted before the
    # verdict, the same way `tools/check.py` refuses a run that found no suites.
    check("the walk produced the entries it was asked for", len(rows) == ENTRIES,
          str(len(rows)))
    # `repr`, because a generated `delivery` can be a dict and a set of those does not
    # build -- the walk is allowed to produce anything a YAML file can.
    _seen = {repr(a.get("delivery")) for a in rows}
    check("...covering every delivery the runner declares",
          {repr(d) for d in runner.DELIVERIES} <= _seen, str(sorted(_seen)[:8]))
    _blank = sum(1 for a in rows if not str(a.get("text") or "").strip())
    check("...with entries whose text is blank, which is the label-with-nothing case",
          _blank > 100, str(_blank))
    _wrong = sum(1 for a in rows
                 if a.get("steps") is not None and not isinstance(a.get("steps"), list))
    check("...and entries whose steps are not a list, which is the quiet one",
          _wrong > 100, str(_wrong))

    # --- THE INVARIANTS CAN FAIL --------------------------------------------------------
    _f1 = render_faults(_always_labels, rows)
    check("a renderer that prints its label unconditionally is caught",
          any(k == "a label with nothing under it" for k, _ in _f1), str(_f1[:2]))
    _f2 = render_faults(_iterates_a_string, rows)
    check("...one that iterates a string of steps is caught, by raising or by the label",
          bool(_f2), str(_f2[:2]))
    _f3 = render_faults(_returns_whatever, rows)
    check("...and one that hands back whatever was stored is caught",
          any(k == "not a string" for k, _ in _f3), str(_f3[:2]))
    check("...while a correct renderer is not caught by any of it",
          not render_faults(lambda a: "[ask] x", rows), "the control renderer was named")

    # --- AND THE REAL ONES --------------------------------------------------------------
    _real = render_faults(ws.payload_text, rows)
    check("the evidence a client is shown survives %d random entries" % ENTRIES,
          not _real, "; ".join("%s %s" % (k, d) for k, d in _real[:3]))

    # A PRICE THAT IS NOT A COUNT REFUSES A BUDGET FOR THE WRONG REASON. `turns` decides
    # whether a run is affordable and `docs/ci.md` prices a sweep with it.
    _bad_turns = []
    for a in rows:
        try:
            t = runner.turns(a)
        except Exception:
            _bad_turns.append(("raised", traceback.format_exc().strip().split("\n")[-1]))
        else:
            if not isinstance(t, int) or isinstance(t, bool) or t < 1:
                _bad_turns.append(("not a count", repr(t)))
    check("...and every entry has a price that is a count",
          not _bad_turns, str(_bad_turns[:3]))

    # THE LINTER IS WHAT STANDS BETWEEN A FILE AND A RUN, so it may refuse anything and may
    # crash on nothing -- and a refusal that does not name the file it read is one an
    # operator with forty arsenals cannot act on.
    # THE VOCABULARY IS READ ONCE HERE TOO. `misspelt_keys` with no `known` walks the whole
    # package per call, which at four thousand entries is five minutes of the same answer --
    # the defect this walk found in `unusable_entries`, arriving through its own harness.
    _known = lint.attack_keys_read()
    _calls = [(lint.bad_delivery, (a, "fuzz.yaml")) for a in rows]
    _calls += [(lint.misspelt_keys, (a, "fuzz.yaml", _known)) for a in rows]
    # AND `unusable_entries` OVER BATCHES, not one entry at a time. It derives the key
    # vocabulary once per FILE, so a file holding one attack is the pathological caller --
    # the same cost this walk found inside that function, arriving from the other side. Four
    # thousand single-entry calls took five minutes; forty batches take three seconds, and a
    # batch still names which hundred a fault came from.
    _calls += [(lint.unusable_entries, (rows[_i:_i + 100], "fuzz.yaml"))
               for _i in range(0, len(rows), 100)]
    _bad_lint = []
    for fn, args in _calls:
        try:
            got = fn(*args)
        except Exception:
            _bad_lint.append((fn.__name__ + " raised",
                              traceback.format_exc().strip().split("\n")[-1]))
            continue
        for e in (got if isinstance(got, (list, tuple)) else ([got] if got else [])):
            if not isinstance(e, str):
                _bad_lint.append((fn.__name__ + " reported a non-string", repr(e)[:80]))
            elif "fuzz.yaml" not in e:
                _bad_lint.append((fn.__name__ + " did not name the file", e[:80]))
    check("...and the linter refuses without crashing, naming the file each time",
          not _bad_lint, str(_bad_lint[:3]))

    print("\n%d/%d passed  (seed %d)" % (checks - len(fails), checks, seed))
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
