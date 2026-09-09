"""
Tests for the cross-target page — no model, no network.

`compare_targets.py` is the client-facing artifact, and it had no tests while being
changed three times in quick succession. Its failures are all of one kind and quiet: a
result that is measured, correct, and simply not on the page. That has already happened
twice here — the rangebot A/B was invisible because pairing was inferred from a `-naive`
suffix, and a declared pair with no differences was dropped entirely, which hid the
strongest conclusion of the foreign-agent work ("the change bought nothing measurable").

So these check what reaches the reader, not just what the functions return.

    python test_compare.py       # exits 1 on any failure (CI gate)
"""
import sys, os
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from compare_targets import pair_diffs, _declared_pairs, benign_noise, esc


def M(name, rows):
    """One (meta, by_id) matrix entry: attack id -> (headline, detectors that fired)."""
    return ({"target": name}, {k: v for k, v in rows.items()})


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- the `-naive` convention still works ------------------------------------------
    matrix = [
        M("bot", {"a1": ("DEFENDED", []), "a2": ("EXPLOITED", ["canary_in_output"]),
                  "a3": ("DEFENDED", [])}),
        M("bot-naive", {"a1": ("EXPLOITED", ["canary_in_output"]),
                        "a2": ("EXPLOITED", ["canary_in_output"]),
                        "a3": ("DEFENDED", [])}),
    ]
    pairs = pair_diffs(matrix)
    check("a -naive twin is still paired", len(pairs) == 1, str(pairs))
    d = pairs[0]["diffs"] if pairs else []
    check("only attacks where the two DISAGREE are listed",
          [x["attack"] for x in d] == ["a1"], str(d))
    check("the direction that is evidence FOR the control is marked",
          d and d[0]["guard_helped"] is True, str(d))

    # Drift in the other direction must not be reported as the control working. Measured:
    # mcpagent's guarded build scored WORSE overall than its naive one while defending the
    # exact attack it exists to defend, because unrelated attacks moved in both directions.
    matrix = [
        M("bot", {"a1": ("EXPLOITED", ["x"]), "a2": ("DEFENDED", [])}),
        M("bot-naive", {"a1": ("DEFENDED", []), "a2": ("EXPLOITED", ["x"])}),
    ]
    d = pair_diffs(matrix)[0]["diffs"]
    helped = [x["attack"] for x in d if x["guard_helped"]]
    drift = [x["attack"] for x in d if not x["guard_helped"]]
    check("a guarded build losing an unrelated attack is drift, not the control",
          helped == ["a2"] and drift == ["a1"], f"helped={helped} drift={drift}")

    # --- an attack only one build ran is not a disagreement ---------------------------
    matrix = [
        M("bot", {"a1": ("DEFENDED", []), "only-here": ("EXPLOITED", ["x"])}),
        M("bot-naive", {"a1": ("DEFENDED", [])}),
    ]
    check("an attack missing from one side is not counted as a difference",
          not pair_diffs(matrix), str(pair_diffs(matrix)))

    # --- BOTH SIDES, DIFFERENT QUESTION ------------------------------------------------
    #
    # The check above handles an attack one build never saw. This is the sharper case: both
    # builds ran it, in different versions of it, so the row LOOKS like a comparison. The
    # fourth element of a matrix entry is a digest over what the attack sends and what
    # scores it, and two that disagree are not evidence about the control either way.
    #
    # Not hypothetical: seven of the ten attacks guardedrag and guardedrag-naive share are
    # recorded with different bodies, and six of portalagent's seventeen.
    matrix = [M("bot", {"a1": ("DEFENDED", [], "x", "aaaa"),
                        "a2": ("DEFENDED", [], "x", "cccc")}),
              M("bot-naive", {"a1": ("EXPLOITED", ["x"], "x", "bbbb"),
                              "a2": ("EXPLOITED", ["x"], "x", "cccc")})]
    _p = pair_diffs(matrix)
    check("an attack both builds ran in DIFFERENT versions is not a difference",
          _p and [x["attack"] for x in _p[0]["diffs"]] == ["a2"], str(_p))
    check("...and is named rather than dropped",
          _p and _p[0]["mismatched"] == ["a1"], str(_p))
    check("...and is not counted among the shared attacks either",
          _p and _p[0]["shared"] == 1, str(_p))

    # AND A MATCHING DIGEST IS NOT A MISMATCH, or the caveat lands on every honest pair.
    matrix = [M("bot2", {"a1": ("DEFENDED", [], "x", "aaaa")}),
              M("bot2-naive", {"a1": ("EXPLOITED", ["x"], "x", "aaaa")})]
    _p = pair_diffs(matrix)
    check("...while the same version on both sides still compares",
          _p and [x["attack"] for x in _p[0]["diffs"]] == ["a1"]
          and _p[0]["mismatched"] == [], str(_p))

    # AND AN ENTRY WITH NO DIGEST SAYS NOTHING, the both-sides-or-nothing rule the history
    # diff and the `inert` comparison already follow: a three-element entry is what every
    # caller wrote before this field existed.
    matrix = [M("bot3", {"a1": ("DEFENDED", [], "x")}),
              M("bot3-naive", {"a1": ("EXPLOITED", ["x"], "x")})]
    _p = pair_diffs(matrix)
    check("an entry with no digest raises nothing",
          _p and [x["attack"] for x in _p[0]["diffs"]] == ["a1"]
          and _p[0]["mismatched"] == [], str(_p))
    # AND NEITHER DOES ONE SIDE HAVING IT. Absence is not disagreement -- the same rule the
    # engine and inert comparisons follow one axis over -- and this is the shape that
    # distinguishes "both sides or nothing" from "compare whatever is there": a digest on one
    # side and none on the other would read as a rewritten attack on every such pair.
    matrix = [M("bot4", {"a1": ("DEFENDED", [], "x", "aaaa")}),
              M("bot4-naive", {"a1": ("EXPLOITED", ["x"], "x")})]
    _p = pair_diffs(matrix)
    check("...nor does a digest on one side and none on the other",
          _p and [x["attack"] for x in _p[0]["diffs"]] == ["a1"]
          and _p[0]["mismatched"] == [], str(_p))

    # AND THE PAGE THIS REPOSITORY SHIPS CARRIES THE NOTICE, which is what makes the rule a
    # measurement rather than a capability. Read from the built page, not recomputed here.
    import io as _io_c, os as _os_c
    _page = _os_c.path.join(_os_c.path.dirname(HERE), "out", "compare_targets.html")
    if _os_c.path.exists(_page):
        _h = _io_c.open(_page, encoding="utf-8").read()
        check("the shipped comparison page says which pairs were asked different questions",
              _h.count("DIFFERENT versions") == 2,
              "%d notices" % _h.count("DIFFERENT versions"))
        check("...and names the attacks rather than only counting them",
              "gr-loyalty" in _h and "pa-bola-order" in _h,
              "the ids are not on the page")

    # --- a declared pair with NO differences is a result, not silence -----------------
    declared = _declared_pairs()
    check("pairs can be declared in a config, not only inferred from a suffix",
          bool(declared), "no config declares compare_with — the mechanism is unused")
    if declared:
        name, (base, label) = next(iter(declared.items()))
        same = {"a1": ("EXPLOITED", ["x"]), "a2": ("DEFENDED", [])}
        pairs = pair_diffs([M(base, same), M(name, dict(same))])
        check("a declared pair survives having nothing to report",
              len(pairs) == 1, "identical builds vanish from the page")
        check("...and says how many attacks it agreed on",
              pairs and pairs[0]["identical"] == 2, str(pairs))
        check("...and carries the label the config wrote, not a generic heading",
              pairs and pairs[0]["label"] == label, str(pairs))
        # an UNdeclared pair with no diffs stays out: there is nothing to say about two
        # unrelated targets that happened to score the same
        check("an undeclared pair with no differences is still dropped",
              not pair_diffs([M("x", same), M("x-naive", dict(same))]))

    # --- the noise column ---------------------------------------------------------------
    noise = benign_noise()
    check("benign runs are read for the noise column", isinstance(noise, dict))
    bad = [k for k, v in noise.items()
           if not (isinstance(v, tuple) and len(v) == 2 and v[0] <= v[1])]
    check("every noise entry is (clean, probes) with clean never above probes",
          not bad, str(bad))
    # A target with no benign run must be absent, so the page can say "not measured"
    # rather than render a blank that reads as zero.
    check("a target with no benign run is absent rather than zero",
          "no-such-target" not in noise)

    check("esc escapes markup so a target name cannot inject into the page",
          esc("<b>&") == "&lt;b&gt;&amp;", esc("<b>&"))

    # THE --help CHECK THAT USED TO LIVE HERE IS NOW IN `test_packaging.py`, over
    # `cli.COMMANDS` rather than over a list of twelve command names typed out when there
    # were twelve. `init`, `fixes`, `discrimination`, `index`, `coverage`, `matrix` and
    # `profiles` all joined the CLI without joining that list, and three of them shipped
    # with the very defect this checked for while it stayed green. A copy is deleted, not
    # synced; what survives is the one that covers a command by virtue of it existing.
    # --- THE MOVEMENT COLUMN DROPPED THE TARGETS IT COULD NOT COMPARE --------------
    #
    # `movement()` returned only the targets whose diff had no `reason`, and the cell for
    # a target it did not return reads `first run`. So `first run` was printed for a
    # target whose timeline could not be read, for one with no timeline at all, and —
    # when the `history` import failed — for every target on the page at once. It keeps
    # them now, reason and all, and the renderer decides what to say.
    import compare_targets as _ct2, tempfile as _tf2, shutil as _sh2, json as _js2
    import pathlib as _pl2
    _w2 = _tf2.mkdtemp()
    os.makedirs(os.path.join(_w2, "history"))
    with open(os.path.join(_w2, "history", "onerun.jsonl"), "w",
              encoding="utf-8") as _f2:
        _f2.write(_js2.dumps({"run": "2026-09-01 10:00", "rows": {},
                              "attacks": 0}) + chr(10))
    with open(os.path.join(_w2, "history", "torn.jsonl"), "w",
              encoding="utf-8") as _f3:
        _f3.write('{"run": ' + chr(10))
    # BOTH ROOTS. `movement` globs its own OUT_DIR and hands the target NAME to
    # `history.diff`, which opens `history.HIST`. In a real workspace both come from
    # `workspace.OUT` and agree; a fixture that moves only one is reading an empty
    # directory and would pass on the wrong evidence.
    import history as _h2
    _real2, _realh2 = _ct2.OUT_DIR, _h2.HIST
    _ct2.OUT_DIR = _pl2.Path(_w2)
    _h2.HIST = os.path.join(_w2, "history")
    try:
        _mv, _why2 = _ct2.movement()
    finally:
        _ct2.OUT_DIR, _h2.HIST = _real2, _realh2
        _sh2.rmtree(_w2, ignore_errors=True)
    check("a target the comparison cannot make is kept, not dropped",
          sorted(_mv) == ["onerun", "torn"], sorted(_mv))
    check("...each carrying why, so the cell is not left to guess",
          "need two runs" in _mv["onerun"].get("reason", "")
          and "could be read" in _mv["torn"].get("reason", ""),
          str(_mv)[:200])
    check("...and the column reports separately that it could be computed at all",
          _why2 == "", _why2)
    # AND THE WHOLE-COLUMN FAILURE, which no workspace can produce on its own: the
    # `except` around the import was reachable only by breaking the import. Left
    # unexercised it is a branch that returns an empty dict, and an empty dict is what
    # made every target on the page read `first run`.
    import types as _ty2
    _saved2 = sys.modules.get("history")
    sys.modules["history"] = _ty2.ModuleType("history")      # no `diff` in it
    try:
        _mv3, _why3 = _ct2.movement()
    finally:
        if _saved2 is not None:
            sys.modules["history"] = _saved2
        else:
            sys.modules.pop("history", None)
    check("a column that could not be computed says so instead of coming back empty",
          _mv3 == {} and "could not be read" in _why3, "%r %r" % (_mv3, _why3))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — measured results reach the page.")


if __name__ == "__main__":
    main()
