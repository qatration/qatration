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

    # --- AN ATTACK BOTH BUILDS ANSWERED THE SAME WAY IS NOT A DIFFERENCE --------------
    #
    # This table's whole claim is "this is what the control buys", and it is kept to the
    # attacks where the two arms disagreed by two lines: `if g[0] == n[0]` and, four lines
    # down, `if gb == nb` over the same pair read as BROKE or not. The first is an
    # EQUIVALENT mutation and is named rather than counted -- two identical verdicts are
    # identical on both readings, so the second catches everything the first does, and it
    # also catches EXPLOITED against PARTIAL, which the first does not.
    #
    # What had no case at all was the ANSWER: every fixture above differs on every shared
    # attack, so nothing here said what happens to the ones that agree.
    matrix = [
        M("agree", {"a1": ("DEFENDED", []), "a2": ("EXPLOITED", ["x"]),
                    "a3": ("DEFENDED", [])}),
        M("agree-naive", {"a1": ("DEFENDED", []), "a2": ("EXPLOITED", ["x"]),
                          "a3": ("EXPLOITED", ["x"])}),
    ]
    _ag = pair_diffs(matrix)
    check("only the attacks the two arms answered differently are differences",
          _ag and [x["attack"] for x in _ag[0]["diffs"]] == ["a3"], str(_ag))
    check("...while the ones they agreed on are still counted as shared",
          _ag and _ag[0]["shared"] == 3, str(_ag))
    # AND A PAIR THAT AGREED EVERYWHERE PRODUCES NO ROW AT ALL, which is the same rule at
    # the other end: nothing disagreed, so there is nothing the control can be credited for.
    matrix = [M("same", {"a1": ("DEFENDED", []), "a2": ("EXPLOITED", ["x"])}),
              M("same-naive", {"a1": ("DEFENDED", []), "a2": ("EXPLOITED", ["x"])})]
    _same = pair_diffs(matrix)
    check("a pair that answered identically everywhere shows no difference",
          not (_same and _same[0]["diffs"]), str(_same))

    # --- A DECLARED PAIR WHOSE GUARDED SIDE WAS NEVER RUN ------------------------------
    #
    # `if base not in by_name: continue` is what stands between a `-naive` artifact with no
    # twin and `by_name[base]`, which is a KeyError out of the page builder. An operator who
    # swept the naive arm first -- the ordinary way round, since it is the cheap one -- is
    # the case, and nothing was driving it.
    matrix = [M("lonely-naive", {"a1": ("EXPLOITED", ["x"])})]
    _lonely = pair_diffs(matrix)
    check("a naive arm whose twin was never run is not a pair", not _lonely, str(_lonely))

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
    # --- AN ARTIFACT OF SOMETHING THAT IS NOT IN THE FLEET --------------------------
    #
    # `out/` keeps whatever ever ran: the deliberately-unreachable fixture the end-to-end
    # suites sweep, and whatever somebody pointed the engine at while debugging. `build_index`
    # learned this once -- it published "32 targets" for a fleet of 30 -- and this page runs
    # the same filter, `if meta.get("target") not in _keep_names`, with no case behind it.
    #
    # Deleting it left every suite green while the comparison page grew a row for a target
    # that has no config: a name in the table a reader cannot look up, carrying a verdict.
    import compare_targets as _ct_o, tempfile as _tf_o, shutil as _sh_o, json as _js_o
    import pathlib as _pl_o, io as _io_o, contextlib as _ctx_o
    _wo = _tf_o.mkdtemp()

    def _art_o(name, headline):
        return {"meta": {"target": name, "model": "m", "trials": 1, "attacks_n": 1,
                         "broke": 1 if headline == "EXPLOITED" else 0, "errors": 0},
                "results": [{"attack": {"id": "a1", "category": "x"},
                             "headline": headline, "rate": "1/1",
                             "fired": ["canary_in_output"] if headline == "EXPLOITED"
                             else [], "trials": []}]}

    try:
        for _n, _h in (("citebot", "EXPLOITED"), ("ghostbot", "EXPLOITED")):
            with open(os.path.join(_wo, "results_%s.json" % _n), "w",
                      encoding="utf-8") as _f_o:
                _js_o.dump(_art_o(_n, _h), _f_o)
        _real_o = _ct_o.OUT_DIR
        _ct_o.OUT_DIR = _pl_o.Path(_wo)
        _buf_o = _io_o.StringIO()
        try:
            with _ctx_o.redirect_stdout(_buf_o):
                _ct_o.main()
            _page_o = _io_o.open(os.path.join(_wo, "compare_targets.html"),
                              encoding="utf-8").read()
        finally:
            _ct_o.OUT_DIR = _real_o
        check("a target the fleet has a config for is on the comparison page",
              "citebot" in _page_o, _buf_o.getvalue()[-300:])
        check("...and one it has no config for is not",
              "ghostbot" not in _page_o, _buf_o.getvalue()[-300:])
    finally:
        _sh_o.rmtree(_wo, ignore_errors=True)

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
