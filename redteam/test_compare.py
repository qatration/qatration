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
    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — measured results reach the page.")


if __name__ == "__main__":
    main()
