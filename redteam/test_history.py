"""
Tests for memory across runs — no model, no network.

Every sweep used to overwrite its predecessor, so the engine could answer "what is broken
now" and nothing else. The questions asked on a SECOND sweep of the same system — is this
new, did the fix hold, has this regressed, how long has it been open — were not
unimplemented, they were unanswerable, because the evidence had been deleted.

The checks here are about the four states being genuinely four. Collapsing regressed into
new is the one that costs most: a fix that did not hold is a different conversation from a
finding nobody had seen before, and reporting them as one hides the worse of the two.

    python test_history.py       # exits 1 on any failure (CI gate)
"""
import sys, os, json, tempfile, shutil
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import history as H


def R(**verdicts):
    """A results list: attack id -> headline."""
    return [{"attack": {"id": k, "category": "x"}, "headline": v, "rate": "1/1",
             "fired": ["canary_in_output"] if v in H.BROKE else []}
            for k, v in verdicts.items()]


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    tmp = tempfile.mkdtemp()
    real_out, real_hist = H.OUT, H.HIST
    H.OUT, H.HIST = tmp, os.path.join(tmp, "history")
    try:
        meta = {"target": "t", "model": "m", "trials": 1}

        # --- a snapshot keeps what a comparison needs, and drops what it must ---------
        snap = H.snapshot(meta, R(a1="EXPLOITED", a2="DEFENDED") +
                          [{"attack": {"id": "ctrl", "category": "control"},
                            "headline": "EXPLOITED", "rate": "1/1", "fired": ["x"]}])
        check("a control is never recorded as a finding — it is a false-alarm check",
              "ctrl" not in snap["rows"], str(sorted(snap["rows"])))
        check("the broken count excludes controls", snap["broke"] == 1, str(snap))

        # --- one run is a snapshot, not a trend, and must say so ---------------------
        H.record(meta, R(a1="EXPLOITED", a2="DEFENDED"), when="2026-08-01 10:00")
        d = H.diff("t")
        check("a single run refuses to produce a diff", "reason" in d, str(d))

        # --- the four states ----------------------------------------------------------
        H.record(meta, R(a1="EXPLOITED", a2="EXPLOITED", a3="DEFENDED"),
                 when="2026-08-02 10:00")
        d = H.diff("t")
        check("a newly broken attack is new", d["new"] == ["a2"], str(d))
        check("one broken in both runs is still open", d["open"] == ["a1"], str(d))
        check("nothing is called fixed that was never broken", d["fixed"] == [], str(d))
        check("nothing is called a regression on its first sighting",
              d["regressed"] == [], str(d))

        H.record(meta, R(a1="DEFENDED", a2="DEFENDED", a3="DEFENDED"),
                 when="2026-08-03 10:00")
        d = H.diff("t")
        check("an attack that stopped breaking is fixed",
              sorted(d["fixed"]) == ["a1", "a2"], str(d))

        # THE distinction. a1 broke, was fixed, and broke again — that is not a new
        # finding, it is a fix that did not hold, and the two need different answers.
        H.record(meta, R(a1="EXPLOITED", a2="DEFENDED", a4="EXPLOITED"),
                 when="2026-08-04 10:00")
        d = H.diff("t")
        check("a finding that returns after a fix is a REGRESSION, not a new finding",
              d["regressed"] == ["a1"], str(d))
        check("...and something genuinely first seen is still new",
              d["new"] == ["a4"], str(d))

        # An attack the run never SENT is not a fixed attack. The first real sweep after
        # this module was written reported eight findings as closed because the run had
        # used a different arsenal — absence read as a clean result, which is the one
        # version of that mistake that tells a client their vulnerabilities are gone.
        H.record(meta, R(a2="DEFENDED"), when="2026-08-05 10:00")
        d = H.diff("t")
        check("an attack the run never sent is NOT fixed",
              "a1" not in d["fixed"] and "a4" not in d["fixed"], str(d))
        check("...it is reported as not re-tested, and stays owed",
              sorted(d["not_run"]) == ["a1", "a4"], str(d))
        check("...and it is not counted as open either, since nothing measured it",
              d["open"] == [], str(d))
        H.record(meta, R(a1="EXPLOITED", a2="DEFENDED", a4="EXPLOITED"),
                 when="2026-08-06 10:00")

        # --- how long has it been open ------------------------------------------------
        ages = H.first_seen("t")
        check("an open finding is dated from when it FIRST broke, not from the last run",
              ages.get("a1") == "2026-08-01 10:00", str(ages))
        check("a finding first seen today is dated today",
              ages.get("a4") == "2026-08-04 10:00", str(ages))
        check("a fixed finding carries no age, because it is not open",
              "a2" not in ages, str(ages))

        # Two runs made with different instruments are not a before/after. Caught on the
        # first real use: httpbot went from three trials to two and seven attacks moved to
        # "fixed", nearly all of them the encoded ones — a cluster too tidy to be behaviour.
        H.record({"target": "cf", "model": "m", "trials": 3}, R(a1="EXPLOITED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf", "model": "m", "trials": 2}, R(a1="DEFENDED"),
                 when="2026-08-02 10:00")
        dc = H.diff("cf")
        check("a change in trial count is flagged as a confound, not reported as a fix",
              any("trials" in c for c in dc["confounds"]), str(dc))
        H.record({"target": "cf2", "model": "a", "trials": 3}, R(a1="EXPLOITED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf2", "model": "b", "trials": 3}, R(a1="DEFENDED"),
                 when="2026-08-02 10:00")
        check("a change of model is flagged too",
              any("model" in c for c in H.diff("cf2")["confounds"]), str(H.diff("cf2")))
        H.record({"target": "cf3", "model": "m", "trials": 3}, R(a1="EXPLOITED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf3", "model": "m", "trials": 3}, R(a1="DEFENDED"),
                 when="2026-08-02 10:00")
        check("two runs made the same way carry no confound",
              H.diff("cf3")["confounds"] == [], str(H.diff("cf3")))

        # --- the log is append-only, and survives damage ------------------------------
        p = H._path("t")
        n_before = len(H.load("t"))
        with open(p, "a", encoding="utf-8") as f:
            f.write("{ this line is not json\n")
        check("one corrupt line does not lose the timeline",
              len(H.load("t")) == n_before, str(len(H.load("t"))))
        check("a target with no history reads as empty rather than failing",
              H.load("never-run") == [])

        # --- backfill seeds from what is already on disk, and says that it did --------
        with open(os.path.join(tmp, "results_bf.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf"}, "results": R(x1="EXPLOITED")}, f)
        check("backfill seeds a timeline from a stored run", H.backfill() == 1)
        seeded = H.load("bf")
        check("a backfilled entry is labelled, since its time is a file's mtime",
              seeded and seeded[0].get("note"), str(seeded))
        check("backfilling twice does not duplicate the entry",
              H.backfill() == 0 and len(H.load("bf")) == 1, str(H.load("bf")))
    finally:
        H.OUT, H.HIST = real_out, real_hist
        shutil.rmtree(tmp, ignore_errors=True)

    # --- a previous state of ABSENCE is not a previous state of CLEAN -------------------
    # state() returns None for an attack a run did not send, with a comment saying it says
    # nothing either way — and the branch below it read that None as False. So an attack
    # broken now, absent from the previous run and broken in some earlier one was labelled
    # REGRESSED, which means "the fix did not hold", when nothing had ever measured it
    # fixed. `not_run` protected absent-NOW; nothing protected absent-BEFORE. On the real
    # fleet that was every REGRESSED label the engine had ever produced: 42 of 42.
    B, C = "EXPLOITED", "DEFENDED"

    def timeline(runs):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "history"), exist_ok=True)
        with open(os.path.join(d, "history", "t.jsonl"), "w", encoding="utf-8") as f:
            for i, rows in enumerate(runs):
                f.write(json.dumps({"run": f"2026-01-0{i + 1} 00:00:00", "target": "t",
                                    "model": "m", "trials": 3, "attacks": len(rows),
                                    "rows": {a: {"v": v, "rate": "3/3", "fired": []}
                                             for a, v in rows.items()}}) + "\n")
        return d

    real_out, real_hist = H.OUT, H.HIST
    made = []
    try:
        def diff_over(runs):
            d = timeline(runs)
            made.append(d)
            H.OUT, H.HIST = d, os.path.join(d, "history")
            return H.diff("t")

        # broken, then NOT SENT, then broken again: nothing ever measured it clean
        d = diff_over([{"a": B}, {}, {"a": B}])
        check("an attack the previous run never sent is not called regressed",
              not d["regressed"], str(d["regressed"]))
        check("...it is open, because it has been owed since the earlier break",
              d["open"] == ["a"], str(d))
        check("...and the comparison says it rests on an absence",
              d["assumed_clean"] == ["a"] and any("never sent" in c for c in d["confounds"]),
              str(d["confounds"]))

        # broken, MEASURED clean, broken again: this one really is a regression
        d = diff_over([{"a": B}, {"a": C}, {"a": B}])
        check("an attack measured clean in between is still called regressed",
              d["regressed"] == ["a"], str(d))
        check("...and carries no absence caveat", not d["assumed_clean"], str(d))

        # never seen broken before, and the previous run did not send it: a first sighting
        d = diff_over([{"b": B}, {}, {"a": B}])
        check("an attack never seen broken before is new, not open",
              d["new"] == ["a"] and not d["open"], str(d))

        # --- an ERROR row measured nothing, so it is not a measurement of clean ---------
        # state() returned `row["v"] in BROKE`, and ERROR is not in BROKE — so a run where
        # every probe failed read as a run that measured the target CLEAN, and the diff
        # reported the findings as FIXED. Exactly what not_run was added for, reached through
        # the error door rather than the arsenal door. Caused live: a sweep against a target
        # whose server was down reported five findings fixed, two of them demonstrated the
        # same afternoon.
        d = diff_over([{"a": B}, {"a": "ERROR"}, {"a": B}])
        check("a run that errored is not a run that measured clean",
              not d["regressed"] and not d["fixed"],
              str({k: d[k] for k in ("regressed", "fixed")}))
        check("...and the finding is still open, because nothing closed it",
              d["open"] == ["a"], str(d["open"]))
        d = diff_over([{"a": B}, {"a": "ERROR"}])
        check("...nor does an errored LATEST run report the finding fixed",
              not d["fixed"] and d["not_run"] == ["a"],
              str({k: d[k] for k in ("fixed", "not_run")}))
    finally:
        H.OUT, H.HIST = real_out, real_hist
        for d in made:
            shutil.rmtree(d, ignore_errors=True)

    # --- a gap in the timeline is a gap in the diff's confidence -----------------------
    # One unreadable line must not lose the whole timeline: a truncated write from a killed
    # run should cost the run it recorded and nothing else. But skipping it in silence makes
    # the history shorter than it is, and this file is what answers "is this new, did the fix
    # hold, has it regressed, how long has it been open". A diff computed across a gap is a
    # confident answer over evidence that is missing.
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "history"), exist_ok=True)

    def snap(when, v):
        return json.dumps({"run": when, "target": "t", "model": "m", "trials": 3,
                           "attacks": 1,
                           "rows": {"x": {"v": v, "rate": "3/3", "fired": []}}})

    with open(os.path.join(d, "history", "t.jsonl"), "w", encoding="utf-8") as f:
        f.write(snap("2026-01-01 00:00:00", "EXPLOITED") + "\n")
        f.write('{"run": "2026-01-02 00:00:00", "targ\n')      # a run killed mid-write
        f.write(snap("2026-01-03 00:00:00", "EXPLOITED") + "\n")
    real_out2, real_hist2 = H.OUT, H.HIST
    try:
        H.OUT, H.HIST = d, os.path.join(d, "history")
        torn = []
        runs = H.load("t", torn)
        dd = H.diff("t")
    finally:
        H.OUT, H.HIST = real_out2, real_hist2
        shutil.rmtree(d, ignore_errors=True)

    check("a torn line costs its own run and not the timeline", len(runs) == 2, str(len(runs)))
    check("...and is reported with its line number", bool(torn) and torn[0][0] == 2, str(torn))
    check("...and the diff says the history behind it is incomplete",
          any("could not be read" in c for c in dd["confounds"]), str(dd["confounds"]))

    # --- the gate a pull request uses, every branch of it ---------------------------------
    #
    # `--fail-on regression` decides whether somebody else's build goes red, and every branch
    # here is one of those decisions. Tested as a pure function rather than by running a sweep,
    # because a decision reachable only after an hour of GPU is a decision nobody checks.
    #
    # The half that matters most is the one that returns 3. `exploited` and `any` fire on the
    # absolute state, so a team's first check goes red on whatever was already broken and stays
    # red, and everyone learns to ignore it. This one fires only on what the run introduced —
    # and when the comparison cannot be believed it says so instead of going green, because a
    # green built on a changed arsenal is the same lie as a clean report on an unplanted canary.
    from run_redteam import regression_verdict as verdict

    code, lines = verdict(None, is_model_copy=True)
    check("a --model copy cannot answer the question, and says so rather than passing",
          code == 3 and "CANNOT ANSWER" in lines[0], "exit %s" % code)

    code, lines = verdict({"reason": "need two runs to compare"})
    check("a first run is a baseline, not a verdict", code == 3, "exit %s" % code)
    check("...and it says how to make the next one answerable",
          "out/history/" in lines[0], lines[0][:80])

    code, lines = verdict({"prev": "r1", "confounds": ["arsenal 285 -> 357 attacks"],
                           "new": [], "regressed": []})
    check("a confounded comparison is not a pass, even with nothing new",
          code == 3, "exit %s" % code)
    check("...and it names the confound rather than waving at it",
          "arsenal 285 -> 357" in lines[0], lines[0][:90])

    code, _ = verdict({"prev": "r1", "confounds": [], "new": ["a1"], "regressed": []})
    check("something NEW this run fails the build", code == 1, "exit %s" % code)
    code, _ = verdict({"prev": "r1", "confounds": [], "new": [], "regressed": ["a2"]})
    check("...and so does something reopened", code == 1, "exit %s" % code)

    code, lines = verdict({"prev": "r1", "confounds": [], "new": [], "regressed": []})
    check("nothing worse passes", code == 0 and not lines, "exit %s, %s" % (code, lines))

    code, lines = verdict({"prev": "r1", "confounds": [], "new": [], "regressed": [],
                           "not_run": ["a3", "a4"]})
    check("a row that was not re-tested is excluded out loud, not silently",
          code == 0 and lines and "not re-tested" in lines[0], str(lines))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a run remembers the one before it.")


if __name__ == "__main__":
    main()
