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
import sys, os, json, tempfile, shutil, time
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

        # ONE ATTEMPT A SIDE IS NOT AGREEMENT. The confound above fires when the trial count
        # CHANGES; at one trial in both runs it stays quiet, and `broke_every_trial` answers
        # honestly that a single hit was every trial -- so a coin the target was already
        # flipping lands in REGRESSED and `--fail-on regression` turns a build red on one
        # sample. Measured from a fresh install against a local model: four sweeps, same
        # config, same model, same 45 attacks, breach count 12 then 4 then 6 then 7, reported
        # as REGRESSED 3 / new 2 / fixed 4 with no caveat at all.
        H.record({"target": "cf4", "model": "m", "trials": 1}, R(a1="DEFENDED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf4", "model": "m", "trials": 1}, R(a1="EXPLOITED"),
                 when="2026-08-02 10:00")
        _d1 = H.diff("cf4")
        check("one trial a side is a confound, however steady the rows look",
              any("one attempt" in c for c in _d1["confounds"]), str(_d1["confounds"]))
        # AND IT REACHES THE GATE, which is the half that matters: `regression_verdict`
        # answers 3 -- "cannot answer" -- on any confounded diff, and 3 is documented as NOT
        # A PASS. Without this the same diff returned 1 and failed somebody's build.
        import run_redteam as _rr
        check("...and the CI gate cannot answer rather than failing the build",
              _rr.regression_verdict(_d1)[0], 3)

        # THE DEFAULT IS UNTOUCHED. `--trials` defaults to 3, so the common path must not
        # gain a caveat -- a confound on every run is a confound nobody reads.
        H.record({"target": "cf5", "model": "m", "trials": 3}, R(a1="DEFENDED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf5", "model": "m", "trials": 3}, R(a1="EXPLOITED"),
                 when="2026-08-02 10:00")
        _d3 = H.diff("cf5")
        check("three trials a side carries no such caveat",
              not any("one attempt" in c for c in _d3["confounds"]), str(_d3["confounds"]))
        check("...and that diff still fails the build", _rr.regression_verdict(_d3)[0], 1)

        # A COUNT THAT IS NOT A NUMBER SAYS NOTHING. An artifact written before `trials` was
        # recorded carries None, and inventing a caveat from a missing field would put one on
        # every legacy timeline. `True` is an int in Python and would read as 1, which is the
        # sort of accident that arrives through a hand-edited config.
        H.record({"target": "cf6", "model": "m", "trials": None}, R(a1="DEFENDED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf6", "model": "m", "trials": None}, R(a1="EXPLOITED"),
                 when="2026-08-02 10:00")
        check("a missing trial count invents no caveat",
              not any("one attempt" in c for c in H.diff("cf6")["confounds"]),
              str(H.diff("cf6")["confounds"]))

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

        # THE CASE THAT MATTERED AND WAS NOT COVERED. The check above backfills the same file
        # twice, so both passes read one mtime and the old clock-based key matched. A run the
        # SWEEP recorded carries `datetime.now()`, taken when the snapshot was built; the file
        # carries its mtime, whenever it was last touched. Two clocks, two moments, so the
        # guard never fired: measured on the real repository, 28 of the 35 targets holding a
        # timeline would be seeded a second time, and every mtime involved read the same
        # instant because a bulk file operation had touched them all.
        #
        # The duplicate line is not the damage. `diff()` compares runs[-2] against runs[-1],
        # so a re-seeded run is compared against its own copy and reports no new, no fixed,
        # nothing regressed — which reads as a stable target and is nothing having been
        # compared at all.
        _rows_live = R(x1="EXPLOITED")
        H.record({"target": "bf2"}, _rows_live)
        _bf2 = os.path.join(tmp, "results_bf2.json")
        with open(_bf2, "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf2"}, "results": _rows_live}, f)
        # THE TWO CLOCKS ARE PUSHED APART ON PURPOSE. Written as-is, `record`'s
        # `datetime.now()` and the file's mtime land in the same second and the old key
        # matched by accident, so this check passed against the code it exists to refuse --
        # caught by mutating and watching it stay green. An mtime an hour off is what the
        # real case looks like: the file was touched when the sweep finished writing, or
        # later by anything that rewrote it.
        os.utime(_bf2, (time.time() - 3600, time.time() - 3600))
        check("a run already recorded live is not seeded again from its own file",
              H.backfill() == 0 and len(H.load("bf2")) == 1, str(H.load("bf2")))
        # ...and the key must still let a run through that the timeline does not hold, or
        # backfill stops being able to seed anything.
        with open(os.path.join(tmp, "results_bf3.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf3"}, "results": R(x1="DEFENDED")}, f)
        check("...while a run the timeline has never seen is still seeded",
              H.backfill() == 1 and len(H.load("bf3")) == 1, str(H.load("bf3")))
        # ...and a re-scored copy of a run the timeline holds is a DIFFERENT run: same target,
        # same model, same trials, different verdicts. Seeding it is right; deduping it would
        # hide a rejudge.
        with open(os.path.join(tmp, "results_bf3.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf3"}, "results": R(x1="EXPLOITED")}, f)
        check("...and a re-scored run is seeded rather than folded into the old one",
              H.backfill() == 1 and len(H.load("bf3")) == 2, str(H.load("bf3")))
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

        # --- AND THE SAME THROUGH THE SKIP DOOR, which the branch above did not name -----
        # `state()` caught ERROR and stopped there. SKIP is not in BROKE either, so it took
        # the value that means MEASURED CLEAN, and an attack that broke last run and was not
        # delivered this run came back FIXED — a finding closed by a config change.
        #
        # A target losing its `history:` block does exactly that: every forged-transcript
        # attack turns to SKIP at once. So does moving a bot behind an adapter with fewer
        # capabilities. Neither event tested anything, and both used to close everything the
        # missing delivery had ever found.
        d = diff_over([{"a": B}, {"a": "SKIP"}])
        check("an attack that was not delivered is not a finding fixed",
              not d["fixed"] and d["not_run"] == ["a"],
              str({k: d[k] for k in ("fixed", "not_run")}))
        d = diff_over([{"a": B}, {"a": "SKIP"}, {"a": B}])
        check("...and it cannot make the next break look like a regression either",
              not d["regressed"] and d["open"] == ["a"], str(d))
    finally:
        H.OUT, H.HIST = real_out, real_hist
        for d in made:
            shutil.rmtree(d, ignore_errors=True)

    # --- a flip the trials do not agree on is not a change -----------------------------
    # Two runs of this engine against one endpoint, nothing changed between them but the
    # sampler: six attacks became "introduced or reopened", four became "fixed", and not one
    # of the ten broke on all three attempts in either run. `--fail-on regression` is the gate
    # `docs/ci.md` puts on pull requests, so that is a red build on somebody's unrelated
    # change, which is the exact outcome the gate exists to prevent.
    #
    # The rate was on disk the whole time. `snapshot()` writes "1/3" per row and the
    # comparison read the verdict beside it, so 0/3 -> 1/3 and 0/3 -> 3/3 were one event.
    #
    # `docs/ci.md` had already reasoned about this mechanism in the case where the INSTRUMENT
    # changed -- comparing three trials against two, where "fewer attempts give a flaky attack
    # fewer chances, which reads as a fix". Same mechanism, same wrong conclusion, and the
    # guarded case was the rarer one.
    rt_dirs = []
    real_out3, real_hist3 = H.OUT, H.HIST
    try:
        def rate_diff(runs):
            """runs = [{aid: (verdict, rate)}, ...] -> diff over that timeline."""
            d = tempfile.mkdtemp()
            rt_dirs.append(d)
            os.makedirs(os.path.join(d, "history"), exist_ok=True)
            with open(os.path.join(d, "history", "t.jsonl"), "w", encoding="utf-8") as f:
                for i, rows in enumerate(runs):
                    f.write(json.dumps(
                        {"run": "2026-02-%02d 00:00:00" % (i + 1), "target": "t", "model": "m",
                         "trials": 3, "attacks": len(rows),
                         "rows": {a: {"v": v, "rate": r, "fired": []}
                                  for a, (v, r) in rows.items()}}) + "\n")
            H.OUT, H.HIST = d, os.path.join(d, "history")
            return H.diff("t")

        D, X = "DEFENDED", "EXPLOITED"

        d = rate_diff([{"a": (D, "0/3")}, {"a": (X, "1/3")}])
        check("an attack that broke on one attempt of three is not a new finding",
              d["new"] == [] and d["regressed"] == [], str(d))
        check("...it is named as unsteady rather than dropped",
              d["unstable"] == ["a"], str(d["unstable"]))

        d = rate_diff([{"a": (D, "0/3")}, {"a": (X, "2/3")}])
        check("two of three is still not a change the trials agree on",
              d["new"] == [] and d["unstable"] == ["a"], str(d))

        d = rate_diff([{"a": (D, "0/3")}, {"a": (X, "3/3")}])
        check("breaking on every attempt after breaking on none is a new finding",
              d["new"] == ["a"] and d["unstable"] == [], str(d))

        d = rate_diff([{"a": (X, "1/3")}, {"a": (D, "0/3")}])
        check("an attack that only ever broke once in three is not called fixed",
              d["fixed"] == [] and d["unstable"] == ["a"], str(d))

        d = rate_diff([{"a": (X, "3/3")}, {"a": (D, "0/3")}])
        check("...but one that broke on every attempt and stopped is",
              d["fixed"] == ["a"] and d["unstable"] == [], str(d))

        # A ROW THAT CANNOT SAY IS NOT A ROW THAT SAYS NO. Snapshots written before `rate`
        # carried anything useful must not be read as reliable breaks; understating a diff is
        # the allowed direction here, and the row is still named.
        d = rate_diff([{"a": (D, "")}, {"a": (X, "")}])
        check("a moved row with no readable rate is not counted as a change",
              d["new"] == [] and d["unstable"] == ["a"], str(d))

        # AND THE GATE ITSELF, because every branch above is only worth what the exit code
        # does with it. Imported here rather than at the top: `run_redteam` pulls in the
        # engine, and this suite is otherwise about one small module.
        from run_redteam import regression_verdict

        code, said = regression_verdict(rate_diff([{"a": (D, "0/3")}, {"a": (X, "1/3")}]))
        check("the CI gate does not fail a build on a flip within the trials",
              code == 0, "exit %s: %s" % (code, said))
        check("...and says so rather than reporting nothing moved",
              any("not on every attempt" in s and "a" in s for s in said), str(said))

        code, said = regression_verdict(rate_diff([{"a": (D, "0/3")}, {"a": (X, "3/3")}]))
        check("the CI gate still fails on a finding the trials all agree on",
              code == 1, "exit %s: %s" % (code, said))

        # BOTH AT ONCE is the case that matters on a real build: a team reading "1 introduced"
        # has to be told that another row moved and was not counted, or the number reads as
        # the whole story.
        code, said = regression_verdict(rate_diff([{"a": (D, "0/3"), "b": (D, "0/3")},
                                                   {"a": (X, "3/3"), "b": (X, "1/3")}]))
        check("a failing build still names what moved without being counted",
              code == 1 and any("not on every attempt" in s for s in said), str(said))
    finally:
        H.OUT, H.HIST = real_out3, real_hist3
        for d in rt_dirs:
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
