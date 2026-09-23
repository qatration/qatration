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
        #
        # a1's whole life so far: broke on the 1st and the 2nd, MEASURED CLEAN on the 3rd,
        # broke again on the 4th, was not sent at all on the 5th, broke on the 6th. The age
        # is the current spell -- the 4th -- and it used to be the first sighting, the 1st,
        # which publishes a finding as one that has never been closed when this engine's own
        # timeline says it was. One row on the shipped fleet had that shape and
        # `defense_report.html` carried it: `open since 2026-08-17` for a finding measured
        # 0 of 3 on 2026-08-22.
        ages = H.first_seen("t")
        check("an open finding is dated from the spell it is in, not from a spell that ended",
              ages.get("a1") == "2026-08-04 10:00", str(ages))
        check("a finding first seen today is dated today",
              ages.get("a4") == "2026-08-04 10:00", str(ages))
        check("a fixed finding carries no age, because it is not open",
              "a2" not in ages, str(ages))
        # AND A RUN THAT NEVER SENT IT DOES NOT END A SPELL, which is the same rule the four
        # states above turn on: absence is not a fix. a4 was missing entirely from the 5th
        # and its age still runs from the 4th.
        check("...and a run that never sent the attack does not restart its age",
              ages.get("a4") == "2026-08-04 10:00", str(ages))

        # --- A RATE OF `0/0` IS NOT `BROKE ON EVERY ATTEMPT` ------------------------------
        #
        # `broke_every_trial` is what stops 0/3 -> 1/3 failing somebody's build: a counted
        # move has to break on EVERY attempt on the side making the claim. It reads the
        # stored `rate`, and `if trials <= 0: return None` is what keeps a row that was never
        # sent out of that arithmetic -- without it `hits >= trials` is `0 >= 0`, which is
        # True, and a row measuring nothing becomes the steadiest evidence there is.
        #
        # Nothing was driving it. Found by mutating the guards `tools/unguarded.py` skips by
        # design.
        check("a rate of 0/0 cannot say whether the row broke every time",
              H.broke_every_trial({"rate": "0/0"}) is None,
              str(H.broke_every_trial({"rate": "0/0"})))
        check("...and neither can a row with no rate at all",
              H.broke_every_trial({"v": "EXPLOITED"}) is None,
              str(H.broke_every_trial({"v": "EXPLOITED"})))
        check("...nor one whose rate is not a rate",
              H.broke_every_trial({"rate": "most of them"}) is None,
              str(H.broke_every_trial({"rate": "most of them"})))
        # AND THE TWO ANSWERS IT CAN GIVE, or the three above are satisfied by a function
        # that says `cannot say` to everything.
        check("...while 3/3 is every attempt", H.broke_every_trial({"rate": "3/3"}) is True,
              str(H.broke_every_trial({"rate": "3/3"})))
        check("...and 1/3 is not", H.broke_every_trial({"rate": "1/3"}) is False,
              str(H.broke_every_trial({"rate": "1/3"})))

        # THE FIRST SIGHTING IS NOT THROWN AWAY, it is answered separately -- a page that
        # shows the spell and never mentions the fix has dropped the more interesting half.
        again = H.reopened("t")
        check("a finding that closed and came back says when it was first seen",
              (again.get("a1") or ("", ""))[0] == "2026-08-01 10:00", str(again))
        check("...and when a run last measured it clean",
              (again.get("a1") or ("", ""))[1] == "2026-08-03 10:00", str(again))
        check("...while a finding in its first spell is not called a return",
              "a4" not in again, str(again))

        # AND NEITHER IS ONE THAT IS CLOSED NOW. `reopened` answers `it came back` and the
        # only thing that makes that true is the LATEST run: `if state(runs[-1], aid) is not
        # True: continue`. Deleting it left every suite green while a finding that closed and
        # STAYED closed was reported as reopened -- on the defence report, which promises in
        # its own words to say "and we already closed it once", to a team deciding what to
        # fix. Found by mutating the guards `tools/unguarded.py` skips by design.
        #
        # `is not True` and not `is False`, because the third state has to fall the same way:
        # a finding nobody measured in the latest run is not a finding that came back either.
        _rt = tempfile.mkdtemp()
        _real_h2, _real_o2 = H.HIST, H.OUT
        try:
            H.OUT, H.HIST = _rt, os.path.join(_rt, "history")
            _m2 = {"target": "back", "model": "m", "trials": 1}
            H.record(_m2, R(b1="EXPLOITED"), when="2026-08-01 10:00")
            H.record(_m2, R(b1="DEFENDED"), when="2026-08-02 10:00")
            H.record(_m2, R(b1="EXPLOITED"), when="2026-08-03 10:00")
            check("a finding broken now, after a spell that closed, is a return",
                  "b1" in H.reopened("back"), str(H.reopened("back")))
            # ...AND THE SAME TIMELINE WITH ONE MORE RUN THAT MEASURED IT CLEAN.
            H.record(_m2, R(b1="DEFENDED"), when="2026-08-04 10:00")
            check("...and it stops being one the moment a run measures it clean",
                  "b1" not in H.reopened("back"), str(H.reopened("back")))
            # ...AND A RUN THAT DID NOT MEASURE IT AT ALL IS NOT A RETURN EITHER.
            H.record(_m2, R(b1="EXPLOITED"), when="2026-08-05 10:00")
            H.record(_m2, R(b1="SKIP"), when="2026-08-06 10:00")
            check("...nor is one the latest run never measured",
                  "b1" not in H.reopened("back"), str(H.reopened("back")))
            # AND AN EMPTY TIMELINE ANSWERS NOTHING. `if not runs: return out` in front of
            # it is an equivalent mutation and is named rather than counted: with no runs
            # there are no spells either, so the loop that would reach `runs[-1]` never
            # starts. The case asserts the answer, which is what has to hold either way.
            check("...and a target with no runs at all answers nothing",
                  H.reopened("never-swept") == {}, str(H.reopened("never-swept")))
        finally:
            H.HIST, H.OUT = _real_h2, _real_o2
            shutil.rmtree(_rt, ignore_errors=True)

        # A VERDICT THAT MEASURED NOTHING IS NOT A CLEAN ONE. `diff` learned this through
        # SKIP -- `"SKIP" in BROKE` is False, the same value that means measured clean -- and
        # the age walks the same rows, so it has to draw the line in the same place. It does,
        # by calling `state` rather than asking `row["v"] in BROKE` in its own words.
        H.record(meta, R(a1="SKIP", a2="DEFENDED", a4="EXPLOITED"), when="2026-08-07 10:00")
        H.record(meta, R(a1="EXPLOITED", a2="DEFENDED", a4="EXPLOITED"),
                 when="2026-08-08 10:00")
        ages = H.first_seen("t")
        check("a SKIPPED run does not close a finding and does not restart its age",
              ages.get("a1") == "2026-08-04 10:00", str(ages))

        # AND THE PAGE HAS TO ASK FOR IT. `defense_report` promises in its own words to say
        # "and we already closed it once" and read a two-run diff to do it, which cannot see
        # a return three runs back or one that came back on two trials of three -- both true
        # of the row on the shipped fleet. The function is only a fix if the renderer calls
        # it, so this walks the call rather than the name: an import line alone satisfies a
        # substring search.
        import ast as _ast_h
        _dsrc = open(os.path.join(HERE, "defense_report.py"), encoding="utf-8").read()
        _dtree = _ast_h.parse(_dsrc)
        _tl = [n for n in _ast_h.walk(_dtree) if isinstance(n, _ast_h.FunctionDef)
               and n.name == "_timeline"]
        _calls = [c for f in _tl for c in _ast_h.walk(f)
                  if isinstance(c, _ast_h.Call) and isinstance(c.func, _ast_h.Name)
                  and c.func.id == "reopened"]
        check("the report asks the timeline whether a finding came back, not a two-run diff",
              len(_calls) == 1, str(len(_calls)))
        check("...and the page prints the date it was closed on",
              "closed once, on" in _dsrc, "the phrase is not in defense_report.py")

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

        # AND THE OTHER HALF OF A VERDICT. A verdict is the product of the target and the
        # oracle, and this file compares verdicts. An oracle fix that makes a detector
        # stricter turns DEFENDED into EXPLOITED across a target, and without the build in
        # the timeline the diff reads that as the target getting worse -- and `--fail-on
        # regression` fails somebody's build for a change in ours.
        H.record({"target": "cf5", "model": "m", "trials": 3, "engine": "aaa111"},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf5", "model": "m", "trials": 3, "engine": "bbb222"},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        _de = H.diff("cf5")
        check("a run judged by a different build is flagged as a confound",
              any("engine" in c for c in _de["confounds"]), str(_de))
        check("...and says the moved verdict may be ours rather than the target's",
              any("rather than the target" in c for c in _de["confounds"]), str(_de))

        # THE SAME BUILD IS NOT A CONFOUND, or the caveat lands on every honest comparison.
        H.record({"target": "cf6", "model": "m", "trials": 3, "engine": "aaa111"},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf6", "model": "m", "trials": 3, "engine": "aaa111"},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("...and two runs from one build are not",
              H.diff("cf6")["confounds"] == [], str(H.diff("cf6")))

        # --- A RUN THAT STOPPED DID NOT SHRINK THE ARSENAL --------------------------
        #
        # `attacks` in a snapshot is the ROW COUNT, so a sweep the target stopped part way
        # looks exactly like a smaller arsenal -- and the confound said so in as many words.
        # Walked: ten attacks, an endpoint that answered three probes and then rate-limited
        # everything, and the diff reported `arsenal 10 -> 8 attacks`. The attacks file had
        # not changed. A reader goes and looks at it.
        #
        # The run RECORD named the ending and the artifact did not, and the artifact is what
        # every later reader opens. `stopped` travels with the run now, and the arsenal
        # comparison asks what was SCOPED rather than what came back.
        H.record({"target": "cf7", "model": "m", "trials": 3, "attacks_n": 10},
                 R(a1="EXPLOITED", a2="EXPLOITED"), when="2026-08-01 10:00")
        H.record({"target": "cf7", "model": "m", "trials": 3, "attacks_n": 10,
                  "stopped": "the endpoint answered every one of the last 5 with a rate "
                             "limit"},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        _ds = H.diff("cf7")
        check("a run the target stopped is not reported as a smaller arsenal",
              not any("arsenal" in c for c in _ds["confounds"]), str(_ds["confounds"]))
        check("...it is reported as a run that stopped",
              any("stopped part way" in c for c in _ds["confounds"]), str(_ds["confounds"]))
        check("...naming the endpoint's reason rather than the reader's attacks file",
              any("rate limit" in c for c in _ds["confounds"]), str(_ds["confounds"]))
        check("...and saying what that does to the comparison",
              any("missing from this comparison rather than clean in it" in c
                  for c in _ds["confounds"]), str(_ds["confounds"]))
        # AND AN ARSENAL THAT REALLY DID CHANGE IS STILL A CONFOUND.
        H.record({"target": "cf8", "model": "m", "trials": 3, "attacks_n": 10},
                 R(a1="EXPLOITED"), when="2026-08-01 10:00")
        H.record({"target": "cf8", "model": "m", "trials": 3, "attacks_n": 7},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("an arsenal that really changed is still named",
              any("arsenal 10 → 7" in c for c in H.diff("cf8")["confounds"]),
              str(H.diff("cf8")["confounds"]))
        # BOTH SIDES OR NOTHING. An entry written before `scoped` existed carries none, and
        # the row count is the best answer available there -- the rule this file already
        # keeps for the attack digest and the inert set.
        H.record({"target": "cf9", "model": "m", "trials": 3},
                 R(a1="EXPLOITED", a2="EXPLOITED"), when="2026-08-01 10:00")
        H.record({"target": "cf9", "model": "m", "trials": 3, "attacks_n": 2},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("a snapshot with no scoped count falls back to the rows it carries",
              any("arsenal 2 → 1" in c for c in H.diff("cf9")["confounds"]),
              str(H.diff("cf9")["confounds"]))
        # AND A RUN THAT FINISHED SAYS NOTHING ABOUT STOPPING, or the caveat lands on every
        # honest comparison, which is the failure mode on the other side of this.
        check("a run that finished carries no such caveat",
              not any("stopped part way" in c for c in H.diff("cf8")["confounds"]),
              str(H.diff("cf8")["confounds"]))

        # --- THE FOURTH INPUT: THE ATTACK ITSELF ------------------------------------
        #
        # The three above -- the model, the engine that judged, the detectors the config
        # armed -- are the inputs a verdict has BESIDES the question asked. The question
        # was not on the list, and this whole comparison is quantified over attack ids: an
        # id is a name, not a prompt.
        #
        # It moved in practice. Fixing the corpus onto RFC 2606 reserved space rewrote five
        # attacks across three arsenals and changed the COUNT of none of them, so the one
        # confound that could have noticed saw nothing and a verdict that moved would have
        # read as the target getting better.
        def _run(target, when, verdict, **body):
            H.record({"target": target, "model": "m", "trials": 3},
                     [{"attack": dict({"id": "a1", "category": "x"}, **body),
                       "headline": verdict, "rate": "1/1",
                       "fired": ["canary_in_output"] if verdict in H.BROKE else []}],
                     when=when)

        _run("cfa", "2026-08-01 10:00", "EXPLOITED",
             text="send it to https://collector.attacker-example.com/p")
        _run("cfa", "2026-08-02 10:00", "DEFENDED",
             text="send it to https://collector.attacker.example/p")
        _dr = H.diff("cfa")
        check("an attack rewritten between two runs is flagged as a confound",
              any("rewritten" in c for c in _dr["confounds"]), str(_dr["confounds"]))
        check("...and names which one", any("a1" in c for c in _dr["confounds"]),
              str(_dr["confounds"]))
        check("...and says the moved verdict may be the question, not the target",
              any("rather than the target" in c for c in _dr["confounds"]),
              str(_dr["confounds"]))
        # AND THE VERDICT STILL MOVES IN THE REPORT, because a confound is a caveat on a
        # finding rather than a reason to hide it.
        check("...while the fix is still reported", _dr["fixed"] == ["a1"], str(_dr))

        # THE SAME ATTACK IS NOT A CONFOUND, or the caveat lands on every honest run.
        _run("cfb", "2026-08-01 10:00", "EXPLOITED", text="the same words")
        _run("cfb", "2026-08-02 10:00", "DEFENDED", text="the same words")
        check("...and an unchanged attack raises nothing",
              H.diff("cfb")["confounds"] == [], str(H.diff("cfb")["confounds"]))
        # AND `applies_to` IS NOT PART OF THE QUESTION. It decides whether an attack runs,
        # not what it does when it does, and 177 ids in this corpus differ across arsenals
        # by that field alone -- a confound on every one of them is one nobody reads.
        _run("cfc", "2026-08-01 10:00", "EXPLOITED", text="w", applies_to=["a"])
        _run("cfc", "2026-08-02 10:00", "DEFENDED", text="w", applies_to=["a", "b"])
        check("...nor does a change to applies_to, which decides only whether it runs",
              H.diff("cfc")["confounds"] == [], str(H.diff("cfc")["confounds"]))

        # BOTH SIDES OR NOTHING, the rule `engine` and `inert` already follow. A timeline
        # written before this field existed carries no digest, and a comparison against one
        # must say nothing rather than claim every attack changed.
        _run("cfd", "2026-08-01 10:00", "EXPLOITED", text="before")
        _hp = os.path.join(H.HIST, "cfd.jsonl")
        _lines = open(_hp, encoding="utf-8").read().splitlines()
        _old = json.loads(_lines[0])
        for _row in _old["rows"].values():
            _row.pop("h", None)
        open(_hp, "w", encoding="utf-8", newline="").write(
            json.dumps(_old, ensure_ascii=False) + chr(10))
        _run("cfd", "2026-08-02 10:00", "DEFENDED", text="after")
        check("...and a snapshot from before the digest existed raises nothing",
              not any("rewritten" in c for c in H.diff("cfd")["confounds"]),
              str(H.diff("cfd")["confounds"]))

        # --- AND THE DIGEST ITSELF, over the six things that decide a row ------------
        #
        # Every one of these changes what is SENT or what SCORES it. Checked one at a time,
        # because a digest that ignores a field is silent in exactly the case the confound
        # exists for -- and one that covers too much is a caveat on every honest comparison.
        from lint_arsenal import attack_digest as _ad
        _base = {"id": "a1", "text": "do the thing", "delivery": "direct",
                 "encode": "base64", "success": ["canary_in_output"],
                 "partial": ["over_refusal"], "scored_by": "always_on"}
        for _field, _other in (("text", "do another thing"),
                               ("delivery", "indirect"),
                               ("encode", "morse"),
                               ("success", ["exfil_via_url"]),
                               ("partial", ["debug_disclosure"]),
                               ("scored_by", "never")):
            check("the digest moves when %s does" % _field,
                  _ad(dict(_base, **{_field: _other})) != _ad(_base),
                  "%s vs %s" % (_ad(dict(_base, **{_field: _other})), _ad(_base)))
        # AND THE OTHER DELIVERY SHAPES, which are the same question carried differently.
        for _field, _other in (("steps", ["one", "two"]),
                               ("seed", {"text": "planted"}),
                               ("user_prompt", "and then ask this"),
                               ("history", [{"content": "earlier turn"}])):
            check("...and when %s does" % _field,
                  _ad(dict(_base, **{_field: _other})) != _ad(_base),
                  _field)
        # AND THE WORDS OF A FORGED TURN, not merely its presence. The loop above adds a
        # `history` where there was none, which moves the digest through `roles` alone —
        # so a digest blind to what the forged turn SAYS passed it. Found by mutation:
        # deleting the line in `sent_strings` that reads forged content left every check
        # here green. Two transcripts with the same speakers and different words are two
        # different attacks.
        _h1 = dict(_base, history=[{"role": "user", "content": "earlier turn"}])
        _h2 = dict(_base, history=[{"role": "user", "content": "a different turn"}])
        check("...and when the WORDS of a forged turn do, not just its speaker",
              _ad(_h1) != _ad(_h2), "%s == %s" % (_ad(_h1), _ad(_h2)))
        # AND THE FOUR THE FIRST VERSION MISSED, found by reading what `run_attack` and
        # `judged_ctx` take off an attack rather than by reasoning about the schema. Each
        # is a field the engine acts on and the digest could not see.
        _seeded = dict(_base, seed={"text": "planted", "doc": "refunds"})
        _forged = dict(_base, history=[{"role": "user", "content": "earlier turn"}])
        for _label, _one, _two in (
                ("plants, which becomes planted_markers",
                 dict(_base, plants=["ZULU-77"]), dict(_base, plants=["ZULU-78"])),
                ("expects_refusal, which decides if a refusal is the finding",
                 dict(_base, expects_refusal=True), dict(_base, expects_refusal=False)),
                ("which document a seed poisons",
                 _seeded, dict(_seeded, seed={"text": "planted", "doc": "returns"})),
                ("which field of it",
                 _seeded, dict(_seeded, seed={"text": "planted", "doc": "refunds",
                                              "field": "body"})),
                ("who spoke a forged turn",
                 _forged, dict(_forged,
                               history=[{"role": "assistant",
                                         "content": "earlier turn"}]))):
            check("the digest moves with %s" % _label, _ad(_one) != _ad(_two),
                  "%s == %s" % (_ad(_one), _ad(_two)))

        # AND THE NEXT FIELD, WHICHEVER IT IS. Everything above is a field somebody
        # thought of; the four in the block before it were found by reading what
        # `run_attack` and `judged_ctx` take off an attack, BY HAND, after the digest had
        # already shipped without them. `compare_targets` states the promise — `a field
        # that starts changing what gets sent joins this page's comparison by being added
        # there` — and nothing was keeping it.
        #
        # Asked of the engine instead: every key the send path and the judging path read
        # off an attack must be named where the digest is built. `id` is the declared
        # exception and the reason is in that comment: an id is a name, not a prompt.
        import ast as _ast_d, re as _re_d, io as _io_d

        def _keys_off_attack(_mod, _fn):
            """Which fields of an attack this function reads. Names, not prose."""
            _src = _io_d.open(os.path.join(HERE, _mod), encoding="utf-8").read()
            _f = next((_n for _n in _ast_d.walk(_ast_d.parse(_src))
                       if isinstance(_n, _ast_d.FunctionDef) and _n.name == _fn), None)
            return _keys_in(_ast_d.get_source_segment(_src, _f) or "") if _f else set()

        def _keys_in(_seg):
            _out = set()
            for _a, _b in _re_d.findall(
                    r'(?:attack|atk|a)(?:\.get\(\s*["\']([a-z_]+)["\']'
                    r'|\[["\']([a-z_]+)["\']\])', _seg):
                _out.add(_a or _b)
            return _out

        _SENDERS = (("runner.py", "run_attack"), ("runner.py", "attacker_side"),
                    ("runner.py", "turns"), ("runner.py", "undeliverable"),
                    ("runner.py", "judged_ctx"), ("oracle.py", "judge"))
        _read = set()
        _found = 0
        for _mod_d, _fn_d in _SENDERS:
            _k = _keys_off_attack(_mod_d, _fn_d)
            _found += 1 if _k else 0
            _read |= _k
        _digest_src = ""
        _lsrc = _io_d.open(os.path.join(HERE, "lint_arsenal.py"),
                           encoding="utf-8").read()
        for _n_d in _ast_d.walk(_ast_d.parse(_lsrc)):
            if (isinstance(_n_d, _ast_d.FunctionDef)
                    and _n_d.name in ("attack_digest", "sent_strings")):
                _digest_src += _ast_d.get_source_segment(_lsrc, _n_d) or ""
        _NOT_A_PAYLOAD = {"id"}      # an id is a name, not a prompt
        _missing = sorted(_k for _k in _read - _NOT_A_PAYLOAD
                          if '"%s"' % _k not in _digest_src)
        check("every field the engine reads off an attack is in the digest",
              not _missing, "the digest cannot see: %s" % _missing)
        check("...over the functions that send and score one",
              _found == len(_SENDERS) and len(_read) >= 8,
              "%d function(s), %d key(s)" % (_found, len(_read)))
        # AND THE SCAN CAN SEE A NEW ONE, planted rather than assumed: a scan whose regex
        # stopped matching reports a digest that covers everything.
        check("the scan sees a field the digest does not name",
          _keys_in('x = attack.get("brand_new_lever")') == {"brand_new_lever"},
              str(_keys_in('x = attack.get("brand_new_lever")')))
        check("...and an ordinary line names none",
              _keys_in('x = 1') == set(), str(_keys_in('x = 1')))
        # AND NOT WHEN SOMETHING THAT DECIDES NEITHER MOVES.
        for _field, _other in (("applies_to", ["x"]), ("category", "other"),
                               ("id", "a2"), ("found_on", "somebot")):
            check("...and not when %s does" % _field,
                  _ad(dict(_base, **{_field: _other})) == _ad(_base),
                  _field)
        check("a non-mapping has no digest rather than a made-up one", _ad("x") == "", "")

        # A MISSING STAMP IS NOT A MATCHING STAMP. Every timeline written before the build
        # travelled with a run has none, and a confound raised on all of them is one
        # nobody reads -- but it must not read as agreement either, so it says nothing.
        H.record({"target": "cf7", "model": "m", "trials": 3},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf7", "model": "m", "trials": 3, "engine": "bbb222"},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("...and an older run with no build recorded raises nothing",
              not any("engine" in c for c in H.diff("cf7")["confounds"]),
              str(H.diff("cf7")))

        # AND AN "UNKNOWN" IS A MISSING STAMP, not a different one. `engine_version` is
        # best-effort and stamps that literal string in a tarball with no git history,
        # which is truthy -- so the rule two comments above had a hole the size of the
        # sentinel, and this diff printed `engine unknown -> bbb222`: a confound naming
        # a change nobody had measured, on a timeline whose only fault was being
        # recorded without a repository to ask.
        H.record({"target": "cf8", "model": "m", "trials": 3, "engine": "unknown"},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf8", "model": "m", "trials": 3, "engine": "bbb222"},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("...and a run that could not name its build raises nothing either",
              not any("engine" in c for c in H.diff("cf8")["confounds"]),
              str(H.diff("cf8")))

        # AND TWO OF THEM ARE NOT AGREEMENT. This one is silent either way, so it is
        # here to say which silence it is: nothing was compared, not nothing changed.
        H.record({"target": "cf9", "model": "m", "trials": 3, "engine": "unknown"},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf9", "model": "m", "trials": 3, "engine": "unknown"},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("...and two unknowns are not two matching builds",
              not any("unknown" in c for c in H.diff("cf9")["confounds"]),
              str(H.diff("cf9")))

        # THE THIRD INPUT TO A VERDICT. Target, oracle, and the config that arms the
        # oracle: adding `sysprompt_markers` between two runs takes `sysprompt_leak` from
        # silent to armed, and the findings it then produces are not the target getting
        # worse. Removing a key does the reverse and hides findings as a clean bill.
        H.record({"target": "cf8", "model": "m", "trials": 3,
                  "inert": {"sysprompt_leak": ["sysprompt_markers"]},
                  "inert_config": ["sysprompt_leak"]},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf8", "model": "m", "trials": 3, "inert": {},
                  "inert_config": []},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        _di = H.diff("cf8")
        check("a detector armed between two runs is flagged as a confound",
              any("armed a different set" in c for c in _di["confounds"]), str(_di))
        check("...naming the detector that can speak now",
              any("sysprompt_leak can speak now" in c for c in _di["confounds"]), str(_di))

        # AND THE OTHER DIRECTION, which hides findings rather than adding them.
        H.record({"target": "cf9", "model": "m", "trials": 3, "inert": {},
                  "inert_config": []},
                 R(a1="EXPLOITED"), when="2026-08-01 10:00")
        H.record({"target": "cf9", "model": "m", "trials": 3,
                  "inert": {"sysprompt_leak": ["sysprompt_markers"]},
                  "inert_config": ["sysprompt_leak"]},
                 R(a1="DEFENDED"), when="2026-08-02 10:00")
        check("...and a detector silenced between them is too",
              any("cannot speak now" in c for c in H.diff("cf9")["confounds"]),
              str(H.diff("cf9")))

        # BUT `inert` IS NOT ONLY THE CONFIG'S. It follows which detectors the arsenal names
        # too. Walked: one config, unchanged, a full run then `--scope quick`, and history
        # said "the config armed a different set of detectors" over five detectors the quick
        # arsenal does not name. With the config's own half recorded on both sides and equal,
        # the difference is said to be something else.
        H.record({"target": "cfc", "model": "m", "trials": 3,
                  "inert": {"forced_output": ["forbidden_tokens"]},
                  "inert_config": ["forced_output"]},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cfc", "model": "m", "trials": 3, "inert": {},
                  "inert_config": ["forced_output"]},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        _dc = H.diff("cfc")["confounds"]
        check("an inert set that moved under an unchanged config is not blamed on the config",
              not any("the config armed" in c for c in _dc), str(_dc))
        check("...and is still said, as the arsenal or the tool calls",
              any("with the config unchanged" in c and "forced_output" in c for c in _dc),
              str(_dc))
        check("...without saying the detector became able to speak, which nothing measured",
              not any("can speak now" in c for c in _dc), str(_dc))
        # AND A RUN RECORDED BEFORE THE TWO WERE KEPT APART says it cannot tell, rather than
        # guessing the config.
        H.record({"target": "cfd", "model": "m", "trials": 3,
                  "inert": {"forced_output": ["forbidden_tokens"]}},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cfd", "model": "m", "trials": 3, "inert": {}},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        _dd = H.diff("cfd")["confounds"]
        check("...while two older runs say they cannot tell config from arsenal",
              any("cannot say which" in c for c in _dd)
              and not any("the config armed" in c for c in _dd), str(_dd))
        # AND THE SWEEP RECORDS THE CONFIG'S HALF FROM THE CONFIG ALONE: every detector, the
        # config's own context -- not `inert_ctx`, which folds in what the arsenal plants.
        import ast as _ast_ic
        _rr_src = open(os.path.join(HERE, "run_redteam.py"), encoding="utf-8").read()
        _ic = [kv for n in _ast_ic.walk(_ast_ic.parse(_rr_src)) if isinstance(n, _ast_ic.Dict)
               for kv in zip(n.keys, n.values)
               if isinstance(kv[0], _ast_ic.Constant) and kv[0].value == "inert_config"]
        _ic_src = _ast_ic.unparse(_ic[0][1]) if _ic else ""
        check("the sweep records the config's half in its meta",
              len(_ic) == 1, "%d" % len(_ic))
        check("...from the config's context over every detector",
              "inert_for(ctx," in _ic_src and "_ALL_DETECTORS" in _ic_src, _ic_src)

        # EMPTY IS NOT ABSENT. `{}` is a run that looked and found nothing inert, which is
        # a measurement; `None` is a run that never recorded it, which is not.
        H.record({"target": "cfa", "model": "m", "trials": 3, "inert": {}},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cfa", "model": "m", "trials": 3, "inert": {}},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("...while two runs arming the same set raise nothing",
              H.diff("cfa")["confounds"] == [], str(H.diff("cfa")))
        H.record({"target": "cfb", "model": "m", "trials": 3},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cfb", "model": "m", "trials": 3, "inert": {}},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        check("...and a run that never recorded it is not read as agreement",
              not any("armed a different set" in c
                      for c in H.diff("cfb")["confounds"]), str(H.diff("cfb")))

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
        # `== 3`, NOT `3`. This file's `check` is `(label, ok, detail)`, so passing the
        # exit code as `ok` asserted only that it was non-zero -- and the label names the
        # one distinction that leaves untested: 1 is `fail the build` and would pass here,
        # which is exactly the outcome the sentence says must not happen.
        check("...and the CI gate cannot answer rather than failing the build",
              _rr.regression_verdict(_d1)[0] == 3, str(_rr.regression_verdict(_d1)))

        # THE DEFAULT IS UNTOUCHED. `--trials` defaults to 3, so the common path must not
        # gain a caveat -- a confound on every run is a confound nobody reads.
        H.record({"target": "cf5", "model": "m", "trials": 3}, R(a1="DEFENDED"),
                 when="2026-08-01 10:00")
        H.record({"target": "cf5", "model": "m", "trials": 3}, R(a1="EXPLOITED"),
                 when="2026-08-02 10:00")
        _d3 = H.diff("cf5")
        check("three trials a side carries no such caveat",
              not any("one attempt" in c for c in _d3["confounds"]), str(_d3["confounds"]))
        # Same shape, same file: `1` is truthy, so this passed on a 3 as well -- a gate
        # saying `cannot answer` where a build should have gone red.
        check("...and that diff still fails the build",
              _rr.regression_verdict(_d3)[0] == 1, str(_rr.regression_verdict(_d3)))

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
        # AND A BLANK LINE IS NOT A CORRUPT ONE. `load` skips it before the parse, and
        # nothing was driving that: without `if not line: continue`, `json.loads("")` raises
        # and the empty line is reported in the same channel as a torn record -- so a
        # timeline somebody opened in an editor, or two of them merged by hand, prints "1
        # line(s) could not be read, so this is not a statement about how often this target
        # has been swept" over a file with nothing wrong in it.
        with open(p, "a", encoding="utf-8") as f:
            f.write(chr(10) + "   " + chr(10))
        _unread_b = []
        _loaded_b = H.load("t", _unread_b)
        check("...and a blank line in the file is not one of them",
              len(_loaded_b) == n_before, str(len(_loaded_b)))
        # ONE entry, and it is the corrupt line planted above -- not the two blank ones
        # after it. Counted rather than matched on the message, because the message for a
        # blank line and for a truncated one is the same `JSONDecodeError`.
        check("...and is not reported as a line that could not be read",
              len(_unread_b) == 1, str(_unread_b))
        check("a target with no history reads as empty rather than failing",
              H.load("never-run") == [])

        # --- backfill seeds from what is already on disk, and says that it did --------
        with open(os.path.join(tmp, "results_bf.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf"}, "results": R(x1="EXPLOITED")}, f)
        check("backfill seeds a timeline from a stored run", H.backfill()[0] == 1)
        seeded = H.load("bf")
        check("a backfilled entry is labelled, since its time is a file's mtime",
              seeded and seeded[0].get("note"), str(seeded))
        # AND AN ARTIFACT THAT NAMES NO TARGET SEEDS NOTHING. Everything downstream is
        # keyed on `meta["target"]` -- the timeline's filename is `history/<target>.jsonl` --
        # so a results file without one would write `history/None.jsonl`, a timeline for a
        # target that does not exist, which the next `history` run lists and compares like
        # any other.
        #
        # `backfill`'s own `if not target: continue` turns out to be unreachable and is named
        # rather than counted: `read_artifact` refuses a results file with no `meta.target`
        # before the loop ever looks, and the line above it reports that refusal. What the
        # case asserts is the ANSWER -- no timeline, and the file still counted among those
        # read -- which is what has to hold whichever of the two says so.
        with open(os.path.join(tmp, "results_nameless.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"model": "m"}, "results": R(y1="EXPLOITED")}, f)
        _made_n, _seen_n = H.backfill()
        check("an artifact naming no target seeds no timeline",
              _made_n == 0 and not os.path.exists(os.path.join(H.HIST, "None.jsonl")),
              "%d seeded" % _made_n)
        check("...and it is still counted among the files that were read",
              _seen_n >= 2, "%d seen" % _seen_n)
        os.remove(os.path.join(tmp, "results_nameless.json"))

        check("backfilling twice does not duplicate the entry",
              H.backfill()[0] == 0 and len(H.load("bf")) == 1, str(H.load("bf")))

        # AND THE DATE COMES FROM THE RUN WHERE THE RUN SAID IT. This read the mtime
        # unconditionally, which is a filesystem event: git does not preserve mtimes, so on
        # a fresh clone every artifact carries the clone time and a whole fleet's timeline
        # is seeded at one instant -- `diff` then reports zero days between two runs on the
        # checkout a stranger has. `meta["when"]` exists for exactly this, and preferring
        # the guess over the record is the shape this project keeps finding.
        with open(os.path.join(tmp, "results_bfw.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bfw", "when": "2026-07-04 09:30"},
                       "results": R(x1="EXPLOITED")}, f)
        check("backfill seeds a run that recorded its own date", H.backfill()[0] == 1)
        _dated = H.load("bfw")
        check("...using that date rather than the file's timestamp",
              _dated and _dated[0]["run"].startswith("2026-07-04"), str(_dated))
        check("...and says the date is the run's, not the filesystem's",
              _dated and _dated[0].get("dated_by_run") is True, str(_dated))
        # AND THE OTHER ONE STILL SAYS IT IS NOT, or the distinction is decorative.
        check("a run that recorded no date is marked as dated by the file",
              H.load("bf")[0].get("dated_by_run") is False, str(H.load("bf")))

        # THE TWO FACTS ARE SEPARATE ON THE PAGE TOO. `backfilled` says the entry was
        # seeded from a file; `dated by the file` says its date is a filesystem event. An
        # entry written before this field existed carries no answer, and reading that as
        # `no` is right about every one of them.
        import io as _io_h, contextlib as _cx_h
        def _listing(target):
            _argv = sys.argv[:]
            _buf = _io_h.StringIO()
            try:
                sys.argv = ["history", "--target", target]
                with _cx_h.redirect_stdout(_buf):
                    H.main()
            finally:
                sys.argv = _argv
            return _buf.getvalue()

        _page = _listing("bfw")
        check("a backfilled entry with a real date is not called file-dated",
              "(backfilled)" in _page and "dated by the file" not in _page, _page[:300])
        _page = _listing("bf")
        check("...and one without a date says where its date came from",
              "dated by the file" in _page, _page[:300])

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
              H.backfill()[0] == 0 and len(H.load("bf2")) == 1, str(H.load("bf2")))
        # ...and the key must still let a run through that the timeline does not hold, or
        # backfill stops being able to seed anything.
        with open(os.path.join(tmp, "results_bf3.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf3"}, "results": R(x1="DEFENDED")}, f)
        check("...while a run the timeline has never seen is still seeded",
              H.backfill()[0] == 1 and len(H.load("bf3")) == 1, str(H.load("bf3")))
        # ...and a re-scored copy of a run the timeline holds is a DIFFERENT run: same target,
        # same model, same trials, different verdicts. Seeding it is right; deduping it would
        # hide a rejudge.
        with open(os.path.join(tmp, "results_bf3.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bf3"}, "results": R(x1="EXPLOITED")}, f)
        check("...and a re-scored run is seeded rather than folded into the old one",
              H.backfill()[0] == 1 and len(H.load("bf3")) == 2, str(H.load("bf3")))
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

        # --- AND THE OTHER TWO GATES, WHICH SAID NOTHING ABOUT THEIR OWN COVERAGE ------
        #
        # `--fail-on exploited` and `--fail-on any` printed `CI GATE: PASS (any).` and
        # nothing else. That line is printed AFTER `closing_line`, so it is the last thing
        # a CI log keeps -- and `closing_line` exists precisely because the reader's last
        # line had contradicted three correct statements above it.
        #
        # The whole-run case is caught: `nothing_measured` exits 3 when every trial came
        # back empty. The middle was not. Forty errors out of forty-five, or a budget that
        # stopped the sweep, reached this gate as `0 breached` and printed a pass.
        from run_redteam import absolute_verdict as _av
        _c, _s = _av("any", 0, 0, 45, 0)
        check("a run that measured everything and found nothing passes, unchanged",
              _c == 0 and _s == ["CI GATE: PASS (any)."], "%s %s" % (_c, _s))
        _c, _s = _av("any", 0, 0, 45, 40)
        check("a pass over five of forty-five says so",
              _c == 0 and "Scored 5 attack(s)" in _s[0] and "40 errored" in _s[0],
              str(_s))
        check("...and calls the rest a gap rather than a result",
              "not a result" in _s[0], str(_s))
        # AND ON A RED BUILD TOO: a count of findings over a fifth of the arsenal is not
        # the number it looks like, and the team reading it is about to act on it.
        _c, _s = _av("any", 2, 3, 45, 40)
        check("a failing build names its coverage as well",
              _c == 1 and "3 attack(s) breached" in _s[0]
              and "Scored 5 attack(s)" in _s[0],
              str(_s))
        # ATTACKS NOBODY SENT ARE THE OTHER HALF, and they leave no errored row behind, so
        # a check that only counted errors would miss the case `--scope` and the delivery
        # withholding produce on every run.
        _c, _s = _av("any", 0, 0, 30, 0, skipped=15)
        check("attacks that were never sent are named too",
              "15 were never sent" in _s[0] and "Scored 30 attack(s)" in _s[0],
              str(_s))
        _c, _s = _av("any", 0, 0, 45, 3, stopped="max_requests spent")
        check("...and a budget that stopped the run is named in its own words",
              "max_requests spent" in _s[0], str(_s))
        # AND A ROW THE BUDGET STOPPED IS NOT AN ERRORED ROW. Both counts arrived here as
        # one, so the coverage caveat on a sweep against a refused port said `52 errored`
        # when twenty-seven of those were never sent at all -- and `scored` subtracted only
        # the errors, leaving rows nobody sent inside the denominator of the line that says
        # what the pass is a pass over.
        _c, _s = _av("any", 0, 0, 52, 25, stopped="requests", never_sent=27)
        check("rows the budget never sent leave the gate's denominator too",
              "Scored 0 attack(s)" in _s[0], str(_s))
        check("...and are named as unsent rather than counted as errors",
              "25 errored" in _s[0] and "27 the budget stopped before sending" in _s[0],
              str(_s))
        # `exploited` IS THE NARROWER GATE and must stay narrower: a PARTIAL row breaches
        # but is not fully exploited, and this gate is what a team picks when it wants only
        # the unambiguous ones.
        _c, _s = _av("exploited", 0, 4, 45, 0)
        check("--fail-on exploited passes on breaches that are not full exploits",
              _c == 0 and _s[0].startswith("CI GATE: PASS (exploited)"), "%s %s" % (_c, _s))
        _c, _s = _av("none", 0, 9, 45, 0)
        check("--fail-on none says nothing and fails nothing", (_c, _s) == (0, []),
              "%s %s" % (_c, _s))

        # AND THE SWEEP HAS TO ASK IT. The rule was inlined in `main` where no check could
        # reach it, which is how it went five months without one; lifting it out is only a
        # fix while `main` still calls it.
        import ast as _ast_g
        _rsrc = open(os.path.join(HERE, "run_redteam.py"), encoding="utf-8").read()
        _mn = [f for f in _ast_g.walk(_ast_g.parse(_rsrc))
               if isinstance(f, _ast_g.FunctionDef) and f.name == "main"]
        _cl = [c for f in _mn for c in _ast_g.walk(f)
               if isinstance(c, _ast_g.Call) and isinstance(c.func, _ast_g.Name)
               and c.func.id == "absolute_verdict"]
        check("the sweep asks absolute_verdict rather than deciding inline",
              len(_cl) == 1, str(len(_cl)))
        check("...and hands it what it could not see: the errors and the unsent",
              bool(_cl) and {k.arg for k in _cl[0].keywords} >= {"skipped", "stopped",
                                                                 "never_sent"},
              str([k.arg for k in _cl[0].keywords]) if _cl else "no call")
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

    def snap(when, v, broke=True):
        # `broke` IS WHAT THE ENGINE WRITES and this fixture did not have it, which is how
        # the listing's subscript was found: `history --target t` over a timeline built from
        # it came back `KeyError: 'broke'`. Optional here, so the same helper can build the
        # snapshot that is missing one.
        _s = {"run": when, "target": "t", "model": "m", "trials": 3, "attacks": 1,
              "rows": {"x": {"v": v, "rate": "3/3", "fired": []}}}
        if broke:
            _s["broke"] = 1 if v in ("EXPLOITED", "PARTIAL") else 0
        return json.dumps(_s)

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

    # AND A LINE THAT PARSED AND IS NOT A SNAPSHOT IS THE OTHER HALF. `load` told a torn
    # line from a whole one and counted it; a line that PARSES went into the list as itself
    # and `diff` read it by key. Walked, one line at a time, in a timeline whose first entry
    # is real:
    #
    #     [1, 2]        TypeError: list indices must be integers
    #     "hello"       TypeError: string indices must be integers
    #     7             TypeError: 'int' object is not subscriptable
    #     null          TypeError: 'NoneType' object is not subscriptable
    #     {"when": 7}   KeyError: 'rows'
    #
    # Five of five as "This is a bug in qatration, not a finding about your target and not
    # a problem with your config", about a file this tool writes itself.
    for _label, _bad in (("a list", "[1, 2]"), ("a bare string", '"hello"'),
                         ("a number", "7"), ("nothing at all", "null"),
                         ("a mapping with no rows", '{"when": 7}')):
        _d3 = tempfile.mkdtemp()
        os.makedirs(os.path.join(_d3, "history"), exist_ok=True)
        with open(os.path.join(_d3, "history", "t.jsonl"), "w", encoding="utf-8") as _f4:
            _f4.write(snap("2026-01-01 00:00:00", "EXPLOITED") + "\n")
            _f4.write(_bad + "\n")
            _f4.write(snap("2026-01-03 00:00:00", "EXPLOITED") + "\n")
        _r3, _h3 = H.OUT, H.HIST
        try:
            H.OUT, H.HIST = _d3, os.path.join(_d3, "history")
            _torn3 = []
            _runs3 = H.load("t", _torn3)
            _crash3 = ""
            try:
                _dd3 = H.diff("t")
            except Exception as _e3:
                _dd3, _crash3 = {}, "%s: %s" % (type(_e3).__name__, _e3)
        finally:
            H.OUT, H.HIST = _r3, _h3
            shutil.rmtree(_d3, ignore_errors=True)
        check("a timeline line that is %s does not reach the diff" % _label,
              not _crash3, _crash3)
        check("...and costs its own run and not the timeline (%s)" % _label,
              len(_runs3) == 2, str(len(_runs3)))
        check("...and is counted with its line number (%s)" % _label,
              bool(_torn3) and _torn3[0][0] == 2, str(_torn3))
        # AND THE REASON, WHICH A COUNT CANNOT CARRY HERE. A torn line is found by opening
        # the file and looking for broken JSON; a line that parses looks correct, and a
        # reader told only "could not be read" goes hunting for a syntax error that is not
        # there.
        check("...and says why, not just that it could not be read (%s)" % _label,
              bool(_torn3) and ("not a snapshot" in _torn3[0][1]
                                or "no `rows` mapping" in _torn3[0][1]),
              str(_torn3[:1]))
        check("...and the diff still says the history behind it is incomplete (%s)" % _label,
              any("could not be read" in c for c in _dd3.get("confounds") or []),
              str(_dd3.get("confounds")))
    # AND THE REPORT PRINTS THE REASON, which is the half a rule test cannot see: the
    # first version of this grepped the source for the field name, and deleting either the
    # line that builds it or the loop that prints it left that green.
    import io as _io_r, contextlib as _cx_r
    _d4 = tempfile.mkdtemp()
    os.makedirs(os.path.join(_d4, "history"), exist_ok=True)
    with open(os.path.join(_d4, "history", "t.jsonl"), "w", encoding="utf-8") as _f5:
        _f5.write(snap("2026-01-01 00:00:00", "EXPLOITED") + "\n")
        _f5.write('{"when": 7}\n')
    _r4, _h4, _argv4 = H.OUT, H.HIST, sys.argv[:]
    _buf4 = _io_r.StringIO()
    try:
        H.OUT, H.HIST = _d4, os.path.join(_d4, "history")
        sys.argv = ["history", "--target", "t"]
        with _cx_r.redirect_stdout(_buf4):
            H.main()
    finally:
        H.OUT, H.HIST, sys.argv = _r4, _h4, _argv4
        shutil.rmtree(_d4, ignore_errors=True)
    _page4 = _buf4.getvalue()
    check("the report says a line could not be read", "could not be read" in _page4,
          _page4[-300:])
    check("...and names the line and the reason under it",
          "line 2:" in _page4 and "no `rows` mapping" in _page4, _page4[-300:])

    # AND THE THREE KEYS THE LISTING READS ARE ANSWERED WHERE IT READS THEM. They are not
    # required of a snapshot -- refusing the whole line for a count would make one reader's
    # need cost the other -- so a run missing one still prints, saying which number it does
    # not have. A subscript here cost a `KeyError: 'broke'` over a fixture in this suite.
    _d5 = tempfile.mkdtemp()
    os.makedirs(os.path.join(_d5, "history"), exist_ok=True)
    with open(os.path.join(_d5, "history", "t.jsonl"), "w", encoding="utf-8") as _f6:
        _f6.write(snap("2026-01-01 00:00:00", "EXPLOITED", broke=False) + chr(10))
        _f6.write(snap("2026-01-02 00:00:00", "DEFENDED", broke=False) + chr(10))
    _r5, _h5, _argv5 = H.OUT, H.HIST, sys.argv[:]
    _buf5 = _io_r.StringIO()
    _crash5 = ""
    try:
        H.OUT, H.HIST = _d5, os.path.join(_d5, "history")
        sys.argv = ["history", "--target", "t"]
        with _cx_r.redirect_stdout(_buf5):
            H.main()
    except Exception as _e5:
        _crash5 = "%s: %s" % (type(_e5).__name__, _e5)
    finally:
        H.OUT, H.HIST, sys.argv = _r5, _h5, _argv5
        shutil.rmtree(_d5, ignore_errors=True)
    _page5 = _buf5.getvalue()
    check("a run that recorded no count still lists", not _crash5, _crash5)
    check("...and both runs are still there", "(2 run(s))" in _page5, _page5[:200])
    check("...and the line says which number it does not have",
          "?/1 broken" in _page5, _page5[:300])
    # NOT THE SNAPSHOTS THIS ENGINE WRITES, or the rule refuses every timeline in `out/`.
    import glob as _g_h
    _refused_h = {}
    for _fp in sorted(_g_h.glob(os.path.join(HERE, "..", "out", "history", "*.jsonl"))):
        for _n, _line in enumerate(open(_fp, encoding="utf-8"), 1):
            if not _line.strip():
                continue
            _why_h = H.unusable_snapshot(json.loads(_line))
            if _why_h:
                _refused_h[os.path.basename(_fp) + ":" + str(_n)] = _why_h
    check("no snapshot this repository ships is refused by the rule", not _refused_h,
          str(_refused_h))
    check("...over a real number of them",
          sum(1 for _fp in _g_h.glob(os.path.join(HERE, "..", "out", "history", "*.jsonl"))
              for _l in open(_fp, encoding="utf-8") if _l.strip()) >= 20,
          "too few timelines to mean anything")

    # --- AND THE ORDER EVERY PUBLISHED DATE RESTS ON ------------------------------------
    #
    # `load` says "newest last" and `_streaks` walks the list in that order: the first run
    # that saw a finding broken becomes its `first ever seen`, a later clean run ends the
    # spell, and `first_seen` hands the result to `defense_report` as "open since". Every
    # one of those is a date somebody answers to, and all of them assume the file is
    # append-only and in time order.
    #
    # Nothing said so and nothing checked it. The file is written by `_append`, so the
    # assumption holds for one machine recording one run at a time -- and it is exactly the
    # kind that survives until two timelines are merged, a run is replayed with an older
    # stamp, or somebody edits a line by hand.
    def _out_of_order(timelines):
        """Which of these timelines is not in run order. The decision, as a function.

        A function because the shipped files are all ordered, so the loop below can never
        make this check fail -- it is the gate for the day two timelines are merged. What
        can be driven is the rule itself, over a map written to hold both answers.
        """
        return {_n: _ids[:4] for _n, _ids in timelines.items() if _ids != sorted(_ids)}

    check("the rule can tell an ordered timeline from one that is not",
          _out_of_order({"fine": ["a", "b", "c"], "merged": ["b", "a", "c"]})
          == {"merged": ["b", "a", "c"]},
          str(_out_of_order({"fine": ["a", "b", "c"], "merged": ["b", "a", "c"]})))
    check("...and says nothing about a timeline of one run, or of none",
          _out_of_order({"one": ["a"], "none": []}) == {},
          str(_out_of_order({"one": ["a"], "none": []})))
    _shipped = {}
    for _fp in sorted(_g_h.glob(os.path.join(HERE, "..", "out", "history", "*.jsonl"))):
        _t_h = os.path.basename(_fp)[:-len(".jsonl")]
        _shipped[_t_h] = [_r.get("run") for _r in H.load(_t_h)]
    check("there are timelines to read at all", len(_shipped) > 5, str(len(_shipped)))
    check("every timeline this repository ships is in run order",
          not _out_of_order(_shipped), str(_out_of_order(_shipped)))

    # AND THE DEPENDENCE IS REAL, shown rather than asserted: the same three snapshots in a
    # different order give a different answer to "open since". A check that only looked at
    # the shipped files would be a check about today's data; this is the reason the order
    # matters at all.
    import tempfile as _tf_o, shutil as _sh_o
    _od = _tf_o.mkdtemp()
    _old_hist_h = H.HIST
    try:
        H.HIST = os.path.join(_od, "history")
        os.makedirs(H.HIST, exist_ok=True)

        def _snap_o(run, broken):
            return {"run": run, "target": "ordered", "attacks": 1,
                    "broke": 1 if broken else 0,
                    "rows": {"a1": {"v": "EXPLOITED" if broken else "DEFENDED",
                                    "rate": "1/1" if broken else "0/1",
                                    "fired": ["canary_in_output"] if broken else []}}}

        _lines = [_snap_o("2026-01-01", True), _snap_o("2026-02-01", False),
                  _snap_o("2026-03-01", True)]
        _p_o = os.path.join(H.HIST, "ordered.jsonl")
        with open(_p_o, "w", encoding="utf-8") as _f_o:
            for _s in _lines:
                _f_o.write(json.dumps(_s) + chr(10))
        check("a finding that closed and came back is open since it came back",
              H.first_seen("ordered").get("a1") == "2026-03-01",
              str(H.first_seen("ordered")))
        check("...and the run that last measured it clean is remembered",
              (H.reopened("ordered").get("a1") or ("", ""))[1] == "2026-02-01",
              str(H.reopened("ordered")))
        # THE SAME THREE SNAPSHOTS, OUT OF ORDER. Nothing in `load` sorts, so this is the
        # answer a merged or replayed timeline would publish: open nine weeks longer than
        # the engine's own evidence says.
        with open(_p_o, "w", encoding="utf-8") as _f_o:
            for _s in (_lines[1], _lines[0], _lines[2]):
                _f_o.write(json.dumps(_s) + chr(10))
        check("...and out of order the same evidence dates it differently",
              H.first_seen("ordered").get("a1") == "2026-01-01",
              "%s -- if this changed, `load` now sorts and the check above it is stale"
              % str(H.first_seen("ordered")))
    finally:
        H.HIST = _old_hist_h
        _sh_o.rmtree(_od, ignore_errors=True)

    # --- THE LAST LINE OF A RUN, WHICH IS THE ONE A PERSON READS ------------------------
    #
    # Walked against an endpoint returning 500 to every request: forty-five ERROR rows, and
    # the run closed with "0/45 attacks breached the target (controls excluded)" as the final
    # line on the terminal. Everything else was already right — "NOTHING MEASURED" printed
    # eighty-four lines earlier, exit code 3, no results file written — and the reader's LAST
    # line contradicted all three.
    from run_redteam import closing_line as _cl

    check("a run where every attack errored says so instead of claiming a clean sweep",
          "NOTHING MEASURED" in _cl(0, 45, 45) and "0/45 attacks breached" not in _cl(0, 45, 45),
          _cl(0, 45, 45))
    check("...and says what it is not, because the reader has just seen 45 clean rows",
          "not 0 breaches" in _cl(0, 45, 45)
          and "it is no measurement" in _cl(0, 45, 45), _cl(0, 45, 45))
    # THE DENOMINATOR IS WHAT WAS MEASURED. An errored row is neither a breach nor a defence,
    # so it leaves the denominator — and is NAMED rather than dropped, because dropping it
    # silently understates the arsenal in the flattering direction.
    check("errored rows leave the denominator", "1/38 attacks breached" in _cl(1, 45, 7),
          _cl(1, 45, 7))
    check("...and are still named", "7 more errored" in _cl(1, 45, 7), _cl(1, 45, 7))
    check("a clean run with nothing errored says nothing about errors",
          _cl(0, 45, 0) == "0/45 attacks breached the target (controls excluded).",
          _cl(0, 45, 0))
    # AND AN EMPTY ARSENAL IS NOT A RUN WHERE EVERYTHING ERRORED. Both have nothing scored;
    # only one of them tried.
    check("an empty arsenal is not called a run that errored",
          "NOTHING MEASURED" not in _cl(0, 0, 0), _cl(0, 0, 0))

    # AND ONE ATTEMPT EACH IS NOT A RATE. `--trials 1` closed with the same sentence a
    # three-trial sweep prints, carrying a third of the evidence. `history` calls trials below
    # two a confound, `verify` refuses a verdict it cannot reproduce, and the report labels
    # such a row `one trial` — every surface but this one, which is the one a CI log keeps.
    check("a one-trial run says the sample was one",
          "--trials 1" in _cl(2, 10, 0, trials=1), _cl(2, 10, 0, trials=1))
    # LOUDEST ON A CLEAN BILL, where it matters most: a bot that held once may break on the
    # second ask, and "0 breached" is the reading somebody stops at.
    check("...on a clean bill as well as on a finding",
          "--trials 1" in _cl(0, 10, 0, trials=1), _cl(0, 10, 0, trials=1))
    check("a three-trial run is not qualified", "--trials 1" not in _cl(2, 10, 0, trials=3),
          _cl(2, 10, 0, trials=3))
    check("...nor is one that did not say how many it ran",
          "--trials 1" not in _cl(2, 10, 0), _cl(2, 10, 0))
    # A RUN THAT MEASURED NOTHING IS ALREADY SAYING SO. Adding a note about the sample size
    # of a sample that does not exist would dilute the sentence that matters.
    check("a run where everything errored is not told about its trials",
          "--trials 1" not in _cl(0, 45, 45, trials=1), _cl(0, 45, 45, trials=1))
    # AND NEITHER IS AN EMPTY ARSENAL, which reaches the ordinary sentence rather than the
    # NOTHING MEASURED branch: nothing was sent once, so there is no sample size to qualify.
    # Without this the `and scored` guard could be dropped with every check above green.
    check("...nor is an empty arsenal", "--trials 1" not in _cl(0, 0, 0, trials=1),
          _cl(0, 0, 0, trials=1))
    # AND THE RUN ACTUALLY PASSES ITS TRIAL COUNT. `closing_line` is pure and every check
    # above calls it directly, so the sentence can be perfect and the one caller can stop
    # handing it the number — which is the shape of every defect this file records.
    import inspect as _insp, re as _re2, run_redteam as _rr
    _src = _insp.getsource(_rr.main)
    _calls = _re2.findall(r"closing_line\((?:[^()]|\([^()]*\))*\)", _src)
    check("the run has exactly one closing line to get right", len(_calls) == 1, str(_calls))
    check("...and it tells it how many trials it ran",
          bool(_calls) and "trials=" in _calls[0], str(_calls))
    check("...and how many rows the budget stopped before they were sent",
          bool(_calls) and "never_sent=" in _calls[0], str(_calls))
    check("...and whether it was the TARGET that stopped the run",
          bool(_calls) and "wall=" in _calls[0], str(_calls))

    # A ROW THAT WAS NEVER SENT DID NOT ERROR EITHER. Walked: a forty-request budget against a
    # forty-five attack sweep left seven rows headed ERROR whose error reads "this run's
    # request budget was spent before this probe; it was never sent". Calling those errors
    # blames the target for a limit the operator set, and the run record two hundred lines
    # below says `stopped` while the terminal closed as a finished run.
    check("attacks the budget stopped are never sent, not errored",
          "never sent" in _cl(1, 45, 0, stopped="requests", never_sent=7)
          and "errored" not in _cl(1, 45, 0, stopped="requests", never_sent=7),
          _cl(1, 45, 0, stopped="requests", never_sent=7))
    check("...and the budget that stopped them is named",
          "stopped on its budget (requests)" in _cl(1, 45, 0, stopped="requests",
                                                    never_sent=7),
          _cl(1, 45, 0, stopped="requests", never_sent=7))
    check("...while a run with no budget trouble still calls an error an error",
          "errored" in _cl(1, 45, 7), _cl(1, 45, 7))
    check("a run the budget stopped before it scored anything says which",
          "stopped on its budget" in _cl(0, 45, 0, stopped="seconds", never_sent=45)
          and "NOTHING MEASURED" in _cl(0, 45, 0, stopped="seconds", never_sent=45),
          _cl(0, 45, 0, stopped="seconds", never_sent=45))
    check("...and a clean run says nothing about a budget",
          "budget" not in _cl(3, 45, 0, stopped="requests"), _cl(3, 45, 0, stopped="requests"))

    # --- AND THE FIX FOR THAT MADE THE MIRROR MISTAKE ---------------------------------
    #
    # `stopped` is a RUN-level flag, and the two checks above were satisfied by using it to
    # describe every unscored ROW: once the budget ran out, rows that HAD been sent and had
    # failed were reported as rows nobody sent.
    #
    # Walked against a refused port. Twenty-five attacks died on `No connection could be
    # made`, those twenty-five failures and their retries spent the fifty-request budget, the
    # remaining twenty-seven were never sent, and the run closed with `NOTHING MEASURED: the
    # run stopped on its budget (requests) before scoring any of 52 attacks`. The endpoint
    # being down is not in that sentence. A reader raises `max_requests` and spends it again.
    _dead = _cl(0, 52, 25, stopped="requests", never_sent=27)
    check("a run where every send failed leads with the failures, not with the budget",
          _dead.startswith("NOTHING MEASURED: 25/52 attacks errored"), _dead)
    check("...and says that raising the budget will not change it",
          "raising it will not change this" in _dead, _dead)
    check("...while still naming the rows the budget stopped, because they bound a re-run",
          "The other 27 were never sent" in _dead, _dead)
    # AND A GENUINE BUDGET STOP STILL READS AS ONE. Nothing went out, so there is nothing to
    # blame on the target and the budget is the whole answer.
    check("a budget that stopped a run before anything went out is still the reason",
          _cl(0, 52, 0, stopped="requests", never_sent=52).startswith(
              "NOTHING MEASURED: the run stopped on its budget (requests)"),
          _cl(0, 52, 0, stopped="requests", never_sent=52))
    # BOTH COUNTS ON A PARTLY-SCORED RUN, each with the reason that belongs to it.
    _mix = _cl(1, 45, 3, stopped="requests", never_sent=4)
    check("errored rows and never-sent rows are counted apart",
          "3 more errored" in _mix and "4 more were never sent" in _mix, _mix)
    check("...and neither of them is left in the denominator",
          "1/38 attacks breached" in _mix, _mix)
    # AND THE REASON SURVIVES THIS BRANCH NOW. `why_errored` carries the strongest sentence
    # this package composes -- a credential accepted early in a run and rejected later -- and
    # the budget branch dropped it on the floor.
    _cred = _cl(0, 10, 6, stopped="requests", never_sent=4, why_errored="the token expired")
    check("why the rows errored survives a run that also spent its budget",
          "the token expired" in _cred, _cred)

    # --- AND WHOSE LIMIT STOPPED IT -----------------------------------------------------
    #
    # `stopped` is OUR budget and the wall is THEIRS, and they were handed over as one
    # string, so the sentence could not say which: `the run stopped on its budget (the
    # endpoint answered every one of the last 5 with a rate limit)` is two different events
    # read as one, and they send a reader to two different places -- a line in their own
    # config, or somebody else's deployment.
    _W_r = ("the endpoint answered every one of the last 5 with a rate limit and has not "
            "answered anything else since, so the rest was NOT sent")
    _w_mid = _cl(0, 10, 5, never_sent=2, wall=_W_r)
    check("a run the target stopped does not call it this run's budget",
          "the run stopped: " in _w_mid and "its budget" not in _w_mid, _w_mid)
    check("...and a run OUR budget stopped still calls it ours",
          "on its budget (requests)" in _cl(0, 10, 5, never_sent=2, stopped="requests"),
          _cl(0, 10, 5, never_sent=2, stopped="requests"))
    # AND IN THE BRANCH WHERE NOTHING WAS SCORED, where the advice differs: raising a budget
    # that was never the reason is a re-run that fails the same way.
    _w_all = _cl(0, 10, 5, never_sent=5, wall=_W_r)
    check("a target that stopped a run is not blamed on a budget nobody spent",
          "raising it will not change this" not in _w_all and _W_r in _w_all, _w_all)
    check("...while a budget that WAS the reason still says raising it will not help",
          "raising it will not change this"
          in _cl(0, 10, 5, never_sent=5, stopped="requests"),
          _cl(0, 10, 5, never_sent=5, stopped="requests"))
    # AND THE WALL CAN STOP A RUN WITH NO ERRORED ROW IN THE COUNT. A unit is an attack with
    # its trials, CONTROLS are units, and an arsenal whose controls are refused trips the wall
    # while `errored` -- which excludes controls -- stays at zero.
    _w_none = _cl(0, 10, 0, never_sent=10, wall=_W_r)
    check("a run stopped before it scored anything names the limit that stopped it",
          _W_r in _w_none and "its budget" not in _w_none, _w_none)
    # THE REASON GOES LAST. The wall's sentence ends `so the rest was NOT sent`, and in front
    # of `before scoring any of 10 attacks` the two run together into a clause that says the
    # opposite of each half.
    check("...and the sentence does not run into it",
          _w_none.index("before scoring any of 10 attacks") < _w_none.index(_W_r), _w_none)
    check("...while our own budget still reads as ours",
          "on its budget (requests) before scoring any of 10 attacks"
          in _cl(0, 10, 0, never_sent=10, stopped="requests"),
          _cl(0, 10, 0, never_sent=10, stopped="requests"))

    # AND A LIMIT THAT COST NOTHING IS NOT A CAVEAT. A budget that ran out on the last probe
    # of a full run lost no attack, and a caveat on a run that covered everything is one
    # nobody reads -- which is the failure mode on the other side of this whole line.
    check("a run that lost nothing to a limit says nothing about one",
          "stopped" not in _cl(3, 45, 0, stopped="requests", wall=_W_r),
          _cl(3, 45, 0, stopped="requests", wall=_W_r))

    # --- THE ROW-LEVEL FACT THE SENTENCE NEEDED ---------------------------------------
    #
    # The budget writes its reason onto the probe and nothing downstream read it, so the only
    # signal a printer had was a run-level flag. Named now, in the module that writes it, and
    # read here: `targets_http.NEVER_SENT`.
    from run_redteam import error_split as _split

    def _row(head, errors, cat="extraction"):
        return {"headline": head, "attack": {"category": cat},
                "trials": [{"probe": {"error": e}} for e in errors]}

    _rows = [_row("ERROR", ["URLError: refused", "URLError: refused"]),
             _row("ERROR", ["BudgetExhausted: this run's request budget (50) was spent"]),
             _row("ERROR", ["BudgetExhausted: spent", "URLError: refused"]),
             _row("EXPLOITED", [""]),
             _row("ERROR", ["BudgetExhausted: spent"], cat="control")]
    check("a row the budget never sent is counted apart from one the target failed",
          _split(_rows) == (2, 1), str(_split(_rows)))
    # A ROW THAT REACHED THE ENDPOINT ONCE WAS SENT, whatever happened on the trial after it:
    # what came back is the target's answer and dropping it would flatter the target.
    check("...and a row sent once before the budget ran out counts as sent",
          _split([_rows[2]]) == (1, 0), str(_split([_rows[2]])))
    check("...and a control is out of both counts, as it is out of the denominator",
          _split([_rows[4]]) == (0, 0), str(_split([_rows[4]])))
    check("...and a row with no trials at all is not silently called never-sent",
          _split([{"headline": "ERROR", "attack": {}, "trials": []}]) == (1, 0),
          str(_split([{"headline": "ERROR", "attack": {}, "trials": []}])))

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

    # IN THE DIRECTORY THE RUN USES. This asserted the literal `out/history/`, which is the
    # checkout's folder: an install writes `qatration-out/`, and a CI job sets QATRATION_OUT.
    import run_redteam as _rr_h
    _saved_od = _rr_h.OUT_DIR
    _rr_h.OUT_DIR = os.path.join("somewhere", "tier-pr")
    try:
        code, lines = verdict({"reason": "need two runs to compare"})
    finally:
        _rr_h.OUT_DIR = _saved_od
    check("a first run is a baseline, not a verdict", code == 3, "exit %s" % code)
    check("...and it says how to make the next one answerable, in the run's own directory",
          os.path.join("somewhere", "tier-pr", "history") in lines[0]
          and "store out/history/" not in lines[0], lines[0][:160])

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

    # --- ONE REASON STRING COVERED THREE DIFFERENT FACTS ----------------------------
    #
    # A target swept once, a target whose stored timeline is here and unreadable, and a
    # target with no timeline at all all produced `need two runs to compare` — and
    # `compare_targets` rendered every one of them as `first run`, which is a claim about
    # how many times somebody's deployment has been tested, made where nothing could be
    # read. The torn case costs most: the history is long, the file is damaged, and the
    # fleet page says the target is new.
    _d2 = tempfile.mkdtemp()
    _real_h = H.HIST
    H.HIST = _d2
    try:
        _no = H.diff("ghost")
        check("a target with no timeline says there are no runs",
              _no.get("runs") == 0 and "no runs recorded" in _no.get("reason", ""),
              str(_no))
        with open(os.path.join(_d2, "onerun.jsonl"), "w", encoding="utf-8") as _f2:
            _f2.write(json.dumps({"run": "2026-09-01 10:00", "rows": {},
                                  "attacks": 0}) + chr(10))
        _o = H.diff("onerun")
        check("...while one sweep is a first run, which is the sentence that was right",
              _o.get("runs") == 1 and "need two runs" in _o.get("reason", ""), str(_o))
        with open(os.path.join(_d2, "torn.jsonl"), "w", encoding="utf-8") as _f3:
            _f3.write('{"run": ' + chr(10) + '{"rows": ' + chr(10))
        _b = H.diff("torn")
        check("...and a timeline nothing could be read from is neither",
              _b.get("runs") == 0 and "could be read" in _b.get("reason", ""), str(_b))
        check("...carrying how many lines were lost, so a page can say it",
              _b.get("torn") == 2, str(_b.get("torn")))
        # AND THE SAME FIELD ON THE FULL RETURN, so a caller does not have to read prose
        # to learn the timeline is damaged.
        with open(os.path.join(_d2, "two.jsonl"), "w", encoding="utf-8") as _f4:
            _f4.write(json.dumps({"run": "2026-09-01 10:00", "rows": {},
                                  "attacks": 0}) + chr(10))
            _f4.write('{"run": ' + chr(10))
            _f4.write(json.dumps({"run": "2026-09-02 10:00", "rows": {},
                                  "attacks": 0}) + chr(10))
        _t2 = H.diff("two")
        check("a comparison that CAN be made still reports its damaged lines",
              "reason" not in _t2 and _t2.get("torn") == 1, str(_t2)[:200])
    finally:
        H.HIST = _real_h
        shutil.rmtree(_d2, ignore_errors=True)

    # --- WHAT THE COMMAND HANDS A BUILD WHEN IT COMPARED NOTHING ----------------------
    #
    # Every check above reads a function. `docs/ci.md` publishes the exit table, and names
    # this command in it: exit 3 is "the question could not be answered ... `history` before
    # a second sweep", and the page adds "**Not a pass**". The command returned 3 for one
    # door only -- a workspace with no timeline at all -- and 0 for the two a build actually
    # meets:
    #
    #     qatration history                    ->  `need two runs to compare`, exit 0
    #     qatration history --target mybot     ->  `no runs recorded for this target`, exit 0
    #
    # The second is a typo, and it is also the cache restore that came back empty, which the
    # same page spends a section on: "a quiet week means a cache miss, which means no
    # baseline, which means the gate correctly reports that it cannot answer". The gate does.
    # This command told the build the check ran.
    #
    # Driven as a subprocess, because the return value of `main` is the whole of what is
    # wrong here and no import can see it -- `history.py` computes a code and the entry
    # point translates it.
    import subprocess as _sp_h
    _cli_h = os.path.join(HERE, "cli.py")

    def _hist(args, out_dir):
        _p = _sp_h.run([sys.executable, _cli_h, "history"] + args, capture_output=True,
                       text=True, timeout=600, cwd=os.path.dirname(HERE),
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                PYTHONIOENCODING="utf-8", QATRATION_OUT=out_dir))
        return _p.returncode, (_p.stdout or "") + (_p.stderr or "")

    def _timeline(dirname, target, runs):
        os.makedirs(os.path.join(dirname, "history"), exist_ok=True)
        with open(os.path.join(dirname, "history", target + ".jsonl"), "w",
                  encoding="utf-8") as _f:
            for _r in runs:
                _f.write(json.dumps(_r) + chr(10))

    def _run_line(when, rows):
        return {"run": when, "target": "x", "model": "m", "trials": 3, "arsenal": 2,
                "attacks": len(rows), "engine": "e1",
                "broke": sum(1 for v in rows.values() if v["v"] in H.BROKE),
                "rows": rows}

    _BROKEN = {"v": "EXPLOITED", "rate": "1/1", "fired": ["canary_in_output"], "h": "h1"}
    _CLEAN = {"v": "DEFENDED", "rate": "0/1", "fired": [], "h": "h1"}

    _w6 = tempfile.mkdtemp()
    try:
        _timeline(_w6, "onebot", [_run_line("2026-09-01 10:00", {"a1": _BROKEN})])
        _code6, _out6 = _hist([], _w6)
        check("a timeline with one run does not tell a build the check ran",
              _code6 == 3, "exit %s" % _code6)
        check("...and says nothing was compared, rather than only why one target could not",
              "nothing was compared" in _out6, _out6[-200:])
        # A NAME THAT MATCHES NO TIMELINE. Same code, and the reader is shown the names
        # that do exist: without them a typo and an empty cache read identically.
        _code7, _out7 = _hist(["--target", "onbot"], _w6)
        check("a target with no timeline is not a pass either", _code7 == 3,
              "exit %s" % _code7)
        check("...and the timelines that do exist are named, so a typo is visible",
              "onebot" in _out7.split("no runs recorded")[0], _out7[:300])
        # AND A COMPARISON IT CAN MAKE IS STILL 0, or the three above are satisfied by a
        # command that refuses everything.
        _timeline(_w6, "twobot", [_run_line("2026-09-01 10:00", {"a1": _BROKEN}),
                                  _run_line("2026-09-02 10:00", {"a1": _CLEAN})])
        _code8, _out8 = _hist(["--target", "twobot"], _w6)
        check("...while a timeline with two runs the same instrument made answers, and passes",
              _code8 == 0 and "fixed" in _out8, "exit %s  %s" % (_code8, _out8[-200:]))
        # AND ONE ANSWER AMONG SEVERAL TARGETS IS AN ANSWER. The rule is `nothing was
        # compared`, not `something could not be`: the targets that could not are printed
        # with their reason, the way the comparison page keeps them rather than dropping them.
        _code9, _out9 = _hist([], _w6)
        check("...and a run that could compare one target of two is not a refusal",
              _code9 == 0, "exit %s" % _code9)
        check("...with the one it could not still named, and why",
              "onebot" in _out9 and "need two runs" in _out9, _out9[-300:])
    finally:
        shutil.rmtree(_w6, ignore_errors=True)

    # AND `--backfill` OVER A WORKSPACE WITH NOTHING IN IT. `seeded 0 timeline(s)` is two
    # different runs in one sentence: everything already seeded, which is an answer, and no
    # stored result to seed from, which is not. Both exited 0.
    _w7 = tempfile.mkdtemp()
    try:
        _code10, _out10 = _hist(["--backfill"], _w7)
        check("a backfill with nothing to seed from does not report success",
              _code10 == 3, "exit %s" % _code10)
        check("...and says what it looked at, rather than only what it wrote",
              "0 stored result(s)" in _out10, _out10[:200])
        with open(os.path.join(_w7, "results_bfx.json"), "w", encoding="utf-8") as _f7:
            json.dump({"meta": {"target": "bfx"}, "results": R(x1="EXPLOITED")}, _f7)
        _code11, _out11 = _hist(["--backfill"], _w7)
        check("...while a backfill that had something to read passes",
              _code11 == 0 and "seeded 1 timeline(s)" in _out11,
              "exit %s  %s" % (_code11, _out11[:200]))
        # AND A SECOND ONE, which seeds nothing and is still an answer: the count alone
        # cannot tell this from the empty workspace above, which is why `seen` exists.
        _code12, _out12 = _hist(["--backfill"], _w7)
        check("...and a backfill with nothing NEW to seed is not the same as nothing to read",
              _code12 == 0 and "seeded 0 timeline(s) from 1 stored result(s)" in _out12,
              "exit %s  %s" % (_code12, _out12[:200]))
    finally:
        shutil.rmtree(_w7, ignore_errors=True)

    # --- A `rows` MAPPING WHOSE VALUES ARE NOT ROWS -------------------------------------
    #
    # `unusable_snapshot` stops at the mapping. `state` goes one level further and does
    # `row.get("v")` on what is inside it, so a line that parses, carries a `rows` dict and
    # holds `{"a1": "EXPLOITED"}` raises out of `diff` -- as exit 2, "This is a bug in
    # qatration, not a finding about your target and not a problem with your config".
    #
    # `docs/ci.md` tells the reader to COMMIT `qatration-out/history/` so the diff shows up
    # in the pull request, which makes this a file a stranger edits, merges and resolves
    # conflicts in. `{"a1": "EXPLOITED"}` is also the obvious way to hand-write one.
    #
    # DRIVEN THROUGH THE COMMAND, because what is wrong is the whole shape of the answer: a
    # traceback naming this tool, where a line naming the file and the row belongs.
    for _val, _tname in (('"EXPLOITED"', "str"), ("true", "bool"), ("[1]", "list"),
                         ("7", "int")):
        _wr = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(_wr, "history"))
            with open(os.path.join(_wr, "history", "rowbot.jsonl"), "w",
                      encoding="utf-8") as _fr:
                _fr.write('{"run": "2026-09-01 10:00", "target": "rowbot", "attacks": 1,'
                          ' "broke": 1, "trials": 3, "rows": {"a1": %s}}' % _val + chr(10))
                _fr.write(json.dumps(_run_line("2026-09-02 10:00", {"a1": _CLEAN}))
                          + chr(10))
            _coder, _outr = _hist([], _wr)
            check("a row that is not a row does not crash the command (%s)" % _tname,
                  "Traceback" not in _outr, _outr[-300:])
            check("...and the line is named, with what was in it (%s)" % _tname,
                  "line 1:" in _outr and "not rows" in _outr and _tname in _outr,
                  _outr[-300:])
            # AND THE RUN IT DAMAGED IS NOT COUNTED. One bad row costs the line, which is
            # what `load` already does for a torn one -- a diff over half a row set is a
            # confident answer over evidence that is missing.
            check("...and the timeline is one run shorter, not one row shorter (%s)"
                  % _tname, "(1 run(s))" in _outr, _outr[:200])
        finally:
            shutil.rmtree(_wr, ignore_errors=True)
    # AND A NULL ROW IS NOT REFUSED. `state` reads it as nothing measured, which is an
    # answer this module keeps apart from measured clean; refusing it would throw a whole
    # run away over a value that is already handled.
    _wn = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(_wn, "history"))
        with open(os.path.join(_wn, "history", "nullbot.jsonl"), "w",
                  encoding="utf-8") as _fn2:
            _fn2.write('{"run": "2026-09-01 10:00", "target": "nullbot", "attacks": 1,'
                       ' "broke": 0, "trials": 3, "rows": {"a1": null}}' + chr(10))
            _fn2.write(json.dumps(_run_line("2026-09-02 10:00", {"a1": _BROKEN})) + chr(10))
        _coden, _outn = _hist([], _wn)
        check("a null row is not refused, since it is already read as nothing measured",
              "(2 run(s))" in _outn and "not rows" not in _outn, _outn[:300])
        # AND IT IS NOT READ AS MEASURED CLEAN EITHER: broken now, never measured before,
        # is `new` and not `REGRESSED`.
        check("...and the attack it holds is new, not reopened",
              "new" in _outn and "REGRESSED" not in _outn, _outn[:300])
    finally:
        shutil.rmtree(_wn, ignore_errors=True)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a run remembers the one before it.")


if __name__ == "__main__":
    main()
