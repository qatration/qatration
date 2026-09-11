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

        # THE FIRST SIGHTING IS NOT THROWN AWAY, it is answered separately -- a page that
        # shows the spell and never mentions the fix has dropped the more interesting half.
        again = H.reopened("t")
        check("a finding that closed and came back says when it was first seen",
              (again.get("a1") or ("", ""))[0] == "2026-08-01 10:00", str(again))
        check("...and when a run last measured it clean",
              (again.get("a1") or ("", ""))[1] == "2026-08-03 10:00", str(again))
        check("...while a finding in its first spell is not called a return",
              "a4" not in again, str(again))

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
                  "inert": {"sysprompt_leak": ["sysprompt_markers"]}},
                 R(a1="DEFENDED"), when="2026-08-01 10:00")
        H.record({"target": "cf8", "model": "m", "trials": 3, "inert": {}},
                 R(a1="EXPLOITED"), when="2026-08-02 10:00")
        _di = H.diff("cf8")
        check("a detector armed between two runs is flagged as a confound",
              any("armed a different set" in c for c in _di["confounds"]), str(_di))
        check("...naming the detector that can speak now",
              any("sysprompt_leak can speak now" in c for c in _di["confounds"]), str(_di))

        # AND THE OTHER DIRECTION, which hides findings rather than adding them.
        H.record({"target": "cf9", "model": "m", "trials": 3, "inert": {}},
                 R(a1="EXPLOITED"), when="2026-08-01 10:00")
        H.record({"target": "cf9", "model": "m", "trials": 3,
                  "inert": {"sysprompt_leak": ["sysprompt_markers"]}},
                 R(a1="DEFENDED"), when="2026-08-02 10:00")
        check("...and a detector silenced between them is too",
              any("cannot speak now" in c for c in H.diff("cf9")["confounds"]),
              str(H.diff("cf9")))

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

        # AND THE DATE COMES FROM THE RUN WHERE THE RUN SAID IT. This read the mtime
        # unconditionally, which is a filesystem event: git does not preserve mtimes, so on
        # a fresh clone every artifact carries the clone time and a whole fleet's timeline
        # is seeded at one instant -- `diff` then reports zero days between two runs on the
        # checkout a stranger has. `meta["when"]` exists for exactly this, and preferring
        # the guess over the record is the shape this project keeps finding.
        with open(os.path.join(tmp, "results_bfw.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": {"target": "bfw", "when": "2026-07-04 09:30"},
                       "results": R(x1="EXPLOITED")}, f)
        check("backfill seeds a run that recorded its own date", H.backfill() == 1)
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

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a run remembers the one before it.")


if __name__ == "__main__":
    main()
