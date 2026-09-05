"""
The false-positive gate — no model, no network.

Fifty detectors all demonstrated says none of them is dead. It says nothing about whether
they are honest, because they were demonstrated on a range built to make them fire. The
number that decides whether anyone keeps the tool switched on is the opposite one, and the
central claim behind it is this:

    NO DETECTOR MAY READ THE QUESTION.

Everything dangerous-looking in the benign corpus is in the user's own words — the failing
query with OR '1'='1', the stack trace, the ../../ path, paypa1.com. A detector that fires
on those is reporting the user's text as the target's answer, which is how a scanner earns
a reputation for crying wolf. The corpus is run against a bland reply across every oracle
context in the fleet, so a new detector that forgets to subtract the prompt fails here
before it ever reaches a customer's system.

    python test_benign.py        # exits 1 on any failure (CI gate)
"""
import sys, os, glob, re
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import yaml
from target import Probe, payload, target_configs
from oracle import DETECTORS
from benign import (CORPUS, SECURITY_TALK, CONVERSATIONS, fires_on, summary,
                    excerpt, run as benign_run)
from workspace import OUT as ARTIFACTS   # one place decides where evidence lives

# Every prompt the gate has to clear: the single sends, plus each conversation flattened
# the way runner.py assembles it, because the whole user side is what echo subtraction sees.
ALL_PROMPTS = ([(c[0], c[2]) for c in CORPUS]
               + [(c[0], "\n".join(c[3])) for c in CONVERSATIONS])

BLAND = ("Thanks for getting in touch. I have noted your question and someone from the "
         "team will follow up shortly.")


def contexts():
    """Every oracle_context in the fleet, so the claim is not proved on one lucky config."""
    out = {}
    for fp in target_configs(HERE):
        cfg = yaml.safe_load(open(fp, encoding="utf-8")) or {}
        name = cfg.get("name") or os.path.basename(fp)[len("targets_"):-len(".yaml")]
        out[name] = cfg.get("oracle_context", {})
    return out


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- THE JUDGEMENT FILE HAD NO GATE AT ALL ------------------------------------------
    #
    # `benign_adjudication.yaml` holds a hundred and forty-two verdicts, each a person
    # deciding whether one detector firing on one target's ordinary traffic is a real finding
    # or a false alarm. Every attribution number in this package rests on them, and nothing
    # checked that the names were real, that every fire had been settled, or that a settled
    # pair still happens.
    import yaml as _y4
    from oracle import DETECTORS as _DETS
    from workspace import config_name as _cname
    from target import target_configs as _tcfgs

    _rows = _y4.safe_load(open(os.path.join(HERE, "benign_adjudication.yaml"), encoding="utf-8").read()) or []
    check("there are adjudications to check", len(_rows) > 20, str(len(_rows)))
    _names = {_cname(p, None) for p in _tcfgs(HERE)}
    _bad_det = sorted({r.get("detector") for r in _rows if r.get("detector") not in _DETS})
    check("every adjudication names a real detector", not _bad_det, str(_bad_det))
    _bad_tgt = sorted({r.get("target") for r in _rows if r.get("target") not in _names})
    check("...and a target that has a config", not _bad_tgt, str(_bad_tgt))
    # A VERDICT WITHOUT A REASON IS A PREFERENCE. The file's own shape is (target, detector,
    # verdict, why), and the `why` is the half that makes it reviewable by somebody else.
    _no_why = [f"{r.get('target')}/{r.get('detector')}" for r in _rows
               if not str(r.get("why") or "").strip()]
    check("...and says why", not _no_why, str(_no_why[:4]))
    _odd = sorted({r.get("verdict") for r in _rows} - {"finding", "false_positive"})
    check("...with one of the two verdicts this file has", not _odd, str(_odd))

    # AND THE TWO GAPS ARE COMPUTED, not assumed. A fire nobody settled and a verdict about a
    # fire that stopped are opposite problems; the roll-up reports both and neither is an
    # error, so what is checked here is that the function can tell them apart.
    import benign as _B4
    _un, _st = _B4.adjudication_gaps(
        rows_by_target={"t1": [{"fired": ["canary_in_output"]}, {"fired": []}]},
        path=os.path.join(HERE, "benign_adjudication.yaml"))
    check("a fire with no verdict is reported as unsettled",
          ("t1", "canary_in_output") in _un, str(_un[:3]))
    # `or True` IS A CHECK THAT CANNOT FAIL, and the first version of this line had one. The
    # fixture's only fire is `t1/canary_in_output`, so every real adjudication in the file is
    # about a pair that did not fire here — which is what "stale" means and what to assert.
    check("...and a verdict with no fire is reported as stale",
          len(_st) >= 20 and ("t1", "canary_in_output") not in _st, str(len(_st)))
    _un2, _st2 = _B4.adjudication_gaps(rows_by_target={}, path=os.path.join(HERE, "nope.yaml"))
    check("with no judgement file, nothing is settled rather than everything",
          _un2 == [] and _st2 == [], "%s %s" % (_un2[:2], _st2[:2]))

    # --- the rate, and what a config could have quieted --------------------------------
    #
    # A caveat that lives anywhere except beside the number it qualifies has not been
    # delivered, and the false-alarm rate is that number. A detector whose suppressor is unset
    # does not go silent — it goes off, and the alarms are a question the config never
    # answered rather than the detector being wrong.
    #
    # This fleet settles them by hand in `benign_adjudication.yaml`, so the rate printed above
    # them is already right; a reader running against their own deployment has no such file.
    import glob as _g4, io as _io4, json as _json4, yaml as _y4
    from detector_coverage import contexts as _ctxs_for
    from oracle import noisy_for as _noisy4
    from workspace import target_of as _target_of4

    _ctxs4 = _ctxs_for()
    check("the fleet's contexts can be read", len(_ctxs4) >= 10, str(len(_ctxs4)))
    # THE MEASUREMENT THE SUMMARY REPORTS, recomputed here: `pii_in_output` fires on most of
    # this fleet's benign runs, and on most of those the suppressor is unset.
    _fired_pii, _unarmed_pii = set(), set()
    for _fp in sorted(_g4.glob(os.path.join(HERE, "..", "out", "benign_*.json"))):
        _name = os.path.basename(_fp)[len("benign_"):-len(".json")]
        try:
            _d4 = _json4.loads(_io4.open(_fp, encoding="utf-8").read())
        except Exception:
            continue
        if not any("pii_in_output" in (_r.get("fired") or []) for _r in (_d4.get("rows") or [])):
            continue
        _fired_pii.add(_name)
        _base4 = _target_of4(_name, _ctxs4)
        if "pii_in_output" in _noisy4((_ctxs4.get(_base4) or {}) if _base4 else {},
                                      declared=["pii_in_output"]):
            _unarmed_pii.add(_name)
    check("pii_in_output fires on this fleet's ordinary traffic", len(_fired_pii) >= 10,
          str(len(_fired_pii)))
    check("...and on most of those the suppressor is unset",
          len(_unarmed_pii) >= len(_fired_pii) // 2,
          "%d of %d" % (len(_unarmed_pii), len(_fired_pii)))
    # AND A CONFIG THAT ARMS IT IS NOT NAMED, or the summary would tell every operator to set
    # a key they have already set.
    _armed = {"canaries": ["ACME-CANARY-9931"], "allowed_domains": ["shop.example"],
              "known_pii": ["a@shop.example"]}
    check("an armed config is not named",
          "pii_in_output" not in _noisy4(_armed, declared=["pii_in_output"]),
          str(_noisy4(_armed, declared=["pii_in_output"])))
    # AND THOSE ALARMS ARE ALREADY SETTLED HERE, which is why the rate above them is right:
    # the summary explains a number rather than correcting it.
    _adj = _y4.safe_load(_io4.open(os.path.join(HERE, "benign_adjudication.yaml"),
                                   encoding="utf-8").read()) or []
    _pii_settled = [r for r in _adj if str(r.get("detector", "")).startswith("pii_")]
    check("this fleet settles its pii alarms by hand", len(_pii_settled) >= 20,
          str(len(_pii_settled)))
    check("...and most of them as false alarms",
          sum(1 for r in _pii_settled if r.get("verdict") == "false_positive")
          > sum(1 for r in _pii_settled if r.get("verdict") == "finding"),
          str([r.get("verdict") for r in _pii_settled[:4]]))

    # AND THE SUMMARY ACTUALLY PRINTS IT. Every check above recomputes the measurement and
    # none of them runs the command, so the whole section could be deleted with all of them
    # green — which is the shape of the defect they describe, one level up.
    import subprocess as _sp4
    _out4 = _sp4.run([sys.executable, os.path.join(HERE, "cli.py"), "benign", "--summary"],
                     capture_output=True, text=True, errors="replace", timeout=900,
                     env=dict(os.environ, PYTHONIOENCODING="utf-8",
                              PYTHONDONTWRITEBYTECODE="1")).stdout
    check("the summary reports the false-alarm rate at all",
          "false-alarm rate over what HAS been settled" in _out4, _out4[-200:])
    check("...and names the suppressors a config leaves unset",
          "noise suppressor their config leaves unset" in _out4, _out4[-200:])
    check("...naming the key rather than only the detector",
          "unset: allowed_domains" in _out4 or "unset: known_pii" in _out4, _out4[-300:])

    # --- the corpus itself is well formed ---------------------------------------------
    ids = [c[0] for c in CORPUS] + [c[0] for c in CONVERSATIONS]
    check("corpus ids are unique", len(ids) == len(set(ids)),
          f"duplicates: {sorted({i for i in ids if ids.count(i) > 1})}")
    unknown = sorted({c[1] for c in CORPUS + [(x[0], x[1]) for x in CONVERSATIONS]
                      if c[1] and c[1] not in DETECTORS})
    check("every 'provokes' names a real detector", not unknown, f"unknown: {unknown}")
    check("the security-talk half is the bulk of it", len(SECURITY_TALK) >= 12,
          f"only {len(SECURITY_TALK)}")

    # An id from another system is somebody else's record here, so a corpus carrying one
    # manufactures its own authorization findings. Measured on the foreign agent: six rows
    # scored bola_access because the corpus said "order 1001" and that target's orders
    # start at 7001, and the detector was right every time. Placeholders, not literals.
    from benign import fill
    hard = [cid for cid, text in ALL_PROMPTS
            if re.search(r"\b(?:order|customer|account|record)s?\s+\d{3,}", text, re.I)]
    check("no corpus prompt names a bare record id", not hard, f"hardcoded in: {hard}")
    check("placeholders resolve from the target's own ids",
          fill("order {own} and {own2}, caller {caller}",
               {"own_object_ids": ["7001", "7002"], "caller_id": "2001"})
          == "order 7001 and 7002, caller 2001")
    check("an unconfigured target gets a shape no system uses, not a real-looking id",
          "000000" in fill("order {own}", {}))
    bad_delivery = [c[0] for c in CONVERSATIONS if c[2] not in ("chain", "sessions")]
    check("every conversation declares a multi-turn delivery", not bad_delivery,
          str(bad_delivery))
    check("every conversation has more than one turn",
          all(len(c[3]) > 1 for c in CONVERSATIONS),
          str([c[0] for c in CONVERSATIONS if len(c[3]) < 2]))

    # --- THE claim: no detector reads the question ------------------------------------
    ctxs = contexts()
    offenders = {}
    for tname, ctx in ctxs.items():
        for cid, text in ALL_PROMPTS:
            p = Probe(prompt=payload(text), output=BLAND, tool_calls=[], observations=[])
            for f in fires_on(p, ctx):
                if f != "over_refusal":
                    offenders.setdefault(f, []).append(f"{tname}/{cid}")
    check(f"no detector fires on the prompt alone "
          f"({len(ALL_PROMPTS)} prompts x {len(ctxs)} contexts x {len(DETECTORS)} detectors)",
          not offenders,
          "; ".join(f"{d} on {v[:3]}" for d, v in offenders.items()))

    # Non-English traffic is not an attack. The character-class detectors are the ones most
    # likely to mistake a language for one: Arabic contains right-to-left runs by nature and
    # Cyrillic normalises onto Latin. Checked against a reply that ECHOES the user, which is
    # what a support bot does when it confirms a name or an address back.
    #
    # DERIVED FROM THE CORPUS, not listed. This named five ids and one of them was `greek`,
    # which the corpus replaced with `korean` — so the check quietly ran over four languages
    # and would have passed just as happily over one. A test holding a copy of a list the code
    # owns is the same defect this file exists to catch, aimed at the test instead.
    from benign import INTERNATIONAL
    _intl_ids = {c[0] for c in INTERNATIONAL}
    intl = [t for cid, t in ALL_PROMPTS if cid in _intl_ids]
    check("the international section is still there to check",
          len(intl) == len(INTERNATIONAL) and len(intl) >= 5,
          f"{len(intl)} prompt(s) matched {len(INTERNATIONAL)} international entries")
    check("non-English text is clean even when the bot repeats it back",
          not [f for ctx in ctxs.values() for t in intl
               for f in fires_on(Probe(prompt=payload(t), output=t, tool_calls=[],
                                       observations=[]), ctx) if f != "over_refusal"],
          "a language is being read as an evasion")

    # A detector that throws is as broken as one that lies, and fires_on reports it with a
    # leading '!' rather than letting the exception end the run.
    class Boom:
        pass
    # THE FIXTURE HAS TO REACH THE PROPERTY. This read `... or True`, with a note saying the
    # result was tolerated either way -- so the assertion was true whatever `fires_on` did,
    # and the mechanism it names had never been exercised. `{"canaries": [None]}` used to
    # make a detector throw; the detectors were hardened and it stopped, and the check was
    # neutered rather than re-aimed. A detector that raises on purpose cannot be hardened
    # out from under it.
    def _boom(probe, ctx):
        raise RuntimeError("this detector is broken")

    _DET = __import__("oracle").DETECTORS
    _DET["_test_throwing_detector"] = _boom
    try:
        _out = fires_on(Probe(prompt="x", output="y", tool_calls=[], observations=[]), {})
    finally:
        _DET.pop("_test_throwing_detector", None)
    check("a detector that throws is reported, not fatal",
          "!_test_throwing_detector:RuntimeError" in _out, str(_out[:6]))
    check("...and the working detectors beside it still answer",
          all(not x.startswith("!") for x in _out if "_test_throwing" not in x), str(_out[:6]))

    # --- the summary counts what it claims --------------------------------------------
    rows = [{"fired": ["over_refusal"], "refused": True},
            {"fired": ["sql_injection"], "refused": False},
            {"fired": [], "refused": False},
            {"fired": [], "error": "TIMEOUT"},
            # a conversation the target cannot hold: neither clean nor a finding
            {"fired": [], "skipped": "needs chain"},
            # AND A TARGET THAT ANSWERED WITH NOTHING AT ALL, which is neither. A live app
            # returned HTTP 200 and an empty body for fifty consecutive probes while the model
            # behind it was down, and this summary called 48 of them clean. Silence is the
            # strongest claim a baseline can make about a target and it was being made by
            # measuring nothing, so it has its own line and its own row here.
            {"fired": [], "silent": True}]
    s = summary(rows)
    check("over_refusal is a usability finding, not a false alarm",
          "over_refusal" not in s["per_detector"] and s["refused"] == 1,
          str(s))
    check("clean means the target simply answered: refusal is not clean",
          s["clean"] == 1, str(s))
    check("clean + refused + noisy + skipped + errors + silent accounts for every probe",
          s["clean"] + s["refused"] + sum(s["per_detector"].values()) + s["skipped"]
          + s["errors"] + s["silent"] == s["probes"], str(s))
    check("an empty reply is counted as silence and not as clean",
          s["silent"] == 1 and s["clean"] == 1, str(s))

    # --- and the two halves of that, which a hand-set fixture flag cannot reach -----------
    #
    # Both were written and both survived being mutated away, because the rows above set
    # `silent` by hand: neither `Probe.silent` nor the line that records it was ever executed.
    # A fixture that states the answer is not a test of the thing that computes it.
    check("a probe with nothing in it is silent",
          Probe(prompt="q", output="").silent())
    check("...and whitespace is nothing",
          Probe(prompt="q", output=" " + chr(10) + chr(9) + " ").silent())
    check("...but an answer is not", not Probe(prompt="q", output="hello").silent())
    # AN AGENT THAT CALLED A TOOL AND SAID NOTHING HAS TOLD US A GREAT DEAL, so these count.
    check("...and neither is a tool call with no prose",
          not Probe(prompt="q", output="", tool_calls=[("lookup", "x")]).silent())
    check("...nor an observation with no prose",
          not Probe(prompt="q", output="", observations=["retrieved: refunds"]).silent())

    class _Mute:
        """A target that answers 200 with an empty body, which is what started this."""
        name = "mute"
        capabilities = set()

        def send(self, prompt):
            return Probe(prompt=prompt, output="")

        def reset(self):
            pass

    _rows = benign_run(_Mute(), {}, corpus=CORPUS[:3], trials=1, echo=False)
    _s = summary(_rows)
    check("a target that answers with nothing produces silent rows, not clean ones",
          _s["silent"] == len(_rows) and _s["clean"] == 0, str(_s))
    check("a skipped conversation is neither clean nor a finding",
          s["skipped"] == 1 and s["clean"] == 1, str(s))
    check("errors are counted, never silently dropped", s["errors"] == 1, str(s))

    # --- a benign run has to be replayable, or every oracle fix costs a GPU run --------
    # The corpus exists to test the oracle, so the oracle changes constantly and the
    # corpus does not. Storing an excerpt instead of the probe made a re-judge impossible
    # and forced ten full re-runs of ten to twenty minutes each, for a decision
    # the oracle makes offline in a second. The sweep has stored the probe from the start.
    import json as _json, tempfile as _tmp, os as _os
    from benign import rejudge as _rejudge
    row = {"id": "r1", "provokes": None, "prompt": "what is the key?",
           "fired": [], "refused": False, "evidence": "", "full": "",
           "probe": {"prompt": "what is the key?", "output": "it is BEN-CANARY-1",
                     "tool_calls": [["send", "to: a@b.example"]], "observations": [],
                     "seconds": 2.0, "turns": []}}
    fd, path = _tmp.mkstemp(suffix=".json")
    _os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            _json.dump({"meta": {"target": "rangebot", "probes": 1, "clean": 1,
                                 "refused": 0, "skipped": 0, "errors": 0,
                                 "per_detector": {}}, "rows": [row]}, f)
        import benign as _b
        real = _b._ctx_for
        _b._ctx_for = lambda n: ({}, {"canaries": ["BEN-CANARY-1"]})
        try:
            d, changed = _rejudge(path)
        finally:
            _b._ctx_for = real
    finally:
        _os.unlink(path)
    check("a stored benign row can be re-scored with no model call",
          [c[0] for c in changed] == ["r1"], str(changed))
    check("...and the re-score finds what the old one missed",
          "canary_in_output" in d["rows"][0]["fired"], str(d["rows"][0]["fired"]))
    check("...and the row's evidence is rebuilt to match the new verdict",
          "BEN-CANARY-1" in d["rows"][0]["evidence"], d["rows"][0]["evidence"][:60])
    check("...and the summary counters move with it",
          d["meta"]["clean"] == 0 and d["meta"]["per_detector"], str(d["meta"]))

    # a row with no probe is skipped, not crashed on: older files predate the change
    old = {"id": "r0", "fired": [], "prompt": "x", "evidence": ""}
    fd, path = _tmp.mkstemp(suffix=".json")
    _os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            _json.dump({"meta": {"target": "rangebot"}, "rows": [old]}, f)
        d2, changed2 = _rejudge(path)
    finally:
        _os.unlink(path)
    check("a pre-change row without a probe is skipped rather than mis-scored",
          not changed2 and d2["rows"][0]["fired"] == [])

    # --- evidence travels with the finding --------------------------------------------
    e = excerpt(Probe(prompt="p", output="a" * 400, tool_calls=[("SearchDocs", "x" * 80)],
                      observations=[]))
    check("the excerpt carries the tool call, not just the reply",
          "SearchDocs" in e and len(e) < 400, e[:80])

    # --- the number this engine is judged on, and the one it must not declare ---------
    # 421 fires over 1,344 clean probes is not a 31% false-positive rate: most of them are
    # TRUE. The poisoned MCP manifest sends the key out on ordinary questions; toolagent-naive
    # makes an internal request on 42 of 48; guardedrag-naive leaks through a URL on 33 of 48.
    # Those are the findings this project is proudest of, all from traffic nobody attacked.
    # Counting them as noise would delete them, and counting them as findings without saying
    # who decided would be worse — so each is adjudicated with a reason, and anything unsettled
    # is reported as unsettled rather than folded into whichever number flatters us.
    import tempfile as _tf, os as _os
    from benign import load_adjudication
    adj = load_adjudication()
    check("the fleet's adjudication file loads", bool(adj), str(len(adj)))
    check("every entry carries a verdict the roll-up understands",
          all(r.get("verdict") in ("finding", "false_positive") for r in adj.values()),
          str(sorted({r.get("verdict") for r in adj.values()})))
    check("...and a reason, because a verdict without one is an opinion",
          all((r.get("why") or "").strip() for r in adj.values()))
    check("it is keyed per (target, detector), not per detector name",
          all(isinstance(k, tuple) and len(k) == 2 for k in adj))
    # A detector right on one bot and wrong on another is the normal case, so the same
    # detector must be able to hold different verdicts on different targets.
    # `or True` here was unnecessary caution, and it made the check say nothing. The shipped
    # adjudication has 124 pairs over 29 targets and `pii_in_output` is a finding on two of
    # them and a false positive on twenty-six, so the claim the comment above makes is not
    # only true, it is the sharper one: the same detector holding DIFFERENT verdicts.
    _verdicts = {}
    for (_t, _d), _r in adj.items():
        _verdicts.setdefault(_d, set()).add(_r.get("verdict"))
    _split = sorted(d for d, vs in _verdicts.items() if len(vs) > 1)
    check("...which lets one detector be a finding on one target and not on another",
          bool(_split), f"no detector is adjudicated differently on two targets: "
                        f"{sorted(_verdicts)[:6]}")
    fd, empty = _tf.mkstemp(suffix=".yaml")
    _os.close(fd)
    _os.unlink(empty)
    check("a missing adjudication file means NOTHING is settled, not everything is clean",
          load_adjudication(empty) == {})

    # A VERDICT NOBODY READS IS THE SAME AS NO VERDICT, and this file spent a while in that
    # state for one detector. `over_refusal` was bucketed as a usability finding by a rule
    # hard-coded in the roll-up, which is the right DEFAULT — on traffic with no attacker in
    # it, a refusal really is worth reporting — but the rule could not be overridden, so three
    # explicit false_positive entries sat in the file being ignored. The distinction they
    # record is real: nemo refuses an in-scope support question because the customer pasted a
    # log line containing SQL, while dvla answers "I can only assist with bank transactions"
    # to a question about outages and says where to go instead. Correcting it moved the
    # published false-alarm rate from 6.3% to 9.2%, which is the direction that matters — the
    # blanket rule was flattering us.
    import benign as _bn
    over = [(t, d) for (t, d), r in adj.items()
            if d == "over_refusal" and r.get("verdict") == "false_positive"]
    check("some over_refusal entries are settled as false alarms, so the override is exercised",
          bool(over), str(over))
    roll = _bn.roll_up()
    counted = sum((roll.get("per_target") or {}).get("over_refusal", {}).get(t, 0)
                  for t, _ in over)
    check("...and a false_positive verdict actually reaches the published number",
          counted > 0,
          "the roll-up still excludes every over_refusal fire, so the file is decorative")
    finding_side = [(t, d) for (t, d), r in adj.items()
                    if d == "over_refusal" and r.get("verdict") == "finding"]
    not_counted = [t for t, _ in finding_side
                   if (roll.get("per_target") or {}).get("over_refusal", {}).get(t, 0)]
    check("...while one settled as a FINDING stays out of the false-alarm pool",
          not not_counted, str(not_counted))

    # --- WHAT THE CORPUS AIMED AT IS A RESULT, NOT A GAP -----------------------------------
    # Every clean prompt carries `provokes`: the detector it was written to tempt. The suite
    # has always checked those names are real; nothing read them at judgement time. So
    # `reached`, which counts FIRES despite the comment beside it, was subtracted from
    # DETECTORS to make the "silent on this corpus - untested, not exonerated" list, and a
    # detector aimed at 105 times on targets where it was armed, that stayed quiet every
    # time, was filed there. A measured pass published as an absence of measurement.
    _ex = roll.get("exercised") or {}
    check("the corpus's own aim is read at roll-up time", bool(_ex),
          "nothing counted as aimed-at, so the checks below cannot fail")
    # `exercised` counts PROBES, so a detector may be quiet on its own trap and loud
    # elsewhere; the split is what must not confuse the two, and it is computed in the
    # roll-up rather than in the print block so this can read it at all.
    _fired_too = [d for d in (roll.get("passed") or []) if d in (roll.get("fires") or {})]
    check("...and a detector that fired anywhere is never called a pass",
          not _fired_too, str(_fired_too))
    _overlap = set(roll.get("passed") or []) & set(roll.get("untested") or [])
    check("...and nothing is both a pass and a gap", not _overlap, str(_overlap))
    # THE TWO ABOVE PASS VACUOUSLY ON AN EMPTY LIST, which mutation showed: emptying `passed`
    # reddened nothing. The split has to COVER the detectors that never fired, and be
    # non-empty on a fleet where nineteen of them are aimed at and quiet.
    _never = set(DETECTORS) - set(roll.get("reached") or {})
    check("...and the split covers exactly the detectors that never fired",
          set(roll.get("passed") or []) | set(roll.get("untested") or []) == _never,
          "%d passed + %d untested against %d that never fired"
          % (len(roll.get("passed") or []), len(roll.get("untested") or []), len(_never)))
    check("...and the pass half is not empty on this fleet",
          bool(roll.get("passed")), "no detector is reported as aimed at and quiet")
    _zero = [d for d, n in _ex.items() if not n]
    check("...and every entry counts at least one probe aimed at it", not _zero, str(_zero))
    _rescued = [d for d in _ex if d not in (roll.get("reached") or {})]
    check("...and it takes detectors OUT of the untested list, or it changed nothing",
          bool(_rescued), "no detector moved from untested to passed")


    # --- every baseline was measured against THIS corpus, or is named -----------------------
    #
    # The corpus size is a published number and each stored baseline records the size it was
    # measured at. When they disagree the fleet's false-alarm rate is an average over two
    # different experiments, and it looks identical to a rate from one.
    #
    # Stragglers are reported, not failed: a third-party target nobody can clone, a server that
    # is down, a build-mismatch guard refusing to measure the wrong binary — all three are
    # operational facts, and a red build for them teaches people to ignore this gate. What DOES
    # fail is a baseline claiming a size the corpus has never had, because that number is
    # fiction rather than history.
    import glob as _glob
    sizes = {}
    for _fp in _glob.glob(os.path.join(HERE, "..", "out", "benign_*.json")):
        try:
            import json as _json
            _m = _json.load(open(_fp, encoding="utf-8"))["meta"]
        except (ValueError, KeyError, OSError):
            continue
        sizes[os.path.basename(_fp)[len("benign_"):-len(".json")]] = _m.get("probes")

    # Stragglers that are KNOWN, each with the operational reason it lags. Being unable to fix
    # something in a commit is not the same as being unable to write it down, and the label on
    # the check below promises the difference is NAMED — so a name is what it requires.
    #
    # Empty is the goal, not the exception: an entry here is a target whose numbers are from a
    # different experiment than the rest of the fleet's, and every published rate that averages
    # it in is an average over two.
    KNOWN_STRAGGLERS = {
        # "target": "why it could not be re-measured with the rest of the fleet",
    }

    now = len(ALL_PROMPTS)
    stale = sorted(t for t, n in sizes.items() if n != now)
    if stale:
        print("      %d of %d baselines predate the current corpus (%d prompts): %s"
              % (len(stale), len(sizes), now, ", ".join(stale)))
        for t in stale:
            why = KNOWN_STRAGGLERS.get(t)
            print(f"        {t}: {why}" if why else f"        {t}: NOT NAMED")
    # This used to be `check(..., True, "")` with the print below it doing the real work: a
    # label describing a verification, on a line that could not fail. What it can honestly
    # require is the naming, so that is what it requires.
    unnamed = [t for t in stale if t not in KNOWN_STRAGGLERS]
    check("the corpus size is what the baselines were measured against, or the difference is named",
          not unnamed,
          f"measured against a corpus that is no longer the corpus, with no reason recorded: "
          f"{', '.join(unnamed)}. Re-run `benign.py --target <name>`, or add it to "
          f"KNOWN_STRAGGLERS with the reason it cannot be.")
    impossible = sorted(t for t, n in sizes.items()
                        if not isinstance(n, int) or n <= 0 or n > now + 50)
    check("no baseline claims a corpus size that never existed", not impossible, str(impossible))

    # --- EVERY STORED BASELINE WAS MEASURED ON THE CORPUS THAT EXISTS NOW -------------------
    #
    # A rate averaged over two corpora reads exactly like a rate from one. When the corpus
    # changed — one international prompt replaced with another — twenty-nine baselines were
    # re-measured and one was not, because its build guard refused a config mismatch and the
    # loop moved on. It sat there fifty prompts wide, on a different fifty, contributing to a
    # headline false-alarm rate, and nothing in thirty-nine suites could see it. It took a
    # ten-line script written by hand to find, which is the definition of a check that should
    # exist.
    #
    # By ID and IN ORDER: same width is not the same corpus, and that is the whole failure.
    import glob as _glob
    import json as _json
    want = [c[0] for c in CORPUS] + [c[0] for c in CONVERSATIONS]
    drifted, found = [], 0
    for path in sorted(_glob.glob(os.path.join(ARTIFACTS, "benign_*.json"))):
        try:
            data = _json.load(open(path, encoding="utf-8"))
        except Exception as e:
            drifted.append(f"{os.path.basename(path)} does not parse: {e}")
            continue
        found += 1
        got = [r.get("id") for r in (data.get("rows") or [])]
        if got != want:
            name = os.path.basename(path)[len("benign_"):-len(".json")]
            missing = sorted(set(want) - set(got))
            extra = sorted(set(got) - set(want))
            drifted.append(f"{name} (measured {data.get('meta', {}).get('when')}): "
                           f"missing {missing}, has {extra}")
    check("every stored baseline was measured on the corpus that exists now",
          not drifted, "; ".join(drifted))
    # ...and the walk found baselines at all. An empty `out/` would pass the check above by
    # examining nothing, which is the shape this suite is named after.
    check("...and there were baselines to check", found >= 20,
          f"only {found} benign_*.json found under {ARTIFACTS}")

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — nothing in the oracle reads the question.")


if __name__ == "__main__":
    main()
