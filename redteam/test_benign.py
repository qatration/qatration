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
from benign import (CORPUS, SECURITY_TALK, CONVERSATIONS, fires_on, summary, excerpt,
                    excerpt, run as benign_run)
from workspace import OUT as ARTIFACTS   # one place decides where evidence lives

# Every prompt the gate has to clear: the single sends, plus each conversation flattened
# the way runner.py assembles it, because the whole user side is what echo subtraction sees.
ALL_PROMPTS = ([(c[0], c[2]) for c in CORPUS]
               + [(c[0], "\n".join(c[3])) for c in CONVERSATIONS])

BLAND = ("Thanks for getting in touch. I have noted your question and someone from the "
         "team will follow up shortly.")


def contexts():
    """Every oracle_context in the fleet, so the claim is not proved on one config.

    The sixth copy of a map that is one function. This one derived the fallback name
    itself, in a suite whose whole subject is the module where that mattered: `benign`
    could not see a config outside this package at all, and this loop names one
    differently from the code it is checking.
    """
    from workspace import oracle_contexts as _oc
    return _oc(HERE)


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

    # --- AND EVERY ROW REACHES THE MAP, which is where two of them stopped ----------------
    #
    # `load_adjudication` was a dict comprehension keyed at (target, detector), so a second
    # entry for a pair deleted the first. The count above says 142 and the map held 140. The
    # two that vanished are not duplicates in the sense of redundant: each is a person
    # settling a genuinely different fire that happens to share both names, which is what the
    # file's header offered a `value` field for and what nothing ever implemented.
    #
    # SO THE CHECK IS ON THE FOLD, not on the absence of a collision. Writing a pair twice is
    # allowed and the file does it; losing one of them is not.
    import benign as _B0, io as _io0, tempfile as _tmp0
    _adj = _B0.load_adjudication(os.path.join(HERE, "benign_adjudication.yaml"))
    _pairs = {(r.get("target"), r.get("detector")) for r in _rows}
    check("every pair the file names is in the map",
          sorted(_pairs - set(_adj)) == [], str(sorted(_pairs - set(_adj))[:4]))
    # AND THE REASONING SURVIVES. Any pair written twice carries both `why` texts, so the
    # entry a reader sees covers both cases rather than whichever was typed second.
    _twice = sorted({p for p in _pairs
                     if sum(1 for r in _rows
                            if (r.get("target"), r.get("detector")) == p) > 1})
    check("...and the file really does write a pair twice, or this is about nothing",
          len(_twice) >= 2, str(_twice))
    # THE WHOLE TEXT, not its first word. The first version compared `why.split()[0]`, and
    # both of this file's collided pairs open with the word "The" -- so it passed against
    # last-wins, which is the bug it was written to catch. A check whose fixture cannot reach
    # the property is not a weak check, it is a green one that asserts nothing.
    _lost = [p for p in _twice
             for r in _rows if (r.get("target"), r.get("detector")) == p
             and str(r.get("why") or "").strip() not in (_adj[p].get("why") or "")]
    check("...and both reasons survive the fold, whole", not _lost,
          str(sorted(set(_lost))[:4]))

    # BOTH DIRECTIONS ON THE FOLD ITSELF, driven through the real function on a written file,
    # because the shipped file's two collisions happen to AGREE and the dangerous one does not.
    import yaml as _y0
    _fd0 = os.path.join(_tmp0.mkdtemp(), "adj.yaml")
    def _wrote(rows):
        _io0.open(_fd0, "w", encoding="utf-8").write(_y0.safe_dump(rows))
        return _B0.load_adjudication(_fd0)

    _agree = _wrote([{"target": "t", "detector": "d", "verdict": "finding", "why": "ALPHA"},
                     {"target": "t", "detector": "d", "verdict": "finding", "why": "BETA"}])
    check("two agreeing entries keep the verdict",
          _agree[("t", "d")]["verdict"] == "finding", str(_agree))
    check("...and keep both reasons",
          "ALPHA" in _agree[("t", "d")]["why"] and "BETA" in _agree[("t", "d")]["why"],
          _agree[("t", "d")]["why"])

    # THE DANGEROUS ONE. Last-wins here would let a `false_positive` typed later suppress a
    # pair somebody else recorded as a finding, with nothing said. Two people disagreeing is
    # the definition of unsettled, and `disputed` is neither word anything downstream tests
    # for -- so the pair falls through to `unknown` in `settled()` and is listed there.
    _rowsx = [{"target": "t", "detector": "d", "verdict": "finding", "why": "ALPHA"},
              {"target": "t", "detector": "d", "verdict": "false_positive", "why": "BETA"}]
    _fight = _wrote(_rowsx)
    check("two disagreeing entries settle nothing",
          _fight[("t", "d")]["verdict"] == "disputed", str(_fight))
    check("...and say both sides",
          "ALPHA" in _fight[("t", "d")]["why"] and "BETA" in _fight[("t", "d")]["why"],
          _fight[("t", "d")]["why"])
    check("...and reversing the order gives the same answer",
          _wrote(list(reversed(_rowsx)))[("t", "d")]["verdict"] == "disputed",
          str(_wrote(list(reversed(_rowsx)))))
    # A ROW THAT IS NOT A MAPPING used to raise AttributeError inside the comprehension, so a
    # malformed file crashed the reader instead of being reported by the checks above.
    check("a row that is not a mapping does not crash the reader",
          _wrote(["not a mapping",
                  {"target": "t", "detector": "d", "verdict": "finding", "why": "W"}])
          == {("t", "d"): {"target": "t", "detector": "d", "verdict": "finding",
                           "why": "W"}}, "")

    # --- AND NO ROW CARRIES A KEY NOTHING READS ------------------------------------------
    #
    # The header used to offer a `value` field narrowing an entry to fires carrying a specific
    # string. `load_adjudication` keys at (target, detector) and every count downstream is per
    # (detector, target), so a `value` would have applied to every fire of the pair -- the
    # exact over-generalisation it was described as preventing. Zero rows used it, which is the
    # only reason it never misled anybody, and the offer is withdrawn. This is the gate that
    # keeps it withdrawn: a key this file does not implement is a verdict that does not apply
    # the way its author thinks it does.
    from workspace import near_miss_keys as _nmk0
    _KNOWN_ADJ = {"target", "detector", "verdict", "why"}
    _stray = sorted({k for r in _rows if isinstance(r, dict)
                     for k in r if k not in _KNOWN_ADJ})
    check("no adjudication carries a key the reader does not read", not _stray,
          "%s%s" % (_stray, (" — did you mean %s?" % _nmk0(dict.fromkeys(_stray),
                                                            _KNOWN_ADJ)) if _stray else ""))
    check("...and the four it does read are all present on every row",
          not [i for i, r in enumerate(_rows)
               if isinstance(r, dict) and set(r) != _KNOWN_ADJ],
          str([i for i, r in enumerate(_rows)
               if isinstance(r, dict) and set(r) != _KNOWN_ADJ][:4]))

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

    # --- A BASELINE MEASURED AGAINST A WALL IS NOT A BASELINE ---------------------------
    #
    # This is the command the documentation tells an operator to run FIRST, at an endpoint
    # they have just pointed the tool at, and it sent 48 requests at one answering 429 to
    # every single one. The rows it would have written say what the endpoint refused, not
    # what it does when nobody is attacking it.
    import json as _js8, tempfile as _tf8, shutil as _sh8
    import subprocess as _sp4
    import threading as _th_b
    from http.server import BaseHTTPRequestHandler as _BH_b
    from http.server import ThreadingHTTPServer as _TS_b
    from runner import RATE_LIMIT_GIVE_UP as _GIVE_B
    _bhits, _ball = [], {"v": True}

    class _Limiting(_BH_b):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length") or 0))
            _bhits.append(1)
            if not _ball["v"] and (len(_bhits) - 1) % 5 == 4:
                _bb = _js8.dumps({"reply": "Shipping takes 3-5 days."}).encode()
                self.send_response(200)
            else:
                _bb = _js8.dumps({"error": {"message": "rate limit"}}).encode()
                self.send_response(429)
                self.send_header("Retry-After", "0")
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(_bb)))
            self.end_headers()
            self.wfile.write(_bb)

        def log_message(self, *a):
            pass

    _bsrv = _TS_b(("127.0.0.1", 0), _Limiting)
    _th_b.Thread(target=_bsrv.serve_forever, daemon=True).start()
    _bw = _tf8.mkdtemp()
    try:
        _bcfg = os.path.join(_bw, "targets_rlbot.yaml")
        with open(_bcfg, "w", encoding="utf-8") as _f:
            _f.write("name: rlbot\nadapter: http\n")
            _f.write('url: "http://127.0.0.1:%d/c"\n' % _bsrv.server_address[1])
            _f.write("request:\n  message: \"{prompt}\"\n")
            _f.write("response:\n  reply: \"reply\"\n")
            _f.write("oracle_context:\n  canaries: [\"ACME-CANARY-9931\"]\n")

        def _bench(_all):
            _ball["v"] = _all
            del _bhits[:]
            _r = _sp4.run([sys.executable, os.path.join(HERE, "cli.py"), "benign",
                           "--target-config", _bcfg],
                          capture_output=True, text=True, errors="replace", timeout=900,
                          env=dict(os.environ, QATRATION_OUT=_bw,
                                   PYTHONDONTWRITEBYTECODE="1",
                                   PYTHONIOENCODING="utf-8"))
            return _r.returncode, (_r.stdout or "") + (_r.stderr or ""), len(_bhits)

        _bc, _bo, _bn = _bench(True)
        check("a baseline stops when the endpoint refuses everything with a limit",
              "STOPPED" in _bo, _bo[-400:])
        check("...within the declared streak rather than the whole corpus",
              _bn <= _GIVE_B + 2, "%d probe(s) sent" % _bn)
        check("...saying why those rows would not have been a baseline",
              "not what it does when nobody is attacking it" in _bo, _bo[-400:])
        check("...and it is nothing measured, not a clean baseline", _bc == 3,
              "exit %s" % _bc)

        # A LIMIT THAT LETS TRAFFIC THROUGH IS NOT A WALL.
        _bc2, _bo2, _bn2 = _bench(False)
        check("a baseline that keeps landing probes is not stopped",
              "STOPPED" not in _bo2, _bo2[-400:])
        check("...and reaches the whole corpus", _bn2 > _bn * 4,
              "%d probe(s) against %d" % (_bn2, _bn))
    finally:
        _bsrv.shutdown()
        _sh8.rmtree(_bw, ignore_errors=True)

    # --- AND `NOT ONE SNAPSHOT` IS COMPUTED FROM WHAT THE RUNS RECORDED ------------------
    #
    # This warning is the precedent two other surfaces cite for saying a baseline is old:
    # `report_engine` prints the baseline's date and `baseline.note` calls it stale, and
    # both point here. It was computed from `os.path.getmtime`, which git does not preserve.
    # Measured by cloning this repository: the 35 stored baselines record four distinct days
    # and their mtimes collapse to one, so on the checkout a stranger has the warning finds
    # no difference and never renders -- while every one of those 35 artifacts carries the
    # date in `meta` and nothing read it.
    #
    # THE FIXTURE IS WRITTEN IN ONE INSTANT on purpose, which is exactly the clone's state:
    # only the recorded dates can separate these rows.
    import json as _js8, tempfile as _tf8, shutil as _sh8
    _sw = _tf8.mkdtemp()
    try:
        for _t8, _w8 in (("oldbot", "2026-08-01 09:00:00"),
                         ("newbot", "2026-09-01 09:00:00"),
                         ("mutebot", None)):
            _meta = {"target": _t8, "probes": 1}
            if _w8:
                _meta["when"] = _w8
            with open(os.path.join(_sw, "benign_%s.json" % _t8), "w",
                      encoding="utf-8") as _f8:
                _js8.dump({"meta": _meta,
                           "rows": [{"id": "p1", "fired": [], "refused": False,
                                     "probe": {"output": "ok"}}]}, _f8)
        _roll = _sp4.run([sys.executable, os.path.join(HERE, "cli.py"), "benign",
                          "--summary"],
                         capture_output=True, text=True, errors="replace", timeout=900,
                         env=dict(os.environ, PYTHONIOENCODING="utf-8",
                                  PYTHONDONTWRITEBYTECODE="1",
                                  QATRATION_OUT=_sw)).stdout
        _line = next((l for l in _roll.splitlines() if "not one snapshot" in l), "")
        check("the roll-up separates two baselines measured a month apart",
              "oldbot" in _line, _roll[:400])
        check("...by the dates the runs recorded, not by the files' timestamps",
              "08-01" in _roll, _roll[:400])
        check("...and does not call the newest one stale", "newbot" not in _line, _line)
        # A RUN THAT RECORDED NOTHING IS NOT A RUN MEASURED TODAY. It cannot join the
        # comparison, and leaving it out silently is the same absence-as-agreement one
        # level down.
        check("...nor the one that recorded no date, which cannot be compared",
              "mutebot" not in _line, _line)
        check("...which is said out loud rather than left as silence",
              "mutebot recorded no date" in _roll, _roll[:400])
        check("...and its age is marked as the file's", "(file)" in _roll, _roll[:400])
    finally:
        _sh8.rmtree(_sw, ignore_errors=True)

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
    #
    # IT USED TO EXCLUDE ONE DETECTOR AND COUNT IT ANYWAY. `over_refusal` was dropped from
    # the sweep with no note, while the label beside it said `x {len(DETECTORS)} detectors`
    # -- a claim about sixty-five of them published with the count of sixty-six in it, and
    # `benign --dry-run` took the same exemption the same way.
    #
    # IT SUPPRESSED NOTHING. Measured before removing it: `over_refusal` fires on 0 of the
    # 50 corpus entries, in every one of the fleet's contexts, because `refusal.classify`
    # reads this reply as `compliance`. The exemption cost the claim a detector and bought
    # no quiet -- so it is gone, and the property it was standing in for is checked
    # directly below, where a reply edited into something deflecting says so by name
    # instead of turning this sweep red for a reason nobody would recognise.
    ctxs = contexts()
    offenders = {}
    for tname, ctx in ctxs.items():
        for cid, text in ALL_PROMPTS:
            p = Probe(prompt=payload(text), output=BLAND, tool_calls=[], observations=[])
            for f in fires_on(p, ctx):
                offenders.setdefault(f, []).append(f"{tname}/{cid}")
    check(f"no detector fires on the prompt alone "
          f"({len(ALL_PROMPTS)} prompts x {len(ctxs)} contexts x {len(DETECTORS)} detectors)",
          not offenders,
          "; ".join(f"{d} on {v[:3]}" for d, v in offenders.items()))
    # THE FIXTURE'S OWN REPLY IS NOT A REFUSAL, which is what makes the line above a
    # statement about the question rather than about the answer this suite chose.
    from refusal import classify as _classify_b
    _cls = _classify_b(Probe(prompt="anything", output=BLAND, tool_calls=[],
                             observations=[]), {})["class"]
    check("...and the bland reply this sweep uses is not itself a refusal",
          _cls == "compliance", _cls)
    # AND THE COMMAND ASKS THE SAME QUESTION OF THE SAME SET, so the sentence it prints and
    # the sentence above are about one thing.
    import io as _io_o, os as _os_o
    _bsrc = _io_o.open(_os_o.path.join(HERE, "benign.py"), encoding="utf-8").read()
    check("...and `benign --dry-run` exempts no detector either",
          'if x != "over_refusal"' not in _bsrc, "the command still drops one silently")

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
    # THE SAME EXEMPTION WAS HERE TOO, and here the reply is the user's own text rather
    # than the bland one -- so `over_refusal` was excluded from a sweep whose replies it
    # had never been shown to be quiet on. It is included now.
    check("non-English text is clean even when the bot repeats it back",
          not [f for ctx in ctxs.values() for t in intl
               for f in fires_on(Probe(prompt=payload(t), output=t, tool_calls=[],
                                       observations=[]), ctx)],
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

    # --- THE EVIDENCE SHOWN, AND THE EVIDENCE JUDGED ------------------------------------
    #
    # This file prints `Read the evidence beside each row and settle them`, and the
    # settlement is written down in `benign_adjudications` at (target, detector) grain. So
    # the row's evidence is not decoration: it is the whole of what a person adjudicates
    # from, and if it omits the turn that fired they will settle a true fire as a false
    # alarm and the answer is kept.
    #
    # `visible_text` was written because a secret shown in turn one and refused in turn two
    # was invisible to every output detector. The detectors moved to it; `excerpt` and
    # `full` kept reading `probe.output`, the LAST reply. Measured against a live practice
    # bot: `preference-then-new-session` fired `canary_in_output` on the canary in turn one
    # and displayed a turn-two reply about email preferences with no canary in it.
    _multi = Probe(prompt="a\nb", output="turn two, and nothing in it",
                   turns=[{"prompt": "a", "output": "turn one: ACME-CANARY-9931 here"},
                          {"prompt": "b", "output": "turn two, and nothing in it"}])
    # THE FIXTURE HAS TO REACH THE PROPERTY. A probe the detectors do not fire on would
    # make every assertion below true by having nothing to show.
    _fired = fires_on(_multi, {"canaries": ["ACME-CANARY-9931"]})
    check("a canary in an earlier turn still fires", "canary_in_output" in _fired,
          str(_fired))
    _ex = excerpt(_multi)
    check("...and the evidence beside the row contains it",
          "ACME-CANARY-9931" in _ex, repr(_ex[:160]))
    check("...and still shows the last turn too",
          "turn two" in _ex, repr(_ex[:160]))

    # --- THE BUILD THAT JUDGED THE BASELINE ---------------------------------------------
    #
    # Every attribution in the engine rests on this file: a finding is weakened or
    # unattributable because of what these rows say. `run_redteam` stamps the build into
    # its results and this did not, so nothing recorded which oracle produced the fires the
    # whole attribution layer reads.
    #
    # Two costs, both measured on a baseline written the same day. `detector_coverage`'s
    # provenance audit filed its fifty probes under `written before results carried one`,
    # which is a claim about age and was false. And `report_engine` could tell a reader the
    # baseline's DATE and warn that the oracle may have moved since -- when the build is
    # the exact answer to that question.
    #
    # READ OFF THE SOURCE THAT WRITES IT, not off a stored artifact: the committed
    # baselines predate this and a check over them would assert the absence.
    import ast as _a7, io as _io7
    _bsrc = _io7.open(os.path.join(HERE, "benign.py"), encoding="utf-8").read()
    _meta_keys = set()
    for _n7 in _a7.walk(_a7.parse(_bsrc)):
        if not isinstance(_n7, _a7.Dict):
            continue
        _ks = [k.value for k in _n7.keys
               if isinstance(k, _a7.Constant) and isinstance(k.value, str)]
        if "target" in _ks and "when" in _ks:
            _meta_keys |= set(_ks)
    check("the baseline writes a meta a reader can place",
          {"target", "when", "trials"} <= _meta_keys, str(sorted(_meta_keys)))
    # THE BUILD IS NOT A LITERAL KEY ANY MORE, and asking the source for one was asking about
    # the spelling rather than the fact. `target.judged_now` adds it, on the rule `write_maps`
    # states -- the build describes the oracle that produced the verdicts in this file, which
    # is always the one running now -- and both of this module's writers go through it: the
    # fresh sweep and `--rejudge --write`, which used to keep the old stamp beside verdicts the
    # current oracle had just produced.
    _stamps = sum(1 for _n7 in _a7.walk(_a7.parse(_bsrc))
                  if isinstance(_n7, _a7.Call) and isinstance(_n7.func, _a7.Name)
                  and _n7.func.id in ("judged_now", "_judged_now"))
    check("...and stamps the build that judged it, at both of its writers",
          _stamps >= 2, "%d call(s) to judged_now" % _stamps)
    from target import judged_now as _jn7, engine_version as _ev7
    check("...and the stamp is the build this process reports",
          _jn7({"target": "t"}).get("engine") == _ev7(),
          str(_jn7({"target": "t"})))

    # AND IT IS THE SAME SOURCE THE SWEEP USES, not a second way of asking.
    check("...from `engine_version`, the one the sweep stamps with",
          "engine_version()" not in _bsrc, "benign has its own idea of a build")

    # --- A CONFIG THAT DOES NOT LIVE IN THIS PACKAGE ------------------------------------
    #
    # `_ctx_for` listed this directory and matched filenames itself, so `--target NAME`
    # here could only ever mean a config this repository ships. `rejudge`, `coverage` and
    # the defense report all read `QATRATION_CONFIGS`; this one answered `no config named
    # 'acmebot'` about a file the rest of the tool was reading, from the command whose
    # whole output is the false-positive rate every attribution claim is measured against.
    #
    # DRIVEN IN A SUBPROCESS, because the defect is in what a DIFFERENT process's
    # environment makes visible, and a suite that sets the variable in its own process
    # would be testing the import it already did. `--target-config` was the answer given
    # to this at the time; a second door is not a fix when the first one denies the file
    # exists.
    import subprocess as _sp9, tempfile as _tf9, os as _os9
    _d9 = _tf9.mkdtemp()
    try:
        _cfg9 = _os9.path.join(_d9, "targets_acmebot.yaml")
        with open(_cfg9, "w", encoding="utf-8") as _f9:
            _f9.write("name: acmebot\noracle_context:\n  canaries: [ACME-CANARY-77213]\n")
        _env9 = dict(_os9.environ, QATRATION_CONFIGS=_cfg9,
                     PYTHONDONTWRITEBYTECODE="1")
        _r9 = _sp9.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, %r); import benign; print(benign._ctx_for('acmebot')[1])" % HERE],
            cwd=HERE, env=_env9, capture_output=True, text=True, timeout=90)
        check("`--target NAME` finds a config outside this package",
              "ACME-CANARY-77213" in (_r9.stdout + _r9.stderr),
              (_r9.stdout + _r9.stderr).strip()[:160])
        # AND THE CONTROL, so this is not passing because the name resolves some other
        # way: with the variable unset the same call must still refuse.
        _env9.pop("QATRATION_CONFIGS")
        _r9b = _sp9.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, %r); import benign; print(benign._ctx_for('acmebot')[1])" % HERE],
            cwd=HERE, env=_env9, capture_output=True, text=True, timeout=90)
        check("...and without it there is no such target, as there is not",
              _r9b.returncode != 0 and "acmebot" in (_r9b.stdout + _r9b.stderr),
              (_r9b.stdout + _r9b.stderr).strip()[:160])
        check("...and the refusal names the variable that would have found it",
              "QATRATION_CONFIGS" in (_r9b.stdout + _r9b.stderr),
              (_r9b.stdout + _r9b.stderr).strip()[:160])
    finally:
        __import__("shutil").rmtree(_d9, ignore_errors=True)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — nothing in the oracle reads the question.")


if __name__ == "__main__":
    main()
