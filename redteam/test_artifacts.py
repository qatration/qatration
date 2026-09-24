"""One unreadable artifact must not take a tool down or vanish from it — no model, no network.

`out/` is read by five separate tools, each written on its own against the same directory, and a
single truncated file killed all five with a raw `JSONDecodeError`: no client report, no index,
no comparison page, no coverage number, no SARIF, and nothing naming the file.

That is not a hypothetical input. A truncated artifact is what an interrupted write leaves, and
stopping a sweep by hand produces one — this repository produced one on the day this was
written. The tool whose subject is a measurement that did not happen should not be the one
unable to say which file it could not read.

BOTH WRONG ANSWERS ARE CHECKED HERE, because they fail in opposite directions and the second is
worse:

  * RAISING makes one bad file hide every good one, and answers a coverage question with a
    stack trace.
  * SKIPPING silently removes a target from a page that then reads as complete. On a
    remediation report that is a clean bill for a system nobody looked at.

So each tool must exit non-fatally AND name the file. The reading itself lives in
`workspace.read_artifact` — one implementation, because five of them is how five tools came to
share one defect.

    python test_artifacts.py     # exits 1 on any failure (CI gate)
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

GOOD = {
    "meta": {"target": "httpbot", "trials": 1, "engine": "test"},
    "results": [{"attack": {"id": "a1", "category": "extraction", "delivery": "direct",
                            "text": "hello", "success": ["canary_in_output"]},
                 "headline": "DEFENDED", "rate": "0/1", "fired": [],
                 "trials": [{"verdict": "DEFENDED", "fired": [],
                             "probe": {"prompt": "hello", "output": "hi", "tool_calls": [],
                                       "observations": [], "turns": [], "seconds": 1}}]}],
}
BENIGN = {"meta": {"target": "httpbot", "probes": 1, "clean": 1, "refused": 0, "errors": 0,
                   "skipped": 0, "when": "2026-01-01 00:00:00", "per_detector": {}},
          "rows": [{"id": "x", "prompt": "hi", "fired": [], "refused": False,
                    "probe": {"prompt": "hi", "output": "ok"}}]}

# The whole-directory readers. `sarif` is checked separately: it is given ONE file by name, so
# there is nothing to carry on with and a refusal is the right answer rather than a skip.
SCANNERS = ["defense_report.py", "build_index.py", "compare_targets.py",
            "detector_coverage.py"]


def _workspace(corrupt):
    """`corrupt` is False, "truncated" (or True) or "shape".

    Two kinds of bad file reach the pages by the same route. One will not parse; the other
    parses and is missing a key the pages subscript, which is a `KeyError` out of a
    comprehension and looks to the reader like a bug in this tool.
    """
    import copy as _cp
    work = tempfile.mkdtemp()
    io.open(os.path.join(work, "results_httpbot.json"), "w",
            encoding="utf-8").write(json.dumps(GOOD))
    io.open(os.path.join(work, "benign_httpbot.json"), "w",
            encoding="utf-8").write(json.dumps(BENIGN))
    text = json.dumps(GOOD)
    if corrupt == "shape":
        _d = _cp.deepcopy(GOOD)
        _d["meta"] = dict(_d.get("meta") or {}, target="opsbot")
        _d["results"][0].pop("headline", None)
        text = json.dumps(_d)
    elif corrupt:
        text = text[:len(text) // 2]
    io.open(os.path.join(work, "results_opsbot.json"), "w",
            encoding="utf-8").write(text)
    return work


def _run(script, work, extra=()):
    env = dict(os.environ, QATRATION_OUT=work, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, os.path.join(HERE, script)] + list(extra),
                       capture_output=True, encoding="utf-8", errors="replace",
                       env=env, cwd=ROOT, timeout=300)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    from workspace import read_artifact, read_artifacts

    # --- the reader itself ------------------------------------------------------------------
    good = os.path.join(HERE, "..", "out", "benign_httpbot.json")
    if os.path.isfile(good):
        data, why = read_artifact(good)
        check("a valid artifact parses and reports no reason", data is not None and why is None,
              str(why))
    check("a file that is not JSON gives a reason rather than raising",
          read_artifact(os.path.join(HERE, "oracle.py"))[1] is not None)
    check("a missing file gives a reason rather than raising",
          read_artifact(os.path.join(HERE, "no-such-file.json"))[1] is not None)
    parsed, bad = read_artifacts([os.path.join(HERE, "oracle.py"),
                                  os.path.join(HERE, "no-such-file.json")])
    check("read_artifacts returns the failures instead of dropping them",
          not parsed and len(bad) == 2, f"{len(parsed)} parsed, {len(bad)} failed")

    # --- AND THE SECOND KIND OF BAD FILE: ONE THAT PARSES --------------------------------
    #
    # `read_artifact` was written because a truncated artifact took all five tools down
    # with a JSONDecodeError. A file that PARSES and is missing a key the pages subscript
    # does the same thing by the same route: a `KeyError` out of a comprehension, no page,
    # no index, no coverage number, and the crash handler telling the reader it is a bug in
    # this tool rather than a fact about their file.
    #
    # MEASURED, one key at a time, by dropping it from a real artifact and running all five
    # consumers: twelve crashes across four keys. The 45 artifacts stored here carry every
    # one of them, which is exactly why nothing noticed -- an artifact from a newer build, a
    # file repaired by hand after an interrupted write, or one from a fork does not.
    import copy as _cp
    import glob as _g_a

    def _minus(where, key):
        d = _cp.deepcopy(GOOD)
        (d["results"][0] if where == "result" else d["meta"]).pop(key, None)
        _fp = os.path.join(tempfile.mkdtemp(), "results_x.json")
        io.open(_fp, "w", encoding="utf-8").write(json.dumps(d))
        return read_artifact(_fp)

    for _w, _k in (("meta", "target"), ("result", "headline"),
                   ("result", "attack"), ("result", "fired")):
        _d, _why = _minus(_w, _k)
        check("a results file with no %s.%s is not handed to the pages" % (_w, _k),
              _d is None and _why is not None, str(_why))
        check("...and the reason names the key", _why and repr(_k) in _why or
              (_why and _k in _why), str(_why))
    # AND THE REASON SAYS WHO NEEDED IT, because `results[0] has no 'fired'` is a fact and
    # not yet a reason to care.
    check("...and says which page would have died on it",
          "`compare`" in (_minus("result", "fired")[1] or ""),
          str(_minus("result", "fired")[1]))

    # THE SAME MEASUREMENT FOR THE BENIGN FAMILY, which comes through the same reader.
    # `benign --summary` dies on a missing `meta.probes` -- the denominator of every rate this
    # project publishes -- and on a missing `rows`, both as a KeyError under the message
    # telling the reader it is a bug in this tool.
    def _minus_benign(fn):
        d = _cp.deepcopy(BENIGN)
        fn(d)
        _fp = os.path.join(tempfile.mkdtemp(), "benign_x.json")
        io.open(_fp, "w", encoding="utf-8").write(json.dumps(d))
        return read_artifact(_fp)

    for _lbl, _fn in (("meta.probes", lambda d: d["meta"].pop("probes", None)),
                      ("meta.target", lambda d: d["meta"].pop("target", None)),
                      ("rows", lambda d: d.pop("rows", None)),
                      ("meta", lambda d: d.pop("meta", None))):
        _d2, _why2 = _minus_benign(_fn)
        check("a benign baseline with no %s is not handed to the roll-up" % _lbl,
              _d2 is None and _why2 is not None, str(_why2))
    check("...and the reason says what the number was for",
          "denominator" in (_minus_benign(lambda d: d["meta"].pop("probes", None))[1] or ""),
          str(_minus_benign(lambda d: d["meta"].pop("probes", None))[1]))

    # IDENTIFIED BY NAME, and that is the results rule's lesson pointed the other way. A `rows`
    # list is not enough to say "this is a benign baseline": `rejudge` hands this same reader a
    # re-scoring input with rows and no `meta.probes`, which is fine for what it is, and
    # content-based identification refused it -- caught by `test_benign` on the first run. This
    # engine names its artifact families on purpose, so the name is what identifies.
    _other = os.path.join(tempfile.mkdtemp(), "tmp-rejudge-input.json")
    io.open(_other, "w", encoding="utf-8").write(json.dumps({"rows": [{"id": "p1"}]}))
    check("a rows file that is not a baseline is not judged by the baseline rule",
          read_artifact(_other)[1] is None, str(read_artifact(_other)[1]))
    # AND THE NAME ALONE IS ENOUGH, which is what catches the file with no rows at all: a
    # baseline cannot be recognised BY its rows when its rows are the missing thing.
    _norows = os.path.join(tempfile.mkdtemp(), "benign_x.json")
    io.open(_norows, "w", encoding="utf-8").write(
        json.dumps({"meta": {"target": "x", "probes": 1}}))
    check("a baseline with no rows at all is still recognised and refused",
          read_artifact(_norows)[1] is not None, str(read_artifact(_norows)[1]))

    # AND THE RESULTS SIDE IS IDENTIFIED BY NAME TOO, for the mirror reason: a results file
    # whose `results` list is the missing thing cannot be recognised by having one.
    _nores = os.path.join(tempfile.mkdtemp(), "results_x.json")
    io.open(_nores, "w", encoding="utf-8").write(json.dumps({"meta": {"target": "x"}}))
    check("a results file with no results list is recognised and refused",
          read_artifact(_nores)[1] is not None, str(read_artifact(_nores)[1]))

    # --- AND THE SHAPES IT COULD SAY THE MOST ABOUT WERE THE ONES IT PASSED ---------------
    #
    # Both rules opened `if not isinstance(data, dict): return None` -- "nothing wrong with
    # this file", from the two functions whose only job is to say what is wrong. A document
    # that is not a mapping is as unusable as an artifact gets: nothing in it can be looked up
    # by key, which is all either family is ever read by.
    #
    # `sarif` believed it and died on `.get` one frame later, under the sentence telling the
    # reader it is a bug in this tool rather than a fact about their file. Walked with `[1, 2]`,
    # with `"hello"` and with `null`, through every command that takes `--results`.
    def _artifact(name, body):
        _fp = os.path.join(tempfile.mkdtemp(), name)
        io.open(_fp, "w", encoding="utf-8").write(json.dumps(body))
        return read_artifact(_fp)

    for _lbl, _body in (("a list", [1, 2]), ("a string", "hello"), ("null", None)):
        _d3, _why3 = _artifact("results_x.json", _body)
        check("a results file that is %s is refused, not handed on" % _lbl,
              _d3 is None and _why3 is not None, str(_why3))
        check("...and the reason says it is not a mapping",
              "not a mapping" in (_why3 or ""), str(_why3))
        _d4, _why4 = _artifact("benign_x.json", _body)
        check("a benign baseline that is %s is refused too" % _lbl,
              _d4 is None and _why4 is not None, str(_why4))
    # AND THE RULE DIED ON ONE OF THEM ITSELF. `(data.get("meta") or {}).get("target")` is a
    # `.get` on whatever `meta` happens to be, so `meta: [1]` raised AttributeError out of the
    # guard written to stop exactly this -- the checker crashing on the file it was checking.
    try:
        _d5, _why5 = _artifact("results_x.json", {"meta": [1], "results": []})
    except Exception as _e5:
        # A CRASH IS NOT A REASON. Caught so the mutation that puts the raise back reads as a
        # named failure here rather than as this suite dying on its own fixture.
        _d5, _why5 = None, "CRASHED %s: %s" % (type(_e5).__name__, _e5)
    check("a results file whose meta is not a mapping is named rather than raising",
          _d5 is None and "meta is list" in (_why5 or ""), str(_why5))
    # AND A MISSING `meta` KEEPS THE ANSWER IT ALREADY HAD, which is a different fact from a
    # `meta` of the wrong kind and had a better sentence for it.
    _d6, _why6 = _artifact("results_x.json", {"results": []})
    check("...while a results file with no meta at all still names the key",
          "meta.target" in (_why6 or ""), str(_why6))

    # --- AND THE MEASUREMENT THAT BUILT THIS RULE WAS HALF OF ONE -------------------------
    #
    # The table above was measured by DROPPING each key from a real artifact and running all
    # five consumers: twelve crashes across four keys. Dropping a key asks whether it is
    # THERE. A page subscripting it needs it to be USABLE, and nothing asked that.
    #
    # Re-measured by giving each key a string, a number and a mapping in turn and running the
    # same five pages: SIXTEEN of forty variants crash, every one as "This is a bug in
    # qatration, not a finding about your target and not a problem with your config" about
    # the reader's own file. Three of the keys were not in the table at all.
    _SHAPES = [
        ({"meta": {"target": 7}, "results": []}, "meta.target", "int", "not str"),
        ({"meta": {"target": {}}, "results": []}, "meta.target", "dict", "not str"),
        ({"meta": {"target": "t", "attacks_n": "many"}, "results": []},
         "meta.attacks_n", "str", "not int"),
        ({"meta": {"target": "t"},
          "results": [{"headline": {}, "attack": {"id": "a"}, "fired": []}]},
         "headline", "dict", "not str"),
        ({"meta": {"target": "t"},
          "results": [{"headline": "DEFENDED", "attack": "a", "fired": []}]},
         "attack", "str", "not dict"),
        ({"meta": {"target": "t"},
          "results": [{"headline": "DEFENDED", "attack": {"id": 7}, "fired": []}]},
         "attack.id", "int", "not str"),
        ({"meta": {"target": "t"},
          "results": [{"headline": "DEFENDED", "attack": {"id": "a"}, "fired": 7}]},
         "fired", "int", "not list"),
        ({"meta": {"target": "t"},
          "results": [{"headline": "DEFENDED", "attack": {"id": "a"}, "fired": [],
                       "trials": "many"}]}, "trials", "str", "not list"),
        ({"meta": {"target": "t"},
          "results": [{"headline": "DEFENDED", "attack": {"id": "a"}, "fired": [],
                       "trials": [{"verdict": 7}]}]}, "verdict", "int", "not str"),
    ]
    for _body, _key, _kind, _want in _SHAPES:
        _d7, _why7 = _artifact("results_x.json", _body)
        check("a results file whose %s is %s is refused" % (_key, _kind),
              _d7 is None and _why7 is not None, str(_why7))
        check("...and the reason names the key and what it holds",
              _key in (_why7 or "") and _kind in (_why7 or ""), str(_why7))
        # AND SAYS WHAT IT SHOULD HAVE BEEN. Without this a mutation that stopped checking
        # `trials` at all stayed green: the loop below it iterates the string, the first
        # CHARACTER is not a mapping, and the file is refused by a sentence about
        # `trials[0]` that names both the key and the kind. Refused for the wrong reason
        # reads the same from outside unless the reason is read.
        check("...and what it should have been",
              _want in (_why7 or ""), str(_why7))

    # --- AND EVERY ROW OF THE TABLE, NOT THE NINE ABOVE -----------------------------------
    #
    # A sweep that set each key of a stored record to a value of the wrong kind and ran all
    # ten readers found thirty-one crash sites, on keys the table did not have. The table
    # has them now, and this walks EVERY row of it rather than a list of cases chosen here:
    # a row the rule never reaches -- a nesting the walker skips -- is a row that refuses
    # nothing, and it fails below by name.
    from workspace import _RESULTS_REQUIRE as _table
    _base = {"meta": {"target": "t"},
             "results": [{"headline": "DEFENDED", "attack": {"id": "a"}, "fired": [],
                          "trials": [{"verdict": "DEFENDED"}]}]}
    _unreached = []
    for _key, (_kind, _req, _) in _table.items():
        _wrong = 7 if _kind is str else "x"
        _b = json.loads(json.dumps(_base))
        _parts = _key.replace("[]", "").split(".")
        _obj = {"meta": _b["meta"], "results": _b["results"][0]}[_parts[0]]
        if _parts[1:2] == ["trials"] and len(_parts) > 2:
            _obj, _parts = _obj["trials"][0], _parts[1:]
        elif _parts[1:2] == ["attack"] and len(_parts) > 2:
            _obj, _parts = _obj["attack"], _parts[1:]
        _field = _parts[1]
        _obj[_field] = [_wrong] if _key.endswith("[]") else _wrong
        _d9, _why9 = _artifact("results_x.json", _b)
        if not (_d9 is None and _field in (_why9 or "")
                and type(_wrong).__name__ in (_why9 or "")):
            _unreached.append((_key, _why9))
    check("every row of the results shape table refuses a value of the wrong kind, by name",
          _unreached == [], str(_unreached))
    # THE HEADLINE IS ONE OF FIVE WORDS. `headline: "x"` is a str and passed the kind; the
    # report colours a row by looking it up, and died on a KeyError.
    _b = json.loads(json.dumps(_base))
    _b["results"][0]["headline"] = "x"
    _whyh = _artifact("results_x.json", _b)[1]
    check("a headline that is not a verdict is refused, and the reason lists the verdicts",
          "headline" in (_whyh or "") and "EXPLOITED" in (_whyh or ""), str(_whyh))
    # THE STORED ATTACK IS HELD TO THE ARSENAL'S RULE, not to a second one written here.
    for _f, _v in (("success", -1), ("partial", "x"), ("steps", True), ("text", ["a"])):
        _b = json.loads(json.dumps(_base))
        _b["results"][0]["attack"][_f] = _v
        _whya = _artifact("results_x.json", _b)[1]
        check("a stored attack whose %s is %s is refused, naming the field"
              % (_f, type(_v).__name__),
              ("attack.%s" % _f) in (_whya or ""), str(_whya))
    # AND THE TABLE HAS A ROW FOR EVERY META KEY A MODULE READS. The walk above proves each
    # row refuses; nothing there proves a row EXISTS, and deleting `meta.errors` from the
    # table left this suite green while `compare` crashed on it again. So the keys are found
    # by reading the code, the way a new reader will add one.
    import glob as _g_m
    import re as _re_m
    _read = set()
    for _src in _g_m.glob(os.path.join(HERE, "*.py")):
        if os.path.basename(_src).startswith("test_"):
            continue
        _read |= set(_re_m.findall(r'\bmeta(?:\.get\(|\[)"([a-z_]+)"',
                                   io.open(_src, encoding="utf-8").read()))
    # Keys of OTHER families' meta, read under the same variable name: a benign baseline's
    # row count and refusals (`_BENIGN_REQUIRE` holds the one a page subscripts), and the
    # snapshot `history` writes for itself, which it reads behind an isinstance.
    _elsewhere = {"probes", "refused", "inert_config"}
    _missing = sorted(k for k in _read - _elsewhere if "meta." + k not in _table)
    check("every meta key a module reads has a row in the results shape table",
          len(_read) >= 15 and _missing == [], "read %d, missing %s" % (len(_read), _missing))
    check("...and the complete record those cases were built from is not",
          _artifact("results_x.json", _base)[1] is None, str(_artifact("results_x.json", _base)[1]))
    # --- AND A NAME MADE OF NOTHING PASSED EVERY ONE OF THEM ------------------------------
    #
    # `""` is a str, so the kind rule above hands it on as usable. Every string in these two
    # tables is something a reader keys BY, and there is no consumer for which the empty one
    # is a value: it is the absence, written down.
    #
    # What it cost was not a crash. `benign.roll_up` carried its own `if not t: continue`
    # for exactly this file and dropped it in silence -- its probes out of the denominator
    # of every published false-alarm rate, its target out of the list of targets -- and the
    # roll-up went on reading as the whole fleet. The case for that is in `test_benign`.
    _BLANK = [
        ({"meta": {"target": ""}, "results": []}, "meta.target", "results_x.json"),
        ({"meta": {"target": "   "}, "results": []}, "meta.target", "results_x.json"),
        ({"meta": {"target": "t"},
          "results": [{"headline": "", "attack": {"id": "a"}, "fired": []}]},
         "headline", "results_x.json"),
        ({"meta": {"target": ""}, "rows": [], "probes": 0}, "meta.target",
         "benign_x.json"),
    ]
    for _body, _key, _name in _BLANK:
        if _name.startswith("benign_"):
            _body = {"meta": {"target": _body["meta"]["target"], "probes": 3}, "rows": []}
        _d8, _why8 = _artifact(_name, _body)
        check("%s whose %s is blank is refused" % (_name, _key),
              _d8 is None and _why8 is not None, str(_why8))
        check("...and the reason says it is blank, naming the key",
              _key in (_why8 or "") and "blank" in (_why8 or ""), str(_why8))
    # AND ONLY THE REQUIRED ROWS, which is the same line the paragraph over
    # `shape_fault` draws for an ABSENT value and the first version of the blank rule
    # broke. `trials`, the `verdict` inside one and the `id` inside an attack are each
    # subscripted by one consumer, and refusing the whole artifact for them "would make one
    # page's need cost every page".
    #
    # Measured before this was fixed: a two-finding artifact with one blank `attack.id` was
    # refused ENTIRELY, so the real finding beside it left the index, the comparison, the
    # coverage number and the remediation page, replaced by `could not be read`. Losing a
    # measured finding to protect a page that can say what it could not quote is the wrong
    # direction for this engine.
    _thin_blank = {"meta": {"target": "t"},
                   "results": [{"headline": "EXPLOITED", "attack": {"id": ""},
                                "fired": ["canary_in_output"],
                                "trials": [{"verdict": ""}]},
                               {"headline": "EXPLOITED", "attack": {"id": "real-one"},
                                "fired": ["pii_in_output"], "trials": []}]}
    _d_tb, _why_tb = _artifact("results_x.json", _thin_blank)
    check("a blank attack id does not cost the whole artifact",
          _why_tb is None, str(_why_tb))
    check("...nor does a blank verdict inside a trial", _d_tb is not None, str(_why_tb))
    check("...and the finding beside it is still there to be read",
          _d_tb and len(_d_tb["results"]) == 2, str(_d_tb)[:120])

    # AND A NAME THAT IS ONE STILL IS, or the rule above is a reader that refuses every
    # artifact in the workspace. The whitespace bound matters both ways: a target called
    # ` citebot ` is a name with room around it, not an absence.
    check("a target with a name is not refused for having one",
          _artifact("results_x.json",
                    {"meta": {"target": "citebot"}, "results": []})[1] is None,
          str(_artifact("results_x.json",
                        {"meta": {"target": "citebot"}, "results": []})[1]))
    check("...and neither is one padded with spaces",
          _artifact("results_x.json",
                    {"meta": {"target": " citebot "}, "results": []})[1] is None,
          str(_artifact("results_x.json",
                        {"meta": {"target": " citebot "}, "results": []})[1]))
    # AND THE 137 ARTIFACTS THIS REPOSITORY SHIPS GO THROUGH, which is the measurement the
    # rule rests on and the one a bound this tight can break. Not a fixture: the workspace.
    import glob as _glob_s
    from workspace import OUT as _OUT_s
    _ship_bad = []
    for _fp_s in sorted(_glob_s.glob(os.path.join(str(_OUT_s), "*.json"))):
        if read_artifact(_fp_s)[1]:
            _ship_bad.append(os.path.basename(_fp_s))
    check("no artifact in this workspace is refused by the blank rule",
          not _ship_bad, ", ".join(_ship_bad[:6]))

    # --- AND FIVE READERS EACH HELD THEIR OWN ANSWER TO IT --------------------------------
    #
    # `benign.roll_up`, `defense_report.response_paths`, `history.backfill`,
    # `discrimination.load` and `detector_coverage` each carried a line of their own for an
    # artifact with no target name, and the five did not agree: three dropped it in silence,
    # one filed it as unreadable, and one INVENTED a name out of the filename -- a target in
    # a coverage table that no run ever wrote. In three of them the silent line sits two or
    # three lines under one that names an unreadable artifact out loud, in the same loop.
    #
    # One rule, one implementation: `read_artifact` refuses it and every one of those loops
    # already has a branch that says which file and why. The copies are deleted, and what is
    # asserted here is that each reader SAYS SO -- the behaviour the copies were hiding.
    import shutil as _sh_n, subprocess as _sp_n
    _wn = tempfile.mkdtemp()

    def _blank_art(name, body):
        with io.open(os.path.join(_wn, name), "w", encoding="utf-8") as _f_n:
            _f_n.write(json.dumps(body))

    _good = {"meta": {"target": "citebot", "model": "m", "trials": 1, "attacks_n": 1,
                      "broke": 0, "errors": 0, "when": "2026-09-01T00:00:00Z"},
             "results": [{"attack": {"id": "a1", "category": "x"}, "headline": "DEFENDED",
                          "rate": "0/1", "fired": [], "trials": []}]}
    _blank_art("results_citebot.json", _good)
    _blank_art("results_nameless.json", dict(_good, meta=dict(_good["meta"], target="  ")))
    _blank_art("benign_citebot.json",
               {"meta": {"target": "citebot", "probes": 1, "when": "2026-09-01T00:00:00Z"},
                "rows": [{"probe": {"prompt": "p", "output": "o"}, "fired": []}]})
    _blank_art("benign_nameless.json",
               {"meta": {"target": "", "probes": 1, "when": "2026-09-01T00:00:00Z"},
                "rows": [{"probe": {"prompt": "p", "output": "o"}, "fired": []}]})
    try:
        for _mod_n, _args_n in (("discrimination", []),
                                ("detector_coverage", []),
                                ("history", ["--backfill"])):
            _p_n = _sp_n.run([sys.executable, _mod_n + ".py"] + _args_n,
                             cwd=os.path.dirname(os.path.abspath(__file__)),
                             capture_output=True, text=True, timeout=300,
                             env=dict(os.environ, QATRATION_OUT=_wn,
                                      PYTHONDONTWRITEBYTECODE="1",
                                      PYTHONIOENCODING="utf-8"))
            _said_n = (_p_n.stdout or "") + (_p_n.stderr or "")
            check("%s names the artifact it could not use" % _mod_n,
                  "nameless" in _said_n, _said_n.strip()[-300:] or "(nothing said)")
            check("...and does not crash over it" ,
                  "Traceback (most recent call last)" not in _said_n,
                  _said_n.strip()[-300:])
    finally:
        _sh_n.rmtree(_wn, ignore_errors=True)

    # AND THE KEY THAT MAY BE ABSENT STILL MAY BE. `attacks_n` is missing from artifacts
    # written before the field existed and `measured` reads that as zero on purpose: absent
    # is "this file predates the question", a string is a denominator nothing can divide by.
    check("an artifact written before attacks_n existed is not refused for lacking it",
          _artifact("results_x.json",
                    {"meta": {"target": "t"}, "results": []})[1] is None,
          str(_artifact("results_x.json", {"meta": {"target": "t"}, "results": []})[1]))
    # AND THE THREE THAT ONE PAGE READS ARE NOT REQUIRED OF THE FILE, because refusing the
    # artifact for them would make one page's need cost the other four -- the inverse of this
    # reader's own rule that one bad file costs one file. They are answered where they are
    # read: `fixes` says which finding it could not quote, `compare` groups an unnamed row
    # under a name that cannot collide with a real id.
    _thin = {"meta": {"target": "t"},
             "results": [{"headline": "EXPLOITED", "attack": {"category": "c"},
                          "fired": []}]}
    check("a row with no trials and no attack id is not refused for the whole file",
          _artifact("results_x.json", _thin)[1] is None,
          str(_artifact("results_x.json", _thin)[1]))
    # AND THE PAGES THAT READ THEM SURVIVE IT, which is the other half of that decision and
    # the half a shape rule cannot make true on its own.
    import defense_report as _dr_a
    _drw = tempfile.mkdtemp()
    io.open(os.path.join(_drw, "results_thin.json"), "w", encoding="utf-8").write(
        json.dumps(dict(_thin, meta={"target": "thin", "attacks_n": 1, "broke": 1,
                                     "errors": 0})))
    _real_dr = _dr_a.OUT_DIR
    try:
        import pathlib as _pl_a
        _dr_a.OUT_DIR = _pl_a.Path(_drw)
        _found = _dr_a.load_all()[0]
        check("`fixes` reads a finding whose row has no trials", len(_found) == 1,
              str(len(_found)))
        check("...and quotes nothing rather than the first trial it can find",
              _found and _found[0][4] == {}, str(_found[:1])[:160])
    finally:
        _dr_a.OUT_DIR = _real_dr
    # AND `compare`, THE OTHER PAGE THAT READS AN ATTACK ID. Driven through the environment
    # the way the command is, because that module reads the workspace at import time.
    import importlib as _il_a
    _was_a = os.environ.get("QATRATION_OUT")
    os.environ["QATRATION_OUT"] = _drw
    try:
        import workspace as _ws_a, compare_targets as _ct_a
        _il_a.reload(_ws_a)
        _il_a.reload(_ct_a)
        _ct_err = ""
        try:
            import contextlib as _ctx_a
            with _ctx_a.redirect_stdout(io.StringIO()):
                _ct_a.main()
        except SystemExit:
            pass
        except Exception as _e_a:
            _ct_err = "%s: %s" % (type(_e_a).__name__, _e_a)
        check("`compare` draws a page over a row whose attack has no id", not _ct_err,
              _ct_err)
        check("...and the row is grouped under a name that cannot collide with a real id",
              "(unnamed attack)" in io.open(os.path.join(_drw, "compare_targets.html"),
                                            encoding="utf-8").read(),
              sorted(os.listdir(_drw)))
    finally:
        if _was_a is None:
            os.environ.pop("QATRATION_OUT", None)
        else:
            os.environ["QATRATION_OUT"] = _was_a
        import workspace as _ws_b, compare_targets as _ct_b
        _il_a.reload(_ws_b)
        _il_a.reload(_ct_b)

    # --- AND THE BENIGN RULE WAS MEASURED THE SAME WAY, SO IT WAS HALF OF ONE TOO ---------
    #
    # `benign --summary`, `compare`, `index`, `fixes` and `coverage`, over a baseline whose
    # keys are present and unusable: TWELVE of fifty variants crash, and not one of them is
    # an absent key. The denominator of every rate this project publishes is `meta.probes`,
    # and a string there came back as `unsupported operand type(s) for +=`.
    _BSHAPES = [
        ({"meta": {"target": 7, "probes": 1}, "rows": []}, "meta.target", "int", "not str"),
        ({"meta": {"target": "t", "probes": "many"}, "rows": []},
         "meta.probes", "str", "not int"),
        ({"meta": {"target": "t", "probes": 1}, "rows": "oops"}, "rows", "str", "not list"),
        ({"meta": {"target": "t", "probes": 1}, "rows": [1]}, "rows[0]", "int",
         "not dict"),
        ({"meta": {"target": "t", "probes": 1}, "rows": [{"fired": 7}]},
         "rows[0].fired", "int", "not list"),
        ({"meta": {"target": "t", "probes": 1}, "rows": [{"probe": "x"}]},
         "rows[0].probe", "str", "not dict"),
        # THE ELEMENTS TOO, which the results family did not need: `fired: [1]` is a list, so
        # a kind on the field itself passes it, and the roll-up counts detectors BY NAME.
        ({"meta": {"target": "t", "probes": 1}, "rows": [{"fired": [1]}]},
         "rows[0].fired[0]", "int", "not str"),
    ]
    for _body, _key, _kind, _want in _BSHAPES:
        _d8, _why8 = _artifact("benign_x.json", _body)
        check("a benign baseline whose %s is %s is refused" % (_key, _kind),
              _d8 is None and _why8 is not None, str(_why8))
        check("...and the reason names the key, what it holds and what it should be",
              all(_s in (_why8 or "") for _s in (_key, _kind, _want)), str(_why8))
    # AND `probe: null` IS A SHAPE THIS ENGINE WRITES. A row records it when the probe was
    # skipped or errored, and `baseline.rates` reads it on purpose -- "a row with no probe
    # was skipped or errored: it is not evidence of quiet". Writing the key with nothing in
    # it says what leaving it out says, and a rule that told them apart would refuse a
    # baseline the tool produced itself.
    _skipped = {"meta": {"target": "t", "probes": 2},
                "rows": [{"fired": [], "probe": None}, {"fired": ["d"], "probe": {}}]}
    check("a benign row whose probe was never sent is not a malformed baseline",
          _artifact("benign_x.json", _skipped)[1] is None,
          str(_artifact("benign_x.json", _skipped)[1]))
    # AND THE TWO FAMILIES SHARE ONE RULE, so a kind learned on one side is not a kind the
    # other is still blind to.
    check("both families are judged by the same shape rule",
          "benign baseline" in (_artifact("benign_x.json", _BSHAPES[0][0])[1] or "")
          and "results file" in (_artifact("results_x.json",
                                           {"meta": {"target": 7}, "results": []})[1] or ""),
          str(_artifact("benign_x.json", _BSHAPES[0][0])[1]))

    # AND NOT BY REFUSING EVERY LIST, which is the fix that would have passed every line
    # above. SIXTEEN artifacts stored here ARE top-level lists -- every `isolation_*.json`
    # coupling map -- and they come through this same reader; a rule that refused a list
    # outright would take all of them out of the pages that read them.
    _lists = [_p for _p in sorted(_g_a.glob(os.path.join(ROOT, "out", "*.json")))
              if isinstance(json.load(io.open(_p, encoding="utf-8")), list)]
    check("the artifacts that are lists by design can be found", len(_lists) >= 5,
          str(len(_lists)))
    _listrefused = {os.path.basename(_p): read_artifact(_p)[1]
                    for _p in _lists if read_artifact(_p)[1]}
    check("...and not one of them is refused for being a list", _listrefused == {},
          str(_listrefused))

    # AND THERE HAVE TO BE SOME. "no shipped file is refused" is satisfied by shipping no
    # files, and an empty `out/` is exactly the state a `--depth 1` clone of a fork can be in.
    # Measured by deleting the artifacts in a clone and re-running: this suite passed.
    _bships = sorted(_g_a.glob(os.path.join(ROOT, "out", "benign_*.json")))
    check("there are baselines committed to check", len(_bships) >= 20, str(len(_bships)))
    _brefused = {os.path.basename(_p): read_artifact(_p)[1]
                 for _p in _bships if read_artifact(_p)[1]}
    check("no baseline this repository ships is refused by the shape rule",
          _brefused == {}, str(_brefused))

    # NOT THE FILE THAT IS FINE, and not the other artifact families: benign baselines, lock
    # maps and recon profiles come through this same reader with their own shapes, and a
    # rule that guessed at those would refuse them.
    _okfp = os.path.join(tempfile.mkdtemp(), "results_x.json")
    io.open(_okfp, "w", encoding="utf-8").write(json.dumps(GOOD))
    check("a complete results file still parses", read_artifact(_okfp)[1] is None,
          str(read_artifact(_okfp)[1]))
    _bfp = os.path.join(tempfile.mkdtemp(), "benign_x.json")
    io.open(_bfp, "w", encoding="utf-8").write(json.dumps(BENIGN))
    check("...and a benign baseline is not judged by the results rule",
          read_artifact(_bfp)[1] is None, str(read_artifact(_bfp)[1]))
    _mfp = os.path.join(tempfile.mkdtemp(), "isolation_x.json")
    io.open(_mfp, "w", encoding="utf-8").write(json.dumps({"meta": {"target": "x"},
                                                           "maps": []}))
    check("...nor is a lock map", read_artifact(_mfp)[1] is None,
          str(read_artifact(_mfp)[1]))

    # AND EVERY SHIPPED ARTIFACT STILL READS, or the rule is one this repository fails.
    _ships = sorted(_g_a.glob(os.path.join(ROOT, "out", "results_*.json")))
    check("there are results committed to check", len(_ships) >= 20, str(len(_ships)))
    _refused = {os.path.basename(_p): read_artifact(_p)[1]
                for _p in _ships if read_artifact(_p)[1]}
    check("no artifact this repository ships is refused by the shape rule",
          _refused == {}, str(_refused))

    # --- and every tool that reads the directory --------------------------------------------
    # BOTH KINDS, over the same drivers. `corrupt="truncated"` is the file that will not
    # parse; `corrupt="shape"` is the one that parses and is missing a key the pages
    # subscript. The consumers cannot tell them apart and must not need to.
    for _kind in ("truncated", "shape"):
        work = _workspace(corrupt=_kind)
        try:
            for script in SCANNERS:
                code, out = _run(script, work)
                name = script[:-3]
                check("%s survives one %s artifact" % (name, _kind),
                      code == 0 and "Traceback" not in out,
                      "exit %s%s" % (code, " with a traceback" if "Traceback" in out
                                     else ""))
                check("...and names the file it could not read (%s)" % _kind,
                      "results_opsbot.json" in out,
                      "it carried on as though the file were not there")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    work = _workspace(corrupt=True)
    try:
        for script in SCANNERS:
            code, out = _run(script, work)
            name = script[:-3]
            check(f"{name} survives one unreadable artifact",
                  code == 0 and "Traceback" not in out,
                  f"exit {code}" + (" with a traceback" if "Traceback" in out else ""))
            check(f"...and names the file it could not read",
                  "results_opsbot.json" in out,
                  "it carried on as though the file were not there")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # ...and the same tools are quiet when nothing is wrong, or the check above would pass for
    # a tool that complains about every file it opens.
    work = _workspace(corrupt=False)
    try:
        for script in SCANNERS:
            code, out = _run(script, work)
            check(f"{script[:-3]} says nothing about unreadable files when there are none",
                  "could not be read" not in out, out[-160:])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # --- AN ATTACK WITH NO ID IS ONE THE TABLE LETS THROUGH, so every reader must take it ---
    #
    # `results[].attack.id` is optional in `_RESULTS_REQUIRE` on purpose: refusing the file
    # would lose the measured findings beside it. A sweep of stored records found `rejudge
    # --pages` and `history` subscripting `["id"]` anyway and dying on the file the table had
    # just passed, under "this is a bug in qatration". A finding and a fired control, both
    # without an id, through every command that reads the rows.
    import copy as _cp_u
    work = _workspace(corrupt=False)
    try:
        _u = _cp_u.deepcopy(GOOD)
        _u["meta"]["target"] = "opsbot"
        _hit = _cp_u.deepcopy(_u["results"][0])
        _hit["attack"].pop("id")
        _hit["headline"], _hit["rate"] = "EXPLOITED", "1/1"
        _ctl = _cp_u.deepcopy(_hit)
        _ctl["attack"]["category"] = "control"
        _ctl["fired"] = ["canary_in_output"]
        _u["results"] = [_hit, _ctl]
        io.open(os.path.join(work, "results_opsbot.json"), "w",
                encoding="utf-8").write(json.dumps(_u))
        for _cmd in (["rejudge", "--pages"], ["history", "--backfill"], ["discrimination"],
                     ["compare"], ["fixes"], ["index"], ["coverage"]):
            code, out = _run("cli.py", work, _cmd)
            check("%s takes a stored attack with no id" % " ".join(_cmd),
                  code in (0, 1, 3) and "Traceback" not in out,
                  "exit %s: %s" % (code, out[-300:]))
        _pages = [p for p in os.listdir(work) if p.endswith(".html") and "opsbot" in p]
        check("...and the report files the row under the one phrase for it",
              any("(unnamed attack)" in io.open(os.path.join(work, p), encoding="utf-8").read()
                  for p in _pages), str(_pages))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    # AND NO READER SUBSCRIPTS IT. Five did while six spelled the fallback out for themselves;
    # `workspace.attack_name` is the one answer now, and a new `["attack"]["id"]` in a module
    # that reads stored rows is the same crash waiting for the same file. `run_redteam` is
    # the one exception: its rows are the live run's, built from an arsenal `lint` has
    # already required an id of.
    import glob as _g_u
    import re as _re_u
    _subs = []
    for _src in sorted(_g_u.glob(os.path.join(HERE, "*.py"))):
        _b = os.path.basename(_src)
        if _b.startswith("test_") or _b == "run_redteam.py":
            continue
        for _n, _line in enumerate(io.open(_src, encoding="utf-8"), 1):
            if _re_u.search(r"""\[['"]attack['"]\]\[['"]id['"]\]""", _line):
                _subs.append("%s:%d" % (_b, _n))
            if "(unnamed attack)" in _line and _b != "workspace.py":
                _subs.append("%s:%d spells the fallback" % (_b, _n))
    check("no reader of stored rows subscripts attack id or spells its own fallback",
          _subs == [], str(_subs))

    # --- sarif: one named file, so a refusal rather than a skip ------------------------------
    work = _workspace(corrupt=True)
    try:
        bad_path = os.path.join(work, "results_opsbot.json")
        code, out = _run("sarif.py", work, ["--results", bad_path])
        check("sarif refuses a truncated results file instead of raising",
              code != 0 and "Traceback" not in out, f"exit {code}")
        check("...and says why, because an absent SARIF upload reads as a clean scan",
              "could not be read" in out, out[-160:])
        code, out = _run("sarif.py", work,
                         ["--results", os.path.join(work, "results_httpbot.json")])
        check("...and still exports a valid one", code == 0 and "Traceback" not in out,
              out[-160:])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # --- nothing reads an artifact behind the shared reader's back --------------------------
    #
    # Derived, not listed. The five tools were fixed one at a time and the fifth was found by
    # running the fourth; a list of files to check would have covered the four somebody
    # remembered.
    #
    # AND READ AS THE CALL, NOT AS ONE WAY OF TYPING IT. This was a one-line regex for
    # `json.load(open(`, so the shape the engine actually used -- `with open(p) as f:` and
    # `json.load(f)` a line later -- passed it in eight places, `json.load(io.open(...))` in a
    # ninth. One of them was `rejudge.rescore`, the command that reads the most records:
    # measured, one truncated `results_*.json` in a workspace of three ended it with a
    # traceback and the two good files were not re-scored either.
    #
    # `json.load` takes a FILE, so every call to it is a read of one. The rule is that the
    # only such read is the one inside `workspace`, which is the reader.
    import glob
    import ast as _ast_j

    def _raw_reads(sources):
        """(name, source) pairs -> ["file:line"] for every `json.load` outside workspace."""
        _out = []
        for _nm, _src in sources:
            if _nm.startswith("test_") or _nm == "workspace.py":
                continue
            try:
                _tree = _ast_j.parse(_src)
            except SyntaxError:
                continue
            for _n in _ast_j.walk(_tree):
                if (isinstance(_n, _ast_j.Call) and isinstance(_n.func, _ast_j.Attribute)
                        and _n.func.attr == "load"
                        and isinstance(_n.func.value, _ast_j.Name)
                        and _n.func.value.id.lstrip("_").startswith("json")):
                    _out.append(f"{_nm}:{_n.lineno}")
        return _out

    # ON PLANTED MODULES FIRST, one per shape the engine has used, and one that parses a
    # string in memory and must NOT be named -- `json.loads` of an HTTP body is not a file.
    _pl = _raw_reads([
        ("a.py", "import json\ndef f(p):\n    return json.load(open(p))\n"),
        ("b.py", "import json\ndef f(p):\n    with open(p) as fh:\n"
                 "        return json.load(fh)\n"),
        ("c.py", "import io, json as _json\ndef f(p):\n"
                 "    return _json.load(io.open(p, encoding='utf-8'))\n"),
        ("d.py", "import json\ndef f(body):\n    return json.loads(body)\n"),
        ("workspace.py", "import json\ndef read(p):\n    return json.load(open(p))\n")])
    check("the scan names a raw read in each shape the engine has used",
          sorted({_x.split(":")[0] for _x in _pl}) == ["a.py", "b.py", "c.py"], str(_pl))
    _mods_j = [(os.path.basename(_fp), io.open(_fp, encoding="utf-8").read())
               for _fp in sorted(glob.glob(os.path.join(HERE, "*.py")))]
    strays = _raw_reads(_mods_j)
    # THE DENOMINATOR, carried into the verdict: a scan over no modules finds no strays.
    check("no module opens a stored artifact without going through workspace.read_artifact"
          " (%d modules read)" % sum(1 for _m, _s in _mods_j if not _m.startswith("test_")),
          not strays and len(_mods_j) > 40, f"raw json.load at: {strays}")

    # --- WHAT THIS REPOSITORY SHIPS AT ITS ROOT -----------------------------------------
    #
    # `qatration init` writes its config into the CURRENT DIRECTORY, which is right: a
    # config is a thing you edit, not an artifact, and burying it in `out/` would hide it.
    # Run from inside a checkout it therefore lands in the repository, and `git add -A`
    # swept `mybot.yaml` into a commit and a push -- carrying a generated canary that would
    # then be shared by everyone who copied it, which is the one thing a canary must not be.
    #
    # Every other command writes through `workspace.artifact` into `out/`, so this door is
    # narrow and the root is small and deliberate. Declared rather than pattern-matched: a
    # new top-level file is a decision, and it should cost one line here to record it.
    # DIRECTORIES ARE NOT LISTED -- the practice fleet adds them and they are somebody's
    # work, not a stray; a stray is a FILE dropped where a command was run.
    _ROOT_FILES = {
        ".gitattributes": "line endings, so a CRLF checkout does not change a hash",
        ".gitignore": "what a working checkout is allowed to leave lying around",
        "AUTHORISED-USE.md": "the authorisation gate this tool refuses to run without",
        "CHANGELOG.md": "what changed per release",
        "CONTRIBUTING.md": "how to run the suites",
        "LICENSE": "Apache-2.0",
        "NOTICE": "attribution required by that licence",
        "README.md": "the front page, whose every number a suite recounts",
        "SECURITY.md": "where to report a vulnerability in this tool",
        "pyproject.toml": "the package",
        "requirements.txt": "what a checkout needs to run the suites",
        "wrangler.jsonc": "how the site is published",
    }
    import subprocess as _sp_r
    _tracked = _sp_r.run(["git", "-C", ROOT, "ls-files"], capture_output=True,
                         text=True).stdout.split()
    check("the repository lists tracked files, so this check can see the root",
          len(_tracked) > 50, "git ls-files returned %d path(s)" % len(_tracked))
    _at_root = sorted(f for f in _tracked if "/" not in f)
    check("no undeclared file sits at the top of the repository",
          sorted(set(_at_root) - set(_ROOT_FILES)) == [],
          "undeclared: %s" % ", ".join(sorted(set(_at_root) - set(_ROOT_FILES))))
    # AND THE DECLARATION IS NOT A LIST OF THINGS THAT LEFT, which is how a list like this
    # stops meaning anything.
    check("...and every declared file is still there",
          sorted(set(_ROOT_FILES) - set(_at_root)) == [],
          "declared but absent: %s" % ", ".join(sorted(set(_ROOT_FILES) - set(_at_root))))
    check("...and each one says why it is there", all(_ROOT_FILES.values()),
          "no reason given for: %s"
          % ", ".join(sorted(k for k, v in _ROOT_FILES.items() if not v)))


    # --- THE PAGES NOTHING BUILDS, NAMED ------------------------------------------------
    #
    # `test_reports` rebuilds every committed page whose command can be derived and diffs
    # it against the code. A page no command builds is invisible to that: it cannot go
    # stale, because nothing can make it fresh. Two of them ship here, and until this check
    # existed neither was named anywhere.
    #
    # `compare.html` has its evidence in `out/compare/` and is recounted from it below.
    # `report.html` does not: no artifact in this repository records a five-trial run of
    # that arsenal, so nothing here can say whether its verdicts are right. What CAN be
    # checked without the run is that the page agrees with itself, and it did not -- the
    # headline said fifteen attacks over a table of sixteen rows whose own category totals
    # add to sixteen.
    #
    # Declared as a pair rather than tolerated as a wildcard: a THIRD orphan is a page
    # somebody added without a generator, and that is worth a red build.
    _ORPHANS = {
        "compare.html": "three models against one target; its runs are in out/compare/ and "
                        "every number on it is recounted from them below",
        "report.html": "one five-trial run of the same arsenal, and that run is not in this "
                       "repository -- nothing here can recount its verdicts, so what is "
                       "checked is that the page agrees with itself",
    }
    import cli as _cli_o
    _buildable = set()
    for _cmd, (_mod, _) in _cli_o.COMMANDS.items():
        _mp = os.path.join(HERE, _mod + ".py")
        if os.path.exists(_mp):
            _buildable |= set(re.findall(r'["\']([a-z_]+\.html)["\']',
                                         io.open(_mp, encoding="utf-8").read()))
    _committed = {os.path.basename(_p)
                  for _p in _g_a.glob(os.path.join(ROOT, "out", "*.html"))}
    # `report_<target>.html` is the per-target scorecard: `report_engine` builds it and
    # `test_reports` explains why those are not rebuilt here.
    _orphan = sorted(_f for _f in _committed - _buildable
                     if not _f.startswith("report_"))
    check("every committed page either has a command that builds it or is named here",
          _orphan == sorted(_ORPHANS), "%s vs %s" % (_orphan, sorted(_ORPHANS)))
    check("...and the derivation found the commands, rather than calling everything an orphan",
          len(_buildable) >= 3, str(sorted(_buildable)))

    # AND THE ONE WITH NO RUN AGREES WITH ITSELF. Its headline count is the only claim on
    # it that can be judged from the page alone.
    _rp = os.path.join(ROOT, "out", "report.html")
    if os.path.exists(_rp):
        _rt = io.open(_rp, encoding="utf-8").read()
        _rows = len(re.findall(r'class="row"', _rt))
        _said = re.search(r'<div class="n">(\d+)</div><div class="l">attacks fired</div>',
                          _rt)
        check("the page with no run behind it counts the rows it prints",
              bool(_said) and _rows and int(_said.group(1)) == _rows,
              "says %s, prints %d" % (_said and _said.group(1), _rows))

    # --- THE PAGE WITH NO GENERATOR -----------------------------------------------------
    #
    # `out/compare.html` is three models against one target, and nothing in this repository
    # writes it: it arrived with the squash, nothing links to it, and the committed-page
    # gate in `test_reports` cannot rebuild it because there is no command to rebuild it
    # with. So every number on it was a declaration, which is the one thing this project
    # says a number may not be -- and all of them were wrong in the same direction.
    #
    # The run holds SIXTEEN attacks and the page said fifteen, so every count on it was one
    # short. Worse, its headline paragraph said the cells that differ between models "are
    # also flaky (2/3, 1/3) ... a single-shot test would miss them": no cell in the run is
    # 2/3, four cells differ, and three of the four are 3/3 against one model and 0/3
    # against the others -- which a single-shot test would find every time.
    #
    # Recounted here from `out/compare/`, the evidence the page was built from, the way
    # `test_readme` recounts every other published number.
    _cmp_dir = os.path.join(ROOT, "out", "compare")
    _cmp_page = os.path.join(ROOT, "out", "compare.html")
    if os.path.isdir(_cmp_dir) and os.path.exists(_cmp_page):
        _runs = {}
        for _f in sorted(_g_a.glob(os.path.join(_cmp_dir, "results_*.json"))):
            _m = json.load(io.open(_f, encoding="utf-8"))
            _runs[_m["model"]] = _m["results"]
        _html = io.open(_cmp_page, encoding="utf-8").read()
        check("the comparison page's evidence is three runs of one arsenal",
              len(_runs) == 3 and len({len(v) for v in _runs.values()}) == 1,
              str({k: len(v) for k, v in _runs.items()}))
        _n = len(next(iter(_runs.values())))
        check("...and the page says how many attacks that was",
              ("Same %d attacks" % _n) in _html, "recounted %d" % _n)
        for _model, _rows in sorted(_runs.items()):
            _ex = sum(1 for r in _rows if r["headline"] == "EXPLOITED")
            _de = sum(1 for r in _rows if r["headline"] == "DEFENDED")
            check("...and %s's fully-exploited count is the one in the run" % _model,
                  ('%d<span class="of">/%d</span>' % (_ex, _n)) in _html,
                  "%d of %d" % (_ex, _n))
            check("...and %s's resisted/breached pair adds up to it" % _model,
                  ("resisted %d \u00b7 breached %d" % (_de, _n - _de)) in _html,
                  "resisted %d, breached %d" % (_de, _n - _de))
        # AND THE CLAIM ABOUT FLAKINESS, which is what the page is FOR. A cell that differs
        # between models and is 3/3 or 0/3 is not flaky, and saying otherwise tells a reader
        # they need repeated trials to see something one trial would have found.
        _ids = sorted({r["payload"]["id"] for _rows in _runs.values() for r in _rows})
        _by = {m: {r["payload"]["id"]: (r["headline"], r.get("pass_rate"))
                   for r in rows} for m, rows in _runs.items()}
        _differ = [i for i in _ids
                   if len({_by[m].get(i, (None,))[0] for m in _by}) > 1]
        _flaky = [i for i in _differ
                  if any(_by[m].get(i, (None, None))[1] not in ("0/3", "3/3", None)
                         for m in _by)]
        check("the page's count of differing cells is the number that differ",
              str(len(_differ)) in ("4",) and "Four cells differ" in _html,
              "%d differ: %s" % (len(_differ), _differ))
        check("...and it names the one that is actually flaky, and only it",
              len(_flaky) == 1 and _flaky[0] in _html
              and all(("<code>%s</code>" % i) in _html for i in _differ),
              "flaky: %s of %s" % (_flaky, _differ))

    # --- A COUNTER THAT NO LONGER DESCRIBES THE ROWS UNDER IT ---------------------------
    #
    # `workspace.measured` is the denominator four surfaces share -- the scorecard, the
    # defence page, the fleet index and the SARIF export -- and it reads `meta["errors"]`.
    # `verdict_for` reads it too, and says HARDENED when it is zero and nothing broke.
    #
    # `out/results_localrag-refusal.json` shipped with `errors: 0` over seven rows whose
    # every trial says `Failed to connect to Ollama`. The target answered nothing, and the
    # fleet index counted it among the four systems that held.
    #
    # Both writers derive these from the rows now and this is what keeps them agreeing: a
    # counter that describes a different set of rows than the file carries is the shape
    # this whole project is named after, and it is invisible from inside any one page.
    from workspace import BROKE as _BROKE_c

    def _counters_off(doc, name):
        """-> the counters in this artifact that do not describe the rows under them."""
        _m = (doc or {}).get("meta") or {}
        _rows = [_r for _r in ((doc or {}).get("results") or [])
                 if (_r.get("attack") or {}).get("category") != "control"]
        _bad = []
        for _key, _want in (("broke", sum(1 for _r in _rows
                                          if _r.get("headline") in _BROKE_c)),
                            ("errors", sum(1 for _r in _rows
                                           if _r.get("headline") == "ERROR"))):
            # AN ABSENT COUNTER IS NOT A WRONG ONE. Artifacts written before a field existed
            # carry none, and `measured` reads that as zero on purpose -- "cannot say" for a
            # file that predates the question, which is a different claim from a number that
            # contradicts its own rows.
            if _m.get(_key) is not None and _m[_key] != _want:
                _bad.append("%s: %s says %s, rows say %d" % (name, _key, _m[_key], _want))
        return _bad

    # ON A PLANTED ONE FIRST, in this process, every time. The shipped corpus is clean now,
    # so a comparison that stopped comparing would change no answer here -- which is the
    # defect this file is about, one level up.
    _PLANTED_A = {"meta": {"broke": 0, "errors": 0},
                  "results": [{"headline": "ERROR", "attack": {"id": "a", "category": "x"}},
                              {"headline": "EXPLOITED",
                               "attack": {"id": "b", "category": "x"}}]}
    check("the comparison finds a counter that does not describe its rows",
          len(_counters_off(_PLANTED_A, "planted.json")) == 2,
          str(_counters_off(_PLANTED_A, "planted.json")))
    # AND A CONTROL IS OUT OF BOTH COUNTS, as it is out of `attacks_n` beside them: this is
    # the one place the two writers could disagree without any row changing.
    _PLANTED_B = {"meta": {"broke": 0, "errors": 0},
                  "results": [{"headline": "ERROR",
                               "attack": {"id": "c", "category": "control"}}]}
    check("...and does not count a control among them",
          not _counters_off(_PLANTED_B, "planted.json"),
          str(_counters_off(_PLANTED_B, "planted.json")))
    _PLANTED_C = {"meta": {}, "results": [{"headline": "ERROR",
                                           "attack": {"id": "a", "category": "x"}}]}
    check("...and says nothing about an artifact written before the field existed",
          not _counters_off(_PLANTED_C, "planted.json"),
          str(_counters_off(_PLANTED_C, "planted.json")))

    _off, _seen_c = [], 0
    for _fp in sorted(_g_a.glob(os.path.join(ROOT, "out", "results_*.json"))):
        try:
            _d = json.load(io.open(_fp, encoding="utf-8"))
        except Exception:
            continue
        _seen_c += 1
        _off += _counters_off(_d, os.path.basename(_fp))
    check("every stored run's counters describe the rows in it",
          not _off, "; ".join(_off[:6]))
    check("...over the artifacts this repository ships", _seen_c >= 20, str(_seen_c))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one bad file costs one file, and it is named.")


if __name__ == "__main__":
    main()
