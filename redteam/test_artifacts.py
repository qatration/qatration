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
    import glob
    import re
    strays = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base.startswith("test_"):
            continue
        src = io.open(fp, encoding="utf-8").read()
        for i, line in enumerate(src.splitlines(), 1):
            code_only = line.split("#")[0]
            if re.search(r"json\.load\(\s*open\(", code_only):
                strays.append(f"{base}:{i}")
    check("no module opens a stored artifact without going through workspace.read_artifact",
          not strays, f"raw json.load(open(...)) at: {strays}")

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

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one bad file costs one file, and it is named.")


if __name__ == "__main__":
    main()
