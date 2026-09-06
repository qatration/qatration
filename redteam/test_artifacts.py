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
    work = tempfile.mkdtemp()
    io.open(os.path.join(work, "results_httpbot.json"), "w",
            encoding="utf-8").write(json.dumps(GOOD))
    io.open(os.path.join(work, "benign_httpbot.json"), "w",
            encoding="utf-8").write(json.dumps(BENIGN))
    text = json.dumps(GOOD)
    io.open(os.path.join(work, "results_opsbot.json"), "w",
            encoding="utf-8").write(text[:len(text) // 2] if corrupt else text)
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

    # --- and every tool that reads the directory --------------------------------------------
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
    check("...and each one says why it is there", all(_ROOT_FILES.values()), True)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one bad file costs one file, and it is named.")


if __name__ == "__main__":
    main()
