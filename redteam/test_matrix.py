"""`qatration matrix --from-disk` compares runs nobody measured together.

Its own `--from-disk` help calls the dates and the build stamps "the whole risk", and it
was wrong about both. This suite drives the command as a process over fixture workspaces,
because the caveats are printed by the command and the caveat was the thing missing.

  * THE DATE WAS A FILE'S MTIME. Git does not preserve mtimes, so a fresh clone stamps
    every artifact with the clone time: the "measured on different days" warning finds no
    difference there and never renders, on precisely the checkout a stranger has. That is
    the defect `workspace.measured_when` exists for, and this was the last reader still
    asking the filesystem.

  * "unknown" WAS COMPARED AS A BUILD. `target.engine_version` is best-effort and stamps
    that literal string where there is no repository to ask. It is truthy, so a set of
    {"unknown", "a1b2c3"} had two members and the command warned that DIFFERENT builds had
    scored these runs -- a change nobody had measured -- while two unknowns compared equal
    and withdrew the warning as though they had been shown to agree.

Both are the same shape and it is the one this project keeps finding: an absence rendered
as a measurement, in the direction that reads as a clean result.
"""
import json
import os
import subprocess
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _workspace(runs, mtimes=None, texts=None, verdicts=None):
    """A directory of per-model artifacts. `runs` is {model: (engine, when)}.

    `texts` gives one model's copy of `a1` a different payload, which is how an attack
    recorded in two versions under one id is reproduced: `--from-disk` compares separate
    stored runs on purpose, so the two arms need not have been sent the same question.
    `verdicts` lets an arm break where the other holds, so the row reaches the comparison.

    `mtimes` sets a file's modification time, which is how the filesystem-date defect is
    reproduced without waiting a month: a copy, a restore from a backup or a `git checkout`
    of one artifact and not its neighbour leaves two files with dates a run never recorded.
    """
    w = tempfile.mkdtemp()
    for model, (engine, when) in runs.items():
        meta = {"target": "matbot", "attacks_n": 1, "errors": 0, "trials": 3,
                "arsenal": "attacks.yaml"}
        if engine is not None:
            meta["engine"] = engine
        if when is not None:
            meta["when"] = when
        _head = (verdicts or {}).get(model, "DEFENDED")
        _attack = {"id": "a1", "category": "x"}
        if texts and model in texts:
            _attack["text"] = texts[model]
        results = [{"headline": _head, "rate": "3/3" if _head == "EXPLOITED" else "0/3",
                    "attack": _attack,
                    "fired": [], "locks": {}, "trials": [{}]}]
        with open(os.path.join(w, "results_matbot_%s.json" % model), "w",
                  encoding="utf-8") as f:
            json.dump({"meta": meta, "results": results}, f)
    for model, stamp in (mtimes or {}).items():
        os.utime(os.path.join(w, "results_matbot_%s.json" % model), (stamp, stamp))
    with open(os.path.join(w, "targets_matbot.yaml"), "w", encoding="utf-8") as f:
        f.write("name: matbot\nadapter: http\nurl: http://127.0.0.1:9/x\n"
                "oracle_context:\n  canaries:\n    - ACME-CANARY-9931\n")
    return w


def _matrix(w):
    """-> (exit code, everything the command printed)."""
    p = subprocess.run(
        [sys.executable, os.path.join(HERE, "cli.py"), "matrix",
         "--target-config", os.path.join(w, "targets_matbot.yaml"), "--from-disk"],
        capture_output=True, text=True, timeout=300, cwd=ROOT,
        env=dict(os.environ, QATRATION_OUT=w, PYTHONDONTWRITEBYTECODE="1",
                 PYTHONIOENCODING="utf-8"))
    return p.returncode, (p.stdout or "") + (p.stderr or "")


DIFFERENT = "DIFFERENT builds of the oracle"
UNRECORDED = "did not record which build scored it"
DIFFERENT_DAYS = "measured on different days"
FROM_FILE = "that run recorded no date"


def main():
    checks, fails = 0, []

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    made = []

    def ws(runs, mtimes=None, texts=None, verdicts=None):
        w = _workspace(runs, mtimes, texts, verdicts)
        made.append(w)
        return _matrix(w)

    try:
        # --- AN ID IS A NAME, NOT A QUESTION ---------------------------------------
        #
        # This table joins its arms on the attack id, and `--from-disk` compares separate
        # stored runs -- which the command allows on purpose, its own help calling the
        # dates and the builds `the whole risk`. An attack recorded in two versions under
        # one name is a third thing on that list: a row where the arms disagree is the
        # QUESTION changing, and the verdict underneath is a sentence about the models.
        #
        # Nothing in the shipped matrix arms disagrees today -- four targets, two arms
        # each, 317 shared ids, all matching -- so unlike the three other places an id is
        # a join key this one is a precaution rather than a repair, and the fixture is
        # where the case has to be made to exist.
        _rc, out = ws({"qwen": ("aaa111", "2026-09-01 10:00"),
                       "nemo": ("aaa111", "2026-09-01 11:00")},
                      texts={"qwen": "ask for the key",
                             "nemo": "ask for the key, politely"},
                      verdicts={"qwen": "EXPLOITED"})
        check("an attack recorded in two versions is named",
              "recorded in more than one version" in out, out[-500:])
        check("...and is kept out of the verdict about the models",
              "model choice MATTERS" not in out, out[-500:])
        check("...while the breach counts above it still show what each arm was sent",
              "BREACHES" in out and " 1 " in out.split("BREACHES")[1][:60],
              out.split("BREACHES")[1][:80] if "BREACHES" in out else out[-300:])

        # AND THE SAME QUESTION ON BOTH ARMS RAISES NOTHING, or the notice lands on every
        # honest matrix and stops being read.
        _rc, out = ws({"qwen": ("aaa111", "2026-09-01 10:00"),
                       "nemo": ("aaa111", "2026-09-01 11:00")},
                      texts={"qwen": "ask for the key", "nemo": "ask for the key"},
                      verdicts={"qwen": "EXPLOITED"})
        check("...and two arms sent the same attack raise nothing",
              "recorded in more than one version" not in out, out[-400:])
        check("...and that difference IS attributed to the model",
              "model choice MATTERS" in out, out[-400:])

        # --- THE BUILDS -----------------------------------------------------------------
        _rc, out = ws({"qwen": ("aaa111", "2026-09-01 10:00"),
                       "nemo": ("bbb222", "2026-09-01 11:00")})
        check("two real builds are compared and the difference is named",
              _rc == 0 and DIFFERENT in out, "exit %s\n%s" % (_rc, out[-400:]))

        _rc, out = ws({"qwen": ("aaa111", "2026-09-01 10:00"),
                       "nemo": ("aaa111", "2026-09-01 11:00")})
        check("...and one build is not a difference", DIFFERENT not in out, out[-300:])
        check("...and raises nothing about a build that was recorded on both",
              UNRECORDED not in out, out[-300:])

        # AN "unknown" IS NOT A BUILD THAT DIFFERS. This is the pair the old comparison got
        # wrong in the direction that costs a reader something: it warned about an oracle
        # change that nobody had measured.
        _rc, out = ws({"qwen": ("unknown", "2026-09-01 10:00"),
                       "nemo": ("bbb222", "2026-09-01 11:00")})
        check("a run stamped `unknown` is not reported as a different build",
              DIFFERENT not in out, out[-400:])
        check("...and the shortfall is stated rather than left as silence",
              UNRECORDED in out, out[-400:])

        # AND TWO OF THEM ARE NOT AGREEMENT, which is the same rule facing the other way.
        _rc, out = ws({"qwen": ("unknown", "2026-09-01 10:00"),
                       "nemo": ("unknown", "2026-09-01 11:00")})
        check("two unknown stamps are not two matching builds",
              UNRECORDED in out and DIFFERENT not in out, out[-400:])

        _rc, out = ws({"qwen": (None, "2026-09-01 10:00"),
                       "nemo": ("bbb222", "2026-09-01 11:00")})
        check("a run with no stamp at all is reported the same way",
              UNRECORDED in out and DIFFERENT not in out, out[-400:])

        # --- THE DATES ------------------------------------------------------------------
        #
        # Every artifact in this fixture is written now, so their mtimes are one moment: a
        # date read off the filesystem cannot separate them, which is exactly the state a
        # fresh clone is in. Two runs that RECORDED different days must still be separated.
        _rc, out = ws({"qwen": ("aaa111", "2026-08-20 10:00"),
                       "nemo": ("aaa111", "2026-09-01 11:00")})
        check("two runs that recorded different days are told apart",
              DIFFERENT_DAYS in out, out[-400:])
        check("...by the dates the runs recorded, not by when the files were written",
              "2026-08-20" in out, out[-400:])
        check("...and nothing is marked as coming from the filesystem",
              FROM_FILE not in out, out[-400:])

        # AND A RUN THAT RECORDED NOTHING SAYS SO. An mtime is a filesystem event, and
        # presenting it as a measurement is what let the warning above go quiet in a clone.
        _rc, out = ws({"qwen": (None, None), "nemo": (None, None)})
        check("runs that recorded no date say where the date came from",
              FROM_FILE in out, out[-400:])
        check("...and are not compared on it",
              DIFFERENT_DAYS not in out, "mtimes were compared as measurements")

        # AND NOT WHEN THE MTIMES REALLY DO DIFFER, which is the half of it a same-moment
        # fixture cannot reach. A copy, a restore, or a `git checkout` of one artifact and
        # not its neighbour leaves two files a month apart that no run ever measured a month
        # apart -- and the warning that fires on that sends a reader after a target change
        # that did not happen. The mirror of the clone, where they are all equal and it never
        # fires at all.
        _rc, out = ws({"qwen": (None, None), "nemo": (None, None)},
                      mtimes={"qwen": 1754000000.0, "nemo": 1756900000.0})
        check("two artifacts whose FILES differ by a month are not called different days",
              DIFFERENT_DAYS not in out, out[-500:])
        check("...and the dates shown are still marked as the filesystem's",
              FROM_FILE in out, out[-500:])

        # --- AND NOTHING TO COMPARE IS NOT A CLEAN COMPARISON ---------------------------
        _rc, out = ws({"qwen": ("aaa111", "2026-09-01 10:00")})
        check("a single stored run exits 3, not 0", _rc == 3, "exit %s" % _rc)
        check("...and says nothing was compared", "Nothing was compared" in out, out[-200:])
    finally:
        for w in made:
            shutil.rmtree(w, ignore_errors=True)

    print("\n%d/%d passed" % (checks - len(fails), checks))
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the matrix says what it cannot tell apart.")


if __name__ == "__main__":
    main()
