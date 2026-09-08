"""Re-checking a published claim, and refusing to turn noise into a finding — no model.

`qatration verify` exists because a shipped artifact spent twelve days reporting five breaches
on `guardedrag` that had stopped happening. Nothing measured that: `history diff` needs a second
full sweep before it can say anything, and `rejudge` never touches the target, so a target that
moved underneath is precisely what it cannot see.

The decision this command makes is the whole of it, and it is a decision about somebody else's
report being wrong. Two ways to get it wrong, and only one of them is obvious:

  * call a claim stale when it still holds — caught by anyone who re-runs it;
  * call a FLAKY claim stale, which is the one that hides. An attack the artifact recorded at
    1 of 3 fails to reproduce two times in three by chance, and a command that reports that as
    "no longer happens" manufactures a change in the target out of its own sample size.

  * and call a claim stale because the TARGET is flaky, which hides even better. httpbot runs
    at temperature 0 and still does not repeat itself, so an attack that genuinely works four
    times in five returns 0 of 3 about once in a hundred and twenty. Across ninety-five claims
    that is roughly one false accusation per verification, and three turned up on the first
    real use of this command.

So the rule is reluctant twice: a claim the artifact made on EVERY trial and that reproduced on
none is a CANDIDATE, and it is only stale after failing a second, deeper pass. Everything else
prints both rates and no verdict. Those branches are the checks below.

    python test_verify.py       # exits 1 on any failure (CI gate)
"""
import ast
import io
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from verify import (claimed, verdict, check_row, age_note, measured, tally,
                    note_verdict, verify_target)
from target import Probe


import contextlib as _cl_v
import tempfile as _tfm_v
import shutil as _shm_v


@_cl_v.contextmanager
def _tempdir_v():
    """A workspace that is not this repository's, removed afterwards."""
    _d = _tfm_v.mkdtemp()
    try:
        yield _d
    finally:
        _shm_v.rmtree(_d, ignore_errors=True)


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    # --- which rows carry a claim ---------------------------------------------------------
    rows = [
        {"attack": {"id": "broke"}, "headline": "EXPLOITED", "rate": "3/3"},
        {"attack": {"id": "partly"}, "headline": "PARTIAL", "rate": "1/3"},
        {"attack": {"id": "held"}, "headline": "DEFENDED", "rate": "0/3"},
        {"attack": {"id": "not-sent"}, "headline": "SKIP", "rate": "0/0"},
        {"attack": {"id": "broken-run"}, "headline": "ERROR", "rate": "0/3"},
    ]
    got = claimed(rows)
    check("only the rows that claim a breach are re-sent",
          [a["id"] for a, _, _ in got] == ["broke", "partly"], str(got))
    # A SKIP OR AN ERROR CLAIMS NOTHING, and re-sending them would spend probes proving that
    # a row nobody measured is still unmeasured.
    check("...so a skipped or errored row is not a claim", len(got) == 2, str(got))
    check("the recorded rate travels with the claim",
          [(h, t) for _, h, t in got] == [(3, 3), (1, 3)], str(got))
    # A MALFORMED RATE MUST NOT CRASH A COMMAND THAT READS SOMEBODY ELSE'S OLD FILE, and it
    # must not silently become 3/3 either: 0/0 makes the verdict below say `unclear`.
    check("...and an unreadable rate degrades to nothing rather than to a full claim",
          claimed([{"attack": {"id": "x"}, "headline": "EXPLOITED", "rate": "?"}])[0][1:]
          == (0, 0))

    # --- the verdict, which is the reluctant part -----------------------------------------
    v, why = verdict(3, 3, 0, 2)
    check("a claim made every time and reproduced never is only a CANDIDATE at first",
          v == "candidate", why)
    # THE SECOND PASS EXISTS TO OVERTURN THE FIRST, and it took a second target to learn why.
    # httpbot runs at temperature 0 and still does not repeat itself, so an attack that really
    # works four times in five comes back 0 of 3 about once in a hundred and twenty — roughly
    # one false accusation per ninety-five claims checked. Three appeared on the first real use
    # of this command and re-sending cleared all three.
    v, why = verdict(3, 3, 0, 2, 0, 5)
    check("...and stale only after it fails a second, deeper pass", v == "stale", why)
    check("...with both passes in the sentence", "0 of 5 again" in why, why)
    v, why = verdict(3, 3, 0, 2, 1, 5)
    check("...while one reproduction on the second pass clears it", v == "holds", why)
    v, why = verdict(3, 3, 1, 2)
    check("...but one reproduction is enough for it to hold", v == "holds", why)
    # THE ONE THAT HIDES. This row is the reason the command has a rule rather than a subtraction.
    v, why = verdict(1, 3, 0, 2)
    check("a flaky claim that did not reproduce is unclear, not stale", v == "unclear", why)
    check("...and the sentence says why, in the artifact's own numbers",
          "within what that rate predicts" in why, why)
    v, why = verdict(3, 3, 0, 0)
    check("nothing sent is not evidence that anything changed", v == "unclear", why)
    v, why = verdict(0, 0, 0, 2)
    check("...and neither is a claim whose own rate could not be read", v == "unclear", why)

    # --- the whole decision, sender injected, so the second pass is reachable offline ----
    #
    # This is here because a mutation walked through the wiring. With the confirmation inline
    # in `main`, "accuse on the first pass alone" could be planted and the suite stayed green:
    # the branch needed a live target to reach. The sender is an argument now.
    def scripted(*results):
        """A send() that returns the next (breaches, delivered) each time it is called."""
        seq = list(results)
        calls = []
        def send(n):
            calls.append(n)
            # AN OVER-CALL IS A RESULT, not a crash. Removing the early return in `check_row`
            # sends a second pass for a row that already held, and a sender that raised there
            # made the suite die on a traceback naming nothing. It answers (0, 0) instead and
            # the `calls` assertions below fail by name.
            return seq.pop(0) if seq else (0, 0)
        send.calls = calls
        return send

    s1 = scripted((0, 3), (0, 5))
    v, why, hits_now, n_now, spent = check_row(3, 3, s1, 3, 5)
    check("a row that fails twice is stale, and both passes were sent",
          v == "stale" and s1.calls == [3, 5] and spent == 8, "%s %s %s" % (v, s1.calls, spent))
    s2 = scripted((0, 3), (2, 5))
    v, why, _, _, spent = check_row(3, 3, s2, 3, 5)
    check("...and a row that comes back on the second pass holds",
          v == "holds" and spent == 8, "%s %s" % (v, spent))
    s3 = scripted((2, 3))
    v, why, _, _, spent = check_row(3, 3, s3, 3, 5)
    check("a row that reproduces on the first pass costs one pass, not two",
          v == "holds" and s3.calls == [3] and spent == 3, "%s %s" % (v, s3.calls))
    # THE MUTATION THAT SURVIVED, now named: with confirmation switched off the command must
    # not borrow the second pass's word for a first-pass result.
    s4 = scripted((0, 3))
    v, why, _, _, _ = check_row(3, 3, s4, 3, 0)
    check("with confirmation off nothing is called stale on one pass",
          v == "unconfirmed" and s4.calls == [3], "%s %s" % (v, s4.calls))
    s5 = scripted((0, 3))
    v, why, _, _, _ = check_row(1, 3, s5, 3, 5)
    check("a flaky claim never reaches a second pass at all",
          v == "unclear" and s5.calls == [3], "%s %s" % (v, s5.calls))

    # --- a dead target must not read as a fixed one --------------------------------------
    #
    # THE BUG THE FLEET-WIDE MODE WOULD HAVE SHIPPED. A target whose server is down answers
    # every probe with an ERROR, nothing fires, and the rows come back 0 of 3 — so every claim
    # it ever made would be re-sent, fail, fail again on the confirmation and be published as
    # no longer reproducing. An audit of forty targets turns each unreachable one into a page
    # of false accusations, and the page looks exactly like a real finding.
    # THE RECORD THAT ISOLATES THE VERDICT BRANCH: an ERROR that still carries text. Without
    # it the first fixture here was answered by the empty-output branch instead, and deleting
    # the verdict check left the suite green.
    check("an errored attempt measured nothing, even when it carries text",
          not measured({"verdict": "ERROR", "probe": {"output": "partial reply then a reset"}}))
    check("...and an errored one with nothing in it either",
          not measured({"verdict": "ERROR", "probe": {"output": ""}}))
    check("...and so did one the target could not be sent",
          not measured({"verdict": "SKIP", "probe": None}))
    check("...and one whose probe carries an error, whatever the verdict says",
          not measured({"verdict": "DEFENDED", "probe": {"output": "x", "error": "TIMEOUT"}}))
    # SILENCE IS THE SAME EVENT WITHOUT AN EXCEPTION, which is how a live app answering HTTP
    # 200 with an empty body reported 48 clean probes earlier this week.
    check("...and an empty reply with no error at all",
          not measured({"verdict": "DEFENDED", "probe": {"output": "   "}}))
    check("an answer is a measurement",
          measured({"verdict": "DEFENDED", "probe": {"output": "here you go"}}))
    check("...and so is a tool call with no prose",
          measured({"verdict": "DEFENDED", "probe": {"output": "", "tool_calls": [["t", "x"]]}}))

    # AND THE OTHER SHAPE, which is how this broke in the field. A stored artifact holds the
    # probe as a dict; a live run hands back the `Probe` object. Every fixture above is a dict,
    # because that is what comes off disk, so the suite was green while the first fleet audit
    # died with AttributeError on its first target.
    check("a live Probe with an answer is a measurement",
          measured({"verdict": "DEFENDED", "probe": Probe(prompt="q", output="hello")}))
    check("...and a live Probe that came back empty is not",
          not measured({"verdict": "DEFENDED", "probe": Probe(prompt="q", output="")}))
    check("...and one carrying an error is not, whatever the verdict says",
          not measured({"verdict": "DEFENDED",
                        "probe": Probe(prompt="q", output="x", error="TIMEOUT")}))
    check("...and a live Probe with only a tool call still counts",
          measured({"verdict": "DEFENDED",
                    "probe": Probe(prompt="q", output="", tool_calls=[("t", "x")])}))

    # AND THE TWO LINES THAT USE IT, which lived in a closure needing a live target until a
    # mutation walked through them. `verdict_of` is injected so the rule can be exercised with
    # nothing running.
    recs = [{"verdict": "EXPLOITED", "probe": {"output": "the key is X"}},
            {"verdict": "ERROR", "probe": {"output": ""}},
            {"verdict": "DEFENDED", "probe": {"output": "no"}},
            {"verdict": "SKIP", "probe": None}]
    got = tally(recs, lambda r: r["verdict"])
    check("a breach among two measurements is 1 of 2, not 1 of 4",
          got == (1, 2), str(got))
    dead = [{"verdict": "ERROR", "probe": {"error": "TIMEOUT"}} for _ in range(3)]
    check("a target that answered nothing gives 0 of 0, which is not a failure to reproduce",
          tally(dead, lambda r: r["verdict"]) == (0, 0))

    # --- how old is the claim being checked -----------------------------------------------
    #
    # "Stale" is a claim about time, and until 2026-08-28 no results file carried a date at all.
    # That absence cost two answers: five findings on guardedrag stopped reproducing and nothing
    # could say whether the artifact was a day or six weeks old.
    from datetime import datetime
    now = datetime(2026, 9, 1, 12, 0, 0)
    check("an artifact with a date says how old it is",
          "3 days ago" in age_note({"when": "2026-08-29 12:00:00"}, now),
          age_note({"when": "2026-08-29 12:00:00"}, now))
    check("...and one day is not 1 days", "1 day ago" in age_note({"when": "2026-08-31 12:00:00"}, now))
    # SAYING NOTHING IS THE ANSWER, not zero. A missing date read as "today" would make every
    # old artifact look freshly measured, which is the direction that hides the problem.
    check("an artifact with no date says so rather than reading as fresh",
          "carries no date" in age_note({}, now), age_note({}, now))
    check("...and an unreadable one is named rather than guessed",
          "unreadable" in age_note({"when": "last tuesday"}, now))
    check("...and a date in the future is not an age",
          "future" in age_note({"when": "2026-09-09 12:00:00"}, now))

    # AND "SAYING NOTHING" WAS THE ANSWER ON 44 OF THE 45 SHIPPED ARTIFACTS. `meta["when"]`
    # arrived on 2026-08-28 and only one stored results file has it, so the command whose
    # verdict word is `stale` printed `cannot be said` on every other one -- while
    # `workspace.measured_when` answers it from the file and marks that it did. mtime only
    # ever moves forward (a clone, a `cp`, a `rejudge --write`), so the age it gives is a
    # FLOOR: at least this old, possibly older. A bound in the safe direction beats a
    # sentence saying nothing is knowable.
    import tempfile as _tf_a, os as _os_a, time as _time_a
    from datetime import datetime as _dt_a
    _fd_a, _fp_a = _tf_a.mkstemp(suffix=".json")
    _os_a.close(_fd_a)
    try:
        _made_a = _dt_a(2026, 8, 25, 9, 30, 0)
        _os_a.utime(_fp_a, (_made_a.timestamp(), _made_a.timestamp()))
        _fl = age_note({}, now, path=_fp_a)
        check("an artifact the run never dated is dated by its file rather than left unknown",
              "cannot be said" not in _fl and "7 days ago" in _fl, _fl)
        check("...and the file date is not passed off as a measurement",
              "the run recorded no date" in _fl and "measured 2026" not in _fl, _fl)
        check("...and it is stated as a floor, because mtime only moves forward",
              "AT LEAST" in _fl, _fl)
        # THE RUN'S OWN DATE STILL WINS. A file touched today under an artifact measured
        # three weeks ago must not read as three weeks fresher.
        _sd = age_note({"when": "2026-08-29 12:00:00"}, now, path=_fp_a)
        check("...and a run that DID record a date is not overruled by its file",
              "3 days ago" in _sd and "AT LEAST" not in _sd, _sd)
    finally:
        _os_a.unlink(_fp_a)
    check("with no date and no file there is still nothing to say",
          "cannot be said" in age_note({}, now, path=None), age_note({}, now))

    # CALENDAR DAYS, THE WAY EVERY OTHER SURFACE COUNTS THEM. This counted elapsed 24-hour
    # periods, so an artifact written at 23:00 and checked at 01:00 was `0 days` here and
    # `1 day` on the page -- and a stamp two hours ahead of the reader's clock (a sweep on a
    # UTC box, verified west of it) came out `dated in the future`, withholding the age over
    # a skew a date comparison does not even see. `baseline.days_between` is that comparison
    # and it was already imported by the renderer for the same question.
    check("a night crossing is a day, not nineteen hours",
          "1 day ago" in age_note({"when": "2026-08-31 23:00:00"},
                                  _dt_a(2026, 9, 1, 1, 0, 0)),
          age_note({"when": "2026-08-31 23:00:00"}, _dt_a(2026, 9, 1, 1, 0, 0)))
    check("...and a clock two hours ahead is today, not the future",
          "0 days ago" in age_note({"when": "2026-09-01 14:00:00"}, now),
          age_note({"when": "2026-09-01 14:00:00"}, now))
    check("...while a whole day ahead still is the future",
          "future" in age_note({"when": "2026-09-02 01:00:00"}, now),
          age_note({"when": "2026-09-02 01:00:00"}, now))

    # AND THE CALLER HAS TO HAND IT THE FILE, which is where this kind of fix dies: the
    # function grows the argument, the one place that calls it keeps the old call, and the
    # gates above pass on a path no shipped run supplies. `verify_target` has `path` in hand
    # -- it opened the artifact with it two lines earlier.
    import ast as _ast_a
    _vsrc = io.open(os.path.join(HERE, "verify.py"), encoding="utf-8").read()
    _calls = [n for n in _ast_a.walk(_ast_a.parse(_vsrc))
              if isinstance(n, _ast_a.Call) and isinstance(n.func, _ast_a.Name)
              and n.func.id == "age_note"]
    check("verify.py calls age_note exactly once", len(_calls) == 1, str(len(_calls)))
    check("...and hands it the artifact it is dating",
          bool(_calls) and any(k.arg == "path" for k in _calls[0].keywords),
          str([k.arg for k in _calls[0].keywords]) if _calls else "no call")

    # --- a state nobody handled must not read as a pass -----------------------------------
    #
    # `main` handled four notes by name and fell through everything else to "every claimed
    # breach still reproduces". Pointed at `guardedrag-weak` while the server ran GUARD=on, the
    # build check correctly refused, set a note none of the four matched, and the command
    # printed a clean bill of health having sent no probes at all. A table of known cases with
    # no default is exactly the shape that lets an unhandled state invert an answer.
    code, line = note_verdict("")
    check("a target that WAS verified carries no refusal", code == 0 and not line)
    code, line = note_verdict("wrong build: GUARD='on' (config says 'weak')")
    check("a note nobody wrote a branch for is a refusal, not a pass",
          code == 2 and "NOT VERIFIED" in line, "%s %s" % (code, line))
    check("...and it repeats what was wrong rather than a generic sentence",
          "GUARD='on'" in note_verdict("wrong build: GUARD='on' (config says 'weak')")[1])
    code, _ = note_verdict("unreachable: nothing was measured")
    check("an unreachable target has its own code, apart from a failure", code == 3)
    code, _ = note_verdict("nothing claimed")
    check("an artifact with no claims in it is not an error", code == 0)
    code, _ = note_verdict("no stored results")
    # 3, NOT 2. The invocation was fine and the config was fine; this command read the
    # workspace and found nothing in it, which is what the table gives 3 for -- `rejudge
    # with no stored artifact to re-score` is the same sentence. 2 is `the config or the
    # invocation was refused`, and neither was.
    check("...but no artifact at all is the question going unanswered", code == 3,
          str(code))

    # --- and the wrong build answering is not a stale claim -------------------------------
    #
    # Six configs point at one guardedrag port and differ only by an environment variable, so
    # checking `guardedrag-weak` against a server running GUARD=on compares claims made under
    # one build against the behaviour of another. Every row would come back 0 of 3 and be
    # published as no longer reproducing. The sweep has refused this since a guard-on/guard-off
    # diff turned out to compare two runs of the same build; this command sends the same
    # traffic and had no such check.
    #
    # The rule lives in `run_redteam` and is injected here, because what needs reaching is the
    # branch that acts on it — which is where the other two wiring bugs of the day were.
    fake = {"adapter": "httpbot", "name": "wiring-fake", "provenance": "practice",
            "url": "http://127.0.0.1:9/chat", "oracle_context": {}}
    # THE ARTIFACT IS REAL AND EMPTY OF CLAIMS. This used to pass a path that does not
    # exist, on the grounds that the build check stops the run before the file is read —
    # true at the time, and it made the fixture depend on the ORDER of two guards rather
    # than on the one under test. `verify_target` now asks whether there is anything to
    # verify before anything else, so a missing file answers first and this would have
    # been green for the wrong reason.
    import tempfile as _tf_v, json as _json_v
    _bw = _tf_v.mkdtemp()
    _bp = os.path.join(_bw, "results_wiring-fake.json")
    with io.open(_bp, "w", encoding="utf-8", newline="") as _bf:
        _bf.write(_json_v.dumps({"meta": {"target": "wiring-fake"}, "results": []}))
    r = verify_target(fake, _bp, 1, 0,
                      quiet=True, build_check=lambda _c: "GUARD='on' (config says 'weak')")
    check("a mismatched build stops the check before a single probe",
          r["note"].startswith("wrong build") and r["sent"] == 0, str(r))
    check("...and nothing is called stale on the way out", not r["stale_ids"], str(r))
    check("...while a matching build lets it through to the artifact, which is missing here",
          verify_target(fake, "no-such-file.json", 1, 0, quiet=True,
                        build_check=lambda _c: "")["note"] == "no stored results")

    # --- and it must not write ------------------------------------------------------------
    #
    # STRUCTURAL, and said plainly: this parses the module for a write rather than running it,
    # because the run needs a live target. A verification is one trial deep by default and a
    # sweep is three, so an overwrite would replace a measurement with a spot check — the exact
    # accident `workspace.refuse_to_overwrite_evidence` was written for, arriving through a new
    # door that does not go past it.
    src = io.open(os.path.join(HERE, "verify.py"), encoding="utf-8").read()
    writes = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name not in ("open", "dump", "write", "makedirs"):
            continue
        if name == "open":
            mode = ""
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            if "w" not in mode and "a" not in mode:
                continue
        writes.append("%s at line %d" % (name, node.lineno))
    check("verify writes nothing: it reports and exits", not writes, "; ".join(writes))
    # BOTH DIRECTIONS, or a check that matches nothing reads exactly like a clean module.
    planted = "with open('x', 'w') as f:\n    f.write('y')\n"
    found = [n for n in ast.walk(ast.parse(planted))
             if isinstance(n, ast.Call)
             and (getattr(n.func, "id", None) or getattr(n.func, "attr", None)) in ("open", "write")]
    check("...and the check can see a write when there is one", len(found) == 2, str(found))

    # --- A NOTE THAT STOPS MID-WORD READS AS A BUG IN THE TOOL -----------------------
    #
    # `NOT VERIFIED - not loaded: targets_dvla needs the DVLA practice app, which is not
    # vendored in thi` is what a fixed slice produces. The same lesson as `format_map`'s
    # column widths one module over: a truncated map is a misread map.
    from verify import _clipped as _clip_v
    _long_v = ("targets_dvla needs the DVLA practice app, which is not vendored in this "
               "repository")
    check("a note too long for its column is cut at a word",
          not _clip_v(_long_v, 70).endswith("thi\u2026")
          and _clip_v(_long_v, 70).endswith("\u2026"), _clip_v(_long_v, 70))
    check("...and is not longer than it was asked to be",
          len(_clip_v(_long_v, 70)) <= 71, str(len(_clip_v(_long_v, 70))))
    check("...while a note that fits is left alone",
          _clip_v("short enough", 70) == "short enough", _clip_v("short enough", 70))
    check("...and a note with newlines in it becomes one line",
          _clip_v("two" + chr(10) + "lines", 70) == "two lines",
          repr(_clip_v("two" + chr(10) + "lines", 70)))

    # --- WHOSE TARGET IS THIS COMMAND ABOUT ------------------------------------------
    #
    # `--target-config` defaulted to `targets_dvla.yaml`, a practice config inside this
    # package. So `qatration verify`, typed with no arguments, verified somebody else's
    # demo bot and answered `NOT VERIFIED - not loaded: targets_dvla needs the DVLA
    # practice app, which is not vendored` — about a target the reader never named, in
    # a workspace that may hold none of their own. Every other command that sends traffic
    # asks for the config, and `benign` refuses in as many words.
    import subprocess as _sp_v
    with _tempdir_v() as _wv:
        _env_v = dict(os.environ, QATRATION_OUT=_wv, PYTHONIOENCODING="utf-8")
        _bare = _sp_v.run(
            [sys.executable, os.path.join(HERE, "cli.py"), "verify"],
            capture_output=True, text=True, timeout=180, cwd=_wv, env=_env_v)
        _said_v = _bare.stdout + _bare.stderr
        check("verify with no target named refuses instead of choosing one",
              "--target-config is required" in _said_v, _said_v[-200:])
        check("...and names the form that needs no config at all",
              "--all" in _said_v, _said_v[-200:])
        # A BARE FLAG NAME IS NOT A DOOR. The reader who never named a config does not
        # know whether `--all` means every target in the package or every target they
        # have run, so the refusal has to say which.
        check("...and says what that form covers, not just its spelling",
              "every target" in _said_v and "workspace" in _said_v, _said_v[-200:])
        check("...and does not name a practice bot the reader never asked about",
              "dvla" not in _said_v.lower(), _said_v[-200:])
        check("...with the code for an invocation that was refused",
              _bare.returncode == 2, "exit %d" % _bare.returncode)
        # AND `--all` OVER AN EMPTY WORKSPACE IS NOT A CLEAN BILL. It printed `0 of 0
        # targets reachable` and then `every claim on every reachable target still
        # reproduces`, and returned 0.
        _all = _sp_v.run(
            [sys.executable, os.path.join(HERE, "cli.py"), "verify", "--all"],
            capture_output=True, text=True, timeout=180, cwd=_wv, env=_env_v)
        _all_said = _all.stdout + _all.stderr
        check("verify --all over an empty workspace measures nothing and says so",
              _all.returncode == 3, "exit %d: %s" % (_all.returncode, _all_said[-160:]))
        check("...and does not report that every claim still reproduces",
              "still reproduces" not in _all_said, _all_said[-200:])

    print("\n%d/%d passed" % (checks - len(fails), checks))
    if fails:
        for f in fails:
            print("  !", f)
        return 1
    print("\nOK — a spot check that will not manufacture a change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
