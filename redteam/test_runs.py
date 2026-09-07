"""The record of what we did, to whom, on whose authority, and what it cost — no model.

Everything else this engine writes is named after the TARGET, which is right for a workbench
and wrong for a service. The questions a service is asked are about the RUN: who authorised
it, what it cost against the budget it was promised, how it ended, and which build produced
it. None of those had anywhere to live.

The checks below are mostly about endings, because that is where a record earns its keep. A
run that finished and a run whose budget ran out are different events, and if the difference
does not survive into the record then the attacks that were never sent become, silently, a set
of rows that held — which is the one mistake this repo is organised around not making.

    python test_runs.py          # exits 1 on any failure (CI gate)
"""
import sys, os, json, tempfile, shutil, datetime
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import runs


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    root = tempfile.mkdtemp()
    try:
        # --- ids a human can use ----------------------------------------------------------
        a = runs.new_id(datetime.datetime(2026, 8, 18, 19, 4))
        b = runs.new_id(datetime.datetime(2026, 8, 18, 19, 4))
        check("an id carries its time, so a directory listing sorts by when",
              a.startswith("2026-08-18T1904"), a)
        check("...and two runs in the same minute are still distinct", a != b, f"{a} {b}")
        check("...and an id is filename-safe", "/" not in a and "\\" not in a and ":" not in a)

        # --- the record exists BEFORE the first probe -------------------------------------
        # Because the runs worth having a record of are disproportionately the ones that did
        # not finish: the target went down, the budget ran out, somebody killed it. A record
        # written only on success describes exactly the runs nobody needs to ask about.
        rec = runs.start(root, a, "acme-support", scope="quick",
                         authorization={"method": "header", "origin": "https://api.acme.example"},
                         budgets={"max_requests": 200, "max_seconds": 1800},
                         engine="abc1234", arsenal="attacks_generic.yaml", trials=2)
        on_disk = runs.load(root, a)
        check("the record is on disk before anything is sent", on_disk is not None)
        check("...and says the run started rather than nothing", on_disk["state"] == "started")
        check("...and carries who authorised it",
              on_disk["authorization"]["method"] == "header", str(on_disk["authorization"]))
        check("...and the budgets it was promised",
              on_disk["budgets"]["max_requests"] == 200, str(on_disk["budgets"]))
        check("...and which build produced it", on_disk["engine"] == "abc1234")
        check("...and has no finish time yet", on_disk["finished_at"] is None)

        # --- endings, which is where a record earns its keep ------------------------------
        done = runs.finish(root, rec, "finished", spent={"requests": 38, "seconds": 412})
        check("a finished run records what it cost",
              runs.load(root, a)["spent"] == {"requests": 38, "seconds": 412},
              str(runs.load(root, a)["spent"]))
        check("...and when it ended", runs.load(root, a)["finished_at"] is not None)
        check("...without losing what it started with",
              runs.load(root, a)["budgets"]["max_seconds"] == 1800)

        # A run stopped by its budget is NOT a run that finished. If that difference does not
        # survive, the attacks that were never sent become rows that held.
        c = runs.new_id()
        rec2 = runs.start(root, c, "acme-support", scope="quick",
                          budgets={"max_requests": 10})
        runs.finish(root, rec2, "stopped", spent={"requests": 10},
                    note="request budget spent; 9 attacks were never sent")
        stopped = runs.load(root, c)
        check("a run stopped by its budget is not recorded as finished",
              stopped["state"] == "stopped", stopped["state"])
        check("...and says what was not sent", "never sent" in (stopped["note"] or ""),
              str(stopped["note"]))
        try:
            runs.finish(root, rec2, "vanished")
            check("an ending the record does not understand is refused", False, "accepted")
        except ValueError:
            check("an ending the record does not understand is refused", True)

        # --- reading them back -------------------------------------------------------------
        rows = runs.listing(root)
        check("every run in the workspace is listed", len(rows) == 2, str(len(rows)))
        check("...newest first, which is where somebody looks",
              rows[0]["started_at"] >= rows[1]["started_at"], str([r["run_id"] for r in rows]))
        line = runs.summarise(stopped)
        check("a run summarises to one line with its state and cost",
              "stopped" in line and "requests 10" in line, line)

        check("a run that never existed reads as absent", runs.load(root, "nope") is None)

        # Unreadable is NOT absent, and saying which is the whole discipline here: a truncated
        # record must not look like a run that never happened.
        with open(os.path.join(root, "run_torn.json"), "w", encoding="utf-8") as f:
            f.write('{"run_id": "torn", "sta')
        torn = runs.load(root, "torn")
        check("a torn record reads as unreadable, not as absent",
              torn and torn["state"] == "unreadable", str(torn))
        check("...and it still appears in the listing rather than vanishing",
              any(r["run_id"] == "torn" for r in runs.listing(root)))

        # --- and writing is atomic, so a killed run cannot leave a torn one ---------------
        src = open(os.path.join(HERE, "runs.py"), encoding="utf-8").read()
        check("records are replaced, not written in place", "os.replace(" in src)
        check("...and nothing is left behind on success",
              not [f for f in os.listdir(root) if f.endswith(".tmp")], str(os.listdir(root)))
    finally:
        shutil.rmtree(root, ignore_errors=True)

    # --- AN ARTIFACT CAN NAME THE RUN THAT MADE IT -------------------------------------
    # `runs.py` records what a sweep did, what it cost and how it ENDED, and forty-five
    # stored results files carried no way to reach it -- the id exists three hundred lines
    # above where the meta is written. A run stopped by hand writes fewer rows and NO errors,
    # so a page shows a small attack count and no reason; the record has the reason.
    import json as _json
    import tempfile as _tf
    import os as _os
    import io as _io
    import runs as _r

    _d = _tf.mkdtemp()
    _io.open(_os.path.join(_d, "run_abc.json"), "w", encoding="utf-8").write(_json.dumps(
        {"run_id": "abc", "state": "stopped", "target": "t",
         "note": "stopped by hand after 7 of 357 attacks"}))
    _io.open(_os.path.join(_d, "run_fin.json"), "w", encoding="utf-8").write(_json.dumps(
        {"run_id": "fin", "state": "finished", "target": "t", "note": ""}))

    check("an artifact carrying a run_id reaches its record",
          (_r.record_for({"run_id": "abc"}, _d) or {}).get("state") == "stopped",
          str(_r.record_for({"run_id": "abc"}, _d)))
    check("...and a stopped run is said, with the reason the record holds",
          "stopped" in _r.unfinished_note({"run_id": "abc"}, _d)
          and "7 of 357" in _r.unfinished_note({"run_id": "abc"}, _d),
          _r.unfinished_note({"run_id": "abc"}, _d))
    check("...and a finished run says nothing",
          _r.unfinished_note({"run_id": "fin"}, _d) == "",
          _r.unfinished_note({"run_id": "fin"}, _d))
    # CANNOT SAY IS NOT IT FINISHED. Every artifact shipped before this link has no id, and
    # inventing a verdict for them would be the claim this whole mechanism exists to avoid.
    check("an artifact from before the link claims nothing",
          _r.record_for({}, _d) is None and _r.unfinished_note({}, _d) == "",
          "an artifact with no run_id was given a verdict")
    check("...and neither does one whose record is gone",
          _r.unfinished_note({"run_id": "missing"}, _d) == "",
          _r.unfinished_note({"run_id": "missing"}, _d))


    # --- THE RECORD HAS A DOOR ---------------------------------------------------------
    #
    # This module opens by naming four things a run record exists to answer -- who
    # authorised this, what did it cost, how did it end, which build produced it -- and
    # calls them "something somebody will actually ask". Nothing could ask. `listing` and
    # `summarise` were reached by the suite and by `worker`, `summarise` describes itself
    # as "one line a human reads in a terminal", and the module had no `main()` to invoke
    # either. `cli.COMMANDS` carries the same lesson twice already, for three commands that
    # "had no door" and three more found the same way.
    #
    # DRIVEN AS A SUBPROCESS, because the exit code is half the contract and a function
    # call cannot see it.
    import subprocess as _sp_d, tempfile as _tf_d, json as _js_d

    def _runs_cmd(work, *flags):
        _p = _sp_d.run(
            [sys.executable, os.path.join(HERE, "cli.py"), "runs"] + list(flags),
            capture_output=True, text=True, timeout=120,
            env=dict(os.environ, QATRATION_OUT=work,
                     PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8"))
        return _p.returncode, (_p.stdout or "") + (_p.stderr or "")

    _w = _tf_d.mkdtemp()
    _rc, _out = _runs_cmd(_w)
    check("an empty workspace is 3, not an empty table", _rc == 3, "exit %s" % _rc)
    check("...and says a record is written when a run STARTS, so a reader knows why",
          "starts" in _out, _out[:200])

    # THE MOMENT IS THE CALLER'S TO GIVE. `start` stamps `started_at` with now() unless told
    # otherwise, so two records made in one breath sort by nothing at all -- and the first
    # version of this check read the ids and believed them.
    _t9 = datetime.datetime(2026, 9, 1, 9, 0, 0)
    runs.start(_w, "2026-09-01T0900-aaaaaa", "botA", scope="full", when=_t9)
    _rec2 = runs.start(_w, "2026-09-01T1000-bbbbbb", "botB", scope="quick",
                       when=_t9 + datetime.timedelta(hours=1))
    runs.finish(_w, _rec2, "finished", spent={"requests": 12})
    _rc, _out = _runs_cmd(_w)
    check("a workspace with records lists them and exits 0", _rc == 0, "exit %s" % _rc)
    check("...newest first", _out.index("botB") < _out.index("botA"), _out[:200])
    check("...with what it cost", "requests 12" in _out, _out[:300])
    # AN OPEN RECORD IS THE ONE WORTH SEEING, and it is said separately: `start` writes
    # before the first probe, so a `started` row is either a sweep in flight or a run that
    # never came back, and those two look identical -- which is the honest answer and the
    # reason it does not sit in the table reading as ordinary.
    check("...and an open record is named under its own heading",
          "still open" in _out and "botA" in _out.split("still open")[1], _out[-300:])
    check("...while a closed one is not", "botB" not in _out.split("still open")[1],
          _out[-300:])

    # AND THE FILTERS NARROW WITHOUT LYING. A filter that matches nothing is not a clean
    # empty list: it is 3, the code this project documents as nothing measured.
    _rc, _out = _runs_cmd(_w, "--target", "botB")
    check("a target filter keeps only that target",
          _rc == 0 and "botB" in _out and "botA" not in _out, _out[:200])
    _rc, _out = _runs_cmd(_w, "--target", "nosuch")
    check("...and a filter that matches nothing is 3, not a clean empty list",
          _rc == 3, "exit %s" % _rc)
    check("...and names the targets there ARE, so the next try can be right",
          "botA" in _out and "botB" in _out, _out[:200])
    _rc, _out = _runs_cmd(_w, "--state", "started")
    check("a state filter keeps only that state",
          _rc == 0 and "botA" in _out and "botB" not in _out.split("still open")[0],
          _out[:200])

    # AN UNREADABLE RECORD IS NOT AN ABSENT ONE, which `load` already decided; the command
    # has to carry that through rather than dropping the row.
    with open(os.path.join(_w, "run_torn.json"), "w", encoding="utf-8") as _f:
        _f.write("{not json")
    _rc, _out = _runs_cmd(_w)
    check("an unreadable record is reported rather than dropped",
          "could not be read" in _out and "torn" in _out, _out[-300:])

    # AND THE COLUMN CANNOT WELD ITSELF TO THE NEXT ONE. At 20 characters the target name
    # ran straight into `scope=` -- `guardedrag-mitigatedscope=full` -- and a row that runs
    # two fields together invents a word, which `run_redteam` had already learned from
    # `refusal_capability:1-`.
    _long = runs.start(_w, "2026-09-01T1100-cccccc", "guardedrag-mitigated", scope="full",
                       when=_t9 + datetime.timedelta(hours=2))
    _rc, _out = _runs_cmd(_w)
    check("a long target name does not weld to the next column",
          "guardedrag-mitigated  " in _out and "mitigatedscope" not in _out,
          _out[:300])

    # --- EVERY EXIT AFTER THE RECORD IS OPENED OWES IT AN ENDING ----------------------
    #
    # `runs.start` writes before the first probe on purpose: "the runs worth having a
    # record of are disproportionately the ones that did not finish". That makes the record
    # open from that line to the end of `main`, and every way out of the function in between
    # is a run that has to say how it ended.
    #
    # FOUR REFUSALS CLOSED IT AND FIVE DID NOT. Each of the five printed `Nothing was sent`
    # and exited -- a published canary, a refusal to overwrite committed evidence, a
    # honeytoken with no verifier, a honeytoken that was never planted, an unusable arsenal
    # -- leaving a record that says `started` for a run that never began. One such record is
    # on disk in this repository: lcagent, 2026-08-19, still open, and a reader of
    # `qatration runs` cannot tell it from a sweep the machine died in the middle of.
    #
    # ASKED OF THE AST, not of the text: an exit is a `sys.exit` call, and what makes it
    # legitimate is a `finish` just above it or a `_refuse` that does the closing itself.
    import ast as _ast_r, io as _io_r
    _src = _io_r.open(os.path.join(HERE, "run_redteam.py"), encoding="utf-8").read()
    _fn = [n for n in _ast_r.walk(_ast_r.parse(_src))
           if isinstance(n, _ast_r.FunctionDef) and n.name == "main"]
    check("run_redteam has a main to walk", bool(_fn), "no main")
    if _fn:
        _fn = _fn[0]

        def _calls(name, attr=True):
            return [n.lineno for n in _ast_r.walk(_fn)
                    if isinstance(n, _ast_r.Call)
                    and ((isinstance(n.func, _ast_r.Attribute) and n.func.attr == name)
                         if attr else
                         (isinstance(n.func, _ast_r.Name) and n.func.id == name))]

        _start = _calls("start")
        _finish = _calls("finish")
        _refuse = _calls("_refuse", attr=False)
        check("the record is opened once", len(_start) == 1, str(_start))
        check("...and closed in more than one place, because a run ends more than one way",
              len(_finish) >= 4, str(len(_finish)))
        _open_at = _start[0] if _start else 0
        _leaks = []
        for _n in _ast_r.walk(_fn):
            if not (isinstance(_n, _ast_r.Call)
                    and isinstance(_n.func, _ast_r.Attribute)
                    and _n.func.attr == "exit" and _n.lineno > _open_at):
                continue
            if any(0 <= _n.lineno - _f <= 12 for _f in _finish):
                continue
            if any(abs(_n.lineno - _r) <= 1 for _r in _refuse):
                continue
            # AFTER THE LAST CLOSE, the record is already ended: the CI gate exits live
            # there and owe nothing.
            if _finish and _n.lineno > max(_finish):
                continue
            _leaks.append(_n.lineno)
        check("no exit between opening the record and closing it leaves it open",
              not _leaks, "run_redteam.py lines %s" % _leaks)
        # AND THE HELPER REALLY DOES CLOSE IT, or every call to it is a leak with a name.
        _ref_fn = [n for n in _ast_r.walk(_fn)
                   if isinstance(n, _ast_r.FunctionDef) and n.name == "_refuse"]
        check("the refusal helper exists", bool(_ref_fn), "no _refuse")
        if _ref_fn:
            _body = _ref_fn[0]
            check("...and it closes the record before exiting",
                  any(isinstance(x, _ast_r.Call)
                      and isinstance(x.func, _ast_r.Attribute)
                      and x.func.attr == "finish" for x in _ast_r.walk(_body)), "")
            check("...as `aborted`, which is what nothing-was-sent means",
                  any(isinstance(x, _ast_r.Constant) and x.value == "aborted"
                      for x in _ast_r.walk(_body)), "")
            check("...and is used by every refusal that used to leak", len(_refuse) >= 5,
                  "%d call(s)" % len(_refuse))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a run leaves evidence of itself.")


if __name__ == "__main__":
    main()
