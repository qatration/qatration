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

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a run leaves evidence of itself.")


if __name__ == "__main__":
    main()
