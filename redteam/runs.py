"""A run is a thing that happened, so it gets a record — not just a folder of artifacts.

Everything this engine writes is named after the TARGET: `results_<target>.json`,
`history/<target>.jsonl`, `benign_<target>.json`. That is right for a workbench, where the
question is "what does this bot do", and wrong once more than one target is in flight, where
the question is "what ran, against what, on whose authority, and what did it cost". Two operators with a bot called
"supportbot" is only the most obvious version of the problem; the deeper one is that a run
currently leaves no evidence of itself at all. `workspace.py` made the artifact root a
variable, which is the namespace. This is the record that goes in it.

Four things it has to answer, and each of them is something somebody will actually ask:

  * **who authorised this** — already verified before the first probe, and the proof belongs
    beside the run rather than only inside one results file;
  * **what did it cost** — requests and seconds, against the budgets it was given, because a
    limited run is a promise about cost and an unmeasured promise is a hope;
  * **how did it end** — finished, or stopped by a budget, or aborted. A run that ran out of
    time and one that finished are different events and the difference must survive into the
    record, not just into a console nobody kept;
  * **which build produced it** — the same `engine_version()` stamp results carry, because a
    stale artifact is a claim about the current engine that nothing re-checks.

Deliberately append-only per run and written TWICE: once when the run starts, so a run that
dies leaves a record saying it started and never finished, and once at the end. A record
written only on success describes exactly the runs that need no explaining.
"""
import datetime, json, os, uuid

STATES = ("started", "finished", "stopped", "aborted")


def new_id(when=None):
    """`2026-08-18T1904-3f7a2b` — sortable by time, unique by luck, readable by a human.

    A bare uuid sorts randomly in a directory listing, which is exactly where somebody looks
    when they are trying to find the run behind a report somebody is questioning.
    """
    when = when or datetime.datetime.now()
    return f"{when.strftime('%Y-%m-%dT%H%M')}-{uuid.uuid4().hex[:6]}"


def _path(root, run_id):
    return os.path.join(str(root), f"run_{run_id}.json")


# THE SAME FUNCTION LIVED HERE AND IN `jobqueue`, docstring and all. Found by asking which
# prose literals appear in more than one module -- the answer was this docstring, twice.
# `jobqueue.scope_of` keeps it because that module owns a job record and this one owns a run
# record, and the field means the same thing in both: what the run was scoped to.
from jobqueue import scope_of as _scope


def record_for(meta, root):
    """The run record that produced this artifact, or None when it cannot be known.

    A results file that predates `run_id` in its meta -- all forty-five shipped when this was
    written -- returns None, and None means "cannot say", never "it finished". The pages have
    to keep those apart: an artifact from a run STOPPED by hand looks exactly like a small
    sweep, and one from a run stopped by its BUDGET looks like a sweep with errors in it.

    Kept here rather than in a page because more than one page wants it, and because this is
    the module that decides what a record is.
    """
    rid = (meta or {}).get("run_id")
    if not rid:
        return None
    try:
        with open(_path(root, rid), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def unfinished_note(meta, root):
    """A sentence when the run behind this artifact did not finish, else "".

    A run STOPPED by hand writes fewer rows and no errors, so the page shows a small attack
    count and no reason; one stopped by its BUDGET writes ERROR rows, which `measured()`
    already subtracts. Neither says WHY, and the record does: `stopped by hand after 7 of 357
    attacks in 42 minutes` is a real note on a real record in this repository.

    Silent for an artifact with no `run_id` -- every one shipped before the link existed --
    because "cannot say" is not "it finished".
    """
    rec = record_for(meta, root)
    if not rec or rec.get("state") == "finished":
        return ""
    why = (rec.get("note") or "").strip()
    return ("the run behind this evidence ended as %r%s"
            % (rec.get("state"), ": " + why if why else ""))


def start(root, run_id, target, scope="full", authorization=None, budgets=None, engine=None,
          arsenal=None, trials=None, when=None):
    """Write the record BEFORE the first probe, and return it.

    Before, not after, because the runs worth having a record of are disproportionately the
    ones that did not finish: the target went down, the budget ran out, somebody killed it. A
    record written only on success describes the runs nobody needs to ask about.
    """
    rec = {
        "run_id": run_id,
        "state": "started",
        "target": target,
        "scope": scope,
        "engine": engine,
        "arsenal": arsenal,
        "trials": trials,
        # The proof carried here as well as in the results file. One is the evidence attached
        # to the findings; this one is the audit trail, and they answer to different people.
        "authorization": authorization,
        "budgets": budgets or {},
        "started_at": (when or datetime.datetime.now()).isoformat(" ", "seconds"),
        "finished_at": None,
        "spent": {},
        "note": None,
    }
    _write(root, rec)
    return rec


def finish(root, rec, state="finished", spent=None, note=None, when=None):
    """Close the record. `state` distinguishes the endings that matter.

    A run stopped by its budget is not a run that finished, and the difference decides what
    the report may claim: the attacks that were never sent are a gap, not a set of defended
    rows. `not_run` draws the same line in the timeline and this is where it starts.
    """
    if state not in STATES:
        raise ValueError(f"unknown run state: {state!r}")
    rec = dict(rec)
    rec["state"] = state
    rec["finished_at"] = (when or datetime.datetime.now()).isoformat(" ", "seconds")
    rec["spent"] = spent or {}
    rec["note"] = note
    _write(root, rec)
    return rec


def _write(root, rec):
    os.makedirs(str(root), exist_ok=True)
    tmp = _path(root, rec["run_id"]) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    # Replaced rather than written in place: a run killed mid-write would otherwise leave a
    # truncated record, and a record that cannot be read is worse than one that says the run
    # died — the timeline already learned that lesson from a torn line in its own file.
    os.replace(tmp, _path(root, rec["run_id"]))


def load(root, run_id):
    p = _path(root, run_id)
    if not os.path.exists(p):
        return None
    try:
        from workspace import read_artifact   # local: this module is imported by
        _d, _why = read_artifact(p)           # the worker before the package is set up
        if _why:
            raise ValueError(_why)
        return _d
    except Exception as e:
        # Unreadable is not absent, and saying which is the whole discipline of this repo.
        return {"run_id": run_id, "state": "unreadable", "note": f"{type(e).__name__}: {e}"}


def listing(root):
    """Every run in this workspace, newest first, with what it cost and how it ended."""
    import glob
    out = []
    for p in glob.glob(os.path.join(str(root), "run_*.json")):
        rid = os.path.basename(p)[len("run_"):-len(".json")]
        rec = load(root, rid)
        if rec:
            out.append(rec)
    return sorted(out, key=lambda r: r.get("started_at") or "", reverse=True)


def summarise(rec):
    """One line a human reads in a terminal."""
    spent = rec.get("spent") or {}
    cost = ", ".join(f"{k} {v}" for k, v in spent.items()) or "nothing recorded"
    auth = (rec.get("authorization") or {}).get("method") or "local"
    # WIDE ENOUGH FOR THE NAMES THAT EXIST. At 20 the column welded itself to the next one --
    # `guardedrag-mitigatedscope=full` -- and a row that runs two fields together invents a
    # word, which `run_redteam` had already learned from `refusal_capability:1-`. A name can
    # be 64 characters by rule, so the pad is a floor and not a ceiling: a longer one pushes
    # the row out rather than being cut.
    return (f"{rec.get('run_id')}  {rec.get('state','?'):<9}"
            f"{str(rec.get('target','?')) + '  ':<26}"
            f"scope={_scope(rec):<6}auth={auth:<11}{cost}")

def main(argv=None):
    """Every run in this workspace: what ran, on whose authority, and how it ended.

    THE RECORD HAD NO DOOR. This module's own docstring lists four things it exists to
    answer -- who authorised this, what did it cost, how did it end, which build produced
    it -- and names them as "something somebody will actually ask". `listing` and
    `summarise` were written to be read by a person, `summarise` says so in one line, and
    nothing outside the suite called either: no command, and not even a `main()` to invoke
    the module with. `cli.COMMANDS` carries the same lesson twice already, once for three
    commands that "had no door" and again for three more found the same way.

    AN OPEN RECORD IS THE ONE WORTH SEEING. `start` writes before the first probe so a run
    that dies leaves evidence, which means a `started` row is either a sweep in flight or a
    run that never came back -- and this repository has one of the latter, from 2026-08-19.
    It is printed last, under its own heading, rather than sorted into the list where it
    reads as ordinary.
    """
    import argparse
    ap = argparse.ArgumentParser(
        prog="qatration runs",
        description="what ran, against what, on whose authority, and what it cost")
    ap.add_argument("--target", default=None,
                    help="only runs against this target name")
    ap.add_argument("--state", default=None, choices=list(STATES),
                    help="only runs that ended this way")
    ap.add_argument("--limit", type=int, default=25,
                    help="how many to show, newest first (0 for all)")
    args = ap.parse_args(argv)

    from workspace import OUT
    rows = listing(OUT)
    if not rows:
        # NOT ZERO ROWS PRINTED AS AN EMPTY TABLE. A workspace with no records and a
        # workspace this command cannot find are different facts, and the second is the
        # one an operator needs to hear.
        print(f"no run records in {OUT}. A record is written when `qatration run` starts, "
              f"so an empty list here means nothing has been run in this workspace.")
        return 3
    picked = [r for r in rows
             if (not args.target or r.get("target") == args.target)
             and (not args.state or r.get("state") == args.state)]
    if not picked:
        print(f"{len(rows)} run(s) recorded, none matching. "
              f"targets: {', '.join(sorted({str(r.get('target')) for r in rows}))}")
        return 3
    shown = picked if args.limit <= 0 else picked[:args.limit]
    for rec in shown:
        print(summarise(rec))
    if len(shown) < len(picked):
        print(f"  ... and {len(picked) - len(shown)} more (--limit 0 for all)")

    # THE OPEN ONES, SAID SEPARATELY. A run still listed as started is either in flight or
    # one that never came back, and the two look identical here -- which is the honest
    # answer, and the reason it is worth a line of its own rather than a row in a table.
    open_ = [r for r in picked if r.get("state") == "started"]
    if open_:
        print(f"\n{len(open_)} run(s) still open — either in flight now, or ended without "
              f"saying so:")
        for rec in open_:
            print(f"  {rec.get('run_id')}  {rec.get('target')}  started {rec.get('started_at')}")
    _unreadable = [r for r in picked if r.get("state") == "unreadable"]
    if _unreadable:
        # Unreadable is not absent, and saying which is the whole discipline of this repo.
        print(f"\n{len(_unreadable)} record(s) could not be read: "
              f"{', '.join(str(r.get('run_id')) for r in _unreadable)}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
