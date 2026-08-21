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


def _scope(rec):
    """How wide a run this record was made at, or "?" when it does not say.

    "?" rather than a guess: a record that does not name its scope was written by something
    that did not record one, and printing a plausible value would make the record say
    something nobody measured.
    """
    return rec.get("scope") or "?"


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
    return (f"{rec.get('run_id')}  {rec.get('state','?'):<9}{rec.get('target','?'):<20}"
            f"scope={_scope(rec):<6}auth={auth:<11}{cost}")
