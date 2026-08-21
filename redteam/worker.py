"""Takes one job off the queue, runs the sweep, closes the job with what happened.

The piece that makes `jobqueue.py` mean something. It is deliberately the dumbest thing that
can work — claim, shell out to the sweep, close — because everything difficult was already
decided somewhere else: `workspace.py` says where the artifacts go, `authorization.py` decides
whether a remote target may be touched at all, `targets_http.py` enforces the budget, and
`runs.py` records the run. The worker's only real job is to make sure a job is CLOSED whatever
happens to the sweep, since a job left running holds the lease and stops the queue.

Two things it must not get wrong, both of them the same mistake in different clothes:

  * **A sweep that fails is not a target that held.** Exit 3 means every trial errored, and the
    engine already refuses to write results in that case; the job goes to `failed` with the
    reason, and no report is generated. The alternative — closing it `done` with an empty run —
    hands somebody a clean report for a target nobody reached.
  * **A crash must not look like a finished job.** The release is in a `finally`, so a worker
    that dies inside the sweep still closes its own job when it can, and when it cannot the
    lease expiry in the queue catches it.

    python worker.py --once            # take one job if there is one, then stop
    python worker.py --root out/queue  # where jobs live (default: the workspace)
"""
import argparse, os, subprocess, sys, traceback

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import jobqueue as q
import runs as _runs
from workspace import OUT

# What the sweep's exit codes mean, kept here because the worker is the only thing that turns
# them into a job state anybody reads. run_redteam exits 3 when nothing was measured and 4 when
# the target was not authorised; both are failures, and they are failures of different people.
EXITS = {
    0: ("done", None),
    3: ("failed", "every trial errored — nothing was measured, so nothing was written"),
    4: ("failed", "not authorised: the target did not prove ownership, so nothing was sent"),
}


def run_dir(root, job):
    """One directory per job. The namespace `workspace.py` made possible, finally used."""
    return os.path.join(str(root), "runs", job["job_id"])


def _scope_of(job):
    """The scope to run a job at. Reads the old `tier` spelling as well as the new one.

    Defaults to a RUNNABLE value rather than to "?", because this one is passed to a
    subprocess: a job written before the rename must still run, at the same scope it asked
    for, rather than dying on an invalid choice.
    """
    return job.get("scope") or job.get("tier") or "quick"


class _Timeout:
    """What a step that ran out of time returns, shaped like a CompletedProcess.

    A distinct returncode rather than one of the engine's: `EXITS` maps the codes a sweep can
    produce, and a step that never produced one has not exited at all. Reusing a real code
    would file a hang under whatever that code means.
    """

    returncode = -9

    def __init__(self, what, secs):
        self.stdout = ""
        self.stderr = (f"{what} did not finish within {secs}s and was stopped. Nothing it "
                       f"wrote after that point exists, and a job cannot be closed by a "
                       f"worker whose lease has expired, so continuing would produce work "
                       f"the queue would refuse.")


def _run(cmd, out, python=None, deadline=None):
    """Run one step of a job, with a ceiling.

    WITHOUT THE CEILING A HUNG STEP TAKES THE WORKER WITH IT. The queue recovers — a lease
    expires after an hour and the job is reclaimed — but this process stays blocked on a pipe,
    never claims another job, and is indistinguishable from one that is busy. The pool shrinks
    by one and nothing reports it.

    The ceiling is the lease, because a step that outlives the lease cannot close its job in
    any case: `release()` refuses a close from a worker that no longer holds it. Past that
    point the step is producing work the queue will throw away.
    """
    env = dict(os.environ, QATRATION_OUT=out, PYTHONIOENCODING="utf-8")
    secs = int(deadline or q.LEASE_SECONDS)
    try:
        return subprocess.run([python or sys.executable] + cmd, env=env,
                              cwd=os.path.dirname(HERE), capture_output=True, text=True,
                              timeout=secs)
    except subprocess.TimeoutExpired:
        return _Timeout(os.path.basename(cmd[0]), secs)


def execute(job, root, python=None):
    """Baseline, then sweep, then the deliverable. Returns (state, note, run_id)."""
    out = run_dir(root, job)
    os.makedirs(out, exist_ok=True)

    # THE BASELINE COMES FIRST, and it is not optional. A breach verdict is worth exactly what
    # the system's silence is worth when nobody attacks it, and a fresh per-job workspace has
    # no benign run in it — so without this every finding on an operator's first report is
    # unattributed. Worse, silently so: the limited run RANKS its sample by ambient noise so it
    # can lead with a finding the reader can reproduce, and with no benign data that ranking
    # sorts every row on a zero and quietly does nothing. A scope designed around a measurement
    # it never took.
    #
    # It is also the cheaper half of the honesty: 48 ordinary questions against 19 attacks x 3
    # trials. A failure here does NOT fail the job — the sweep is still worth running, the
    # report says which findings could not be attributed, and the operator gets a narrower
    # answer rather than none.
    base = _run([os.path.join(HERE, "benign.py"), "--target-config", job["config"]],
                out, python)
    baseline_note = None
    if base.returncode != 0:
        baseline_note = ("the benign baseline did not complete, so nothing has measured what "
                         "this target does unattacked; the findings are reported unattributed")

    cmd = [os.path.join(HERE, "run_redteam.py"),
           "--target-config", job["config"], "--scope", _scope_of(job),
           "--trials", str(job.get("trials") or 3)]
    if job.get("attacks"):
        cmd += ["--attacks", job["attacks"]]
    proc = _run(cmd, out, python)
    if isinstance(proc, _Timeout):
        # Named, not filed under an exit code it never produced. "the sweep exited -9" would
        # read as a crash and send somebody looking for a traceback that does not exist.
        state, note = "failed", proc.stderr
    else:
        state, note = EXITS.get(proc.returncode,
                                ("failed", f"the sweep exited {proc.returncode}"))

    # Join the job to the run it produced. The run record is the thing that knows what it cost
    # and how it ended; without the link, the queue can only say a job "finished" and the
    # question an operator actually asks — how far did it get before the budget stopped it —
    # has no answer.
    rec = (_runs.listing(out) or [None])[0]
    run_id = rec.get("run_id") if rec else None
    if rec and rec.get("state") == "stopped" and state == "done":
        note = f"budget stopped it: {rec.get('note') or 'the remaining attacks were not sent'}"
    if state != "done" and not note:
        note = (proc.stderr or proc.stdout or "").strip()[-300:]

    # THE DELIVERABLE. Without this a finished job leaves a per-target scorecard and a run
    # record, and the deliverable the run exists to produce does not exist. Only on a run
    # that produced results: a report rendered over an aborted sweep is a page describing
    # nothing, and an empty page is the most flattering possible answer.
    if state == "done":
        rep = _run([os.path.join(HERE, "defense_report.py")], out, python)
        if rep.returncode != 0:
            note = ((note + "; ") if note else "") + "the report could not be rendered"
    if baseline_note:
        note = ((note + "; ") if note else "") + baseline_note
    return state, note, run_id


def once(root, worker_name="worker", python=None):
    """Claim at most one job and close it. Returns the reason, whatever happened."""
    job, why = q.claim(root, worker_name)
    if job is None:
        return why                       # "empty: ..." or "busy: ...", never a bare None
    print(f"{job['job_id']}  {job['target']}  ({why})")
    state, note, run_id = "failed", None, None
    try:
        state, note, run_id = execute(job, root, python)
    except Exception:
        # A worker that dies mid-sweep still closes its own job where it can. Where it cannot,
        # the queue's lease expiry catches it — but only after an hour, and a job that says
        # what killed it is worth more than one reclaimed silently.
        note = traceback.format_exc().strip().splitlines()[-1][:300]
    finally:
        # A REFUSED CLOSE IS NEWS. `release` now checks the lease is still this worker's, and
        # says so instead of closing somebody else's job. Printing it is the only way anybody
        # learns that two workers were on one endpoint; swallowing it would leave the queue
        # looking orderly while a second sweep runs.
        _closed, _why = q.release(root, job, state, run_id=run_id, note=note)
        if _why:
            state, note = "lost", _why
    print(f"  -> {state}" + (f" ({note})" if note else "") + (f"  run {run_id}" if run_id else ""))
    return f"{state}: {job['job_id']}"


def main():
    ap = argparse.ArgumentParser(description="run queued sweeps, one at a time")
    ap.add_argument("--root", default=str(OUT), help="where jobs live")
    ap.add_argument("--name", default=f"worker-{os.getpid()}")
    ap.add_argument("--once", action="store_true", help="take one job then stop")
    ap.add_argument("--drain", action="store_true", help="keep going until the queue is empty")
    args = ap.parse_args()

    if args.drain:
        while True:
            why = once(args.root, args.name)
            if why.startswith("empty") or why.startswith("busy"):
                print(why)
                return
    print(once(args.root, args.name))


if __name__ == "__main__":
    main()
