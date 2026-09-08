"""One sweep at a time, and a record of the ones waiting — file-based, no service.

NOT AN ABSTRACT SCALING FEATURE. It is the fix for a measured failure: two sweeps pointed at
one Ollama took a request from 5 seconds to 148, and the run that came second produced ERROR
rows that a later diff read as findings being fixed. The engine's own timeouts then reported a
contention problem as target behaviour. Serialising is the fix, and a queue is what
serialising looks like when more than one person can ask for a run.

Deliberately files in a directory. A queue that needs Redis before it can accept
its second job has bought an operational dependency to solve a problem it does not have
yet, and `runs.py` already proved the shape works: write it before, close it after, name the
ending. The state machine here is the same idea one level up.

The three states worth being careful about, because each is a place this repo has been wrong:

  * **claimed is not finished.** A worker that dies holds a LEASE, and a lease has to expire
    or one crash stops the queue forever. But an expired lease is not a job that never ran:
    reclaiming records the attempt, so a job that kills its worker three times goes to `dead`
    with the reason rather than looping.
  * **empty is not busy.** `claim()` returning nothing has two meanings and they are opposite
    ones. A worker that reports "nothing to do" while a job sits blocked behind a live lease
    is a gap reported as a measurement, which is the defect class this whole engine exists to
    catch. `claim()` returns a reason, always.
  * **a queued job is a promise about cost.** The budgets travel with the job, not with the
    worker, because the submitter was told a number when they submitted and the worker that
    eventually picks it up may be running a different build.
"""
import datetime, io, json, os, glob, time, uuid

STATES = ("queued", "running", "done", "failed", "dead", "cancelled")
LEASE_SECONDS = 3600        # a full sweep over 19 attacks x 3 trials runs well under this
MAX_ATTEMPTS = 3            # after which the job is dead and says why, rather than looping


def _now():
    return datetime.datetime.now()


def _path(root, job_id):
    return os.path.join(str(root), f"job_{job_id}.json")


def _write(root, job):
    os.makedirs(str(root), exist_ok=True)
    tmp = _path(root, job["job_id"]) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(job, f, indent=2, ensure_ascii=False)
    os.replace(tmp, _path(root, job["job_id"]))


def _marker(root, job_id):
    return os.path.join(str(root), "claims", f"{job_id}.claim")


def _take(root, job_id, worker, now):
    """Create the claim marker, atomically. True if THIS caller got the job.

    THE CLAIM WAS A READ, A DECISION AND A WRITE, and nothing joined them. Two workers could
    both list the queue, both see the same job as `queued`, and both write it as `running`
    with their own lease. The file write is atomic, so the job ends up looking sane and the
    last lease wins — and both workers go and run the sweep. Two sweeps against one operator's
    endpoint, which is the exact thing the per-resource lock was just built to prevent.

    It was theoretical while there was one worker behind a global lock. Removing that lock and
    waking workers on submission makes concurrent claims the normal case, so the race had to
    close in the same change that opened it.

    O_CREAT|O_EXCL rather than a lock file around the whole decision. A lock needs a staleness
    rule, and a staleness rule is a timing assumption: two workers that both decide a lock is
    old enough to clear will both clear it and both proceed, which is the bug wearing a hat.
    The marker needs no such rule, because it is not a lock on the queue — it IS the claim, and
    the lease machinery that already exists handles a worker that dies holding one.
    """
    path = _marker(root, job_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    try:
        os.write(fd, f"{worker} {now.isoformat(' ', 'seconds')}".encode())
    finally:
        os.close(fd)
    return True


# HOW LONG A CLAIM MAY EXIST WITHOUT A JOB TO MATCH IT. `_take` and the state write that
# follows it are two operations, and a worker killed between them leaves a marker for a job
# still recorded as `queued`. Nothing reclaimed that: the lease machinery only looks at jobs
# in `running`, and this one never got there.
#
# The gap between the two operations is a few file writes. A minute is six orders of
# magnitude more, which is what makes clearing it safe rather than a guess.
ORPHAN_SECONDS = 60


def _marker_holder(root, job_id):
    """-> (worker, age in seconds) for an existing claim marker, or None."""
    path = _marker(root, job_id)
    try:
        raw = io.open(path, encoding="utf-8", errors="replace").read()
        age = max(0.0, time.time() - os.path.getmtime(path))
    except OSError:
        return None
    return (raw.split(" ", 1)[0] if raw else ""), age


def _still_ours(root, job_id, worker):
    """Does the claim marker still name this worker?

    THE BRANCH THAT READS THIS CANNOT BE REACHED BY ONE PROCESS, and that is worth saying
    rather than dressing up. It fires when a worker is descheduled between taking the
    marker and writing the job, for longer than `ORPHAN_SECONDS`, so that another worker
    clears the orphan and takes it in between. Getting there needs two processes and a
    stall; a single-threaded test reads the marker it just wrote and always sees itself.

    So the PREDICATE is what the suite exercises, in both directions, and an AST check asks
    whether `claim` still consults it. What it prevents is the two-sweeps race the marker
    exists to close, arriving through the machinery that recovers from it: the late worker
    writing `running` with its own lease over a run already in flight.
    """
    held = _marker_holder(root, job_id)
    return bool(held) and held[0] == worker


def _drop(root, job_id):
    """Release the marker. Missing is fine: the job may never have been claimed."""
    try:
        os.remove(_marker(root, job_id))
    except FileNotFoundError:
        pass
    except OSError:
        pass


def contended_resource(config_path, target):
    """What this job will CONTEND FOR, as a string, or None when that cannot be known.

    The origin of the endpoint, because that is the thing two runs can genuinely collide over:
    hammering one operator's bot with two sweeps at once is rude to them and it corrupts the
    measurement, since their own latency and rate limits get attributed to the attacks.

    None for an in-process target, and that answer is load-bearing rather than a shrug. Those
    are the practice fleet, they all talk to one local Ollama, and two of them at once was
    measured taking a request from 5 seconds to 148. So a job that cannot name its endpoint
    falls back to blocking everything, which is exactly right for the resource it is really
    sharing.
    """
    try:
        import yaml
        cfg = yaml.safe_load(open(config_path, encoding="utf-8")) or {}
    except Exception:
        return None
    url = cfg.get("url")
    if not url:
        return None
    try:
        from authorization import origin_of
        return origin_of(url)
    except Exception:
        return None


def scope_of(rec):
    """How wide a run this record was made at, or "?" when it does not say.

    "?" rather than a guess: a record that does not name its scope was written by something
    that did not record one, and printing a plausible value would make the record say
    something nobody measured.
    """
    return rec.get("scope") or "?"


def submit(root, target, config_path, scope="quick", authorization=None, budgets=None,
           attacks=None, trials=3, requester=None, when=None):
    """Put a run in the queue and return the job. Nothing is executed here.

    `budgets` travels with the JOB rather than being decided by whichever worker picks it up,
    because it is a promise made to somebody at submit time and the worker may be a different
    build by the time the job runs.
    """
    job = {
        "job_id": f"{(when or _now()).strftime('%Y-%m-%dT%H%M')}-{uuid.uuid4().hex[:6]}",
        "state": "queued",
        "target": target,
        "config": config_path,
        # Recorded at SUBMIT time rather than read at claim time: the config file may be gone,
        # rewritten, or on a filesystem the worker cannot see, and a queue that silently fails
        # to identify a job's endpoint would fall back to blocking the whole service.
        "resource": contended_resource(config_path, target),
        "scope": scope,
        "attacks": attacks,
        "trials": trials,
        "authorization": authorization,
        "budgets": budgets or {},
        "requester": requester,
        "submitted_at": (when or _now()).isoformat(" ", "seconds"),
        "attempts": 0,
        # Written by the worker, so a job and the run it produced can be joined up later.
        "run_id": None,
        "lease": None,
        "history": [],
        "note": None,
    }
    _write(root, job)
    return job


def load(root, job_id):
    p = _path(root, job_id)
    if not os.path.exists(p):
        return None
    try:
        from workspace import read_artifact   # local: this module is imported by
        _d, _why = read_artifact(p)           # the worker before the package is set up
        if _why:
            raise ValueError(_why)
        return _d
    except Exception as e:
        # Unreadable is not absent. A torn job file must not look like a job nobody submitted.
        return {"job_id": job_id, "state": "unreadable", "note": f"{type(e).__name__}: {e}"}


def listing(root, state=None):
    out = []
    for p in sorted(glob.glob(os.path.join(str(root), "job_*.json"))):
        jid = os.path.basename(p)[len("job_"):-len(".json")]
        j = load(root, jid)
        if j and (state is None or j.get("state") == state):
            out.append(j)
    return sorted(out, key=lambda j: j.get("submitted_at") or "")


def _lease_expired(job, now=None):
    lease = job.get("lease") or {}
    until = lease.get("until")
    if not until:
        return False
    try:
        return datetime.datetime.fromisoformat(until) < (now or _now())
    except Exception:
        return True      # an unparseable lease is not a live one, and pretending it is hangs


def claim(root, worker="worker", now=None, lease_seconds=LEASE_SECONDS):
    """Take the oldest runnable job, or say WHY there is none. Returns (job, reason).

    ONE JOB PER CONTENDED RESOURCE, not one job in total. The lock used to be global, and it
    is correct for a single-machine fleet: every practice target talks to the same
    local Ollama, and two sweeps at once was measured taking a request from 5 seconds to 148.

    Against remote endpoints that shared resource does not exist. Two runs talk to two
    different endpoints and contend for nothing but sockets: a run is roughly eleven minutes
    of wall clock and 0.08 seconds of local CPU, because all of it is waiting for somebody
    else's bot to answer. A global lock therefore blocked every other run during time when
    this machine was doing nothing at all, and capped throughput at about 130 runs a day for
    a reason that had stopped applying.

    So a job blocks another only when they would hit the SAME origin — which is still worth
    preventing, since two sweeps against one bot is rude to its owner and corrupts the
    measurement by attributing their own latency to the attacks. A job whose endpoint cannot
    be named blocks everything, because that is the in-process fleet sharing one model host.

    The reason matters as much as the job. "queue empty" and "a job is running" are opposite
    facts and both come back as no work to do, so a worker that could not tell them apart
    would report an idle queue while a queued run sat blocked behind a dead lease.
    """
    now = now or _now()
    jobs = listing(root)

    # A live lease blocks everything. An expired one is reclaimed, and the attempt is recorded
    # rather than forgotten, so a job that keeps killing its worker becomes visible.
    live = []
    for j in jobs:
        if j.get("state") != "running":
            continue
        if not _lease_expired(j, now):
            live.append(j)
            continue
        j["history"] = (j.get("history") or []) + [
            {"at": now.isoformat(" ", "seconds"), "event": "lease expired",
             "worker": (j.get("lease") or {}).get("worker")}]
        j["attempts"] = int(j.get("attempts") or 0)
        if j["attempts"] >= MAX_ATTEMPTS:
            j["state"], j["lease"] = "dead", None
            j["note"] = (f"gave up after {j['attempts']} attempt(s): every worker that claimed "
                         f"it stopped without closing the job")
            _write(root, j)
            continue
        j["state"], j["lease"] = "queued", None
        _write(root, j)
        # The marker outlives the worker that made it, so a reclaimed job would be
        # permanently unclaimable without this: state says queued, the marker says taken,
        # and nothing would ever run it again.
        _drop(root, j["job_id"])

    # AND A CLAIM WITH NO JOB BEHIND IT. `_take` and the state write below are two
    # operations, and a worker killed between them leaves a marker on a job still recorded
    # as `queued`. The loop above cannot see it -- it reclaims leases, and this job never
    # got one -- so every later claim picked the job, failed to take it, and returned
    # `was claimed by another worker between listing the queue and taking it`: a sentence
    # about a race that lasts microseconds, describing a state that lasts forever.
    #
    # AND IT BLOCKED EVERYTHING BEHIND IT. `claim` stops at the first runnable job, so one
    # stuck at the head made the whole queue unclaimable, with the same misleading line.
    #
    # Clearing it is safe in a way clearing a lock is not, which is the objection `_take`
    # raises against lock files: after the marker is gone both workers still have to take it
    # again, and only one can. What the grace period buys is not exclusion, it is not
    # deleting a claim a live worker made a moment ago.
    for j in [x for x in listing(root) if x.get("state") == "queued"]:
        _held = _marker_holder(root, j["job_id"])
        if not _held or _held[1] < ORPHAN_SECONDS:
            continue
        j["history"] = (j.get("history") or []) + [
            {"at": now.isoformat(" ", "seconds"), "event": "orphaned claim cleared",
             "worker": _held[0]}]
        _write(root, j)
        _drop(root, j["job_id"])

    queued = [j for j in listing(root) if j.get("state") == "queued"]
    if not queued:
        blocked = [j for j in listing(root) if j.get("state") == "running"]
        if blocked:
            return None, f"busy: {blocked[0]['job_id']} is running"
        return None, "empty: nothing is queued"

    # An unnamed resource on EITHER side blocks: an in-process job shares the one local model
    # with everything, so it cannot run beside anything and nothing can run beside it.
    busy = {j.get("resource") for j in live}
    exclusive_live = any(j.get("resource") is None for j in live)

    # In SUBMIT ORDER, and an exclusive job at the head holds the line. The first version took
    # "every queued job whose endpoint is free", which quietly meant an in-process job was
    # skipped for as long as any remote job was queued — it needs an empty queue to start, and
    # a busy queue is never empty. The in-process fleet would have starved behind remote
    # jobs, permanently, and nothing would have said so.
    runnable = []
    for j in queued:
        if j.get("resource") is None:
            if live:
                break                    # needs the machine to itself: wait, do not be passed
            runnable = [j]
            break
        if exclusive_live:
            break                        # an in-process run owns the machine while it lasts
        if j.get("resource") not in busy:
            runnable = [j]
            break
        # Same endpoint as a running job: skip it, a job against another endpoint may go ahead.
    if not runnable:
        held = live[0] if live else None
        if held:
            who = (held.get("lease") or {}).get("worker", "?")
            what = held.get("resource") or "the local model"
            return None, (f"busy: {held['job_id']} is running against {what} "
                          f"(leased by {who})")
        return None, "empty: nothing is queued"

    job = runnable[0]
    # THE ATOMIC STEP. Everything above is a read of a directory that another worker may be
    # writing to at the same moment, so the decision is provisional until this succeeds.
    if not _take(root, job["job_id"], worker, now):
        _who = _marker_holder(root, job["job_id"])
        return None, (f"busy: {job['job_id']} is claimed by "
                      f"{(_who or ('another worker',))[0]}"
                      + (f" and has been for {int(_who[1])}s; it will be cleared after {ORPHAN_SECONDS}s if that worker never comes back" if _who else ""))
    # AND THE MARKER IS STILL OURS AT THE MOMENT WE WRITE. A worker descheduled past the
    # grace period would find its claim cleared and re-taken by somebody else, and writing
    # the state anyway would clobber a run already in flight -- the two-sweeps race the
    # marker exists to prevent, arriving through the machinery that recovers from it.
    if not _still_ours(root, job["job_id"], worker):
        _mine = _marker_holder(root, job["job_id"])
        return None, (f"busy: {job['job_id']} was taken and then reclaimed by "
                      f"{(_mine or ('another worker',))[0]} while this worker was stopped")
    job["state"] = "running"
    job["attempts"] = int(job.get("attempts") or 0) + 1
    job["lease"] = {"worker": worker,
                    "since": now.isoformat(" ", "seconds"),
                    "until": (now + datetime.timedelta(seconds=lease_seconds)
                              ).isoformat(" ", "seconds")}
    job["history"] = (job.get("history") or []) + [
        {"at": now.isoformat(" ", "seconds"), "event": "claimed", "worker": worker}]
    _write(root, job)
    return job, f"claimed by {worker} (attempt {job['attempts']})"


def release(root, job, state="done", run_id=None, note=None, when=None):
    """Close a claimed job. `state` distinguishes the endings, exactly as `runs.finish` does.

    `failed` is a job whose run ended badly and `dead` is a job that will not be retried; the
    difference is whether anybody should look at the target or at the harness.

    THE CLOSER MUST STILL HOLD THE LEASE. Without that check a worker whose lease expired could
    close a job that a second worker had already reclaimed and was still sweeping: the queue
    would report a clean single-attempt success while two sweeps ran against one endpoint, which
    is the exact contention `claim()` was made careful to prevent. Care at the opening door and
    trust at the closing one is not a lock.

    Refuses rather than raises. A worker that has lost its job should write that down and move
    on; an exception here would take its run record with it.
    """
    if state not in STATES:
        raise ValueError(f"unknown job state: {state!r}")

    mine = (job.get("lease") or {}).get("worker")
    if mine:
        current = load(root, job["job_id"])
        theirs = (current or {}).get("lease") or {}
        if current is None:
            return job, "the job is gone: it was closed or removed while this run was going"
        if theirs.get("worker") and theirs.get("worker") != mine:
            return current, (f"refusing to close: the lease is held by {theirs['worker']!r}, "
                             f"not by {mine!r} — this run lost the job and another is on it")
        if theirs.get("since") and theirs.get("since") != (job.get("lease") or {}).get("since"):
            return current, ("refusing to close: the job was re-claimed since this run took it, "
                             "so closing it now would report somebody else's sweep as finished")

    job = dict(job)
    now = when or _now()
    job["state"] = state
    job["lease"] = None
    job["run_id"] = run_id or job.get("run_id")
    job["note"] = note
    job["history"] = (job.get("history") or []) + [
        {"at": now.isoformat(" ", "seconds"), "event": state, "run_id": job["run_id"]}]
    job["closed_at"] = now.isoformat(" ", "seconds")
    _write(root, job)
    _drop(root, job["job_id"])
    return job, None


def cancel(root, job_id, note=None, when=None):
    """Withdraw a job that has not started. A RUNNING job is not cancelled from here.

    Killing a sweep mid-flight leaves a half-written results file that later reads as a target
    that held, and this queue has no way to reach into the worker. Say so rather than
    pretending, and let the worker's own budget stop it.
    """
    job = load(root, job_id)
    if not job:
        return None, "no such job"
    if job.get("state") == "running":
        return job, ("running: cannot be cancelled from the queue — its budget will stop it, "
                     "and killing it mid-sweep leaves a partial run that reads as a defence")
    if job.get("state") != "queued":
        return job, f"already {job.get('state')}"
    closed, why = release(root, job, "cancelled", note=note, when=when)
    return closed, why or "cancelled"


def depth(root):
    """Queued, running, and how long the head of the queue has been waiting."""
    jobs = listing(root)
    q = [j for j in jobs if j.get("state") == "queued"]
    r = [j for j in jobs if j.get("state") == "running"]
    waiting = None
    if q:
        try:
            waiting = (_now() - datetime.datetime.fromisoformat(q[0]["submitted_at"])
                       ).total_seconds()
        except Exception:
            waiting = None
    return {"queued": len(q), "running": len(r),
            "head_waiting_seconds": None if waiting is None else round(waiting)}


def summarise(job):
    lease = job.get("lease") or {}
    held = f"  leased by {lease['worker']}" if lease.get("worker") else ""
    return (f"{job.get('job_id')}  {job.get('state','?'):<10}{job.get('target','?'):<20}"
            f"scope={scope_of(job):<6}attempts={job.get('attempts', 0)}{held}")


if __name__ == "__main__":
    import argparse
    from workspace import OUT
    ap = argparse.ArgumentParser(description="inspect the run queue")
    ap.add_argument("--root", default=str(OUT))
    ap.add_argument("--cancel", default=None, metavar="JOB_ID")
    args = ap.parse_args()
    if args.cancel:
        job, why = cancel(args.root, args.cancel)
        print(why)
    d = depth(args.root)
    print(f"{d['queued']} queued, {d['running']} running"
          + (f", head waiting {d['head_waiting_seconds']}s" if d["head_waiting_seconds"] else ""))
    for j in listing(args.root):
        print("  " + summarise(j))
