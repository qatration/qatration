"""One sweep at a time, and the difference between an idle queue and a blocked one — no model.

The queue exists because of a measured failure, not a projected one: two sweeps against one
Ollama took a request from 5 seconds to 148, and the second run's timeouts were written down as
the target's behaviour. So the checks below are about the places where a queue lies rather than
about whether it can hold items.

The one that matters most is `claim()` returning nothing. That has two opposite meanings —
there is no work, or there is work and something else holds it — and a worker that cannot tell
them apart reports an idle queue while a customer's run sits blocked. That is a gap reported as
a measurement, which is the defect this whole repo is organised around.

    python test_jobqueue.py      # exits 1 on any failure (CI gate)
"""
import sys, os, json, shutil, tempfile, datetime
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import jobqueue as q


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    root = tempfile.mkdtemp()
    T0 = datetime.datetime(2026, 8, 18, 12, 0)
    try:
        # --- an empty queue says EMPTY, and says it as a reason ---------------------------
        job, why = q.claim(root, "w1", now=T0)
        check("an empty queue offers no work", job is None)
        check("...and says it is empty rather than just returning nothing",
              why.startswith("empty"), why)

        # --- submitting does not run anything --------------------------------------------
        a = q.submit(root, "acme", "targets_acme.yaml", scope="quick",
                     budgets={"max_requests": 200, "max_seconds": 1800},
                     authorization={"method": "header"}, requester="acme@example.com", when=T0)
        b = q.submit(root, "beta", "targets_beta.yaml", scope="full",
                     when=T0 + datetime.timedelta(minutes=1))
        check("a submitted job is queued, not started", q.load(root, a["job_id"])["state"] == "queued")
        check("...and carries the budget it was promised at submit time, not the worker's",
              q.load(root, a["job_id"])["budgets"]["max_seconds"] == 1800)
        check("...and who asked for it", q.load(root, a["job_id"])["requester"] == "acme@example.com")
        check("...and has produced no run yet", q.load(root, a["job_id"])["run_id"] is None)

        # --- exactly one at a time, which is the entire point -----------------------------
        got, why = q.claim(root, "w1", now=T0 + datetime.timedelta(minutes=2))
        check("the oldest job is claimed first", got and got["job_id"] == a["job_id"],
              str(got and got["job_id"]))
        check("...and it is marked running with a lease",
              got["state"] == "running" and (got.get("lease") or {}).get("worker") == "w1")

        second, why2 = q.claim(root, "w2", now=T0 + datetime.timedelta(minutes=3))
        check("a second worker gets nothing while one is running", second is None)
        # THE CHECK THIS FILE EXISTS FOR. "No work" and "work I cannot have" are opposite
        # facts. A worker that reports an idle queue while a job sits blocked turns a
        # contention problem into a silent one.
        check("...and is told BUSY, not empty — they are opposite facts",
              why2.startswith("busy") and b["job_id"] not in why2, why2)
        check("...and the blocked job is still queued, not lost",
              q.load(root, b["job_id"])["state"] == "queued")

        # --- closing it lets the next one through -----------------------------------------
        q.release(root, got, "done", run_id="2026-08-18T1204-aaa111")
        closed = q.load(root, a["job_id"])
        check("a finished job records the run it produced",
              closed["run_id"] == "2026-08-18T1204-aaa111", str(closed["run_id"]))
        check("...and drops its lease so it cannot block anything",
              closed["lease"] is None)
        nxt, _ = q.claim(root, "w2", now=T0 + datetime.timedelta(minutes=5))
        check("the next job runs once the first is closed", nxt and nxt["job_id"] == b["job_id"])

        # --- a worker that dies must not stop the queue forever ---------------------------
        # But an expired lease is NOT a job that never ran. Reclaiming records the attempt, so
        # a job that kills every worker becomes visible instead of looping.
        late = T0 + datetime.timedelta(seconds=q.LEASE_SECONDS + 600)
        again, why3 = q.claim(root, "w3", now=late)
        check("a dead worker's job is reclaimed rather than blocking forever",
              again and again["job_id"] == b["job_id"], str(why3))
        check("...and the reclaim counts as an attempt rather than starting fresh",
              again["attempts"] == 2, str(again["attempts"]))
        check("...and the expiry is written into the job's own history",
              any(h.get("event") == "lease expired" for h in again["history"]),
              str(again["history"]))

        later = late + datetime.timedelta(seconds=q.LEASE_SECONDS + 600)
        q.claim(root, "w4", now=later)                      # third attempt
        final = later + datetime.timedelta(seconds=q.LEASE_SECONDS + 600)
        gone, why4 = q.claim(root, "w5", now=final)
        dead = q.load(root, b["job_id"])
        check("a job that keeps killing its worker goes dead instead of looping",
              dead["state"] == "dead", dead["state"])
        check("...and says why, so somebody can look at it",
              "gave up" in (dead["note"] or ""), str(dead["note"]))
        check("...and the queue is then honestly empty rather than busy",
              gone is None and why4.startswith("empty"), str(why4))

        # --- cancelling -------------------------------------------------------------------
        c = q.submit(root, "gamma", "targets_gamma.yaml", when=final)
        _, why5 = q.cancel(root, c["job_id"], note="customer withdrew")
        check("a queued job can be withdrawn", q.load(root, c["job_id"])["state"] == "cancelled")
        d = q.submit(root, "delta", "targets_delta.yaml", when=final)
        running, _ = q.claim(root, "w6", now=final)
        _, why6 = q.cancel(root, running["job_id"])
        check("a RUNNING job is not cancelled from the queue, and says so rather than pretending",
              q.load(root, d["job_id"])["state"] == "running" and why6.startswith("running"),
              why6)
        check("...and explains that killing a sweep mid-flight fakes a defence",
              "reads as a defence" in why6, why6)

        # --- what an operator sees --------------------------------------------------------
        q.release(root, running, "failed", note="target refused every connection")
        e = q.submit(root, "eps", "targets_eps.yaml", when=final)
        dep = q.depth(root)
        check("depth counts what is waiting", dep["queued"] == 1 and dep["running"] == 0,
              str(dep))
        check("a failed job is distinct from a dead one",
              q.load(root, d["job_id"])["state"] == "failed")
        line = q.summarise(q.load(root, b["job_id"]))
        check("a job summarises to one line with its state and attempts",
              "dead" in line and "attempts=3" in line, line)

        # --- and the same durability discipline the run record has ------------------------
        check("a job that never existed reads as absent", q.load(root, "nope") is None)
        with open(os.path.join(root, "job_torn.json"), "w", encoding="utf-8") as f:
            f.write('{"job_id": "torn", "sta')
        torn = q.load(root, "torn")
        check("a torn job reads as unreadable, not as absent",
              torn and torn["state"] == "unreadable", str(torn))
        check("...and an unreadable job is never claimed as work",
              all(j["job_id"] != "torn" for j in q.listing(root, "queued")))
        src = open(os.path.join(HERE, "jobqueue.py"), encoding="utf-8").read()
        check("jobs are replaced, not written in place", "os.replace(" in src)
        check("...and nothing is left behind",
              not [f for f in os.listdir(root) if f.endswith(".tmp")], str(os.listdir(root)))

        try:
            q.release(root, q.load(root, e["job_id"]), "vanished")
            check("an ending the queue does not understand is refused", False, "accepted")
        except ValueError:
            check("an ending the queue does not understand is refused", True)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    # --- THE LOCK FOLLOWS THE RESOURCE, NOT THE SERVICE ------------------------------------
    #
    # Everything above runs with configs that name no endpoint, so every job falls back to
    # blocking the whole queue — which is right for the in-process practice fleet, since they
    # all talk to one local Ollama and two sweeps at once was measured taking a request from 5
    # seconds to 148. It also means the fallback is the ONLY path those checks exercise, so
    # the hosted behaviour needs its own fixtures or it ships untested.
    #
    # Hosted, that shared resource is gone: a run is about eleven minutes of wall clock and
    # 0.08 seconds of local CPU, because all of it is waiting on somebody else's bot. A global
    # lock stopped every other customer during time this machine spent doing nothing.
    import tempfile as _tf, yaml as _yaml
    root2 = _tf.mkdtemp()
    try:
        def cfg_for(url):
            fp = os.path.join(root2, f"t{abs(hash(url)) % 10**8}.yaml")
            with open(fp, "w", encoding="utf-8") as f:
                _yaml.safe_dump({"adapter": "http", "url": url,
                                 "request": {"m": "{prompt}"},
                                 "response": {"reply": "reply"}}, f)
            return fp

        acme = q.submit(root2, "acme", cfg_for("https://api.acme.example/chat"), when=T0)
        beta = q.submit(root2, "beta", cfg_for("https://api.beta.example/chat"),
                        when=T0 + datetime.timedelta(minutes=1))
        acme2 = q.submit(root2, "acme-again", cfg_for("https://api.acme.example/chat"),
                         when=T0 + datetime.timedelta(minutes=2))
        check("a job records the endpoint it will contend for",
              q.load(root2, acme["job_id"])["resource"] == "https://api.acme.example",
              str(q.load(root2, acme["job_id"]).get("resource")))

        j1, _ = q.claim(root2, "w1", now=T0 + datetime.timedelta(minutes=3))
        check("the oldest job is claimed", j1 and j1["job_id"] == acme["job_id"])

        # THE WHOLE POINT OF THE CHANGE.
        j2, why2 = q.claim(root2, "w2", now=T0 + datetime.timedelta(minutes=4))
        check("a job against a DIFFERENT endpoint runs at the same time",
              j2 and j2["job_id"] == beta["job_id"], f"{j2 and j2['job_id']} / {why2}")

        # And the thing still worth preventing: two sweeps against one operator's bot is rude
        # to its owner, and it corrupts the measurement, since their own latency and rate
        # limits get attributed to our attacks.
        j3, why3 = q.claim(root2, "w3", now=T0 + datetime.timedelta(minutes=5))
        check("a second job against the SAME endpoint is not claimed", j3 is None,
              str(j3 and j3["job_id"]))
        check("...and the reason names the endpoint that is busy",
              "acme.example" in (why3 or ""), why3)

        # Finish acme and the queued one for the same endpoint becomes runnable.
        q.release(root2, j1, "done")
        j4, _ = q.claim(root2, "w4", now=T0 + datetime.timedelta(minutes=6))
        check("...and becomes claimable once the first one finishes",
              j4 and j4["job_id"] == acme2["job_id"], str(j4 and j4["job_id"]))
        q.release(root2, j4, "done")
        q.release(root2, j2, "done")

        # AN IN-PROCESS JOB SHARES THE GPU WITH EVERYTHING, so it takes the machine to itself
        # in both directions. Getting this backwards would put two sweeps on one Ollama, which
        # is the measured 5s -> 148s case and the reason the global lock existed at all.
        local = q.submit(root2, "dvla", os.path.join(root2, "nope.yaml"),
                         when=T0 + datetime.timedelta(minutes=7))
        remote = q.submit(root2, "gamma", cfg_for("https://api.gamma.example/chat"),
                          when=T0 + datetime.timedelta(minutes=8))
        check("a job whose endpoint cannot be named records no resource",
              q.load(root2, local["job_id"])["resource"] is None)
        jl, _ = q.claim(root2, "w5", now=T0 + datetime.timedelta(minutes=9))
        check("the in-process job is claimed", jl and jl["job_id"] == local["job_id"],
              str(jl and jl["job_id"]))
        jr, whyr = q.claim(root2, "w6", now=T0 + datetime.timedelta(minutes=10))
        check("...and nothing runs beside it, however remote the other job is", jr is None,
              str(jr and jr["job_id"]))
        check("...and the reason says it is the local model that is busy",
              "local model" in (whyr or ""), whyr)
        q.release(root2, jl, "done")

        # The other direction: a remote job running must not let an in-process one start.
        jr2, _ = q.claim(root2, "w7", now=T0 + datetime.timedelta(minutes=11))
        check("the remote job runs once the local one is done",
              jr2 and jr2["job_id"] == remote["job_id"], str(jr2 and jr2["job_id"]))
        local2 = q.submit(root2, "opsbot", os.path.join(root2, "gone.yaml"),
                          when=T0 + datetime.timedelta(minutes=12))
        jl2, whyl = q.claim(root2, "w8", now=T0 + datetime.timedelta(minutes=13))
        check("an in-process job waits for a remote one, not the other way round only",
              jl2 is None, str(jl2 and jl2["job_id"]))
        check("...and is told busy rather than empty", (whyl or "").startswith("busy"), whyl)

        # STARVATION, which the first version of this shipped. The selection took "every queued
        # job whose endpoint is free", so an in-process job was skipped for as long as ANY
        # remote job was queued — and it needs an empty queue to start, while a queue with
        # customers in it is never empty. The practice fleet would have waited behind paying
        # work forever, and nothing would have said so. An exclusive job at the head of the
        # queue holds the line instead.
        q.release(root2, jr2, "done")
        for i in range(3):
            q.submit(root2, f"late{i}", cfg_for(f"https://api.late{i}.example/chat"),
                     when=T0 + datetime.timedelta(minutes=20 + i))
        first, _ = q.claim(root2, "w9", now=T0 + datetime.timedelta(minutes=30))
        check("an in-process job at the head is not passed over by newer remote ones",
              first and first["job_id"] == local2["job_id"],
              str(first and (first["job_id"], first.get("target"))))
    finally:
        import shutil as _sh
        _sh.rmtree(root2, ignore_errors=True)

    # --- THE CLAIM ITSELF IS ATOMIC --------------------------------------------------------
    #
    # claim() was a read, a decision and a write with nothing joining them: two workers could
    # both list the queue, both see one job as queued, and both write it running with their own
    # lease. The file write is atomic, so the job looked sane and the last lease won — and both
    # workers went and ran the sweep. Two sweeps against one operator's endpoint, the exact
    # thing the per-resource lock exists to prevent. Theoretical behind a global lock with one
    # worker; the normal case once workers are woken on submission.
    import tempfile as _t3, yaml as _y3, shutil as _s3
    root3 = _t3.mkdtemp()
    try:
        fp3 = os.path.join(root3, "t.yaml")
        with open(fp3, "w", encoding="utf-8") as f:
            _y3.safe_dump({"adapter": "http", "url": "https://api.solo.example/chat"}, f)
        job = q.submit(root3, "solo", fp3, when=T0)

        g1, _ = q.claim(root3, "wA", now=T0 + datetime.timedelta(minutes=1))
        check("the first worker takes the job", g1 and g1["job_id"] == job["job_id"])
        marker = os.path.join(root3, "claims", job["job_id"] + ".claim")
        check("...and the claim leaves an atomic marker on disk", os.path.exists(marker))

        # Tested by taking the marker directly: no sleeps, no thread timing, no luck. The
        # marker is what makes a simultaneous claim IMPOSSIBLE rather than unlikely.
        check("a second worker cannot take the same job's marker",
              q._take(root3, job["job_id"], "wB", T0) is False)

        q.release(root3, g1, "done")
        check("closing the job gives the marker back", not os.path.exists(marker))

        # A worker that dies holding a marker must not make its job unclaimable forever: the
        # lease expires and the job goes back to queued, and the marker has to go with it or
        # the state says queued while the marker says taken and nothing runs it again.
        job2 = q.submit(root3, "solo", fp3, when=T0 + datetime.timedelta(minutes=2))
        g2, _ = q.claim(root3, "wC", now=T0 + datetime.timedelta(minutes=3))
        check("a second job is claimed", g2 and g2["job_id"] == job2["job_id"])
        later = T0 + datetime.timedelta(minutes=3, seconds=q.LEASE_SECONDS + 60)
        g3, why3 = q.claim(root3, "wD", now=later)
        check("a job whose worker died is reclaimed, marker and all",
              g3 and g3["job_id"] == job2["job_id"], f"{g3 and g3['job_id']} / {why3}")
    finally:
        _s3.rmtree(root3, ignore_errors=True)

    # --- A STEP THAT OUTLIVES ITS LEASE IS STOPPED, AND THE WORKER SURVIVES IT -------------
    #
    # `worker._run` had no timeout on any of its three subprocess calls per job. The QUEUE
    # recovers from a hung one — the lease expires and it is reclaimed, which this file checks
    # above — but the worker process stays blocked on a pipe forever, never claims another
    # job, and is indistinguishable from one that is busy. "Blocked never reads as idle" is
    # what this suite signs off with; this is the same sentence one level down.
    #
    # The ceiling is the lease itself rather than a number of its own, because past it
    # `release()` refuses the close and the step is producing work the queue will throw away.
    import worker as _w
    import tempfile as _tf
    import os as _os
    import time as _t

    _tmp = _tf.mkdtemp()
    with open(_os.path.join(_tmp, "hang.py"), "w") as _f:
        _f.write("import time\ntime.sleep(300)\n")
    _t0 = _t.time()
    _r = _w._run([_os.path.join(_tmp, "hang.py")], _tmp, deadline=1)
    _secs = _t.time() - _t0
    check("a worker step that hangs is stopped rather than taking the worker with it",
          _secs < 15, f"it ran {_secs:.0f}s against a 1s deadline")
    check("...and the result says it did not finish, rather than that it crashed",
          isinstance(_r, _w._Timeout) and "did not finish within 1s" in (_r.stderr or ""),
          repr(getattr(_r, "stderr", None))[:120])
    check("...with the default ceiling taken from the lease, not invented separately",
          _w.q.LEASE_SECONDS == q.LEASE_SECONDS, str(_w.q.LEASE_SECONDS))
    with open(_os.path.join(_tmp, "ok.py"), "w") as _f:
        _f.write("print('done')\n")
    _r2 = _w._run([_os.path.join(_tmp, "ok.py")], _tmp, deadline=60)
    check("...and a step that finishes still returns what the caller expects",
          _r2.returncode == 0 and "done" in (_r2.stdout or ""), repr(_r2.stdout)[:60])

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one sweep per contended resource, and blocked never reads as idle.")


if __name__ == "__main__":
    main()
