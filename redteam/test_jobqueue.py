"""One sweep at a time, and the difference between an idle queue and a blocked one — no model.

The queue exists because of a measured failure, not a projected one: two sweeps against one
Ollama took a request from 5 seconds to 148, and the second run's timeouts were written down as
the target's behaviour. So the checks below are about the places where a queue lies rather than
about whether it can hold items.

The one that matters most is `claim()` returning nothing. That has two opposite meanings —
there is no work, or there is work and something else holds it — and a worker that cannot tell
them apart reports an idle queue while a real run sits blocked. That is a gap reported as
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
from workspace import atomic_write as workspace_atomic


def _collision_rule_on_an_unreadable_config(check):
    """What a job contends for, when nobody can read the config that names it.

    `contended_resource` answers None -- "this job contends for nothing anybody can name"
    -- for a config that cannot be opened or cannot be parsed, and then asked a config that
    parses to a LIST for its `url` and raised `AttributeError` out of the rule the queue
    uses to decide what may run beside what. Two answers to one question, and the one that
    raises is in the worker.
    """
    import tempfile as _tf_c, shutil as _sh_c
    _d = _tf_c.mkdtemp()
    try:
        _cases = (("a list", "- name: listy" + chr(10)),
                  ("a string", "just a sentence" + chr(10)),
                  ("a number", "7" + chr(10)),
                  ("empty", ""),
                  ("not YAML", "a: [1, 2" + chr(10)))
        for _why, _body in _cases:
            _p = os.path.join(_d, "cfg_%s.yaml" % _why.replace(" ", "_"))
            with open(_p, "w", encoding="utf-8") as _f:
                _f.write(_body)
            _said = ""
            try:
                _got = q.contended_resource(_p, "bot")
            except Exception as _e:
                _got, _said = "raised", "%s: %s" % (type(_e).__name__, _e)
            check("a config that is %s contends for nothing nameable" % _why,
                  _got is None, _said or repr(_got))
        # AND A REAL CONFIG STILL NAMES ITS ORIGIN, or the guard above could answer None to
        # everything and every sweep would be allowed to run beside every other.
        _good = os.path.join(_d, "good.yaml")
        with open(_good, "w", encoding="utf-8") as _f:
            _f.write("name: bot" + chr(10) + "url: http://127.0.0.1:8123/chat" + chr(10))
        check("...while a config that names an endpoint still contends for it",
              q.contended_resource(_good, "bot") == "http://127.0.0.1:8123",
              repr(q.contended_resource(_good, "bot")))
    finally:
        _sh_c.rmtree(_d, ignore_errors=True)


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    _collision_rule_on_an_unreadable_config(check)

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

        # --- AND THE WORKER OVER AN EMPTY QUEUE -------------------------------------------
        #
        # `worker.once` opens with `job, why = q.claim(...)` and `if job is None: return why`.
        # Delete it and the next line is `job['job_id']` on None: a worker started against a
        # queue with nothing in it dies with a TypeError instead of saying `empty:`. That is
        # the normal state of a queue -- it is what every poll between jobs looks like -- and
        # nothing was driving it.
        import worker as _wk
        _rootw = tempfile.mkdtemp()
        try:
            _why_w = _wk.once(_rootw, "w-empty")
            check("a worker over an empty queue says so rather than crashing",
                  isinstance(_why_w, str) and _why_w.startswith("empty"), repr(_why_w))
        finally:
            shutil.rmtree(_rootw, ignore_errors=True)

        # --- A RECORD THAT IS MISSING A FIELD ---------------------------------------------
        #
        # Two more survivors from the same sweep, and neither is closed by changing anything:
        # both answers are the right ones and nothing was driving them.
        #
        # `load` raises the reason `read_artifact` gave before it asks whether what came back
        # is a job. Delete that line and the next guard still produces an `unreadable` record
        # -- the state is identical, and the NOTE, which is the whole of what an operator has
        # to go on, drops from the parse error to "the file is nothing, not a job record".
        _rootn = tempfile.mkdtemp()
        try:
            with open(os.path.join(_rootn, "job_torn.json"), "w",
                      encoding="utf-8") as _ftorn:
                _ftorn.write("{ not json")
            _torn_rec = q.load(_rootn, "torn")
            check("a torn job file comes back as unreadable rather than absent",
                  _torn_rec.get("state") == "unreadable", str(_torn_rec))
            check("...and its note carries what actually stopped the read",
                  "JSONDecode" in (_torn_rec.get("note") or ""), str(_torn_rec.get("note")))
        finally:
            shutil.rmtree(_rootn, ignore_errors=True)

        # AND A LEASE WITH NO EXPIRY IN IT. `_lease_expired` answers False there and True for
        # an expiry it cannot parse, which reads like an inconsistency and is not one: the
        # reclaim path DROPS THE CLAIM MARKER, so treating a missing field as an expiry hands
        # a job to a second worker while the first may still be sweeping the same endpoint --
        # two runs against one operator's system, which is what the marker exists to prevent.
        # A record with no expiry blocks the queue visibly instead, as `busy: <id> is
        # running`, and an operator can act on that. An unparseable value is a corrupt record
        # rather than an incomplete one, and the line above it says why that one is reclaimed.
        check("a lease with no expiry is not read as an expired lease",
              q._lease_expired({"lease": {"worker": "w", "since": "2026-01-01 00:00:00"}})
              is False, "a running job would be handed to a second worker")
        check("...nor is a running record with no lease at all",
              q._lease_expired({"job_id": "x", "state": "running"}) is False, "")
        check("...while an expiry that cannot be parsed is not a live lease",
              q._lease_expired({"lease": {"until": "banana"}}) is True,
              "an unparseable lease would hang the queue forever")

        # --- AND THE JOBS THAT ARE NOT THERE, OR ARE ALREADY OVER ------------------------
        #
        # Three decisions in this file that nothing drove. Found by pointing
        # `tools/unguarded.py` at the guards it skips by design -- a branch with no comment
        # above it -- and deleting them one at a time: all three could go with every suite
        # green.
        #
        # `cancel` opens with `job = load(...)`, and without `if not job` the next line is
        # `job.get("state")` on None: a 404 answered as a traceback out of the queue a
        # service calls.
        _gone, _why_gone = q.cancel(root, "2026-01-01T0000-nosuch")
        check("cancelling a job that is not there is an answer, not a crash",
              _gone is None and _why_gone == "no such job", str(_why_gone))
        # AND ONE THAT IS OVER STAYS OVER. Without the state check a `done` record is
        # rewritten as `cancelled`: a finished sweep's own history, edited by a caller who
        # asked too late.
        _fin = q.submit(root, "zeta", "targets_zeta.yaml", when=final)
        q.release(root, q.load(root, _fin["job_id"]), "done")
        _after, _why_after = q.cancel(root, _fin["job_id"])
        check("a job that already finished is not cancelled after the fact",
              q.load(root, _fin["job_id"])["state"] == "done", str(_why_after))
        check("...and the refusal names the state it is already in",
              _why_after == "already done", str(_why_after))
        # AND A CLOSE OVER A RECORD THAT IS GONE. `release` reloads the job to check the
        # lease; without `if current is None` the lease checks read an empty mapping, every
        # refusal below them is skipped, and the close WRITES A NEW FILE -- recreating a job
        # somebody removed, and telling the worker it ended cleanly.
        # ITS OWN ROOT, because what is being asked is about one job and nothing else: in
        # the shared one above, `claim` hands back whatever is queued and blocked by the
        # same-origin rule, and the case would be about the fixture's history.
        _rootv = tempfile.mkdtemp()
        try:
            q.submit(_rootv, "eta", "targets_eta.yaml", when=final)
            _held, _why_claim = q.claim(_rootv, "w-vanish", now=final)
            check("there is a running job to close", bool(_held), str(_why_claim))
            if _held:
                os.remove(q._path(_rootv, _held["job_id"]))
                _closed_v, _why_v = q.release(_rootv, _held, "done")
                check("closing a job whose record was removed says the job is gone",
                      bool(_why_v) and "gone" in _why_v, str(_why_v))
                check("...and does not write the record back",
                      not os.path.exists(q._path(_rootv, _held["job_id"])),
                      "the removed job was recreated by its own close")
        finally:
            shutil.rmtree(_rootv, ignore_errors=True)

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
        # AND A FILE THAT PARSES AND IS NOT A JOB IS THE OTHER HALF. `load` goes through
        # `read_artifact`, which names its families by FILE NAME -- `results_`, `benign_` --
        # and a `job_*.json` is neither, so a file holding `[1, 2]` came back with no
        # complaint and every reader of the queue called `.get` on it. `listing` crashed
        # with `AttributeError: 'list' object has no attribute 'get'`, and that listing is
        # what `onboard --submit` prints and what the worker claims from.
        for _lbl, _body in (("a list", "[1, 2]"), ("a scalar", '"hello"'),
                            ("nothing at all", "null")):
            _jp = os.path.join(root, "job_shape.json")
            with open(_jp, "w", encoding="utf-8") as _fj:
                _fj.write(_body)
            _shaped = q.load(root, "shape")
            check("a job file that is %s reads as unreadable, not as a job" % _lbl,
                  bool(_shaped) and _shaped.get("state") == "unreadable", str(_shaped))
            check("...and the note says what the file holds instead (%s)" % _lbl,
                  "not a job record" in ((_shaped or {}).get("note") or ""), str(_shaped))
            _crash = ""
            try:
                _rows = q.listing(root)
            except Exception as _ej:
                _rows, _crash = [], "%s: %s" % (type(_ej).__name__, _ej)
            check("...and the listing survives it (%s)" % _lbl, not _crash, _crash)
            check("...and never offers it as work (%s)" % _lbl,
                  all(j.get("job_id") != "shape" for j in q.listing(root, "queued")),
                  str(q.listing(root, "queued")))
            os.remove(_jp)
        # DRIVEN, NOT GREPPED. This asked whether `jobqueue.py` CONTAINS `os.replace(`, and
        # the moment that rule moved into `workspace.atomic_write` -- one implementation for
        # the sixteen artifact writers that never had it -- the check went red over a
        # property that had not changed. A gate quantified over a spelling in one file is a
        # gate about the spelling.
        _keep = q.load(root, b["job_id"])
        _before = open(q._path(root, b["job_id"]), encoding="utf-8").read()
        try:
            with workspace_atomic(q._path(root, b["job_id"])) as _f:
                _f.write('{"job_id": "half')
                raise RuntimeError("killed mid-write")
        except RuntimeError:
            pass
        check("a job killed mid-write leaves the previous record intact",
              open(q._path(root, b["job_id"]), encoding="utf-8").read() == _before,
              open(q._path(root, b["job_id"]), encoding="utf-8").read()[:80])
        check("...and it is still the job the queue had",
              (q.load(root, b["job_id"]) or {}).get("state") == (_keep or {}).get("state"),
              str(q.load(root, b["job_id"])))
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
    # Against an outside target that shared resource is gone: a run is about eleven minutes of
    # wall clock and 0.08 seconds of local CPU, because all of it is waiting on somebody else's
    # bot. A global lock stopped every other job during time this machine spent doing nothing.
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
        # remote job was queued — and it needs an EMPTY queue to start, which a queue doing
        # any work never is. The practice fleet would have waited behind remote jobs forever
        # and nothing would have said so. An exclusive job at the head of the queue holds the
        # line instead.
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

    # --- A CLAIM WITH NO JOB BEHIND IT ------------------------------------------------
    #
    # `_take` and the state write that follows it are two operations. A worker killed
    # between them leaves a marker on a job still recorded as `queued`, and nothing
    # reclaimed that: the lease loop only looks at jobs in `running`, and this one never
    # got there. Every later claim picked the job, failed to take it, and returned `was
    # claimed by another worker between listing the queue and taking it` -- a sentence about
    # a race lasting microseconds, describing a state that lasted forever.
    #
    # AND IT BLOCKED EVERYTHING BEHIND IT, because `claim` stops at the first runnable job.
    # One stuck at the head made the whole queue unclaimable, with the same wrong sentence.
    import time as _time_o
    _CFG_O = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets_httpbot.yaml")
    _w = tempfile.mkdtemp()
    _a = q.submit(_w, "bot", _CFG_O, scope="quick")
    assert q._take(_w, _a["job_id"], "w1", q._now())
    _got, _why = q.claim(_w, worker="w2")
    check("a fresh claim marker is respected", _got is None, str(_why))
    check("...and the reason names the holder rather than a race",
          "claimed by w1" in _why, _why)
    check("...and says when it will be cleared, so the state is not read as permanent",
          "will be cleared after" in _why, _why)
    check("...and the job is still queued, not lost", 
          q.load(_w, _a["job_id"])["state"] == "queued",
          q.load(_w, _a["job_id"])["state"])

    # PAST THE GRACE PERIOD it is an orphan, and clearing it is safe in a way clearing a
    # lock is not: after the marker is gone both workers still have to take it again, and
    # only one can. The grace period is not exclusion, it is not deleting a claim a live
    # worker made a moment ago.
    _m = q._marker(_w, _a["job_id"])
    _old = _time_o.time() - q.ORPHAN_SECONDS - 5
    os.utime(_m, (_old, _old))
    _got, _why = q.claim(_w, worker="w2")
    check("an orphaned claim is cleared and the job runs",
          _got is not None and _got["job_id"] == _a["job_id"], str(_why))
    check("...and the clearing is recorded rather than silent",
          "orphaned claim cleared" in [e.get("event") for e in
                                       q.load(_w, _a["job_id"])["history"]],
          str(q.load(_w, _a["job_id"])["history"]))

    # AND A WORKER THAT COMES BACK LATE YIELDS INSTEAD OF CLOBBERING. One descheduled past
    # the grace period finds its claim cleared and re-taken; writing the state anyway would
    # overwrite a run already in flight, which is the two-sweeps race the marker exists to
    # prevent, arriving through the machinery that recovers from it.
    _w2 = tempfile.mkdtemp()
    _c = q.submit(_w2, "bot", _CFG_O, scope="quick")
    assert q._take(_w2, _c["job_id"], "slow", q._now())
    _m2 = q._marker(_w2, _c["job_id"])
    os.utime(_m2, (_old, _old))
    _fresh, _ = q.claim(_w2, worker="fresh")
    check("a fresh worker takes over an orphaned claim", _fresh is not None, "")
    check("...and the lease names the worker that is actually running it",
          (q.load(_w2, _c["job_id"]).get("lease") or {}).get("worker") == "fresh",
          str(q.load(_w2, _c["job_id"]).get("lease")))
    # THE LATE ONE, arriving now: it must not write the job at all.
    _late, _why_late = q.claim(_w2, worker="slow")
    check("...and the late worker gets no job", _late is None, str(_late))
    check("...and the lease it would have clobbered is untouched",
          (q.load(_w2, _c["job_id"]).get("lease") or {}).get("worker") == "fresh",
          str(q.load(_w2, _c["job_id"]).get("lease")))

    # AND THE PREDICATE THE LATE WORKER CONSULTS, in both directions. The BRANCH cannot be
    # reached by one process -- it fires when a worker is descheduled between taking the marker
    # and writing the job, long enough for another to clear the orphan and take it, which needs
    # two processes and a stall -- so what is exercised is the question it asks, plus an AST
    # check that `claim` still asks it. Saying that is better than a fixture pretending to be
    # a race.
    _w3 = tempfile.mkdtemp()
    _d = q.submit(_w3, "bot", _CFG_O, scope="quick")
    assert q._take(_w3, _d["job_id"], "mine", q._now())
    check("the marker names the worker that took it",
          q._still_ours(_w3, _d["job_id"], "mine"), "")
    check("...and not one that did not",
          not q._still_ours(_w3, _d["job_id"], "other"), "")
    q._drop(_w3, _d["job_id"])
    assert q._take(_w3, _d["job_id"], "other", q._now())
    check("...and after a clear and a re-take it names the new holder",
          q._still_ours(_w3, _d["job_id"], "other")
          and not q._still_ours(_w3, _d["job_id"], "mine"), "")
    check("a missing marker is not ours either",
          (q._drop(_w3, _d["job_id"]) or True)
          and not q._still_ours(_w3, _d["job_id"], "other"), "")

    # AND `claim` STILL ASKS IT between taking the marker and writing the state. A predicate
    # nothing consults is the guard removed with its name left behind.
    import ast as _ast_o
    _qsrc = _ast_o.parse(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "jobqueue.py"), encoding="utf-8").read())
    _claim = [n for n in _ast_o.walk(_qsrc)
              if isinstance(n, _ast_o.FunctionDef) and n.name == "claim"]
    check("claim can be walked", bool(_claim), "")
    if _claim:
        _asks = [n.lineno for n in _ast_o.walk(_claim[0])
                 if isinstance(n, _ast_o.Call) and isinstance(n.func, _ast_o.Name)
                 and n.func.id == "_still_ours"]
        _takes = [n.lineno for n in _ast_o.walk(_claim[0])
                  if isinstance(n, _ast_o.Call) and isinstance(n.func, _ast_o.Name)
                  and n.func.id == "_take"]
        check("claim asks whether the marker is still its own", bool(_asks), str(_asks))
        check("...after taking it, not before",
              bool(_asks) and bool(_takes) and min(_asks) > min(_takes),
              "take at %s, ask at %s" % (_takes, _asks))

    # AND THE GRACE PERIOD IS LONGER THAN THE GAP IT COVERS, by a margin that is the whole
    # reason clearing is not a guess: the gap is a few file writes.
    check("the grace period is not a timing guess", q.ORPHAN_SECONDS >= 30,
          str(q.ORPHAN_SECONDS))

    # --- A JOB RECORD NOBODY CAN READ IS NOT A JOB THAT IS NOT RUNNING --------------
    #
    # `load` says exactly that in its own comment and returns `state: unreadable` rather
    # than None. Every question in `claim` then asked `state == "running"` and got False
    # for it, so a torn record — what a worker killed mid-write leaves, which is the
    # failure this module is written around — took its endpoint out of `busy`, and the
    # next claim handed out a second job against the same deployment. That is the one
    # thing the per-resource lock exists to prevent, arriving through the door marked
    # `unreadable is not absent`.
    #
    # Reproduced before it was fixed: a torn record for a job running against
    # `http://bot.example`, one queued job for the same endpoint, and `claim` handed the
    # queued one out.
    _tr = tempfile.mkdtemp()
    try:
        with open(os.path.join(_tr, "job_torn.json"), "w", encoding="utf-8") as _ft:
            _ft.write('{"job_id": "torn", "state": "running", '
                      '"resource": "http://bot.example", "target": "b", ')
        with open(os.path.join(_tr, "job_queued.json"), "w",
                  encoding="utf-8") as _fq:
            json.dump({"job_id": "queued", "state": "queued",
                       "resource": "http://bot.example", "target": "b",
                       "config": "cfg.yaml", "scope": "quick",
                       "submitted_at": "2026-09-09 00:00:00"}, _fq)
        check("a torn job record is seen as unreadable, not as absent",
              [j.get("state") for j in q.listing(_tr) if j.get("job_id") == "torn"]
              == ["unreadable"], str(q.listing(_tr)))
        _job2, _why2 = q.claim(_tr, "w-torn")
        check("...and no job is handed out while one record cannot be read",
              _job2 is None, str((_job2 or {}).get("job_id")))
        check("...with a reason naming the record, so a person can repair it",
              "torn" in _why2 and _why2.startswith("busy:"), _why2)
        # UNDER `busy:` DELIBERATELY. `worker --drain` stops on `empty` or `busy`, so a new
        # prefix would spin that loop forever over a queue it can never claim from.
        import worker as _wk
        check("...and the drain loop recognises the prefix it stops on",
              _why2.split(":")[0] in ("busy", "empty"), _why2)
        # AND THE CLOSING DOOR HAD THE SAME BLINDNESS. `release` reads the stored record
        # to check the lease is still this worker's -- `care at the opening door and trust
        # at the closing one is not a lock`, in its own words. A torn record has no
        # `lease` key, so `theirs` was empty and every refusal below it was skipped: the
        # close went through looking like an ordinary clean ending. Writing it is still
        # right, it replaces a damaged file with a readable one, but the record has to say
        # the lease could not be checked.
        with open(os.path.join(_tr, "job_close.json"), "w", encoding="utf-8") as _fc:
            _fc.write('{"job_id": "close", "state": "running", ')
        _closed, _cwhy = q.release(
            _tr, {"job_id": "close", "state": "running", "target": "b",
                  "lease": {"worker": "w-close", "since": "2026-09-09 00:00:00"}},
            "done")
        check("a close over a record nobody could read still lands",
              _cwhy is None and _closed.get("state") == "done", "%r %r" % (_cwhy, _closed))
        check("...but says the lease could not be checked, rather than reading clean",
              "not be checked against the lease" in (_closed.get("note") or ""),
              str(_closed.get("note")))
    finally:
        shutil.rmtree(_tr, ignore_errors=True)

    # --- THE ONE LINE A QUEUE READER GETS FOR A RUN THAT ENDED EARLY --------------------
    #
    # A run ends early for two reasons and only one of them is ours: the request budget the
    # operator set, and the target refusing every attack until `GiveUpWall` gives up on it.
    # The run record carries the reason in its own words and the queue's note asserted the
    # other one over the top of it -- `budget stopped it: the endpoint answered every one of
    # the last 5 with a rate limit` -- in the line a reader sees instead of the run.
    import worker as _wk
    _wall_note = ("the endpoint answered every one of the last 5 with a rate limit and has "
                  "not answered anything else since; the remaining attacks were never sent")
    _said = _wk.stopped_note({"note": _wall_note})
    check("a run the target stopped is not reported as a budget of ours",
          "budget" not in _said, _said)
    check("...and the record's own reason is what is carried",
          _wall_note in _said, _said)
    check("...under a word that says it did not finish",
          _said.startswith("stopped part way"), _said)
    # AND OURS STILL READS AS OURS, because the record says so in its own words.
    _ours = _wk.stopped_note({"note": "budget spent (requests); the remaining attacks were "
                                      "never sent"})
    check("a run our own budget stopped still says so", "budget spent (requests)" in _ours,
          _ours)
    # AND A RECORD THAT SAYS NOTHING GETS A SENTENCE RATHER THAN AN EMPTY ONE: a note that
    # is blank reads as a job with nothing to report, which is the opposite of the truth.
    check("...and a record with no reason still says the rest was not sent",
          "the remaining attacks were not sent" in _wk.stopped_note({}),
          _wk.stopped_note({}))
    check("...and so does one that is missing entirely",
          _wk.stopped_note(None) == _wk.stopped_note({}), _wk.stopped_note(None))
    # AND THE JOB RUNNER ASKS IT. The rule above is only a fix while `execute` still calls
    # it, and the one state that reaches it -- a queued sweep the target stopped part way --
    # needs a queue, a worker and an endpoint that answers and then refuses.
    import ast as _ast_w
    _wsrc = open(os.path.join(os.path.dirname(os.path.abspath(_wk.__file__)),
                              "worker.py"), encoding="utf-8").read()
    _ex = next((_n for _n in _ast_w.walk(_ast_w.parse(_wsrc))
                if isinstance(_n, _ast_w.FunctionDef) and _n.name == "execute"), None)
    check("the job runner asks for that line rather than composing one",
          bool(_ex) and any(isinstance(_c, _ast_w.Call)
                            and getattr(_c.func, "id", "") == "stopped_note"
                            for _c in _ast_w.walk(_ex)),
          "execute does not call stopped_note")

    # --- FINDINGS OF AN INDEPENDENT REVIEW OF THE SERVICE PATH ----------------------------
    import worker as _wk
    _sw = tempfile.mkdtemp()
    try:
        # A STALE CLOSE DOES NOT REVIVE A DEAD JOB. Its record carries no lease, so every
        # refusal compared against nothing, and a late `done` erased "gave up".
        _sj = q.submit(_sw, "t", os.path.join(_sw, "t.yaml"))
        _cj, _ = q.claim(_sw, worker="w1")
        _dead = dict(q.load(_sw, _sj["job_id"]), state="dead", lease=None, note="gave up")
        json.dump(_dead, open(os.path.join(_sw, "job_%s.json" % _sj["job_id"]), "w",
                             encoding="utf-8"))
        _rel, _why_rel = q.release(_sw, _cj, "done")
        check("a late close of a job that was given up on is refused, and the job stays dead",
              (bool(_why_rel), (q.load(_sw, _sj["job_id"]) or {}).get("state")) == (True, "dead"),
              str((_why_rel, q.load(_sw, _sj["job_id"]))))
        # DEPTH COUNTS WHAT IT COULD NOT READ, which `claim` refuses to work past.
        open(os.path.join(_sw, "job_torn.json"), "w", encoding="utf-8").write("{")
        check("depth counts a job record it could not read",
              q.depth(_sw).get("unreadable") == 1, str(q.depth(_sw)))
        os.remove(os.path.join(_sw, "job_torn.json"))

        # THE RECLAIM RE-READS BEFORE IT WRITES. A worker that closed `done` between the
        # reclaim's listing and its write had its close overwritten with `queued`.
        _rj = q.submit(_sw, "r", os.path.join(_sw, "r.yaml"))
        _rc, _ = q.claim(_sw, worker="w2")
        _snap = q.listing(_sw)
        q.release(_sw, _rc, "done", run_id="RUN-R")
        _real_listing = q.listing
        q.listing = lambda root, state=None: [dict(j) for j in _snap]
        try:
            q.claim(_sw, worker="w3", now=q._now() + datetime.timedelta(
                seconds=q.LEASE_SECONDS + 600))
        finally:
            q.listing = _real_listing
        check("a close written between the reclaim's listing and its write is kept",
              (q.load(_sw, _rj["job_id"]) or {}).get("state") == "done",
              str(q.load(_sw, _rj["job_id"])))

        # THE THREE STEPS SHARE ONE LEASE, and a retry is joined only to its OWN run record.
        class _Done:
            returncode, stdout, stderr = 0, "", ""
        _deadlines = []
        _real_run = _wk._run
        _wk._run = lambda cmd, out, python=None, deadline=None: (
            _deadlines.append(deadline), _Done())[1]
        try:
            _job = {"job_id": "jx", "config": os.path.join(_sw, "t.yaml"), "scope": "quick"}
            _out = _wk.run_dir(_sw, _job)
            os.makedirs(_out, exist_ok=True)
            json.dump({"run_id": "RUN-ATTEMPT-1", "state": "finished",
                       "started_at": "2026-09-01 10:00:00"},
                      open(os.path.join(_out, "run_RUN-ATTEMPT-1.json"), "w", encoding="utf-8"))
            _st, _note, _rid = _wk.execute(_job, _sw)
        finally:
            _wk._run = _real_run
        check("every step of a job is bounded by the one lease, not a lease each",
              len(_deadlines) >= 2 and all(d is not None and d <= q.LEASE_SECONDS
                                           for d in _deadlines), str(_deadlines))
        check("...and an attempt that wrote no run record is not joined to the last one's",
              _rid is None, str(_rid))
        # EXIT 2 AFTER THE RUN BEGAN IS A CRASH, not "refused, nothing was sent".
        class _Crashed:
            returncode, stdout, stderr = 2, "", "KeyError: 'x'"

        def _crash(cmd, out, python=None, deadline=None):
            if cmd and cmd[0].endswith("run_redteam.py"):
                json.dump({"run_id": "RUN-CRASHED", "state": "aborted", "target": "t",
                           "started_at": "2026-09-02 10:00:00",
                           "note": "crashed: KeyError after 140 requests"},
                          open(os.path.join(out, "run_RUN-CRASHED.json"), "w",
                               encoding="utf-8"))
                return _Crashed()
            return _Done()
        _wk._run = _crash
        try:
            _st2, _note2, _rid2 = _wk.execute(dict(_job, job_id="jy"), _sw)
        finally:
            _wk._run = _real_run
        check("a sweep that crashed after it began is failed with its own reason, not dead",
              (_st2, _rid2) == ("failed", "RUN-CRASHED") and "crashed: KeyError" in (_note2 or ""),
              str((_st2, _note2, _rid2)))
    finally:
        shutil.rmtree(_sw, ignore_errors=True)

    # --- A JOB RECORD WHOSE FIELDS ARE THE WRONG KIND IS UNREADABLE, NOT A CRASH -----------
    #
    # A field-type sweep over a job queued by `onboard --submit` found the listing dying on
    # `state: null` and `lease: "x"`, the worker on `history: 7` and `attempts: [1]` while
    # claiming, `onboard --submit` on `submitted_at: 7`. `load` goes through `read_artifact`,
    # which now asks `_JOB_REQUIRE`; every row is walked through `load`, and the listing and
    # the worker are driven over one of them.
    import subprocess as _sp_j
    from workspace import _JOB_REQUIRE as _jtable
    _jw = tempfile.mkdtemp()
    try:
        _jb = q.submit(_jw, "t", os.path.join(_jw, "t.yaml"))
        _jid = _jb["job_id"]
        _jmissed = []
        for _key, (_kind, _req, _) in _jtable.items():
            if _key == "job_id":
                continue
            _wrong = 7 if _kind is str else "x"
            _b = json.loads(json.dumps(_jb))
            _parts = _key.replace("[]", "").split(".")
            _obj = _b
            for _p in _parts[:-1]:
                _obj[_p] = _obj.get(_p) or {}
                _obj = _obj[_p]
            _obj[_parts[-1]] = [_wrong] if _key.endswith("[]") else _wrong
            json.dump(_b, open(os.path.join(_jw, "job_%s.json" % _jid), "w", encoding="utf-8"))
            _rec = q.load(_jw, _jid) or {}
            if not (_rec.get("state") == "unreadable" and _parts[-1] in str(_rec.get("note"))):
                _jmissed.append((_key, _rec.get("state"), _rec.get("note")))
        check("every row of the job table makes a record unreadable, by name",
              _jmissed == [], str(_jmissed[:3]))
        _b = dict(_jb, state=None)
        json.dump(_b, open(os.path.join(_jw, "job_%s.json" % _jid), "w", encoding="utf-8"))
        check("a job with no state is unreadable, not listed as one",
              (q.load(_jw, _jid) or {}).get("state"), "unreadable")
        json.dump(dict(_jb, history=7), open(os.path.join(_jw, "job_%s.json" % _jid), "w",
                                             encoding="utf-8"))
        _outs = []
        for _script in (["jobqueue.py", "--root", _jw], ["worker.py", "--root", _jw, "--once"]):
            _pj = _sp_j.run([sys.executable, os.path.join(HERE, _script[0])] + _script[1:],
                            capture_output=True, text=True, errors="replace", timeout=300,
                            env=dict(os.environ, QATRATION_OUT=_jw, PYTHONIOENCODING="utf-8"))
            _outs.append((_script[0], "Traceback" in (_pj.stdout or "") + (_pj.stderr or "")))
        check("the listing and the worker over a job holding `history: 7` do not crash",
              _outs, [("jobqueue.py", False), ("worker.py", False)])
        json.dump(_jb, open(os.path.join(_jw, "job_%s.json" % _jid), "w", encoding="utf-8"))
        check("...while the job the walk mutates is itself readable",
              (q.load(_jw, _jid) or {}).get("state"), "queued")
    finally:
        shutil.rmtree(_jw, ignore_errors=True)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one sweep per contended resource, and blocked never reads as idle.")


if __name__ == "__main__":
    main()
