"""The door: an HTTP front end for the queue, for driving the engine from CI or another
machine on a trusted network.

`workspace.py` gave a run its own namespace, `authorization.py` decides whether a target may be
touched, `targets_http.py` turns a YAML into a driveable target, `jobqueue.py` and `worker.py`
serialise the GPU, `runs.py` records what happened and `defense_report.py` renders
what the sweep found. All of it works, and all of it needs a shell on the machine that runs
it. This is the smallest thing that changes that:

    POST /runs            a target config -> a job id
    GET  /runs/<id>       what happened to it
    GET  /runs/<id>/report  the quick report, once there is one

WHAT IT IS NOT. There is no authentication, no per-caller quota and no rate limit on the
intake itself, so it is not something to expose to the internet as it stands. That is said here
rather than left for somebody to discover, because a half-built service whose gaps are undocumented
is worse than no service: the gaps get assumed away.

WHAT IT DOES GET RIGHT, because these are the parts that cannot be bolted on afterwards:

  * **The local rule inverts.** On a workstation `localhost` is the practice fleet and needs no
    proof of ownership. Here `localhost` is THIS MACHINE, and an intake that accepts it is an
    SSRF proxy with an attack arsenal attached, pointed at that host's own metadata endpoint.
    `QATRATION_HOSTED=1` is mandatory, and it makes `authorization.unreachable_by_policy` refuse
    every loopback, private and link-local address before anything is queued.
  * **Only `adapter: http` is accepted.** The other adapters run in-process code in this repo; a
    submitted config naming one would be arbitrary local execution wearing a target's clothes.
  * **Paths are derived from the job id**, never from anything a caller sent, so no request can
    name a file to read.
  * **The submitted config is stored**, under a name this service chooses, and the job points at
    it — so what was submitted survives beside what it produced. An assessment whose inputs are
    gone is not reproducible, and the config is the whole input.

    QATRATION_HOSTED=1 QATRATION_AUTH_SECRET=... python intake.py --port 8300
"""
import argparse, json, os, re, subprocess, sys, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import yaml
import authorization
import jobqueue as q
import runs as _runs
from workspace import OUT

MAX_BODY = 64 * 1024          # a target config, not a payload

# WHAT A STRANGER MAY CALL A THING THAT BECOMES A FILENAME. `name` lands in
# `results_<name>.json` and `history/<name>.jsonl`; `job_id` lands in `job_<id>.json` and
# `claims/<id>.claim`. It must start with a letter or a digit, which rules out three separate
# things at once and is why the rule is a shape rather than a blocklist:
#
#   `..` and `.`   — no separator is in the class, so these cannot climb out of a directory on
#                    their own, but `results_...json` is a file nobody asked for and a name made
#                    only of dots is never a name somebody meant.
#   a leading `-`  — an id that reaches an argv list is an option, not a value.
#   `:`            — WAS in this class and is now gone. It appears in no id this service mints
#                    (they are `2026-08-21T1645-a1b2c3`), and on Windows `job_x:y.json` writes
#                    an NTFS alternate data stream: a file that exists, holds what was written,
#                    and does not appear in a directory listing.
ID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.\-]{0,63}$")

# The scopes `run_redteam.py` accepts. Checked HERE, at submission, because argparse rejecting
# it later means the API answered 202 for a job that cannot run — an acceptance is not a
# delivery, and the submitter is long gone by the time the worker finds out.
SCOPES = ("full", "quick")


def _problem(status, detail):
    return status, {"error": detail}


def submit(root, body, policy=None, wake=None):
    """Validate, prove, enqueue. Returns (status, payload). Sends at most one probe.

    The network policy applies HERE UNCONDITIONALLY, not only when `QATRATION_HOSTED` is set.
    Anything reaching this function arrived over a socket, so a local intake that waived
    loopback would be an SSRF proxy on somebody's laptop rather than on a server — the same
    defect with a smaller blast radius, which is not the same as not having it. The flag guards
    startup; the door does not have a friendly mode.

    `wake` is injected for the same reason `policy` is, and with the same guard: the suite
    asserts the defaults ARE the real functions, so an injection point cannot become the place
    a check or a trigger quietly went missing.

    `policy(url) -> reason or None` is injected only so the accept path can be exercised
    against a scripted bot on 127.0.0.1 with no network, exactly as `authorization.check` takes
    a `fetch`. The test that uses it also asserts the default IS the real function, because an
    injection point is otherwise a place a check can quietly go missing.
    """
    policy = policy or authorization.unreachable_by_policy
    wake = wake or wake_worker
    try:
        payload = json.loads(body or b"{}")
    except Exception as e:
        return _problem(400, f"the body is not JSON: {type(e).__name__}")
    raw = payload.get("config")
    if not raw:
        return _problem(400, "no `config`: send the target YAML as a string, or an object")
    if isinstance(raw, str):
        try:
            cfg = yaml.safe_load(raw) or {}
        except Exception as e:
            return _problem(400, f"the config is not valid YAML: {type(e).__name__}: {e}")
    elif isinstance(raw, dict):
        cfg = raw
    else:
        return _problem(400, "`config` must be a YAML string or an object")
    if not isinstance(cfg, dict):
        return _problem(400, "the config did not parse to a mapping")

    # ONLY THE CONFIGURED ADAPTER. Every other adapter in this repo runs code that lives here,
    # so accepting one would be arbitrary local execution dressed as a target.
    if (cfg.get("adapter") or "") != "http":
        return _problem(400, "only `adapter: http` may be submitted; the other adapters run "
                             "code inside this service rather than against your endpoint")

    url = cfg.get("url") or ""
    why = policy(url)
    if why:
        # Refused BEFORE the queue, so a job that cannot legally run is never accepted. A queue
        # full of jobs that will abort is a queue whose depth means nothing.
        return _problem(422, f"refusing {url!r}: {why}")

    # NO DEFAULT. This read `cfg.get("name") or "target"`, so a submission with no name was
    # silently renamed rather than refused — and `targets_http` then refused it anyway, on the
    # grounds that a nameless target has nowhere to put its results. Two rules for one field,
    # and the invented one wins first: every unnamed submission became `results_target.json`,
    # which is the same file for all of them.
    name = str(cfg.get("name") or "")
    if not ID_RE.match(name):
        return _problem(400, f"`name` must match {ID_RE.pattern} — it becomes a filename, in "
                             f"results_<name>.json and history/<name>.jsonl")

    # Written BEFORE the job is submitted, and under a name this service chose. The queue mints
    # the job id, so writing into the job's own directory would mean submitting a path that does
    # not exist yet and racing a worker to create it — the worker only has to poll once to win.
    # Stored either way, which is the point: an assessment whose inputs are gone is not
    # reproducible, and the config is the whole input.
    cfg_dir = os.path.join(str(root), "configs")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, f"{name}-{uuid.uuid4().hex[:12]}.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    # One probe, through the same check `onboard.py` runs, so the operator hears "your endpoint
    # is unreachable" now rather than after a queue wait. It also runs the authorization gate.
    from onboard import check as onboard_check
    try:
        ok, rep = onboard_check(cfg_path)
    except SystemExit as e:
        return _problem(403, f"not authorised: {e}")
    except Exception as e:
        return _problem(400, f"the config could not be driven: {type(e).__name__}: {e}")
    if not ok:
        return _problem(422, {"problems": rep.get("problems"), "notes": rep.get("notes")})

    scope = payload.get("scope") or "quick"
    if scope not in SCOPES:
        return _problem(400, f"scope={scope!r} is not one of {list(SCOPES)}")

    job = q.submit(root, name, cfg_path,
                   scope=scope,
                   authorization=rep.get("authorization"),
                   budgets=dict(cfg.get("rate") or {}),
                   attacks=os.path.join(HERE, "attacks_generic.yaml"))
    woken = wake(root)
    return 202, {"job_id": job.get("job_id"), "state": job.get("state"), "target": name,
                 "deliveries": rep.get("capabilities"),
                 "note": ("queued; poll /runs/<job_id>" if woken else
                          "queued, but no worker could be started — it will run when one is")}


def wake_worker(root, python=None):
    """Start a detached worker to drain the queue. Returns True if one was launched.

    EVENT-DRIVEN, NOT POLLED. A timer that checks the queue every minute does the same work
    whether one job arrives or a hundred, and keeps whatever it polls awake for nothing.

    So nothing here asks the queue whether there is anything to do. The intake already knows —
    it just accepted the job — and it says so once.

    Detached and not waited on, because a submission must return a job id in milliseconds
    while the run it started takes ten minutes. Concurrent wakes are harmless and expected: a
    worker with nothing to claim prints a reason and exits, and the claim marker makes two
    workers reaching for one job impossible rather than unlikely.
    """
    try:
        kwargs = {"cwd": os.path.dirname(HERE),
                  "env": dict(os.environ, QATRATION_OUT=str(root), PYTHONIOENCODING="utf-8"),
                  "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                  "stdin": subprocess.DEVNULL}
        if os.name == "nt":
            # Otherwise the child dies with the intake's console, and a submission accepted
            # right before a restart would be accepted and never run.
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | \
                getattr(subprocess, "DETACHED_PROCESS", 0)
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([python or sys.executable, os.path.join(HERE, "worker.py"),
                          "--drain", "--root", str(root)], **kwargs)
        return True
    except Exception:
        # A worker that could not be started is NOT a submission that failed: the job is on
        # the queue and the next wake, or a human, will run it. Saying nothing here would be
        # the honest-looking version of losing it, so the caller reports it on the job.
        return False


def status(root, job_id):
    if not ID_RE.match(job_id or ""):
        return _problem(400, "bad job id")
    for j in q.listing(root):
        if j.get("job_id") == job_id:
            out = {k: j.get(k) for k in ("job_id", "state", "target", "scope", "note",
                                         "run_id", "attempts")}
            rec = _runs.load(os.path.join(str(root), "runs", job_id), j.get("run_id") or "")
            if rec:
                out["run"] = {k: rec.get(k) for k in ("state", "spent", "started_at",
                                                      "finished_at", "note")}
            out["report"] = (f"/runs/{job_id}/report" if j.get("state") == "done" else None)
            return 200, out
    return _problem(404, "no such job")


def report(root, job_id):
    if not ID_RE.match(job_id or ""):
        return None
    # Derived from the id, never from anything the caller sent.
    p = os.path.join(str(root), "runs", job_id, "defense_report.html")
    if not os.path.exists(p):
        return None
    return open(p, encoding="utf-8").read()


def make_handler(root):
    class Handler(BaseHTTPRequestHandler):
        server_version = "qatration-intake"

        def _send(self, status_code, obj, ctype="application/json"):
            body = (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False,
                                                                indent=2)).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            # The report is a rendering of a target's own words. It is escaped at build time,
            # and these say so to the browser as well rather than relying on that alone.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src "
                                                        "'unsafe-inline'; img-src data:")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (ConnectionError, OSError):
                pass

        def do_POST(self):
            if self.path.rstrip("/") != "/runs":
                return self._send(*_problem(404, "POST /runs"))
            # THE LENGTH IS THE SUBMITTER'S, SO IT IS CHECKED BEFORE IT IS USED. `int(...)`
            # raised on `Content-Length: abc` and answered a traceback and a 500; and a
            # NEGATIVE length passed `n > MAX_BODY` and then reached `rfile.read(-1)`, which
            # reads to EOF — the one call the limit above exists to prevent, reached through
            # the limit itself.
            raw = self.headers.get("Content-Length")
            try:
                n = int(raw) if raw not in (None, "") else 0
            except ValueError:
                return self._send(*_problem(400, f"Content-Length: {raw!r} is not a number"))
            if n < 0:
                return self._send(*_problem(400, "Content-Length may not be negative"))
            if n > MAX_BODY:
                return self._send(*_problem(413, f"a target config is under {MAX_BODY} bytes"))
            # `read(n)` can return less if the connection ends early; that is the submitter's
            # problem to see as a parse error, not this loop's to wait out.
            code, obj = submit(root, self.rfile.read(n))
            self._send(code, obj)

        def do_GET(self):
            parts = [p for p in self.path.split("?")[0].strip("/").split("/") if p]
            if parts == ["runs"]:
                return self._send(200, {"jobs": [{k: j.get(k) for k in
                                                  ("job_id", "state", "target")}
                                                 for j in q.listing(root)]})
            if len(parts) == 2 and parts[0] == "runs":
                return self._send(*status(root, parts[1]))
            if len(parts) == 3 and parts[0] == "runs" and parts[2] == "report":
                html = report(root, parts[1])
                if html is None:
                    return self._send(*_problem(404, "no report for that job yet"))
                return self._send(200, html, "text/html")
            self._send(*_problem(404, "GET /runs, /runs/<id>, /runs/<id>/report"))

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description="the intake door")
    ap.add_argument("--port", type=int, default=8300)
    ap.add_argument("--root", default=str(OUT), help="where jobs and their workspaces live")
    args = ap.parse_args()

    # MANDATORY, not a default. Without it the authorization gate WAIVES local targets, which
    # is correct on a workstation and turns this into an SSRF proxy the moment it is a service.
    # Refusing to start is the only safe reading of an unset flag.
    if not authorization.hosted():
        sys.exit("QATRATION_HOSTED=1 is required to run the intake. Without it the "
                 "authorization gate treats localhost as a practice target and waives it, "
                 "which on a service pointed at its own machine is an SSRF proxy with an "
                 "attack arsenal attached. Nothing was started.")
    if not os.environ.get("QATRATION_AUTH_SECRET"):
        sys.exit("QATRATION_AUTH_SECRET is required: without it no proof of ownership can be "
                 "verified, so every submission would be a scan of somebody's system on their "
                 "say-so. Nothing was started.")
    os.makedirs(args.root, exist_ok=True)
    print(f"intake on http://localhost:{args.port}/runs   (jobs in {args.root})")
    print("  no authentication and no per-caller rate limit: bind it to a trusted network.")
    ThreadingHTTPServer(("localhost", args.port), make_handler(args.root)).serve_forever()


if __name__ == "__main__":
    main()
