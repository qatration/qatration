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
from workspace import OUT, DEFAULT_ARSENAL

# NO CLI DOOR, ON PURPOSE, and said here rather than in the gate: a list of exempt
# modules living in the check is a second copy of this judgement, and the next module
# added would join it by whoever happened to be editing the check.
NO_CLI_DOOR = "the HTTP door itself; a server runs it, a person does not"


MAX_BODY = 64 * 1024          # a target config, not a payload
# HOW LONG, AND HOW MUCH, a refusal waits for the body it is refusing -- see `_refuse_unread`.
LINGER_SECONDS = 2.0
LINGER_BYTES = 8 * 1024 * 1024

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
# `\A` and `\Z`, not `^` and `$`. In Python `$` also matches immediately BEFORE a trailing
# newline, so `httpbot\n` satisfied this and the message beside it says the value becomes a
# filename. It does: `configs/<name>-<uuid>.yaml`, `results_<name>.json`,
# `history/<name>.jsonl`. A newline is not a filename character on Windows -- the write
# raises OSError 22 and the endpoint answers a traceback to a submission it had just
# accepted -- and on Linux it succeeds, which is worse: `httpbot` and `httpbot\n` are two
# targets that render identically in every report built from those names.
#
# Nothing else in the repo has this shape. `authorization.TOKEN_RE` is anchored the same
# way and is safe, because a token that passes its shape check is then compared exactly
# with `hmac.compare_digest`, so the trailing newline fails closed.
ID_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z_.\-]{0,63}\Z")

# The scopes `run_redteam.py` accepts. Checked HERE, at submission, because argparse rejecting
# it later means the API answered 202 for a job that cannot run — an acceptance is not a
# delivery, and the submitter is long gone by the time the worker finds out.
#
# AND IMPORTED RATHER THAN RETYPED, which is what makes that sentence true. The set was
# written out here and again as `choices=` in each of the two parsers, so "the scopes
# run_redteam accepts" was a claim about a literal in another file.
from workspace import SCOPES


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
    # AND WHAT PARSED IS A SUBMISSION. `[1,2]`, `"hi"`, `7`, `true` and `null` are all valid
    # JSON and none of them has a `.get`, so five one-byte bodies reached
    # `payload.get("config")` as an AttributeError. The try above catches a body that is not
    # JSON; nothing asked whether the JSON was the document.
    #
    # Walked over a socket, which is where it matters: an unhandled exception inside
    # `do_POST` never reaches `_send`, so `BaseHTTPRequestHandler` closes the connection with
    # no reply at all -- `RemoteDisconnected` on the client, a traceback on this service's
    # stderr, and a caller with no idea which half was wrong. Every other refusal in this
    # file is a number and a sentence; this one was a dropped socket.
    if not isinstance(payload, dict):
        return _problem(400, f"the body must be a JSON object holding a `config`, not "
                             f"{type(payload).__name__}")
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

    # THE SCOPE BEFORE ANYTHING IS WRITTEN OR SENT: it was checked after the probe, so a
    # `scope: bogus` submission had already reached the submitter's endpoint and left its
    # config on disk before its 400. Found by an independent review.
    scope = payload.get("scope") or "quick"
    if scope not in SCOPES:
        return _problem(400, f"scope={scope!r} is not one of {list(SCOPES)}")

    # Written BEFORE the job is submitted, and under a name this service chose. The queue mints
    # the job id, so writing into the job's own directory would mean submitting a path that does
    # not exist yet and racing a worker to create it — the worker only has to poll once to win.
    # Stored either way, which is the point: an assessment whose inputs are gone is not
    # reproducible, and the config is the whole input.
    cfg_dir = os.path.join(str(root), "configs")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, f"{name}-{uuid.uuid4().hex[:12]}.yaml")
    from workspace import atomic_write as _atomic
    with _atomic(cfg_path) as f:
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
        # A REFUSED CONFIG IS NOT KEPT: it is the input to an assessment that will not run,
        # and every refusal left one in `configs/`. And NOT AUTHORISED IS 403: `onboard.check`
        # catches the gate itself and reports exit 4, so the `except SystemExit` above never
        # saw it and a missing proof came back as 422, "fix your config". Found by an
        # independent review.
        try:
            os.remove(cfg_path)
        except OSError:
            pass
        _code = 403 if rep.get("exit") == 4 else 422
        return _problem(_code, {"problems": rep.get("problems"), "notes": rep.get("notes")})

    job = q.submit(root, name, cfg_path,
                   scope=scope,
                   authorization=rep.get("authorization"),
                   budgets=dict(cfg.get("rate") or {}),
                   attacks=DEFAULT_ARSENAL)
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
    # A SUITE THAT QUEUES JOBS IT DOES NOT MEAN TO RUN says so, and no detached sweep outlives
    # it: a worker started from a test runs against a fixture server the test is about to shut.
    from workspace import env_flag as _env_flag
    if _env_flag("QATRATION_NO_WORKER"):
        return False
    try:
        kwargs = {"cwd": os.path.dirname(HERE),
                  "env": dict(os.environ, QATRATION_OUT=str(root), PYTHONIOENCODING="utf-8"),
                  "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                  "stdin": subprocess.DEVNULL}
        if os.name == "nt":
            # Otherwise the child dies with the intake's console, and a submission accepted
            # right before a restart would be accepted and never run.
            #
            # A CONSOLE OF ITS OWN, HIDDEN -- NOT NONE. This was DETACHED_PROCESS: a worker with
            # no console at all, so every console program IT starts -- the sweep, the report,
            # each a `python` -- got a brand-new console, and Windows hands a new console to
            # the default terminal, which opens a window on the user's screen. Measured with a
            # window hook over `test_onboard`'s one `--submit`: three terminal windows, one per
            # python the worker started. CREATE_NO_WINDOW gives the worker a console nobody
            # sees, and its children inherit that one.
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
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
    """The report, and only for a job that finished.

    Returns the HTML, or (None, reason) when there is nothing this caller should be handed.

    THE STATE CHECK IS THE POINT. `status()` withholds the report link unless the job is
    `done`, on purpose — and this served the file to anyone who typed the URL, which is four
    characters of guessing. A sweep that stopped early renders the same shape of page as one
    that finished: findings, counts, a fix list. What differs is the attacks that never ran,
    and those look exactly like attacks that held. Handing that over as a plain 200 is this
    engine's own defect in the one endpoint whose entire job is giving somebody a conclusion.
    """
    if not ID_RE.match(job_id or ""):
        return None, "bad job id"
    # Derived from the id, never from anything the caller sent.
    p = os.path.join(str(root), "runs", job_id, "defense_report.html")
    if not os.path.exists(p):
        return None, "no report for that job yet"

    state = None
    for j in q.listing(root):
        if j.get("job_id") == job_id:
            state = j.get("state")
            break
    if state != "done":
        return None, (f"this job is {state or 'unknown'}, not done, so its report covers "
                      f"however much of the sweep ran. Attacks that were never sent read the "
                      f"same as attacks that held, which is why this is not served.")
    return open(p, encoding="utf-8").read(), None


def make_handler(root):
    class Handler(BaseHTTPRequestHandler):
        server_version = "qatration-intake"

        def _send(self, status_code, obj, ctype="application/json", send_body=True):
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
            if not send_body:
                return
            try:
                self.wfile.write(body)
            except (ConnectionError, OSError):
                pass

        def send_error(self, code, message=None, explain=None):
            """Every response through the one path that sets the headers above.

            THE BASE CLASS ANSWERS SOME REQUESTS ITSELF, and it answers them in HTML. Any
            method this handler does not define -- PUT, DELETE, PATCH, OPTIONS -- and any
            request line it cannot parse reached `BaseHTTPRequestHandler.send_error`, which
            writes its own `text/html` page with neither `nosniff` nor a content policy.
            Measured over the running server: four methods, four HTML pages without either
            header, on the service whose own check said every response carried them because
            the header's NAME appeared in this file.

            So the base class's errors become this door's errors: the same JSON problem
            shape a submitter already parses, the same two headers, the connection closed as
            the base class would have closed it -- and no body for HEAD, which must not have
            one.
            """
            self.close_connection = True
            _reason = message or self.responses.get(code, ("error",))[0]
            self._send(*_problem(code, _reason),
                       send_body=getattr(self, "command", None) != "HEAD")

        def do_POST(self):
            if self.path.rstrip("/") != "/runs":
                # THE BODY IS READ BEFORE THE REFUSAL, and that is not politeness. A server
                # that answers and closes while the client is still sending leaves the
                # client with a reset rather than the 404: on Windows that is
                # `ConnectionAbortedError [WinError 10053]`, raised inside `getresponse()`,
                # so a submitter who typed the wrong path gets no status code at all -- the
                # same dropped-connection failure this door already has cases for on
                # `/runs`, one route over. Measured on a CI runner; the loopback here is
                # fast enough to hide it.
                self._drain()
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
                return self._refuse_unread(400, f"Content-Length: {raw!r} is not a number")
            if n < 0:
                return self._refuse_unread(400, "Content-Length may not be negative")
            if n > MAX_BODY:
                return self._refuse_unread(413, f"a target config is under {MAX_BODY} bytes")
            # `read(n)` can return less if the connection ends early; that is the submitter's
            # problem to see as a parse error, not this loop's to wait out.
            code, obj = submit(root, self.rfile.read(n))
            self._send(code, obj)

        def _refuse_unread(self, code, why):
            """Refuse on the header alone, and let the refusal survive the body still coming.

            A REFUSAL THE SUBMITTER NEVER SEES. These three are decided before the body is
            read, and the connection was then closed with that body unread -- which a TCP
            stack answers with a reset, taking the response already on the wire with it.
            Measured against this handler: a body that arrives 50 ms after its headers, which
            is any client not on this machine, got `ConnectionAbortedError` instead of the 413
            twenty times in twenty; a 2 MB body sent at once, six in twenty. The submitter of
            an oversized config learned that the door was broken, not that the config was too
            big. `test_intake` had met the same race on the two 400s and stopped sending a
            body to them, calling the server blameless.

            So: answer, half-close, and read what is still coming until it ends -- bounded in
            time and in bytes, for the reason `_drain` is bounded: the length is the
            submitter's number, and a door that reads without limit to be polite is holding
            itself open.
            """
            import socket as _socket
            import time as _time
            self._send(*_problem(code, why))
            self.close_connection = True
            try:
                self.wfile.flush()
                self.connection.shutdown(_socket.SHUT_WR)
                deadline = _time.monotonic() + LINGER_SECONDS
                left = LINGER_BYTES
                while left > 0:
                    wait = deadline - _time.monotonic()
                    if wait <= 0:
                        break
                    self.connection.settimeout(wait)
                    chunk = self.connection.recv(min(65536, left))
                    if not chunk:
                        break
                    left -= len(chunk)
            except OSError:
                pass

        def _drain(self):
            """Read whatever the submitter sent, so the refusal reaches them.

            Bounded by `MAX_BODY` for the reason every other read here is: the length is the
            submitter's number, and a refusal that reads an unbounded body to be polite is
            the door holding itself open.
            """
            raw = self.headers.get("Content-Length")
            try:
                n = int(raw) if raw not in (None, "") else 0
            except ValueError:
                n = 0
            if 0 < n <= MAX_BODY:
                try:
                    self.rfile.read(n)
                except OSError:
                    pass

        def do_GET(self):
            parts = [p for p in self.path.split("?")[0].strip("/").split("/") if p]
            if parts == ["runs"]:
                return self._send(200, {"jobs": [{k: j.get(k) for k in
                                                  ("job_id", "state", "target")}
                                                 for j in q.listing(root)]})
            if len(parts) == 2 and parts[0] == "runs":
                return self._send(*status(root, parts[1]))
            if len(parts) == 3 and parts[0] == "runs" and parts[2] == "report":
                html, why = report(root, parts[1])
                if html is None:
                    # 409 when the job exists and is not done: the request is well formed and
                    # the answer is "not yet, and here is why", which a 404 would not say.
                    code = 404 if (why or "").startswith(("no report", "bad job")) else 409
                    return self._send(*_problem(code, why or "no report for that job yet"))
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
