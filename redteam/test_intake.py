"""The door, attacked. No model, no GPU — a scripted bot and a scripted network.

An intake is the one component here that a stranger drives, so its tests are mostly about what
it REFUSES. The single worst thing this repo could ship is an SSRF proxy with an attack arsenal
attached: on a workstation `localhost` is the practice fleet and the authorization gate waives
it, and on a server `localhost` is that host itself and the same waiver hands an attacker its
metadata endpoint. That inversion is the first thing checked here, in both directions, because
a control that is only correct in one mode is a control shipped backwards half the time.

    python test_intake.py        # exits 1 on any failure (CI gate)
"""
import sys, os, re, json, shutil, tempfile, threading, importlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


class Bot(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        out = json.dumps({"reply": "Hello, how can I help with your order?"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Bot)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    root = tempfile.mkdtemp()
    old_env = os.environ.get("QATRATION_HOSTED")

    def body(**kw):
        cfg = {"adapter": "http", "name": "acme-bot",
               "url": f"http://127.0.0.1:{port}/chat",
               "request": {"message": "{prompt}"}, "response": {"reply": "reply"}}
        cfg.update(kw.pop("cfg", {}))
        return json.dumps({"config": cfg, **kw}).encode()

    try:
        os.environ.pop("QATRATION_HOSTED", None)
        import authorization
        importlib.reload(authorization)
        import intake
        importlib.reload(intake)

        # THE ACCEPT PATH, exercised against a scripted bot on loopback — which the real policy
        # refuses, correctly, since the door has no friendly mode. Injected exactly as
        # `authorization.check` takes a `fetch`, and the default is asserted to BE the real
        # function, because an injection point is otherwise a place a check goes quietly
        # missing.
        import inspect
        check("the network policy defaults to the real one, not to the injected stub",
              inspect.signature(intake.submit).parameters["policy"].default is None
              and "policy or authorization.unreachable_by_policy" in
              inspect.getsource(intake.submit))
        check("the worker trigger defaults to the real one too",
              inspect.signature(intake.submit).parameters["wake"].default is None
              and "wake or wake_worker" in inspect.getsource(intake.submit))
        allow_loopback = lambda u: None
        woke = []
        code, obj = intake.submit(root, body(), policy=allow_loopback,
                                  wake=lambda r: woke.append(r) or True)
        check("a reachable, authorised target is accepted", code == 202, f"{code} {obj}")
        # EVENT-DRIVEN, NOT POLLED. On a database that bills for the time it is awake, a cron
        # checking the queue every minute keeps it awake permanently and costs the same
        # whether three jobs arrive or three hundred: the bill is set by the polling
        # interval and has nothing to do with the work.
        check("...and accepting a job wakes a worker straight away", woke == [root], str(woke))
        job_id = obj.get("job_id")
        check("...and comes back with a job id", bool(job_id), str(obj))
        check("...and says what deliveries the config exposes",
              obj.get("deliveries") is not None, str(obj))

        # The submitted config survives: an assessment whose inputs are gone is not reproducible.
        import glob
        check("the submitted config is stored",
              bool(glob.glob(os.path.join(root, "configs", "acme-bot-*.yaml"))),
              str(os.listdir(root)))

        # A typo in a config key must not build a target that reads nothing — this project's
        # own defect class, reachable by a stranger, so the intake has to surface it rather
        # than queue a run that will come back with a clean bill. Checked here rather than in
        # the hosted phase because `onboard.check` runs the authorization gate itself — a
        # second door on purpose — and in hosted mode that refuses the loopback fixture first.
        code, obj = intake.submit(root, body(cfg={"respones": {"reply": "reply"}}),
                                  policy=allow_loopback, wake=lambda r: True)
        check("a misspelled config key is reported rather than queued",
              code in (400, 422) and "respones" in json.dumps(obj), f"{code} {obj}")

        code, obj = intake.status(root, job_id)
        check("a submitted job can be looked up", code == 200 and obj["state"] == "queued",
              f"{code} {obj}")
        check("...and offers no report while there is none", obj.get("report") is None)
        check("an unknown job is a 404, not an empty success",
              intake.status(root, "2026-01-01T0000-aaaaaa")[0] == 404)
        check("a job id shaped like a path is refused before any lookup",
              intake.status(root, "../../etc/passwd")[0] == 400)
        check("...and so is one at the report route",
              intake.report(root, "../../../secrets") is None)

        # --- HOSTED: the same target is now OUR machine and must be refused ---------------
        os.environ["QATRATION_HOSTED"] = "1"
        importlib.reload(authorization)
        importlib.reload(intake)
        code, obj = intake.submit(root, body())
        check("ON a service, that same loopback target is REFUSED", code == 422,
              f"{code} {obj}")
        check("...and the reason names the machine rather than the rule",
              "this machine" in json.dumps(obj) or "own machine" in json.dumps(obj),
              json.dumps(obj))

        for bad, why in (("http://169.254.169.254/latest/meta-data/", "metadata"),
                         ("http://10.1.2.3/api", "private"),
                         ("http://192.168.0.9/api", "private"),
                         ("http://db.internal/q", "internal"),
                         ("file:///etc/passwd", "host")):
            code, obj = intake.submit(root, body(cfg={"url": bad}))
            check(f"hosted: {bad} is refused", code in (400, 422), f"{code} {obj}")

        # An SSRF refusal must happen BEFORE the queue. A queue full of jobs that cannot
        # legally run is a queue that reads as demand, and each one still costs a worker a
        # claim and a release.
        n_jobs = len(__import__("jobqueue").listing(root))
        check("nothing refused ever reached the queue", n_jobs == 1, str(n_jobs))

        # --- the shapes a stranger sends -------------------------------------------------
        check("the door refuses loopback even with the hosted flag unset",
              intake.submit(root, body())[0] == 422)
        check("a body that is not JSON is a 400", intake.submit(root, b"not json")[0] == 400)
        check("an empty body is a 400", intake.submit(root, b"{}")[0] == 400)
        check("a config that is not a mapping is a 400",
              intake.submit(root, json.dumps({"config": "- just\n- a list"}).encode())[0] == 400)
        check("unparseable YAML is a 400, with the reason",
              intake.submit(root, json.dumps({"config": "a: [1,\n"}).encode())[0] == 400)

        # ONLY adapter: http. Every other adapter runs code that lives in this repo, so
        # accepting one would be arbitrary local execution wearing a target's clothes.
        for adapter in ("dvla", "mcpagent", "foreign", None):
            code, obj = intake.submit(root, body(cfg={"adapter": adapter}),
                                      policy=allow_loopback, wake=lambda r: True)
            check(f"adapter {adapter!r} is refused", code == 400, f"{code} {obj}")

        # The name becomes a filename.
        code, obj = intake.submit(root, body(cfg={"name": "../../etc/passwd",
                                                  "url": "https://api.acme.example/c"}))
        check("a name that is a path is refused", code == 400, f"{code} {obj}")

        # --- and the service refuses to START in the dangerous configuration --------------
        src = open(os.path.join(HERE, "intake.py"), encoding="utf-8").read()
        check("the intake refuses to start without the hosted flag",
              "if not authorization.hosted():" in src and "sys.exit(" in src)
        check("...and without an authorization secret",
              "QATRATION_AUTH_SECRET" in src)
        # Two properties, and the second one is why this check exists in this shape. The path
        # must be built from the validated job id and nothing the caller sent — and the
        # FILENAME must be the one the report writer actually produces. Asserting only the
        # string let the route point at `defense_report_free.html` for as long as it took
        # somebody to notice that nothing had written that name since the rename: a 404 no
        # test could see, because the test was checking that the wrong name was spelled right.
        dr_src = open(os.path.join(HERE, "defense_report.py"), encoding="utf-8").read()
        written = re.search('OUT_DIR / "(defense_report[^"]*[.]html)"', dr_src)
        check("the report writer has one output name", written is not None)
        check("the report route reads a path built from the job id alone",
              'os.path.join(str(root), "runs", job_id,' in src)
        check("...and serves the file the report writer actually writes",
              written and ('"%s"' % written.group(1)) in src,
              written.group(1) if written else "no match")
        check("responses carry a content-type-options header, since one of them is HTML",
              "X-Content-Type-Options" in src)
        # Nothing in the service asks the queue on a timer. A cost property, not a style
        # one: with scale-to-zero billing a scheduled check IS the bill.
        for mod in ("intake.py", "worker.py", "jobqueue.py"):
            src2 = open(os.path.join(HERE, mod), encoding="utf-8").read()
            check(f"{mod} does not poll on a timer", "time.sleep" not in src2, mod)
        check("the worker is started detached, so a submission returns while the run continues",
              "Popen(" in src and ("start_new_session" in src or "DETACHED_PROCESS" in src))
    finally:
        srv.shutdown()
        if old_env is None:
            os.environ.pop("QATRATION_HOSTED", None)
        else:
            os.environ["QATRATION_HOSTED"] = old_env
        shutil.rmtree(root, ignore_errors=True)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the door refuses what it must, and says why.")


if __name__ == "__main__":
    main()
