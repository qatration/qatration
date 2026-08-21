"""The target must not be able to stop the measurement — no model, no network beyond localhost.

Everything else here asks whether the engine judges a target correctly. This asks whether the
engine is still running afterwards, which is a different property and was not held:

  * `r.read()` with no argument reads to EOF, so a bot answering with a gigabyte decided how
    much memory this process used. The same reply then went into `results_<target>.json` and was
    re-read and re-judged by every later artifact build, so one hostile answer taxed the
    pipeline permanently.

  * `McpAgentTarget._calc` ran `eval(re.sub(r"[^0-9+\\-*/(). ]", "", expr))`. That class admits
    `*` twice, and `9**9**8` — a well-formed arithmetic expression under it — did not finish in
    sixty seconds, measured. On this target the MODEL writes that string and the model is the
    thing under attack, so a successful injection could stop the engine measuring it.

AND THE FINDING HAS TO SURVIVE THE FIX, which is the harder half. The first version of the reply
cap truncated the body and handed the fragment to `json.loads`; truncated JSON does not parse,
so the probe came back empty and `unbounded_output` — the detector whose whole job is to notice
an oversized reply — stopped firing. A defence that deletes the evidence it was protecting is
worse than the exposure, so that is checked here explicitly rather than assumed.

    python test_survives_target.py     # exits 1 on any failure (CI gate)
"""
import json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    import targets_http
    from targets_http import HttpConfiguredTarget
    from oracle import DETECTORS

    # --- A REPLY LARGER THAN THE ENGINE WILL HOLD -------------------------------------------
    BIG = "a." * 200_000                       # 400,000 characters, and none of them repeat oddly
    real_max = targets_http.MAX_REPLY

    class Flood(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            b = json.dumps({"reply": BIG}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Flood)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        targets_http.MAX_REPLY = 50_000        # so the fixture stays small; the default is pinned below
        t = HttpConfiguredTarget(name="flood", url=f"http://127.0.0.1:{srv.server_address[1]}/c",
                                 request={"message": "{prompt}"}, response={"reply": "reply"})
        t0 = time.time()
        probe = t.send("hello")
        took = time.time() - t0
    finally:
        targets_http.MAX_REPLY = real_max
        srv.shutdown()

    check("a reply past the cap is held at the cap, not to EOF",
          len(probe.output) == 50_000, f"{len(probe.output):,} characters")
    # THE RAW BODY, envelope included. A truncated JSON document cannot be parsed, so the
    # `response.reply` path cannot be walked and there is no field to extract — but the bytes
    # that arrived are still the target's own output, and every content detector reads
    # `probe.output`. Handing them the whole body is strictly more than the reply would have
    # been, at the cost of a `{"reply": ` prefix; handing them nothing was the earlier
    # behaviour, and it is what made the finding disappear.
    check("...and the body is readable text, not an error and not empty",
          "a.a.a" in probe.output and not probe.error, repr(probe.output[:24]))
    # THE SIZE IS THE FINDING. Truncating without recording it would hide the one number the
    # detector below exists to report.
    check("...and the true size travels with the probe",
          getattr(probe, "reply_bytes", None) == len(json.dumps({"reply": BIG}).encode()),
          str(getattr(probe, "reply_bytes", None)))
    check("...and it did not take long enough to be a stall", took < 30, f"{took:.1f}s")

    # The half that the first version of this cap broke.
    check("unbounded_output still fires on the truncated body",
          bool(DETECTORS["unbounded_output"](probe, {"max_output_chars": 12000})))

    # THE SHIPPED DEFAULT, not the fixture's. A cap set below what the arsenal legitimately
    # produces would silently truncate real evidence: the longest reply in the shipped run is
    # about 45,000 characters, from an attack that asks a bot to generate until something stops
    # it, and that attack has to keep working.
    check("the shipped cap is far above the longest legitimate reply",
          real_max >= 500_000, f"MAX_REPLY={real_max:,}")

    # --- AND THE ORACLE HAS TO SURVIVE READING IT --------------------------------------------
    #
    # A cap on the reply is only half. Four patterns in `oracle.py` were written with `\b` in
    # front of a character class containing `.` or `_`, and inside a run like `a.a.a.a…` there
    # is a boundary at every other character — so the scan re-started at each one and ran to the
    # end of the text every time. Measured on 64,000 characters: 22.8s for one of them, 13.7s
    # for another, and it is quadratic, so the shipped one-megabyte cap would have been about an
    # hour and a half of judging FOR ONE PROBE. A sweep judges hundreds.
    #
    # The fix is a lookbehind over the whole class, so a run of any length is attempted once.
    # This is a stopwatch, not a style rule: it does not care how the patterns are written, only
    # that a hostile megabyte does not stop the run. The threshold is far above the 1.2 seconds
    # measured, because a CI runner is slower — and three orders of magnitude below the defect.
    # IN A SUBPROCESS WITH A DEADLINE, because a regular expression cannot be interrupted. The
    # first version timed the loop in-process, and when the quadratic form was replanted the
    # suite did not fail — it HUNG, past three minutes, and only the runner's 600s per-suite
    # deadline eventually said so. A check that can only report after the thing it is timing
    # finishes cannot report the case it exists for. A suite about surviving a hostile target
    # is a poor place to leave that.
    import subprocess
    SHAPES = {"dotted": f'"a." * ({real_max} // 2)',
              "one long word": f'"a" * {real_max}',
              "repeated words": f'"the quick brown fox " * ({real_max} // 20)'}
    for shape, expr in SHAPES.items():
        code = ("import sys; sys.path.insert(0, %r)\n"
                "from target import Probe\n"
                "from oracle import DETECTORS\n"
                "p = Probe(prompt='x', output=%s)\n"
                "print(','.join(d for d, fn in DETECTORS.items() "
                "if fn(p, {'max_output_chars': 12000})))\n" % (HERE, expr))
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                               timeout=60)
            elapsed, fired, timed_out = time.time() - t0, r.stdout.strip().split(","), False
        except subprocess.TimeoutExpired:
            elapsed, fired, timed_out = time.time() - t0, [], True
        check(f"a hostile reply at the cap is judged in seconds, not hours — {shape}",
              not timed_out, f"still judging {real_max:,} characters after {elapsed:.0f}s")
        check(f"...and the oversized reply is still reported — {shape}",
              "unbounded_output" in fired, "timed out" if timed_out else str(fired))

    # --- A TOOL A POISONED MODEL GETS TO CALL ------------------------------------------------
    import targets_mcpagent
    calc = targets_mcpagent.McpAgentTarget.__new__(targets_mcpagent.McpAgentTarget)

    check("the calculator still calculates", calc._calc("(1+2)*3") == "9", calc._calc("(1+2)*3"))
    check("...including division and unary minus",
          calc._calc("10 / 4") == "2.5" and calc._calc("-(3*4)+1") == "-11")
    check("...and refuses what is not arithmetic",
          calc._calc('__import__("os").system("x")') == "could not evaluate")

    # Two seconds is not a threshold, it is an assertion that nothing was computed. The old
    # implementation did not finish `9**9**8` in sixty.
    for tower in ("9**9**9**9", "9**9**8", "2**2**2**2**2**2"):
        t0 = time.time()
        got = calc._calc(tower)
        elapsed = time.time() - t0
        check(f"a power tower is refused rather than evaluated — {tower}",
              got == "could not evaluate" and elapsed < 2.0, f"{got!r} in {elapsed:.1f}s")

    check("a very long expression is refused before it is parsed",
          calc._calc("1+" * 5000 + "1") == "could not evaluate")

    # DERIVED, NOT LISTED. The point is not that this one function stopped calling `eval`; it is
    # that nothing in the engine calls it. A named exemption would be visible here; silence is
    # the answer that means something.
    import glob, re
    dynamic = []
    for p in sorted(glob.glob(os.path.join(HERE, "*.py"))
                    + glob.glob(os.path.join(os.path.dirname(HERE), "tools", "*.py"))):
        if os.path.basename(p).startswith("test_"):
            continue
        for i, line in enumerate(open(p, encoding="utf-8").read().splitlines(), 1):
            code = line.split("#")[0]
            if re.search(r"(?<![\w.])(eval|exec)\s*\(", code) or "shell=True" in code:
                dynamic.append(f"{os.path.basename(p)}:{i}")
    check("nothing in the engine evaluates a string as code", not dynamic, "; ".join(dynamic))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a target cannot stop the engine measuring it.")


if __name__ == "__main__":
    main()
