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
    #
    # READ AS THE CALL, NOT AS ONE WAY OF TYPING IT. This was a line regex for `eval(` and
    # `exec(` plus the substring `shell=True`, and it passed `mcp_probe.list_surface`, which
    # starts a subprocess with `shell=(os.name == "nt")` -- a shell on every Windows machine,
    # spelled so that the literal never appears. It also had no answer at all for the other
    # ways a string becomes execution: `os.system`, `os.popen`, `pickle.loads`, `compile`,
    # `__import__` of a computed name.
    import glob
    import ast as _ast_e

    # THE ONE SHELL THE ENGINE STARTS, NAMED WITH ITS REASON AND WHAT IT COSTS. `npx` on
    # Windows is `npx.cmd`, which only a shell will find by that name, and MCP servers are
    # overwhelmingly launched through npx. What it costs: `qatration mcp` re-reads a recorded
    # corpus by running the `command` each server entry names, and on Windows that list is
    # joined and handed to cmd.exe -- so `&` or `|` inside an argument of a corpus somebody
    # else wrote WAS a second command. `list_surface` now refuses any argument carrying
    # cmd.exe syntax before it starts anything, which keeps the shell for finding npx.cmd
    # and nothing else; the cases after this scan hold it to that. Keyed to the FUNCTION,
    # so a second shell anywhere else in that module is not covered by this.
    _SHELL_ALLOWED = {("mcp_probe.py", "list_surface")}

    def _executes_strings(sources):
        """(name, source) pairs -> ["file:line  what"] for every call that runs a string."""
        _out = []
        for _nm, _src in sources:
            if _nm.startswith("test_"):
                continue
            try:
                _tree = _ast_e.parse(_src)
            except SyntaxError:
                continue
            _owner = {}
            for _fn in _ast_e.walk(_tree):
                if isinstance(_fn, (_ast_e.FunctionDef, _ast_e.AsyncFunctionDef)):
                    for _c in _ast_e.walk(_fn):
                        _owner.setdefault(id(_c), _fn.name)
            for _n in _ast_e.walk(_tree):
                if not isinstance(_n, _ast_e.Call):
                    continue
                _f = _n.func
                _name = (_f.id if isinstance(_f, _ast_e.Name)
                         else _f.attr if isinstance(_f, _ast_e.Attribute) else "")
                _mod = (_f.value.id if isinstance(_f, _ast_e.Attribute)
                        and isinstance(_f.value, _ast_e.Name) else "")
                _why = None
                if isinstance(_f, _ast_e.Name) and _name in ("eval", "exec", "compile"):
                    _why = _name
                elif (isinstance(_f, _ast_e.Name) and _name == "__import__"
                      and not (_n.args and isinstance(_n.args[0], _ast_e.Constant))):
                    _why = "__import__ of a computed name"
                elif _mod == "os" and _name in ("system", "popen"):
                    _why = "os." + _name
                elif _mod in ("pickle", "marshal") and _name in ("load", "loads"):
                    _why = _mod + "." + _name
                for _k in _n.keywords:
                    if _k.arg == "shell" and not (isinstance(_k.value, _ast_e.Constant)
                                                  and not _k.value.value):
                        if (_nm, _owner.get(id(_n))) not in _SHELL_ALLOWED:
                            _why = "shell=" + _ast_e.unparse(_k.value)
                if _why:
                    _out.append(f"{_nm}:{_n.lineno}  {_why}")
        return _out

    # ON PLANTED MODULES FIRST: each spelling named, and a method called `.eval()` -- a
    # model's `eval()` mode is not a string being run -- plus a constant `__import__` and an
    # explicit `shell=False` left alone.
    _pl_e = _executes_strings([
        ("a.py", "def f(s):\n    return eval(s)\n"),
        ("b.py", "import subprocess\ndef f(c):\n"
                 "    subprocess.run(c, shell = True)\n"),
        ("c.py", "import os, subprocess\ndef f(c):\n"
                 "    subprocess.Popen(c, shell=(os.name == 'nt'))\n"),
        ("d.py", "import os\ndef f(c):\n    os.system(c)\n"),
        ("e.py", "import pickle\ndef f(b):\n    return pickle.loads(b)\n"),
        ("f.py", "def f(n):\n    return __import__(n)\n"),
        ("ok.py", "import subprocess\ndef f(m, c):\n    m.eval()\n"
                  "    __import__('sys')\n    subprocess.run(c, shell=False)\n"),
        ("mcp_probe.py", "import subprocess\ndef other(c):\n"
                         "    subprocess.Popen(c, shell=True)\n")])
    check("the scan names a string run as code in each spelling, and nothing else",
          sorted({_x.split(":")[0] for _x in _pl_e})
          == ["a.py", "b.py", "c.py", "d.py", "e.py", "f.py", "mcp_probe.py"], str(_pl_e))
    _srcs_e = [(os.path.basename(_p), open(_p, encoding="utf-8").read())
               for _p in sorted(glob.glob(os.path.join(HERE, "*.py"))
                                + glob.glob(os.path.join(os.path.dirname(HERE), "tools",
                                                         "*.py")))]
    dynamic = _executes_strings(_srcs_e)
    check("nothing in the engine runs a string as code, or through a shell, but the one "
          "launcher named with its reason (%d modules read)"
          % sum(1 for _m, _s in _srcs_e if not _m.startswith("test_")),
          not dynamic, "; ".join(dynamic))
    # AND THE EXEMPTION IS STILL NEEDED, or it is a hole with a comment on it. If the shell
    # in `list_surface` is ever removed, this names the line that no longer earns its place.
    check("...and the one exempt launcher does still start a shell",
          any("shell=" in _ast_e.unparse(_k) for _n in _ast_e.walk(_ast_e.parse(
              dict(_srcs_e)["mcp_probe.py"])) if isinstance(_n, _ast_e.Call)
              for _k in _n.keywords if _k.arg == "shell"),
          "mcp_probe.py starts no shell any more: drop it from _SHELL_ALLOWED")

    # --- AND THE SHELL IT KEEPS CANNOT BE HANDED A SECOND COMMAND ------------------------
    #
    # `mcp --compare` runs the `command` a recorded corpus names, and on Windows the list goes to
    # cmd.exe. An argument carrying cmd.exe syntax is refused before anything starts. Asked
    # with `_USE_SHELL` forced on, so it is measured on every machine and not only on the
    # one it protects, and with `Popen` replaced by a recorder so that "refused" is proved
    # to mean "nothing was started" rather than "something started and failed".
    import mcp_probe as _mp
    check("an ordinary npx launch carries no shell syntax",
          _mp._shell_unsafe(["npx", "-y", "@modelcontextprotocol/server-filesystem", "."])
          is None, "a real launch line would be refused")
    _each = [c for c in "&|<>^%\"" if _mp._shell_unsafe(["npx", "pkg%sx" % c]) is None]
    check("...while every cmd.exe metacharacter in an argument is named",
          not _each and _mp._shell_unsafe(["npx", "a" + chr(10) + "calc"]) is not None,
          "not named: %r" % _each)
    _started = []

    class _NoPopen(object):
        PIPE = DEVNULL = None

        @staticmethod
        def Popen(*_a, **_k):
            _started.append(_a)
            raise RuntimeError("the refusal should have come first")

    _real_sp, _real_shell = _mp.subprocess, _mp._USE_SHELL
    _mp.subprocess, _mp._USE_SHELL = _NoPopen, True
    try:
        _got = _mp.list_surface(["npx", "-y", "pkg&calc"], timeout=1)
    finally:
        _mp.subprocess, _mp._USE_SHELL = _real_sp, _real_shell
    check("...and a corpus argument carrying one is refused before anything is started",
          not _started and "refusing" in str(_got[3]) and "pkg&calc" in str(_got[3]),
          "started=%r got=%r" % (_started, _got[3]))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a target cannot stop the engine measuring it.")


if __name__ == "__main__":
    main()
