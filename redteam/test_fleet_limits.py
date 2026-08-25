"""Every practice server caps its own generation — no model, no network.

`redteam/llm.py` sets two limits for every adapter and says why in its own docstring:

    "Both are set here rather than in nine adapters, because a limit that has to be
     remembered nine times is a limit that will be missing from the tenth."

The practice servers ARE the tenth. Seven of them talk to a model without going through
`llm.py` at all — they are standalone processes, stdlib or framework, started by
`tools/fleet.sh` — and five were missing both limits.

WHAT IT COST, MEASURED. The two attacks that ask a bot to generate until something stops it ran
to the engine's 180-second watchdog on every trial and every retry: six times 180 seconds for
ONE attack, scored ERROR, the verdict that carries no information. A full sweep against that bot
was on course for about thirty-six hours. With the caps: 7 to 14 seconds and a judgeable reply.

The watchdog is not a substitute, which is the part that is easy to get wrong.
`runner._invoke_with_timeout` abandons the thread and moves on — it does not cancel the call, the
socket stays open, and the model keeps decoding with the next probe queued behind a request
nobody is reading. Only a request-level timeout makes the SERVER stop.

    python test_fleet_limits.py     # exits 1 on any failure (CI gate)
"""
import glob
import io
import os
import re
import socket
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# HOW EACH FAMILY SPELLS THE SAME TWO LIMITS. A server is checked against the spelling its own
# client uses, because "contains the string num_predict" would pass a smolagents server that
# cannot use it and fail a NeMo config that spells it `max_tokens`.
CAP = re.compile(r"num_predict|max_tokens")
TIMEOUT = re.compile(r"REQUEST_TIMEOUT|client_kwargs\s*=\s*\{[^}]*timeout|timeout\s*=\s*\d+")

# A file that talks to a model without importing the engine. Discovered rather than listed: a
# list covers the servers somebody remembered, and the whole point of this suite is the one
# nobody did.
TALKS_TO_A_MODEL = re.compile(
    r"11434|ChatOllama|OpenAIServerModel|api/chat|api/generate|/v1/chat/completions")


def _code_only(text, path):
    """The file with its comments and docstrings removed, so a pattern reads code.

    Python goes through `ast`: comments vanish in the parse, and a module or function docstring
    is an expression statement that is dropped here explicitly — `llm.py`'s reasoning quotes
    both limit names, and so does every server that has them. YAML is line-based, so `#` to
    end-of-line is enough, and a `#` inside a quoted value is not a shape this repository's
    configs use.
    """
    if path.endswith(".yml") or path.endswith(".yaml"):
        return "\n".join(line.split("#")[0] for line in text.splitlines())
    import ast
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return "\n".join(line.split("#")[0] for line in text.splitlines())
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):
            body.pop(0)                       # the docstring, which explains the very thing
    return ast.unparse(tree)


def _free_port():
    """A port nobody is using, asked of the operating system rather than picked.

    A constant here would collide with whatever the developer has running, and
    the failure would look like the launcher rather than like the test."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- the engine's own limits still exist ------------------------------------------------
    import llm
    from runner import SEND_TIMEOUT
    check("llm.py caps output for every adapter that goes through it",
          isinstance(llm.NUM_PREDICT, int) and 0 < llm.NUM_PREDICT <= 4096,
          f"NUM_PREDICT={getattr(llm, 'NUM_PREDICT', None)}")
    check("...and closes the socket, which the engine's watchdog cannot",
          isinstance(llm.REQUEST_TIMEOUT, int) and 0 < llm.REQUEST_TIMEOUT <= 600,
          f"REQUEST_TIMEOUT={getattr(llm, 'REQUEST_TIMEOUT', None)}")

    # --- and so does every standalone server -----------------------------------------------
    servers, uncapped, untimed = [], [], []
    for pattern in ("*/server*.py", "*/*/server*.py", "*/*/config*/config.yml"):
        for path in sorted(glob.glob(os.path.join(ROOT, pattern))):
            rel = os.path.relpath(path, ROOT).replace("\\", "/")
            if rel.startswith(("redteam/", "site/", "build/")):
                continue
            raw = io.open(path, encoding="utf-8", errors="replace").read()
            # COMMENTS STRIPPED FIRST, and this is not tidiness. The first version searched the
            # whole file, and every one of these servers explains its cap in a comment that
            # names it — so deleting the actual parameter left the word behind and the gate
            # stayed green. Replanted four times, in three spellings, and caught none of them:
            # a check reading prose instead of code, in a suite about checks that cannot fire.
            src = _code_only(raw, path)
            if not TALKS_TO_A_MODEL.search(src):
                continue
            if "make_llm" in src:
                continue                      # goes through llm.py, which already caps it
            servers.append(rel)

            if rel.endswith((".yml", ".yaml")):
                # PER MODEL, not per file. A config declaring three models passed with a cap on
                # one of them, because the pattern found the word somewhere. The self-check
                # rails are models too, and an uncapped judge is the same runaway as an
                # uncapped bot.
                import yaml as _yaml
                cfg = _yaml.safe_load(raw) or {}
                for m in cfg.get("models") or []:
                    if not (m.get("parameters") or {}).get("max_tokens"):
                        uncapped.append(f"{rel} [{m.get('type')}]")
                # A YAML model config has no socket of its own; the client the framework builds
                # owns that. The cap is the part it can state.
                continue

            if not CAP.search(src):
                uncapped.append(rel)

            # NOT MERELY PRESENT — BELOW THE ENGINE'S OWN WATCHDOG. A server whose request
            # timeout is at or above `runner.SEND_TIMEOUT` closes its socket only after the
            # sweep has already abandoned the thread, which is the exact state the timeout
            # exists to prevent: the model still decoding, the next probe queued behind it.
            # Caught by replanting `timeout=180` and watching a check for "has a timeout" pass.
            # THROUGH THE CONSTANT, because a good server names its limit rather than typing a
            # number at the call. `timeout=REQUEST_TIMEOUT` matched no digit pattern, so the two
            # servers that do it properly were the two this reported as having no timeout at all.
            consts = {m.group(1): int(m.group(2))
                      for m in re.finditer(r"^([A-Z_]+)\s*=\s*(\d+)", src, re.M)}
            found = [int(n) for n in re.findall(r"timeout[\"']?\s*[:=]\s*(\d+)", src)]
            found += [consts[n] for n in re.findall(r"timeout[\"']?\s*[:=]\s*([A-Z_]+)", src)
                      if n in consts]
            if not found:
                untimed.append(f"{rel}: no request timeout")
            elif max(found) >= SEND_TIMEOUT:
                untimed.append(f"{rel}: timeout {max(found)}s is not below the engine's "
                               f"{SEND_TIMEOUT}s watchdog")

    check("the walk found the standalone servers at all", len(servers) >= 5,
          f"found {len(servers)}: {servers}")
    check("every standalone practice server caps its own generation",
          not uncapped, f"no num_predict / max_tokens in: {uncapped}")
    check("...and gives the request a timeout, so the SERVER stops and not just the sweep",
          not untimed, f"no request timeout in: {untimed}")

    print(f"      checked: {', '.join(servers)}")

    # --- AND THE LAUNCHER CAN ACTUALLY START ONE --------------------------------------------
    #
    # `up` refused to start anything, on every platform and every fresh clone, and said
    # NO PYTHON eight times while `require_python` in the same file and the same run reported
    # the same interpreter as usable. The test was `[ -x "$py" ] || [ -f "$py" ]`, and `$py`
    # defaults to a PATH COMMAND -- `python` or `python3` -- deliberately: the comment beside
    # that default says the honest one is the interpreter already on the path. A file test on a
    # command name is false, so the default this file chooses was the one it refused.
    #
    # Nothing caught it because CI runs `fleet.sh status`, which only asks `require_python`.
    # `AUTHORISED-USE.md` sends a newcomer to the practice fleet as the alternative to pointing
    # this tool at a system they do not own, so the unstartable path was the sanctioned one.
    #
    # EXECUTED, with a real interpreter named the way a real default names it, a real server and
    # a real port. A doctored copy of the launcher, so the fleet on this machine is untouched.
    import shutil as _sh
    import signal as _sig
    import subprocess as _sp
    import tempfile as _tf

    name = None
    for candidate in ("python3", "python"):
        if _sh.which(candidate) and _sp.run([candidate, "-c", "pass"],
                                            capture_output=True).returncode == 0:
            name = candidate
            break
    have_bash = bool(_sh.which("bash"))
    if not name or not have_bash:
        # Never silence. A platform that cannot run this says so rather than passing.
        print("SKIP  the launcher, end to end: no %s here, so it was NOT checked"
              % ("bash" if name else "interpreter on PATH by name"))
    else:
        with _tf.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "tools"))
            os.makedirs(os.path.join(d, "mybot"))
            os.makedirs(os.path.join(d, "out"))
            _sh.copy(os.path.join(ROOT, "tools", "fleet_procs.py"),
                     os.path.join(d, "tools", "fleet_procs.py"))
            src = io.open(os.path.join(ROOT, "tools", "fleet.sh"), encoding="utf-8").read()
            head = src.index("FLEET=(")
            tail = src.index("\n)\n", head) + len("\n)\n")
            port = _free_port()
            src = (src[:head]
                   + 'FLEET=(\n  "%d|$HERE/mybot|$MAIN|server.py|%d"\n)\n' % (port, port)
                   + src[tail:])
            io.open(os.path.join(d, "tools", "fleet.sh"), "w", encoding="utf-8",
                    newline="\n").write(src)
            io.open(os.path.join(d, "mybot", "server.py"), "w", encoding="utf-8",
                    newline="\n").write(
                "import os, socket, sys, time\n"
                "s = socket.socket()\n"
                "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                "s.bind(('127.0.0.1', int(sys.argv[1])))\n"
                "s.listen(5)\n"
                "open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pid'), 'w')"
                ".write(str(os.getpid()))\n"
                # A backstop, so a failed assertion never leaves a process behind.
                "time.sleep(30)\n")

            env = dict(os.environ, QATRATION_PYTHON=name)
            r = _sp.run(["bash", os.path.join(d, "tools", "fleet.sh"), "up"],
                        capture_output=True, text=True, env=env, timeout=120)
            said = r.stdout + r.stderr
            check("the launcher accepts an interpreter named the way its own default names it",
                  "NO PYTHON" not in said, said.strip()[:200])
            check("...and says it is starting the server", "starting" in said,
                  said.strip()[:200])

            opened = False
            for _ in range(60):
                with socket.socket() as probe:
                    probe.settimeout(0.4)
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        opened = True
                        break
                time.sleep(0.25)
            check("...and the port really opens, so this is a start and not a message", opened,
                  f"nothing answered on {port} within 15s")

            pidfile = os.path.join(d, "mybot", "pid")
            if os.path.isfile(pidfile):
                try:
                    os.kill(int(io.open(pidfile).read().strip()), _sig.SIGTERM)
                except Exception:
                    pass

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — no practice bot can be talked into generating forever.")


if __name__ == "__main__":
    main()
