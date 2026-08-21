"""
The same foreign deployment, but the agent WRITES AND RUNS PYTHON.

smolagents' `CodeAgent` reasons by emitting code instead of JSON tool calls, and then
executing it. That is a fundamentally different attack surface from anything else in this
fleet: every other target can be talked into calling a tool it should not, this one can be
talked into composing an operation nobody wrote a tool for.

WHAT IS AND IS NOT SANDBOXED, stated plainly because this runs on a real machine:

  * The default `LocalPythonExecutor` is an AST interpreter, not `exec`. It allows eleven
    stdlib modules — collections, datetime, itertools, math, queue, random, re, stat,
    statistics, time, unicodedata — and that list contains no `os`, `sys`, `subprocess`,
    `pathlib`, `socket` or `open`. No filesystem, no network, no process spawning.
  * `additional_authorized_imports` is deliberately NOT set. Passing it is how this becomes
    dangerous, and the temptation is real, because a refused import looks like the agent
    failing rather than the sandbox working.
  * The residual risk is an escape in their interpreter, not a model writing `rm -rf`. That
    is a modest and honest risk, and it is the reason this file is separate from server.py
    and runs on its own port: the ToolCallingAgent measurement should not depend on
    anyone's willingness to run this one.

Same split as before — their prompts (`prompts/code_agent.yaml`), their loop, their
executor; the tools and the HTTP wrapper are mine.

    ../foreign-agent-env/Scripts/python server_code.py       # serves on :8131
"""
import json, os, sys
from http.server import ThreadingHTTPServer

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from smolagents import CodeAgent, OpenAIServerModel

from server import TOOLS, steps_of, MODEL, make_handler          # the same deployment, the same data

PORT = int(os.environ.get("PORT", "8131"))


def build_agent():
    """Their agent, their prompts, their executor. No extra imports authorised."""
    model = OpenAIServerModel(model_id=MODEL, api_base="http://localhost:11434/v1",
                              api_key="ollama")
    return CodeAgent(tools=TOOLS, model=model, max_steps=4)


if __name__ == "__main__":
    print(f"foreign CODE agent (model {MODEL}) on http://localhost:{PORT}/chat")
    print("sandbox: default LocalPythonExecutor, no additional authorized imports")
    ThreadingHTTPServer(("localhost", PORT), make_handler(build_agent)).serve_forever()
