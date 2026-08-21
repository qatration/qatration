"""
Adapter for a target nobody here designed: a support agent built on smolagents.

Every measurement in this repo so far ran against bots written here, so the target
and the thing shooting at it. That is fine for proving a detector is not dead and useless
for proving it is honest — a check that only works because it was tuned to our own adapters
would look perfect on our own adapters. This is the control.

The agent's system prompt, reasoning loop, tool-call protocol, output parsing and memory
are the framework's, untouched (`foreign-agent/server.py` supplies only tools
and an HTTP wrapper, the way any deployment does). It runs in its own venv and answers over
HTTP, which is also the shape of a real deployment rather than an import.

Grey box, not black: the framework records its own steps, and a customer running it can
hand that log over. So the tool surface is visible when the server exposes it and the
adapter degrades to output-only when it does not.
"""
import json, time, urllib.request
from target import Probe, Target


class ForeignAgentTarget(Target):
    name = "foreign"
    # No `seed`: nothing here lets a tester plant content in the agent's retrieval path,
    # which is the honest state — indirect-delivery attacks will be SKIPped rather than
    # scored, and a skip is not a defence.
    capabilities = {"tool_visibility"}

    def __init__(self, url="http://localhost:8130/chat", timeout=180, **_):
        self.url = url
        self.timeout = timeout

    def send(self, prompt):
        body = json.dumps({"message": prompt}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        t0 = time.time()
        calls, obs, res, reply, err = [], [], [], "", None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                d = json.loads(r.read())
            reply = d.get("reply") or ""
            # tuples, because the oracle unpacks `for name, arg in probe.tool_calls`
            calls = [(str(c[0]), str(c[1])) for c in (d.get("tool_calls") or []) if c]
            obs = [str(o) for o in (d.get("observations") or [])]
            # What the tools actually received, when the deployment reports it. On a code
            # agent this is the only way the oracle can see what crossed the boundary: the
            # step log holds a variable name, this holds its value.
            res = [(str(c[0]), str(c[1])) for c in (d.get("resolved") or []) if c]
            err = d.get("error")
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        return Probe(prompt=prompt, output=reply, tool_calls=calls, observations=obs,
                     resolved=res, error=err, seconds=round(time.time() - t0, 1))
