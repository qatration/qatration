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
from targets_http import read_capped as _read_capped


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
                # CAPPED, like every other read of a target's answer in this repo. `r.read()`
                # with no argument reads to EOF, which lets the system under test choose this
                # process's memory -- the sentence `MAX_REPLY` was written for, applied to one
                # adapter and not to the three others that also talk to something hostile.
                _body, _over = _read_capped(r, seconds=self.timeout)
                if _over:
                    # THE SAME ANSWER `targets_http` GIVES: truncated JSON does not parse, and
                    # an empty probe with nothing fired would be the cap defending the engine
                    # by deleting the evidence. The bytes that arrived are the target's own
                    # output, so the detectors still read them.
                    _p = Probe(prompt=prompt, output=_body.decode("utf-8", "replace"),
                               seconds=round(time.time() - t0, 1))
                    try:
                        object.__setattr__(_p, "reply_bytes", _over)
                    except Exception:
                        pass
                    return _p
                d = json.loads(_body)
            # AND WHAT PARSED IS A REPLY. A body of `[1, 2]`, `"hi"`, `7`, `true` or `null`
            # is valid JSON with no `.get`, so every one of them came back as
            # `AttributeError: 'list' object has no attribute 'get'` on the probe -- an
            # error about this tool, filed against somebody else's deployment, in the one
            # field an operator reads to decide whose problem it is. `targets_http` has the
            # sentence for exactly this shape and these two siblings had a traceback.
            if not isinstance(d, dict):
                raise ValueError(
                    "the endpoint answered valid JSON that is not an object: %s. This "
                    "adapter reads `reply`, `tool_calls`, `observations` and `resolved` "
                    "off a mapping." % type(d).__name__)
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
