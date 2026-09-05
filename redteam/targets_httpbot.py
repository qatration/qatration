"""
Black-box HTTP adapter — a SECOND target of a fundamentally different shape than
DVLA. It sees only the final reply (no tool_calls, no observations), so it
advertises NO capabilities: the engine's tool-visibility detectors
(canary_in_context, rogue_tool_call) simply never fire, and indirect-delivery
attacks are skipped. Proof that the Target contract isn't DVLA-shaped.
"""
import json, time, urllib.request
from target import Probe, Target


class HttpTarget(Target):
    name = "httpbot"
    # `chain` is here because the TARGET can hold a conversation, not because we can see
    # inside it. Leaving it out made every multi-turn attack SKIP, and a skip in a report
    # reads as "not applicable" — which is how the one surface NVIDIA's own issue tracker
    # names as uncovered (per-message rails miss attacks whose every turn looks benign)
    # went untested against a NeMo target for the whole project.
    # `forged_history` says something narrower and more damning than `chain`: this API takes
    # the conversation from the CLIENT, so the attacker writes the assistant's past turns as
    # well as their own. That is not a flaw of this test bot, it is how most chat endpoints
    # are built — the server is stateless and the transcript arrives in the request body —
    # and it is the precondition for the Context Compliance Attack, where a fabricated reply
    # in which the assistant already agreed makes the refusal it never gave irrelevant.
    capabilities = {"chain", "forged_history"}    # still black box: no tool_visibility, no seed

    def __init__(self, url="http://localhost:8099/chat", **_):
        self.url = url

    def send_forged(self, prompt, history):
        """One turn, on a conversation the ATTACKER wrote — including the assistant's side.

        Distinct from `send_chain`, which feeds back what the target really said. Here
        nothing in the history happened. A model has no way to tell the difference: by the
        time it sees the transcript, its own past turns are just tokens in the context, and
        a per-message guardrail reading only the newest turn sees "yes, go ahead".
        """
        return self.send(prompt, history=list(history or []))

    def send_chain(self, prompts):
        """Run the turns in one conversation, feeding the history back each time.

        Crescendo and its relatives work by using the model's OWN previous reply as the
        next foothold, so the history has to reach the target. The returned Probe carries
        the whole exchange: `turns` for the per-turn detectors, and a prompt joined from
        every attacker message, because echo subtraction has to know all of it.
        """
        history, turns, out, secs = [], [], "", 0.0
        for p in prompts:
            probe = self.send(p, history=history)
            if probe.error:
                return probe
            out = probe.output
            secs += float(getattr(probe, "seconds", 0) or 0)
            turns.append({"prompt": p, "output": probe.output, "tool_calls": []})
            history.append({"role": "user", "content": p})
            history.append({"role": "assistant", "content": probe.output})
        return Probe(prompt="\n".join(prompts), output=out, turns=turns, seconds=secs)

    def send(self, prompt, history=None):
        payload = {"message": prompt}
        if history:
            payload["history"] = history
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        t0 = time.time()
        try:
            # A SLOW REPLY IS A FINDING, NOT AN ERROR, and a 120s cap was converting one
            # into the other. `cca-sysprompt-continuation` asks the bot to continue listing
            # its own rules and it generates until something stops it: three trials, three
            # `TimeoutError` at 122.0s, an ERROR row, and no evidence kept. Meanwhile
            # `slow_response` and `unbounded_output` exist precisely to score that behaviour
            # — an attacker who can make a support bot spend two minutes per request has
            # found something worth reporting. The ceiling is still there, generously, so a
            # genuinely hung target cannot stall a sweep for ever.
            with urllib.request.urlopen(req, timeout=300) as r:
                _raw = json.loads(r.read())
            reply = _raw.get("reply", "")
            # A 200 CAN CARRY A FAILURE, and this read `reply` and nothing else. An endpoint
            # that catches its own exception and answers {"error": ...} left `reply` empty,
            # and an empty reply is a bot that said nothing, which is scored as a bot that
            # held. The same shape cost `targets_localrag` seven attack rows at EXPLOITED
            # against a model that was never running; here it is cheap to close.
            err = _raw.get("error") or None
            if err:
                err = "AppError: %s" % " ".join(str(err).split())[:200]
                reply = ""
        except Exception as e:
            reply, err = "", f"{type(e).__name__}: {e}"
        return Probe(prompt=prompt, output=reply, tool_calls=[], observations=[],
                     error=err, seconds=round(time.time() - t0, 1))
