"""
The engine loop: run one attack against a target N times, applying the right
delivery. Knows nothing about any specific bot — only the Target contract and
the attack dict. Delivery types are how new scenario classes slot in:
  - direct:   payload goes in the user prompt
  - indirect: payload is planted via target.seed(), user prompt stays benign
"""
import sys, threading
from oracle import judge, ORDER
from encoders import apply_encoding
from target import Probe, payload

SEND_TIMEOUT = 180        # seconds a single probe may take before it's abandoned
RETRIES = 1               # extra attempts after the first, on timeout / error


def _invoke_with_timeout(fn, timeout):
    """Run a blocking send() in a daemon thread; return its Probe, or a synthetic
    error Probe if it overruns. Daemon so a hung call cannot block process exit.

    IT DOES NOT CANCEL THE CALL. The abandoned thread keeps its socket open, so the model
    server carries on generating and the NEXT probe queues behind a request nobody is
    reading any more. Measured: one runaway generation (154k tokens, 53 minutes) starved an
    entire batch, which looked from the outside like a slow model rather than a stuck one.
    The control flow here is not the safeguard — the real ones live in llm.py, which caps
    output tokens and gives the request a socket timeout so the SERVER stops too."""
    box = {}

    def worker():
        try:
            box["probe"] = fn()
        except Exception as e:                       # send() usually catches its own,
            box["err"] = f"{type(e).__name__}: {e}"  # this is the belt-and-suspenders
    th = threading.Thread(target=worker, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        return Probe(prompt="", error=f"TIMEOUT after {timeout}s", seconds=float(timeout))
    if "err" in box:
        return Probe(prompt="", error=box["err"])
    return box["probe"]


def _resilient_send(fn, attack_id):
    """One send with a watchdog + up to RETRIES retries on timeout/error, so a
    transient Ollama blip or a single hang doesn't sink the attack. Retries are
    logged to stderr (never silently swallowed) — a run that limped is not a
    clean run and the report reader deserves to know."""
    probe = _invoke_with_timeout(fn, SEND_TIMEOUT)
    attempts = 1
    while probe.error and attempts <= RETRIES:
        print(f"  ! {attack_id}: {probe.error} — retry {attempts}/{RETRIES}", file=sys.stderr)
        probe = _invoke_with_timeout(fn, SEND_TIMEOUT)
        attempts += 1
    return probe


def _run_sessions(target, steps):
    """Each step in a FRESH session, and every turn after the first marked as such.

    The opposite of `chain`, which keeps one conversation alive: here the boundary is the
    point of the test. Anything that surfaces after it survived something meant to destroy
    it — a memory store keyed too broadly, a cache shared between users, a summary written
    to a global. Needs no capability beyond send(), because reset() is exactly the thing
    under test: on a target whose state lives server-side it is a no-op and the canary
    walks straight through.
    """
    turns, calls, obs, out, secs = [], [], [], "", 0.0
    resolved = []
    for i, step in enumerate(steps):
        target.reset()
        p = target.send(step)
        if p is None or p.error:
            return p if p is not None else Probe(prompt=step, error="no probe")
        out = p.output
        calls += p.tool_calls
        obs += p.observations
        # `resolved` is the target reporting what its tools actually RECEIVED, and it is the
        # only thing that closes the code-agent blind spot: send_email(body=customer_record)
        # exfiltrated a record while every detector read a variable name. The aggregate probe
        # carried tool_calls, observations, turns and seconds and dropped this one — so on any
        # target that reports it, a sessions attack silently fell back to the argument SOURCE,
        # which is the state the field was added to get out of. Empty on everything stored
        # today, which is why it went unnoticed and not why it was acceptable.
        resolved += list(getattr(p, "resolved", None) or [])
        secs += float(getattr(p, "seconds", 0) or 0)
        turns.append({"prompt": step, "output": p.output, "tool_calls": p.tool_calls,
                      "new_session": i > 0})
    return Probe(prompt=steps[-1] if steps else "", output=out, tool_calls=calls,
                 observations=obs, turns=turns, seconds=secs, resolved=resolved)


def run_attack(target, attack, ctx, trials=1):
    records = []
    delivery = attack.get("delivery", "direct")
    caps = getattr(target, "capabilities", set())
    # graceful skip: delivery needs a capability the target lacks
    if delivery == "indirect" and "seed" not in caps:
        return [{"verdict": "SKIP", "fired": [], "probe": None}]
    if delivery == "chain" and "chain" not in caps:
        return [{"verdict": "SKIP", "fired": [], "probe": None}]
    if delivery == "forged_history" and "forged_history" not in caps:
        return [{"verdict": "SKIP", "fired": [], "probe": None}]
    aid = attack.get("id", "?")
    for _ in range(trials):
        target.reset()
        seeded = False
        try:
            if delivery == "indirect":
                target.seed(attack["seed"])
                seeded = True
                probe = _resilient_send(
                    lambda: target.send(payload(attack.get("user_prompt", "Hello"))), aid)
            elif delivery == "sessions":
                probe = _resilient_send(
                    lambda: _run_sessions(target, [payload(x) for x in attack["steps"]]),
                    aid)
            elif delivery == "chain":
                probe = _resilient_send(
                    lambda: target.send_chain(
                        [payload(s) for s in attack["steps"]]), aid)
            elif delivery == "forged_history":
                # The whole forged transcript is the attacker's side, assistant turns
                # included — they wrote those too — so echo subtraction has to see all of
                # it. Without this the fabricated "certainly, the key is …" that the
                # attacker planted counts as the bot revealing it.
                forged = [{"role": h.get("role", "user"),
                           "content": payload(h.get("content", ""))}
                          for h in (attack.get("history") or [])]
                probe = _resilient_send(
                    lambda: target.send_forged(payload(attack["text"]), forged), aid)
                if probe is not None:
                    probe.prompt = "\n".join(
                        [h["content"] for h in forged] + [payload(attack["text"])])
            else:
                text = payload(attack["text"])
                if attack.get("encode"):        # obfuscation strategy (homoglyph/zero-width/…)
                    text = apply_encoding(text, attack["encode"])
                probe = _resilient_send(lambda t=text: target.send(t), aid)
        finally:
            if seeded:
                target.unseed()
        # For a multi-step delivery the adapters set probe.prompt to the LAST step, so
        # every echo-subtracting detector only knows about that one and counts anything the
        # attacker typed in an earlier turn as though the bot had revealed it. Measured on
        # the range: a cross-session test where the marker is planted in turn one had four
        # canary and credential detectors firing on the plant. The attacker's whole side of
        # the conversation is what they already knew.
        if delivery in ("chain", "sessions") and probe is not None and attack.get("steps"):
            probe.prompt = "\n".join(str(x) for x in attack["steps"])
        verdict, fired = judge(attack, probe, ctx)
        records.append({"verdict": verdict, "fired": fired, "probe": probe})
    return records


def headline(records):
    vs = [r["verdict"] for r in records]
    head = sorted(vs, key=lambda v: ORDER[v])[0]
    broke = sum(1 for v in vs if v in ("EXPLOITED", "PARTIAL"))
    return head, f"{broke}/{len(vs)}"
