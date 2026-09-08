"""
The engine loop: run one attack against a target N times, applying the right
delivery. Knows nothing about any specific bot — only the Target contract and
the attack dict. Delivery types are how new scenario classes slot in:
  - direct:   payload goes in the user prompt
  - indirect: payload is planted via target.seed(), user prompt stays benign
"""
import sys, threading, time
from oracle import judge, ORDER
from encoders import apply_encoding
from target import Probe, payload
from workspace import BROKE            # one definition of what counts as a breach

# When judging one reply is slow enough that an operator would think the run had
# hung. Ten seconds, because the measured cost of the whole oracle on a hostile
# megabyte is 1.2 seconds and on an ordinary reply it is milliseconds: anything at
# this scale is a new quadratic path, which `test_survives_target.py` is supposed to
# have caught at build time. This is the second line, for the case where it did not.
SLOW_JUDGE_S = 10.0
SEND_TIMEOUT = 180        # seconds a single probe may take before it's abandoned
RETRIES = 1               # extra attempts after the first, on timeout / error
# The longest this will wait when an endpoint answers 429 and asks for a pause. A
# target may say `Retry-After: 86400`, and honouring that would hang a sweep for a
# day; refusing to wait at all is what this is fixing. Beyond the ceiling the retry
# is abandoned and the row says the endpoint asked for longer than a run can give.
MAX_BACKOFF = 30
# How many units of work in a row may come back entirely rate-limited before the
# command stops sending. Five is enough to be sure it is not one busy moment and
# small enough to matter: measured against an endpoint answering 429 to everything,
# a sweep sent 92 requests and a benign run 48 before this existed.
RATE_LIMIT_GIVE_UP = 5


class RateLimitWall(object):
    """Counts units of work the target refused with a rate limit, in a row.

    A `unit` is whatever the caller sends and scores as one thing: an attack with its
    trials in a sweep, one probe in a benign run. `saw` takes the probes for one unit
    and returns True once the wall is reached; `reason` is the sentence to print.

    `IN A ROW` IS THE WHOLE RULE. A single 429 in the middle of a working run does not
    end it -- a limit that lets some traffic through is one the run can live within,
    and stopping on it throws away a measurement the operator can have. A first draft
    also required that nothing had ever succeeded, which is a hole rather than a
    safeguard: the commonest real shape is a metered endpoint answering happily until
    the quota runs out, and every one of those has succeeded.
    """

    def __init__(self, limit=RATE_LIMIT_GIVE_UP):
        self.limit = limit
        self.streak = 0
        self.reason = ""

    def saw(self, probes):
        probes = [p for p in (probes or []) if p is not None]
        if probes and all(str(getattr(p, "error", "") or "").startswith("RateLimited")
                          for p in probes):
            self.streak += 1
        else:
            self.streak = 0
        if self.streak >= self.limit and not self.reason:
            self.reason = (
                "the endpoint answered every one of the last %d with a rate limit "
                "and has not answered anything else since, so the rest was NOT sent"
                % self.streak)
        return bool(self.reason)


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
        # A 429 IS THE ONE ERROR WHERE RETRYING AT ONCE IS BOTH USELESS AND RUDE. The
        # endpoint said stop; sending again 0.0 seconds later doubles the traffic at
        # exactly that moment and cannot succeed. The adapter attaches the pause the
        # endpoint asked for, and a 429 with no `Retry-After` still gets a small one,
        # because the header being absent does not mean the limit is not there.
        _wait = getattr(probe, "retry_after", None)
        if _wait is None and str(probe.error or "").startswith("RateLimited"):
            _wait = 1.0
        if _wait is not None and _wait > MAX_BACKOFF:
            print(f"  ! {attack_id}: {probe.error} — asked for {_wait:g}s, longer than "
                  f"a run can wait ({MAX_BACKOFF}s); not retried", file=sys.stderr)
            break
        print(f"  ! {attack_id}: {probe.error} — retry {attempts}/{RETRIES}"
              + (f" after {_wait:g}s" if _wait else ""), file=sys.stderr)
        if _wait:
            time.sleep(_wait)
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
            # WHAT THE EARLIER STEPS ALREADY SHOWED IS NOT UNDONE BY A LATER FAILURE. This
            # returned the error probe alone, so a sequence that leaked in step one and hit a
            # socket reset in step two came back as verdict ERROR, output '', turns [] — the
            # leak observed and then discarded, filed as a row nobody measured. `_resilient_send`
            # then re-sends the whole sequence, which on a memory-poisoning target applies the
            # plant twice.
            #
            # The error travels with the evidence rather than instead of it, and `judge` reads
            # both: a breach already seen stands, a clean bill does not, because the steps that
            # would have found one never ran. That asymmetry is the engine's own rule, written
            # for `workspace.verdict_for` and applied here.
            err = (p.error if p is not None else "no probe")
            if not turns:
                return p if p is not None else Probe(prompt=step, error=err)
            return Probe(prompt="\n".join(steps[:i + 1]), output=out, tool_calls=calls,
                         observations=obs, turns=turns, seconds=secs, resolved=resolved,
                         error=err)
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


# WHAT EACH DELIVERY FAMILY NEEDS FROM THE TARGET, in one place, because two readers need
# it: `run_attack` guards on it so no caller can send something the target cannot take, and
# the sweep reads it before the first request so an attack it cannot deliver is counted as
# NOT SENT rather than as fired. `sessions` is deliberately absent — it needs nothing beyond
# send(), since reset() is the thing it tests (see `_run_sessions`).
# THE DELIVERIES THIS ENGINE HAS, beside the branch chain that implements them. The
# linter kept its own copy and the two could drift: a delivery added here and not
# there is refused as a typo, and one removed here and not there is accepted and then
# silently sent as something else. `test_lint` reads the branches back out of
# `run_attack` and requires them to agree.
DELIVERIES = ("direct", "indirect", "chain", "sessions", "forged_history")

DELIVERY_CAPABILITY = {
    "indirect": "seed",
    "chain": "chain",
    "forged_history": "forged_history",
}


def turns(attack):
    """How many REQUESTS one trial of this attack costs. A three-step chain costs three.

    `docs/ci.md` prices a sweep with this rule and `test_readme` recounts that table with
    it, so those two have always agreed. `onboard` needed the same number to tell an
    operator whether their budget can hold a run, and multiplied ATTACKS by trials: on the
    shipped arsenal that is 1,137 requests where the run sends 1,464, because 69 of the 379
    attacks are chains and one of them is six steps long.

    The direction is the one that matters. That note exists to say `it will STOP part way`,
    and understating the requirement keeps it quiet exactly when it should speak: a budget
    of 1,200 passed the check and stops the sweep at four fifths.

    Here rather than in either caller, because it is a fact about how a delivery is sent
    and this module is what sends it.
    """
    steps = attack.get("steps") if isinstance(attack, dict) else None
    return len(steps) if isinstance(steps, list) and steps else 1


def requests_for(attacks, trials):
    """Requests one sweep of these attacks costs, before any retry."""
    return sum(turns(a) for a in attacks) * int(trials)


def undeliverable(attack, caps):
    """-> the capability this attack's delivery needs and the target lacks, else None."""
    need = DELIVERY_CAPABILITY.get(attack.get("delivery", "direct"))
    return need if need and need not in (caps or set()) else None


def judged_ctx(attack, ctx):
    """The context this attack is judged against, plus anything the ATTACK itself planted.

    WHY AN ATTACK NEEDS TO BRING ITS OWN MARKER. `planted_markers` comes from the target
    config, which means a marker has to be arranged with the operator before the run: it is
    something already sitting in the target. That works for the memory bots, where the plant
    is a standing rule the tester typed in earlier, and it does not work at all for the case
    a benchmark made obvious.

    Measured against a third-party RAG app: every finding rested on a canary planted in the
    corpus BEFORE the run, so none of them could be attributed to the attack that found it —
    the same string comes back on an ordinary question about refunds. A tool that carries its
    own payload into the prompt does not have that problem: the string exists nowhere but in
    the attack, so the target repeating it is caused by the attack, by construction.

    So an attack may declare `plants:` and those values join `planted_markers` FOR ITS OWN
    JUDGEMENT ONLY. Not merged into the shared context: two attacks planting different
    markers must not make each other's findings possible, and a marker must not survive into
    the judgement of an attack that never sent it.

    `canaries` are deliberately untouched. A value the TARGET holds and a value the ATTACKER
    supplied are different findings at different severities, and `oracle._markers` exists to
    keep them apart.
    """
    plants = [str(m) for m in (attack.get("plants") or []) if str(m).strip()]
    expects = bool(attack.get("expects_refusal"))
    if not plants and not expects:
        return ctx
    merged = dict(ctx)
    if plants:
        merged["planted_markers"] = list(ctx.get("planted_markers") or []) + plants
    if expects:
        # Same rule as the markers: for THIS attack's judgement only. A sweep where one attack
        # asks for something a bot must decline does not make the next attack's ordinary
        # request into a refusal test.
        merged["expects_refusal"] = True
    return merged


def attacker_side(attack):
    """Everything the attacker put in front of the target, AS IT WAS SENT.

    Echo subtraction compares a reply against this string, so it has to be what the target
    saw rather than what the arsenal says. `run_attack` writes that rule down where it
    assembles a multi-step prompt -- "recording the plain steps for a run that sent encoded
    ones would subtract text the target never saw, and fail to subtract the text it did" --
    and `rejudge._prompt_of` did the thing that comment forbids, for any stored probe with
    no recorded prompt: it joined the raw `steps`, or returned the raw `text`, with neither
    `payload()` nor the attack's `encode:` applied and with a forged transcript ignored
    altogether. Its docstring said "reconstructed from the attack exactly as runner.py
    assembles it".

    THE DIRECTION IT FAILS IN IS THE BAD ONE. Subtracting the plain words of an encoded
    attack subtracts almost nothing, so the encoded payload coming back in the reply is
    counted as the target revealing it -- a manufactured finding on replay, out of an
    artifact that was fine. 820 stored probes here have no recorded prompt; none of them
    belongs to an encoded or forged attack today, which is why nothing has gone wrong yet
    and not a reason for the reconstruction to be wrong.

    So there is one implementation and both callers use it: `run_attack` below for the two
    deliveries whose adapters cannot set it themselves, and `rejudge` for a probe that
    never recorded one.
    """
    enc = attack.get("encode")

    def _t(s):
        s = payload(s)
        return apply_encoding(s, enc) if enc else s

    delivery = attack.get("delivery", "direct")
    if delivery in ("chain", "sessions") and attack.get("steps"):
        return "\n".join(_t(x) for x in attack["steps"])
    if delivery == "forged_history":
        return "\n".join(
            [_t((h or {}).get("content", "")) for h in (attack.get("history") or [])]
            + [_t(attack.get("text") or "")])
    if delivery == "indirect":
        return _t(attack.get("user_prompt", "Hello"))
    return _t(attack.get("text") or attack.get("user_prompt") or "")


def run_attack(target, attack, ctx, trials=1):
    records = []
    delivery = attack.get("delivery", "direct")
    caps = getattr(target, "capabilities", set())
    # graceful skip: delivery needs a capability the target lacks. The rule lives in
    # `undeliverable` because the sweep has to read it BEFORE the run to count these as not
    # sent; a second copy here would drift, and the drift would surface as coverage the run
    # never had.
    if undeliverable(attack, caps):
        return [{"verdict": "SKIP", "fired": [], "probe": None}]
    aid = attack.get("id", "?")
    # EVERY STRING THE ATTACKER SENDS, normalised and then obfuscated. `encode:` was applied
    # in the `else` branch alone, so a `chain`, `sessions`, `forged_history` or `indirect`
    # attack that asked for an encoding was sent IN THE CLEAR -- and a DEFENDED verdict then
    # described a target that was never shown the technique. That is the same failure `lint`
    # already refuses for `ascii_art` with no marker, reached through the delivery instead of
    # through the text. 193 attacks in this corpus use one of those four deliveries.
    #
    # NOT THE SEED, and that is not an omission: `target.seed` takes a structured record
    # whose field names belong to the target, and encoding those would break the plant
    # rather than obfuscate it. For an `indirect` attack the encoding applies to the prompt
    # that asks the question, which is the string a filter on the way in would read.
    _enc = attack.get("encode")

    def _text(s):
        _t = payload(s)
        return apply_encoding(_t, _enc) if _enc else _t
    for _ in range(trials):
        target.reset()
        seeded = False
        try:
            if delivery == "indirect":
                target.seed(attack["seed"])
                seeded = True
                probe = _resilient_send(
                    lambda: target.send(_text(attack.get("user_prompt", "Hello"))), aid)
            elif delivery == "sessions":
                probe = _resilient_send(
                    lambda: _run_sessions(target, [_text(x) for x in attack["steps"]]),
                    aid)
            elif delivery == "chain":
                probe = _resilient_send(
                    lambda: target.send_chain(
                        [_text(s) for s in attack["steps"]]), aid)
            elif delivery == "forged_history":
                # The whole forged transcript is the attacker's side, assistant turns
                # included — they wrote those too — so echo subtraction has to see all of
                # it. Without this the fabricated "certainly, the key is …" that the
                # attacker planted counts as the bot revealing it.
                forged = [{"role": h.get("role", "user"),
                           "content": _text(h.get("content", ""))}
                          for h in (attack.get("history") or [])]
                probe = _resilient_send(
                    lambda: target.send_forged(_text(attack["text"]), forged), aid)
                if probe is not None:
                    # Same one implementation as the multi-step branch below.
                    probe.prompt = attacker_side(attack)
            else:
                text = _text(attack["text"])
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
            # WHAT WAS SENT, not what was written. Echo subtraction compares the reply
            # against this string, so recording the plain steps for a run that sent
            # encoded ones would subtract text the target never saw -- and fail to
            # subtract the text it did. Through `attacker_side` because `rejudge` needs
            # the same answer for a probe that recorded no prompt, and had its own.
            probe.prompt = attacker_side(attack)
        # NO WATCHDOG HERE, AND THAT IS NOT AN OVERSIGHT. Judging is CPU inside this process:
        # `signal.alarm` does not exist on Windows, a thread cannot interrupt a regular
        # expression, and a subprocess per probe would cost more than the sweep. Nothing that
        # could be written at this line would actually stop a slow judge.
        #
        # The protection is upstream and it is real. `targets_http.MAX_REPLY` bounds what a
        # target can hand the oracle, and four patterns in `oracle.py` that were quadratic in
        # the reply length are not any more — measured, a hostile megabyte went from about an
        # hour and a half to 1.2 seconds. `test_survives_target.py` holds a stopwatch on that,
        # in a subprocess with a deadline, so a new quadratic detector fails the build rather
        # than a customer's run.
        #
        # What is left here is to SAY IT. A judge that takes minutes is not going to be
        # interrupted, but it must not be silent either: an operator watching a sweep that has
        # stopped printing deserves to know it is the oracle and which attack it is on.
        _t0 = time.time()
        verdict, fired = judge(attack, probe, judged_ctx(attack, ctx))
        _took = time.time() - _t0
        if _took > SLOW_JUDGE_S:
            print(f"  ! judging {aid} took {_took:.0f}s on a "
                  f"{len(getattr(probe, 'output', '') or ''):,}-character reply. The run is "
                  f"not stuck; the oracle is reading it.", file=sys.stderr)
        records.append({"verdict": verdict, "fired": fired, "probe": probe})
    return records


def headline(records):
    vs = [r["verdict"] for r in records]
    head = sorted(vs, key=lambda v: ORDER[v])[0]
    broke = sum(1 for v in vs if v in BROKE)
    return head, f"{broke}/{len(vs)}"
