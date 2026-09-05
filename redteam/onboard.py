"""The front door: check a target config against its live endpoint, then queue the run.

A configured target can be wrong in ways nothing notices until an hour later, inside a worker,
as a job that failed. `response.reply` pointing at a path the endpoint does not return is the
common one, and its symptom is not an error — it is an empty string, which every detector reads
as a bot that said nothing, which reads as a bot that held. The most expensive shape of wrong
in this whole system is a misconfiguration that reports as a defence, and the place to catch it
is before the run rather than in the results.

So this sends ONE probe, an ordinary question, and answers five things you should learn
in ten seconds rather than in an hour:

  * does the endpoint answer at all, and what did it cost in seconds;
  * does `response.reply` resolve to text, and if not, WHAT the response actually contained —
    naming the paths that do hold strings, because "reply is empty" without that is a riddle;
  * which capabilities the config implies, since `chain` and `forged_history` are derived from
    `history` and their absence silently removes whole classes of attack from the run;
  * whether the target is authorised, which for anything but localhost has to be proved;
  * what the budget allows, because a run that cannot finish inside it is a partial run and the
    operator should hear that word before the wait, not after.

Nothing is queued if the probe fails. A job submitted against a config that cannot be reached
is an hour of queue time spent to produce the sentence this command prints immediately.

    python onboard.py --config targets_acme.yaml            # check only
    python onboard.py --config targets_acme.yaml --submit   # check, then queue it
"""
import argparse, json, os, sys, time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import yaml

import authorization
import jobqueue as q
from targets_http import HttpConfiguredTarget, CONFIG_ONLY_KEYS, dig
from workspace import OUT, safe_target_name

PROBE = "Hello, I have a question about my recent order."

# Paths worth naming when `response.reply` comes back empty. Not a guess at the operator's
# schema — a shortlist of the shapes an LLM endpoint actually ships, so the error can say
# "your text is probably at choices.0.message.content" instead of "reply was empty".
COMMON = ("choices.0.message.content", "choices.0.text", "message.content", "content",
          "output", "output_text", "response", "reply", "text", "answer", "result",
          "data.content", "completion", "candidates.0.content.parts.0.text",
          "messages.0.content")


def _strings(obj, prefix="", out=None, depth=0):
    """Every path in a decoded response that holds a non-trivial string, for the error message."""
    out = [] if out is None else out
    if depth > 6 or len(out) > 40:
        return out
    if isinstance(obj, str):
        if len(obj.strip()) > 12:
            out.append((prefix, obj.strip()))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _strings(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:4]):
            _strings(v, f"{prefix}.{i}" if prefix else str(i), out, depth + 1)
    return out


def _arsenal_size(path=None):
    """How many attacks a default run will actually send.

    Read rather than remembered: the number this replaced was a literal that had been true of a
    nineteen-attack arsenal, and nothing re-read it when the arsenal grew. A budget warning
    computed from a stale count is worse than none, because the operator sizes the budget
    against it and the sweep stops part way with no explanation.
    """
    import yaml as _yaml
    p = path or os.path.join(HERE, "attacks_generic.yaml")
    try:
        return len(_yaml.safe_load(open(p, encoding="utf-8")) or [])
    except (OSError, ValueError):
        return 0


def unread_context_keys(cfg):
    """Keys in this config's `oracle_context` that no part of the engine reads.

    A KEY NOTHING READS IS A DETECTOR NOBODY ARMED. `canaries` misspelled `canarys` parses,
    sweeps, and disarms every canary detector in the oracle -- a clean bill for checks that
    could not fire, out of the one file an operator edits by hand. This command exists to
    catch a config that would otherwise produce a clean report from a broken mapping, and it
    was reading the reply path only.

    Derived through `workspace.context_keys_read`, which scans the package rather than keeping
    a list: forty-nine keys typed here would be the copy that goes stale, and noticing a name
    that should not be there is the entire job.
    """
    # ONE IMPLEMENTATION, in `workspace`, beside the scan it consults. `run` needs the same
    # answer and used to reach into this command for it, which is the wrong direction between
    # a command and the thing it onboards.
    from workspace import unread_context_keys as _unread
    return _unread(cfg)


def check(cfg_path, probe_text=PROBE):
    """Returns (ok, report dict). Sends exactly one request."""
    rep = {"config": cfg_path, "problems": [], "notes": [], "unread_keys": []}
    try:
        cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
    except Exception as e:
        rep["problems"].append(f"the config file could not be read: {type(e).__name__}: {e}")
        return False, rep
    # ONLY THE CONTEXT LEVEL HERE. The top level is already refused by the adapter this
    # command onboards — `HttpConfiguredTarget` raises on a key it does not know — so a note
    # would repeat the PROBLEM printed below it. The built-in adapters have no such refusal,
    # and this command does not accept them: it onboards `adapter: http` configs. Their guard
    # is a check over the shipped configs, in `test_http_adapter`, where it can run without a
    # target at all.
    rep["unread_keys"] = unread_context_keys(cfg)
    # THE SAME QUESTION ONE LEVEL DOWN. `refusal_patterns` is a key the engine reads, so the
    # check above passes it; what it CONTAINS is a second vocabulary with its own spellings,
    # and a class name nothing names disarms the whole list under it in silence.
    from refusal import bad_patterns as _bad_patterns
    for _where, _why in _bad_patterns((cfg or {}).get("oracle_context") or {}):
        rep["problems"].append("%s %s" % (_where, _why))
    # AND THE SHAPE OF WHAT IS THERE. A string is iterable, so a scalar where a list belongs
    # raises nothing and empties nothing — it just gets used one character at a time.
    from workspace import bad_context_shapes as _bad_shapes
    for _where, _why in _bad_shapes(cfg):
        rep["problems"].append("oracle_context.%s %s" % (_where, _why))
    # AND WHETHER THE CANARY CAN CARRY THE EVIDENCE. A NOTE rather than a problem: a
    # customer's real secret may genuinely be short, and refusing that would block the test
    # they came to run. The benign sweep answers it properly and this points there.
    from honeytoken import weak_canaries as _weak
    for _c, _why in _weak((cfg or {}).get("oracle_context") or {}):
        rep["notes"].append("canary %r %s" % (_c, _why))
    if (cfg.get("adapter") or "") != "http":
        rep["problems"].append(
            f"adapter is {cfg.get('adapter')!r}; this command onboards `adapter: http` configs, "
            f"which is the configured-target path. A built-in target does not need onboarding.")
        return False, rep

    rep["name"] = cfg.get("name") or "(unnamed)"
    rep["url"] = cfg.get("url")

    # THE NAME, THROUGH THE RULE THAT ALREADY OWNS IT. `intake.submit` refuses a nameless
    # submission and writes down why: the name becomes `results_<name>.json`,
    # `report_<name>.html` and `history/<name>.jsonl`, so a default means every unnamed
    # target writes the same files. This is the other door into the same queue and it
    # invented `(unnamed)` instead, printed it, and said `ready to queue`.
    #
    # The default is not even the name the run would use. A nameless `adapter: http` config
    # constructs as `http-target`, so the queue records one target and the artifacts are
    # written under another -- and two different endpoints onboarded this way collide on
    # one set of files.
    #
    # `safe_target_name` rather than a second copy of the rule: it already refuses the
    # empty name AND the ones that cannot be part of a filename, which this accepted too.
    # Every shipped `adapter: http` config carries a name and `qatration init` writes one,
    # so nothing that worked before is refused now.
    try:
        rep["name"] = safe_target_name(cfg.get("name"), "target config")
    except SystemExit as e:
        rep["problems"].append(str(e))
        return False, rep

    # AUTHORIZATION BEFORE THE PROBE. Even one request to somebody else's endpoint is a
    # request to somebody else's endpoint, so the gate cannot sit after the thing it gates.
    try:
        rep["authorization"] = authorization.gate(cfg, cfg_path)
    except SystemExit as e:
        rep["problems"].append(f"not authorised: {e}")
        return False, rep

    try:
        target = HttpConfiguredTarget(**{k: v for k, v in cfg.items()
                                 if k not in CONFIG_ONLY_KEYS})
    except SystemExit as e:
        rep["problems"].append(str(e))
        return False, rep

    t0 = time.time()
    try:
        probe = target.send(probe_text)
    except Exception as e:
        rep["problems"].append(f"the endpoint could not be reached: {type(e).__name__}: {e}")
        return False, rep
    rep["seconds"] = round(time.time() - t0, 1)

    if probe is not None and (probe.error or "").startswith("ExtractionFailed"):
        # THE EXPENSIVE ONE. The endpoint answered; the mapping is wrong. Left to the run this
        # would not fail — an unmapped reply is an empty reply, which every detector scores as
        # a bot that said nothing, which scores as a bot that held. A misconfiguration that
        # reports as a defence is the worst outcome this system can produce.
        raw = getattr(probe, "raw", None)
        path = (cfg.get("response") or {}).get("reply")
        rep["problems"].append(
            f"`response.reply: {path!r}` resolved to nothing. The endpoint ANSWERED, so this is "
            f"a mapping problem rather than a connectivity one — and it would not have failed "
            f"the run: an unmapped reply is an empty reply, and an empty reply scores as a "
            f"target that held.")
        if raw is not None:
            for p2 in COMMON:
                v = dig(raw, p2)
                if isinstance(v, str) and v.strip():
                    rep["notes"].append(f'try `response.reply: "{p2}"` — it holds text')
                    break
            for p2, v in _strings(raw)[:4]:
                rep["notes"].append(f"  {p2} = {v[:70]!r}")
        return False, rep

    if probe is None or probe.error:
        # AND THE HEADER MUST NOT SAY "answered". `render` prints the elapsed time under
        # that word whenever a probe came back at all, so a refused connection printed
        # "answered in 4.1s" three lines above "the endpoint returned an error". The
        # PROBLEM line was right and the header contradicted it, which is the same
        # overstatement this tool refuses everywhere else: a thing that did not happen,
        # reported in the vocabulary of the thing that did.
        rep["answered"] = False
        rep["problems"].append(f"the endpoint returned an error: "
                               f"{(probe.error if probe else 'no reply')}")
        return False, rep

    reply = (probe.output or "").strip()
    if not reply:
        # The important branch. An empty reply is not an error anywhere downstream — it is a
        # bot that said nothing, which every detector scores as a bot that held.
        raw = getattr(probe, "raw", None)
        found = _strings(raw) if raw is not None else []
        path = (cfg.get("response") or {}).get("reply")
        rep["problems"].append(
            f"`response.reply: {path!r}` resolved to nothing. The endpoint answered, so this is "
            f"a mapping problem, not a connectivity one — and it would NOT have failed the run: "
            f"an empty reply scores as a target that said nothing, which scores as a target that "
            f"held.")
        if raw is not None:
            for p in COMMON:
                if isinstance(dig(raw, p), str) and dig(raw, p).strip():
                    rep["notes"].append(f"try `response.reply: \"{p}\"` — it holds text")
                    break
            for p, v in found[:4]:
                rep["notes"].append(f"  {p} = {v[:70]!r}")
        return False, rep

    rep["reply"] = reply[:200]
    rep["capabilities"] = sorted(getattr(target, "capabilities", ()) or ())

    # Capabilities are DERIVED, and their absence deletes whole classes of attack silently.
    if "chain" not in rep["capabilities"]:
        rep["notes"].append(
            "no `history` block, so multi-turn deliveries (chain, forged_history) will be "
            "SKIPPED rather than failed. Roughly a third of what this engine knows how to do "
            "needs more than one turn, and a run without them is not a weaker verdict, it is a "
            "narrower one.")
    if "tool_visibility" not in rep["capabilities"]:
        rep["notes"].append(
            "no `tool_calls` mapping, so nothing can be said about what your tools RECEIVED. "
            "On an agent that is the blind spot: the prose can be impeccable while the call "
            "carries the secret.")
    import honeytoken as _ht
    if not _ht.declared(cfg.get("oracle_context") or {}):
        rep["notes"].append(
            "no `oracle_context.canaries`, so leak detection has no planted value to look for. "
            "Declare the secret your system prompt holds; without it a leak is invisible.")

    rate = getattr(target, "rate", None)
    if rate is not None:
        rep["budget"] = {"max_requests": rate.max_requests, "max_seconds": rate.max_seconds}
        # The REQUEST budget is the one that can be checked without guessing, because the
        # arithmetic is fixed: attacks x trials, before any retry. Seconds depend on the
        # endpoint's mood; requests do not.
        # COUNTED, NOT REMEMBERED. This was `19 * 3`, true of an arsenal that had nineteen
        # attacks in it. The intake queues the portable arsenal, which has 362, so the advice
        # said a run needs 57 requests while the run needed nearly twenty times that — and the
        # operator sized a budget against it and had the sweep stop a fraction of the way in.
        need_att = _arsenal_size()
        need_req = need_att * 3
        if rate.max_requests and rate.max_requests < need_req:
            rep["notes"].append(
                f"a default run sends about {need_req} requests ({need_att} attacks x 3 trials) and "
                f"the budget allows {rate.max_requests}. It will STOP part way, and the "
                f"attacks it never sent are a gap rather than rows that held.")
        if rep["seconds"] and rate.max_seconds:
            # An estimate, said as one. The arsenal size x 3 trials is the default shape.
            #
            # AND IT WAS 19 UNTIL NOW, which is the literal `_arsenal_size()` exists to replace.
            # Its docstring says so twelve lines up: "the number this replaced was a literal
            # that had been true of a nineteen-attack arsenal, and nothing re-read it when the
            # arsenal grew". The request estimate above got the fix; this one, in the same
            # function, kept the literal -- so the sentence named `need_att` (379) while the
            # arithmetic used 19 and the answer came out TWENTY TIMES SMALL. A budget warning
            # that understates is worse than none in the one direction that matters: it stays
            # quiet exactly when it should speak. At a 3s reply it reported 3 minutes against
            # a real 57, so an 1800s budget looked comfortable and would stop a third of the
            # way in.
            need = rep["seconds"] * need_att * 3
            if need > rate.max_seconds:
                rep["notes"].append(
                    f"that reply took {rep['seconds']}s, so a default run ({need_att} attacks x 3 "
                    f"trials) needs roughly {need / 60:.0f} min against a budget of "
                    f"{rate.max_seconds / 60:.0f} min. It will STOP part way, and the attacks "
                    f"it never sent are a gap rather than rows that held.")
    return True, rep


def render(ok, rep):
    print(f"config      {rep.get('config')}")
    print(f"target      {rep.get('name')}  {rep.get('url') or ''}")
    auth = rep.get("authorization")
    if auth:
        print(f"authorised  {auth.get('method')}" + (f"  {auth.get('origin')}"
                                                     if auth.get("origin") else ""))
    if rep.get("seconds") is not None:
        print(f"answered    in {rep['seconds']}s" if rep.get("answered", True)
              else f"no answer   after {rep['seconds']}s")
    if rep.get("reply"):
        print(f"reply       {rep['reply'][:120]!r}")
    if rep.get("capabilities") is not None:
        print(f"deliveries  {', '.join(rep['capabilities']) or '(single-turn only)'}")
    if rep.get("budget"):
        b = rep["budget"]
        print(f"budget      {b.get('max_requests')} requests / {b.get('max_seconds')} seconds")
    # A NOTE, NEVER A REFUSAL. The key list is derived by scanning this package's source, so a
    # key reached through a variable this scan cannot resolve would look unknown; being wrong
    # here costs a line somebody dismisses, and being silent costs a run.
    if rep.get("unread_keys"):
        print("\n  note      oracle_context has %d key(s) nothing in this engine reads: %s"
              % (len(rep["unread_keys"]), ", ".join(rep["unread_keys"])))
        print("            a misspelled key arms no detector and the run reports a clean "
              "bill for a check that never ran")

    for p in rep.get("problems") or []:
        print(f"\n  PROBLEM   {p}")
    for nline in rep.get("notes") or []:
        print(f"  note      {nline}")
    print()
    print("ready to queue" if ok else "not queued — fix the problem above first")


def main():
    ap = argparse.ArgumentParser(description="check a target config, then queue the run")
    # BOTH SPELLINGS, because every other command in this tool takes `--target-config` and this
    # one took `--config`. The README's quickstart, two shipped example configs and cli.py's own
    # docstring all told people to type `qatration onboard --target-config …`, which argparse
    # then rejected — the very first command a new user runs, failing on a flag name. Aliased
    # rather than renamed so anything already scripted against `--config` keeps working.
    ap.add_argument("--target-config", "--config", dest="config", required=True,
                    help="the YAML describing the target (`--config` is accepted too)")
    ap.add_argument("--submit", action="store_true", help="queue the run if the check passes")
    ap.add_argument("--root", default=str(OUT))
    ap.add_argument("--scope", dest="scope", choices=("full", "quick"), default="quick",
                    help="how much traffic a queued sweep may send: `quick` is one attack per "
                         "category, `full` is the whole arsenal")
    # THE TARGET-AGNOSTIC ARSENAL BY DEFAULT. The engine's default is attacks.yaml, in which
    # almost every attack is scoped `applies_to` a specific practice bot, so a customer coming
    # through this door got 5 of 137 attacks sent and 132 skipped — a 3% assessment presented
    # as an assessment. attacks_generic.yaml is the set written to run against anything.
    ap.add_argument("--attacks", default=os.path.join(HERE, "attacks_generic.yaml"),
                    help="arsenal to queue; defaults to the target-agnostic set")
    from workspace import trial_count as _trial_count
    ap.add_argument("--trials", type=_trial_count, default=3)
    ap.add_argument("--requester", default=None)
    ap.add_argument("--mint-honeytoken", action="store_true",
                    help="print a token pair and the snippet to paste, then stop. The secret "
                         "is generated here, so no real credential goes into the target prompt")
    ap.add_argument("--verify-honeytoken", metavar="VERIFY_TOKEN", default=None,
                    help="ask the target for its deployment reference and say whether the "
                         "snippet actually landed")
    args = ap.parse_args()

    # --- the honeytoken flow ---------------------------------------------------------------
    #
    # Every canary detector needs a value that should never appear in a reply, and asking the
    # for a real key is the wrong ask in both directions: production credentials should not
    # go into a test prompt, and a harness that holds one has to protect it. So the value
    # is ours. They paste it in for the duration of the test and revert it afterwards.
    import honeytoken as _ht
    if args.mint_honeytoken:
        # Delegated rather than duplicated. This message names a command, and the day a second
        # copy of it starts naming one that no longer exists, it will be the copy nobody ran.
        import mint as _mint
        secret, verify = _ht.mint()
        print(_mint.instructions(secret, verify, args.config or "<your.yaml>"))
        return

    if args.verify_honeytoken:
        cfg = yaml.safe_load(open(args.config, encoding="utf-8")) or {}
        # THE RULE IS STATED NINETY LINES UP AND THIS BRANCH BROKE IT. `check()` runs the gate
        # before its probe, with the comment "the gate cannot sit after the thing it gates" —
        # and this path does not go through `check()`. It built the target and sent a real
        # request to whatever URL the config named, with no proof of ownership, which on a
        # hosted instance is an SSRF primitive aimed by the submitted config. `mint` prints
        # this command as step 3, so it is the path an operator is told to run.
        #
        # A second entry point that skips a control is the shape a control is usually defeated
        # by: nobody removed the gate, somebody added a door beside it.
        authorization.gate(cfg, args.config)
        target = HttpConfiguredTarget(**{k: v for k, v in cfg.items()
                                         if k not in CONFIG_ONLY_KEYS})
        probe = target.send(_ht.VERIFY_PROMPT)
        _why = _ht.verify_refusal(probe, args.verify_honeytoken)
        if _why is None:
            print(f"planted: the deployment returned {args.verify_honeytoken}. Canary "
                  f"detectors can speak here.\n")
            # FALL THROUGH TO THE REAL REPORT. This used to `return` here, which made the flag
            # a REPLACEMENT rather than an addition: one line instead of the mapping check, the
            # delivery notes and the budget arithmetic. `qatration init` prints this exact
            # command as the step after writing a config, so the path a newcomer is told to
            # walk was the one that told them least -- including the warning that their request
            # budget stops the run part way through.
            #
            # Two requests rather than one, which is the honest cost of asking two questions.
        else:
            # NOT "the target refused", and not silence. An unplanted token is invisible: every
            # canary detector finds nothing, every attack comes back DEFENDED, and the report
            # says the deployment held. That is a gap reported as a measurement, on the run a
            # customer is judged by.
            print(f"{_why[0]} \u2014 {_why[1]}", file=sys.stderr)
            # Only when something answered. "what it said instead: ''" under a refused
            # connection describes a bot that stayed silent, which is a different bug to
            # go looking for than a server that is not running.
            if _why[0] == "NOT PLANTED":
                print(f"\nwhat it said instead: {(probe.output or '')[:200]!r}",
                      file=sys.stderr)
            sys.exit(5)

    ok, rep = check(args.config)
    render(ok, rep)
    if not ok:
        sys.exit(2)
    if not args.submit:
        return

    cfg = yaml.safe_load(open(args.config, encoding="utf-8")) or {}
    job = q.submit(args.root, rep["name"], os.path.abspath(args.config), scope=args.scope,
                   authorization=rep.get("authorization"), budgets=cfg.get("rate") or {},
                   attacks=args.attacks, trials=args.trials, requester=args.requester)
    d = q.depth(args.root)
    print(f"\nqueued      {job['job_id']}")
    print(f"position    {d['queued']} queued, {d['running']} running")


if __name__ == "__main__":
    main()
