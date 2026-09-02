"""
Entry point: pick a target + its config + the shared arsenal, run, print.
Note how DVLA-specific knowledge is entirely in the adapter + the YAML — this
script (the engine's face) is target-agnostic.

    python run_redteam.py [--trials N]
"""
import sys, os, re, argparse, json
from datetime import datetime
try:                                    # survive any console codepage, not just UTF-8
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from workspace import (OUT as WORKSPACE_OUT, safe_target_name,
                       refuse_to_overwrite_evidence)   # one place decides where output goes
OUT_DIR = WORKSPACE_OUT

import yaml
from runner import run_attack, headline
from refusal import classify, summarize
from report_engine import build_html
from target import engine_version

# --- registry: add a line here to make a new target selectable ---------------
def load_target(cfg):
    adapter = cfg.get("adapter", "dvla")
    if adapter == "dvla":
        from targets_dvla import DvlaTarget
        return DvlaTarget(model=cfg.get("model", "mistral-nemo"))
    if adapter == "foreign":
        from targets_foreign import ForeignAgentTarget
        return ForeignAgentTarget(url=cfg.get("url", "http://localhost:8130/chat"))
    if adapter == "http":
        # The one adapter that needs no Python. Everything a customer's endpoint differs by —
        # url, auth header, request shape, where the reply lives, whether the API carries a
        # transcript, whether it reports tool calls — is a key in their config file, so
        # onboarding is a YAML rather than a module written by someone who knows this repo.
        from targets_http import HttpConfiguredTarget, CONFIG_ONLY_KEYS
        return HttpConfiguredTarget(**{k: v for k, v in cfg.items()
                               if k not in CONFIG_ONLY_KEYS})
    if adapter == "httpbot":
        from targets_httpbot import HttpTarget
        return HttpTarget(url=cfg.get("url", "http://localhost:8099/chat"))
    if adapter == "opsbot":
        from targets_opsbot import OpsBotTarget
        return OpsBotTarget(model=cfg.get("model", "mistral-nemo"))
    if adapter == "ragbot":
        from targets_ragbot import RagTarget
        return RagTarget(model=cfg.get("model", "mistral-nemo"))
    if adapter == "localrag":
        from targets_localrag import LocalRagTarget
        return LocalRagTarget(url=cfg.get("url", "http://localhost:8000/rag"))
    if adapter == "toolagent":
        from targets_toolagent import ToolAgentTarget
        return ToolAgentTarget(model=cfg.get("model", "mistral-nemo"), strict=cfg.get("strict", True))
    if adapter == "portalagent":
        from targets_portalagent import PortalAgentTarget
        return PortalAgentTarget(model=cfg.get("model", "mistral-nemo"), strict=cfg.get("strict", True))
    if adapter == "memorybot":
        from targets_memorybot import MemoryBotTarget
        return MemoryBotTarget(model=cfg.get("model", "mistral-nemo"), guard=cfg.get("guard", True))
    if adapter == "mcpagent":
        from targets_mcpagent import McpAgentTarget
        return McpAgentTarget(model=cfg.get("model", "mistral-nemo"), guard=cfg.get("guard", True),
                              variant=cfg.get("variant", "direct"))
    if adapter == "secretbot":
        from targets_secretbot import SecretBotTarget
        return SecretBotTarget(model=cfg.get("model", "mistral-nemo"), guard=cfg.get("guard", True))
    if adapter == "rangebot":
        from targets_rangebot import RangeBotTarget
        return RangeBotTarget(model=cfg.get("model", "mistral-nemo"),
                              slow_seconds=cfg.get("slow_seconds", 25),
                              append_sources=cfg.get("append_sources", False))
    if adapter == "guardbot":
        from targets_guardbot import GuardBotTarget
        return GuardBotTarget(model=cfg.get("model", "mistral-nemo"))
    raise SystemExit(f"unknown adapter: {adapter!r}")


def load_target_or_explain(cfg, config_path, was_default):
    """Build the target, and turn the one import failure a stranger will hit into a sentence.

    The default `--target-config` is `targets_dvla.yaml`, whose adapter imports langchain and
    two modules that live in `dvla/` — a third-party clone this repository deliberately does not
    ship. So a bare `qatration run` after `pip install qatration` ended in a raw
    ModuleNotFoundError, and no extra fixes it, because the missing pieces are not ours to
    distribute. Inside a checkout with the practice fleet set up it works, which is why it went
    unnoticed: the failure is invisible from exactly where the code is written.
    """
    try:
        return load_target(cfg)
    except ImportError as e:
        why = ("the practice fleet's own target, which needs a third-party clone this "
               "package does not ship" if was_default
               else "this config's adapter, %r" % cfg.get("adapter"))
        lines = [
            f"ABORT — cannot load {why}: {type(e).__name__}: {e}",
            f"  config: {config_path}",
        ]
        if was_default:
            lines += [
                "  There is no default target worth having. Point it at your own deployment:",
                "    qatration mint",
                "    qatration onboard --target-config mybot.yaml",
                "  or copy redteam/targets_openai_compatible.yaml to start from a working one.",
            ]
        else:
            lines.append('  Install the extra that adapter needs: pip install "qatration[fleet]"')
        lines.append("  Nothing was sent.")
        raise SystemExit("\n".join(lines))


def regression_verdict(d, is_model_copy=False):
    """(exit code, lines to print) for `--fail-on regression`. A pure function on purpose.

    THE GATE A PULL REQUEST ACTUALLY WANTS, and the reason the other two are wrong for one.
    `exploited` and `any` fire on the ABSOLUTE state, so the first check a team adds goes red on
    whatever was already broken and stays red — which teaches everyone to ignore it, the exact
    outcome the exit-code table warns about. A pull request is not asking "is this bot perfect",
    it is asking "did I make it worse".

    And the honest half: a comparison this engine cannot believe must not report a pass. A
    changed arsenal, a changed model, fewer trials, a torn timeline — each makes before and
    after two different instruments, and `diff()` already names them. When it does this returns
    3, "nothing was measured", rather than the green that would be a lie. A team seeing that
    once re-baselines, which is the correct response and takes a minute.

    Pure so it can be tested without a sweep: every branch here is a decision about somebody
    else's build going red, and a decision like that should not be reachable only by spending
    an hour of GPU to get to it.
    """
    if is_model_copy:
        return 3, ["CI GATE: CANNOT ANSWER — a --model run is a second measurement of the same "
                   "sweep, so it has no timeline of its own to compare against."]
    if not isinstance(d, dict) or "reason" in d:
        why = (d or {}).get("reason", "no previous run for this target")
        return 3, ["CI GATE: CANNOT ANSWER — %s. A first run is a baseline, not a verdict; "
                   "store out/history/ and the next run can answer this." % why]
    if d.get("confounds"):
        return 3, ["CI GATE: CANNOT ANSWER — the comparison is confounded: %s. Before and after "
                   "were measured with different instruments, so neither a pass nor a failure "
                   "here would mean anything." % "; ".join(d["confounds"])]
    # SAID ON A RED BUILD AS WELL AS A GREEN ONE. A row that moved without the trials agreeing
    # is excluded from the count either way, and a team reading "6 introduced" needs to know
    # that four more moved and were not counted, or the number looks like the whole story.
    noise = list(d.get("unstable") or [])
    heard = (["  (%d row(s) moved, but not on every attempt, so nothing here separates them "
              "from the sampling: %s%s)"
              % (len(noise), ", ".join(noise[:8]),
                 " +%d" % (len(noise) - 8) if len(noise) > 8 else "")] if noise else [])
    worse = list(d.get("regressed") or []) + list(d.get("new") or [])
    if worse:
        return 1, ["CI GATE: FAIL — %d finding(s) this run introduced or reopened since %s: %s%s"
                   % (len(worse), d["prev"], ", ".join(worse[:8]),
                      " +%d" % (len(worse) - 8) if len(worse) > 8 else "")] + heard
    out = list(heard)
    if d.get("not_run"):
        # Not a failure, but not silence either: a row that was not sent cannot have got better
        # or worse, and a gate that ignores it is claiming to have compared it.
        out.append("  (%d row(s) were not re-tested and are excluded from this verdict — they "
                   "remain whatever they were)" % len(d["not_run"]))
    return 0, out


def _build_mismatch(tcfg):
    """-> a sentence naming the disagreement, or "" when the server is what the config says.

    `expect_build` is a plain dict of key -> value the target reports on a GET to its url's
    origin. A target that does not answer, or does not report a key, is NOT a mismatch: the
    check exists to catch the wrong build answering, not to require every bot to grow an
    endpoint. Silence is the absence of evidence, which is the one thing this repo refuses to
    read as evidence of absence — so it is stated rather than treated as a pass.
    """
    want = tcfg.get("expect_build") or {}
    url = tcfg.get("url")
    if not want or not url:
        return ""
    import json as _json
    import urllib.request
    from urllib.parse import urlparse
    u = urlparse(url)
    probe = f"{u.scheme}://{u.netloc}/"
    try:
        with urllib.request.urlopen(probe, timeout=5) as r:
            got = _json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        print(f"  ! could not ask {probe} what build it is ({type(e).__name__}) — this run "
              f"is not verified against expect_build {want}")
        return ""
    bad = [f"{k}={got.get(k)!r} (config says {v!r})"
           for k, v in want.items() if str(got.get(k, "")).lower() != str(v).lower()]
    return "; ".join(bad)


def _spend(target):
    """What this run cost, when the adapter counted. Empty is honest for one that did not.

    Only the configured HTTP adapter keeps a budget, because it is the only one pointed at
    somebody else's endpoint. An in-process practice target costs GPU and nobody's goodwill,
    so it reports nothing rather than a zero that would read as "free".
    """
    rate = getattr(target, "rate", None)
    if rate is None:
        return {}
    return {"requests": rate.used, "seconds": round(rate.elapsed, 1)}


def _side_artifact(explicit, default_name, key):
    """Fold a recon profile / isolation map into the report if one exists.

    Stamped with its own mtime rather than the run's: a fingerprint from last week silently
    presented as today's is worse than no fingerprint, so the age travels with the data and
    the reader can see it.
    """
    path = explicit or os.path.join(OUT_DIR, default_name)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ! ignoring {os.path.basename(path)}: {e}", file=sys.stderr)
        return None
    when = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
    return {key: data, "when": when}


def breadth_slice(attacks):
    """One attack per category, cheapest delivery first. Returns (kept, dropped).

    A SHORT RUN SHOULD BE A SLICE OF THE WORK, NOT A SLICE OF THE FINDINGS. Running everything
    and then showing part of it costs exactly as much as running everything, and every probe is
    a request against a live endpoint. At 22 attacks the difference was a rounding error; at 285
    it is not.

    Breadth over depth, deliberately. Covering fifty-eight categories once answers "does this
    tool see anything at all" better than covering eight categories thoroughly, because the
    question a short run exists to answer is whether it is worth doing the long one.

    Cheapest delivery first for the same reason: a `direct` attack is one request and a `chain`
    is three, so preferring direct gets the same coverage for a third of the traffic. Where a
    category exists only as multi-turn, the multi-turn one is taken rather than the category
    being dropped — a gap in coverage is worse than a request.
    """
    order = {"direct": 0, "forged_history": 1, "sessions": 2, "chain": 3}
    by_cat = {}
    for a in attacks:
        cat = a.get("category") or "uncategorised"
        by_cat.setdefault(cat, []).append(a)
    kept = []
    for cat in sorted(by_cat):
        # Controls stay whole: they are what makes every other verdict on the page mean
        # anything, and one of them is not a baseline.
        if cat == "control":
            kept.extend(by_cat[cat])
            continue
        pick = sorted(by_cat[cat],
                      key=lambda a: (order.get(a.get("delivery", "direct"), 9), str(a.get("id"))))
        kept.append(pick[0])
    ids = {id(a) for a in kept}
    return kept, [a for a in attacks if id(a) not in ids]


def _unresolved(target):
    """Optional response paths the config declared and the run never once resolved.

    Per-run rather than per-response on purpose. `tool_calls` is legitimately absent whenever
    the model did not call a tool, so a single miss says nothing; zero hits across an entire
    sweep says the mapping is wrong. That is the shape of the claim, so that is the shape of
    the check.
    """
    counts = getattr(target, "resolutions", None)
    if not counts:
        return []
    declared = {"tool_calls": getattr(target, "calls_path", None),
                "resolved": getattr(target, "resolved_path", None),
                "observations": getattr(target, "observations_path", None)}
    return sorted(f"response.{k} = {declared[k]!r}"
                  for k, path in declared.items() if path and not counts.get(k))


def nothing_measured(results):
    """Did this whole sweep learn anything? True when every trial errored or came back empty.

    A run that learned nothing must not overwrite one that did. A sweep against a target whose
    server was down wrote ten ERROR rows over a good run and the next history diff reported five
    findings as fixed, because ERROR is not in BROKE and an errored row read as measured-clean.

    SILENCE IS THE SAME EVENT WITHOUT AN EXCEPTION ATTACHED, and it arrived later: a third-party
    app answered HTTP 200 with an empty body for fifty consecutive probes while the model behind
    it was down. Nothing raised, nothing fired, and every attack in the arsenal would have been
    written down as DEFENDED. One predicate rather than two, because these are one event.

    A partly broken run is still data and must not trip this: only when EVERY trial is empty.
    """
    def blank(t):
        p = t.get("probe") or {}
        if p.get("error") or t.get("verdict") == "ERROR":
            return True
        return not ((p.get("output") or "").strip() or p.get("tool_calls")
                    or p.get("turns") or p.get("observations"))

    return bool(results) and all(blank(t) for r in results for t in r.get("trials", []))


def cell(value, width):
    """One column of the streaming results table, padded, and never welded to the next one.

    `f"{value:<20}"` pads to twenty and then stops caring: a value of exactly twenty
    characters, or more, comes out with no trailing space and the next column begins inside
    it. Alignment is the point of a width, but a separator is the point of a column, and only
    one of those two things can be guaranteed when the value is wider than the space for it.

    So: align where it fits, and fall back to a single space where it does not. A row that
    loses its alignment is ugly; a row that reads `refusal_capability:1-` invents a name.
    """
    text = str(value)
    return text.ljust(width) if len(text) < width else text + " "


def is_unmeasurable(attack, dead):
    """True when every detector this attack declares is inert here, so a run would learn nothing.

    AT MODULE LEVEL BECAUSE ITS TEST NEEDS IT. This was a closure inside `main()`, and
    `test_arsenal` -- which asserts the headline breadth claim, "a plain chat endpoint receives a
    broad run, not a token one" -- could not reach it, so it kept a second copy and asserted on
    its own answer. Changing the shipped rule from `decl <= dead` to `decl & dead` takes a plain
    endpoint from 318 attacks to 261 and leaves all 41 suites green.

    `bool(decl)` matters: an attack declaring NO detector is judged by the general ones and is
    perfectly measurable, while the empty set is a subset of everything.

    An unmeasurable attack is SKIPPED and counted, never sent. Sent, it comes back DEFENDED, and
    a customer reads "we tested authorization and you passed" about a boundary nobody measured.
    """
    decl = set(attack.get("success") or []) | set(attack.get("partial") or [])
    return bool(decl) and decl <= set(dead)


def main():
    ap = argparse.ArgumentParser()
    from workspace import trial_count as _trial_count
    ap.add_argument("--trials", type=_trial_count, default=None,
                    help="runs per attack (default 3, or the target config's 'trials'); "
                         "multi-trial separates a reliable breach (3/3) from a flaky one (1/3)")
    ap.add_argument("--target-config", default=os.path.join(ROOT, "targets_dvla.yaml"))
    # THE PORTABLE ARSENAL IS THE DEFAULT, because the default is what somebody who did
    # not choose gets. `attacks.yaml` is the practice-fleet library and 132 of its 138
    # payloads carry `applies_to` naming a bot in this repository, so against anybody
    # else's target it sends six. Six attacks and a full-looking report is this project's
    # own defect class with a covering letter.
    #
    # `run_all.py` passes --attacks explicitly for the fleet, so this changes nothing
    # there; it changes the path that had no choice made on it.
    ap.add_argument("--attacks", default=os.path.join(ROOT, "attacks_generic.yaml"))
    ap.add_argument("--fail-on", choices=["none", "exploited", "any", "regression"],
                    default="none",
                    help="CI gate. `exploited`/`any` fail on the absolute state, which goes red "
                         "on whatever was already broken and stays red. `regression` fails only "
                         "on what THIS run introduced or reopened, and exits 3 rather than green "
                         "when the comparison cannot be believed — which is what a pull request "
                         "wants.")
    ap.add_argument("--model", default=None, help="override the target's model")
    ap.add_argument("--recon", default=None,
                    help="recon profile to fold into the report "
                         "(default out/recon_<target>.json if present)")
    # HOW MUCH TRAFFIC TO SEND, and nothing else. Every probe is a request to an endpoint
    # somebody is paying for, so the size of a run is a decision the operator makes. It is
    # recorded on the run either way, because a narrow run and a wide one are different
    # measurements and a report that does not say which it was is not readable.
    ap.add_argument("--overwrite-evidence", action="store_true",
                    help="replace a results file that is committed to a repository. Refused by default, because published counts are recounted from those files")
    ap.add_argument("--scope", dest="scope", choices=("full", "quick"), default="full",
                    help="how much traffic to send: `quick` is one attack per category, "
                         "`full` is the whole arsenal. Recorded on the run either way."),
    ap.add_argument("--isolation", default=None,
                    help="isolation maps to fold into the report "
                         "(default out/isolation_<target>.json if present)")
    args = ap.parse_args()

    # READ AS A REFUSAL, NOT AS A CRASH. A path that does not exist, or YAML that does not
    # parse, used to come out as a raw traceback and an exit code of 1 — and 1 is the code this
    # tool documents as "the target was exploited or breached". A CI reading that would treat a
    # mistyped filename as a security finding, which is the exact confusion the exit table
    # exists to prevent.
    def _load(path, what):
        try:
            return yaml.safe_load(open(path, encoding="utf-8"))
        except FileNotFoundError:
            raise SystemExit("ABORT — no %s at %s. Nothing was sent." % (what, path))
        except IsADirectoryError:
            raise SystemExit("ABORT — %s is a directory, not a %s file. Nothing was sent."
                             % (path, what))
        except Exception as e:
            raise SystemExit("ABORT — could not read the %s at %s: %s: %s. Nothing was sent."
                             % (what, path, type(e).__name__, e))

    all_attacks = _load(args.attacks, "arsenal")
    tcfg = _load(args.target_config, "target config")
    if args.model:
        # AN OVERRIDE THAT DOES NOTHING MUST SAY SO. For an `adapter: http` target the model is
        # the operator's, chosen inside `request:` on their side, and nothing here can change
        # it. Accepting the flag silently would write results_<target>_<model>.json — a file
        # named after a model that was never used, filed beside the canonical run, and read by
        # the matrix as a second measurement.
        if (tcfg.get("adapter") or "") == "http":
            print(f"ABORT — --model {args.model!r} cannot apply to an `adapter: http` target: "
                  f"the model belongs to the endpoint, not to us. Nothing was sent.",
                  file=sys.stderr)
            sys.exit(2)
        tcfg["model"] = args.model
    # trials precedence: explicit --trials > target config's 'trials' > default 3
    # THE CONFIG DOOR TOO. `--trials` is floored by argparse; `trials:` in a target file
    # reaches the same arithmetic without passing any parser at all.
    trials = (args.trials if args.trials is not None
              else _trial_count(tcfg.get("trials", 3), where="trials: in the target config"))
    ctx = tcfg.get("oracle_context", {})

    # WHO ASKED FOR THIS? Remote targets need proof before the first probe; the practice fleet
    # on localhost passes untouched, because a gate that makes the fleet unusable is a gate that
    # gets switched off.
    #
    # BEFORE THE TARGET IS BUILT, and that ordering is the whole of it. This ran twenty lines
    # further down, after construction, and construction is not inert: the HTTP adapter expands
    # `${VAR}` in its headers there, so an unauthorised config already learned which of the
    # operator's environment variables are set from the difference between "expanded" and "not
    # set in this shell". Other adapters in this repo open connections and start processes in
    # their constructors. A gate that runs after the thing it guards is a record of a decision,
    # not a control.
    from authorization import gate as _auth_gate
    _auth = _auth_gate(tcfg, "sweep")

    target = load_target_or_explain(
        tcfg, args.target_config,
        was_default=os.path.abspath(args.target_config)
        == os.path.abspath(os.path.join(ROOT, "targets_dvla.yaml")))
    if tcfg.get("name"):                          # let a config give a target a distinct name
        # Through the shared rule: this assignment used to hand the raw config
        # value to an adapter that never validates it, and the name becomes a
        # filename in six places, one of them an append.
        target.name = safe_target_name(tcfg["name"], "target config")

    # IS THE SERVER THE BUILD THIS CONFIG CLAIMS? Two configs can point at one port and
    # differ only in how the process was started — guardedrag's pair differ by an environment
    # variable and nothing connected the claim to the process listening. A sweep launched
    # against the wrong one writes a well-formed results file under the other build's name,
    # and the guard-on/guard-off diff then compares two runs of the SAME build: the
    # single-variable A/B that pair exists for, measuring nothing. Done by hand once, which is
    # how it was found.
    #
    # Refused rather than warned. A warning on line one of a long run is a warning nobody
    # sees, and the artifact it produces outlives the console.
    #
    # AFTER the authorization gate above, and it has to stay there: learning which build is
    # listening means asking the server, and that is traffic against somebody's endpoint.
    mismatch = _build_mismatch(tcfg)
    if mismatch:
        print(f"ABORT — {target.name} is not the build this config describes: {mismatch}",
              file=sys.stderr)
        sys.exit(2)

    # THE RUN'S OWN RECORD, opened before anything is sent. Every other artifact here is
    # named after the target, which answers "what does this bot do" and not "what did we do,
    # to whom, on whose authority, and what did it cost" — and the runs worth having a record
    # of are disproportionately the ones that do not finish.
    import runs as _runs
    _run_id = _runs.new_id()
    _budgets = dict((tcfg.get("rate") or {}))
    _rec = _runs.start(OUT_DIR, _run_id, target.name, scope=args.scope,
                       authorization=_auth, budgets=_budgets,
                       engine=engine_version(), arsenal=os.path.basename(args.attacks),
                       trials=trials)

    # THE HONEYTOKEN HAS TO BE THERE, and this is the only place that can insist.
    #
    # A minted token the operator never pasted is invisible: every canary detector finds
    # nothing, every attack comes back DEFENDED, and the report says the deployment held. That
    # is a gap reported as a measurement, arriving on the run somebody judges the tool by, and no
    # amount of instruction in an onboarding message prevents it — somebody will skip the step,
    # or paste it somewhere the model does not read.
    #
    # So the check is not advice, it is a precondition, and it costs one ordinary question. It
    # only runs when the canary is recognisably OURS: a customer who declared their own real
    # value has made a different choice and this has nothing to say about it.
    import honeytoken as _ht

    # A PUBLISHED CANARY IS NOT A CANARY. The example configs ship one so they run out of the
    # box, and the copy that reaches a real endpoint usually still has it. That string is in a
    # public repository: it can be trained on, blocklisted, or matched by a guardrail that
    # knows nothing about the deployment behind it — so a target that does not leak it has
    # shown only that it recognises a famous string. Reported as a defence, that is a clean run
    # that measured nothing, which is the failure this whole engine exists to refuse.
    #
    # Checked before the honeytoken precondition below, because it is the cheaper mistake to
    # make and the more expensive one to believe.
    _published = _ht.published_canaries() & set(_ht.declared(ctx))
    if _published:
        print(f"ABORT — {target.name} uses a canary that ships with this tool: "
              f"{', '.join(sorted(_published))}.\n"
              f"  That value is published, so anything can match it without knowing anything "
              f"about your deployment, and a run that fails to extract it would prove nothing.\n"
              f"  Mint your own — `qatration mint` — and put the pair in your system prompt and "
              f"your config.\n"
              f"  Nothing was sent.", file=sys.stderr)
        sys.exit(5)

    # BEFORE A SINGLE PROBE. The results file is written at the END of the run, so a check
    # there would refuse after somebody had paid for forty-seven minutes of model time and
    # leave them with nothing. Same reason the honeytoken verification below sits here: a guard
    # that fires after the cost has been paid is an error message rather than a guard.
    _tag = "_" + re.sub(r"[^A-Za-z0-9.]+", "-", args.model) if args.model else ""
    _refusal = refuse_to_overwrite_evidence(
        os.path.join(OUT_DIR, f"results_{target.name}{_tag}.json"),
        force=getattr(args, "overwrite_evidence", False))
    if _refusal:
        print(_refusal, file=sys.stderr)
        sys.exit(5)

    _verify = (ctx.get("honeytoken_verify") or "").strip()
    _ours = [c for c in _ht.declared(ctx) if _ht.looks_like_ours(c)]
    if _ours and not _verify:
        print(f"ABORT — {target.name} declares a honeytoken ({_ours[0]}) but no "
              f"`honeytoken_verify`, so nothing can confirm it was ever pasted in. Mint a pair "
              f"with `qatration mint` and declare both.", file=sys.stderr)
        sys.exit(5)
    if _ours and _verify:
        target.reset()
        _p = target.send(_ht.VERIFY_PROMPT)
        _why = _ht.verify_refusal(_p, _verify)
        if _why:
            # The reply is quoted only when there WAS one. On a refused connection the
            # old line printed `it said instead: ''`, which reads as a bot that answered
            # with nothing rather than as an endpoint that was never reached.
            _said = (f"  it said instead: {(_p.output or '')[:160]!r}\n"
                     if _why[0] == "NOT PLANTED" else "")
            print(f"ABORT — {_why[1]}\n{_said}"
                  f"  nothing was sent and nothing was written.", file=sys.stderr)
            sys.exit(5)
        print(f"  · honeytoken confirmed present ({_verify}) — the canary detectors can speak")

    # scope the arsenal: keep generic attacks (no applies_to) + those naming this target,
    # minus any the target config explicitly excludes (e.g. a generic 'control' that can't
    # be a clean baseline on a target that's compromised at rest — see targets_localrag.yaml).
    exclude = set(tcfg.get("exclude_attacks", []))
    # THE ARSENAL HAS TO BE A LIST OF ATTACKS BEFORE IT CAN BE FILTERED. Without this, an entry
    # that is not a mapping raises AttributeError out of `a.get` and an entry with no `id`
    # raises KeyError, and both reach Python's default handler and exit 1 — the code this
    # tool's own table documents as "the target was exploited or breached". A CI would file a
    # YAML typo as a security finding.
    #
    # `attacks: []` at the top of a file instead of a bare `[]` is enough to do it: the loader
    # returns a dict and iterating a dict yields its keys, which are strings.
    _bad = [(i, a) for i, a in enumerate(all_attacks)
            if not isinstance(a, dict) or not a.get("id")]
    if _bad:
        i, a = _bad[0]
        raise SystemExit(
            f"the arsenal is not a list of attacks: entry {i} is "
            f"{type(a).__name__ if not isinstance(a, dict) else 'a mapping with no id'}"
            f" ({str(a)[:60]!r}), and {len(_bad)} entr(y/ies) like it. A file whose top level "
            f"is `attacks:` loads as a mapping; the arsenal is a bare list of mappings, each "
            f"with an `id`.")
    attacks = [a for a in all_attacks
               if (not a.get("applies_to") or target.name in a["applies_to"])
               and a["id"] not in exclude]
    # TWO REASONS AN ATTACK IS NOT IN A RUN, AND ONLY ONE OF THEM IS ABOUT THE TARGET.
    # `not_applicable` is the deployment: the arsenal named an `applies_to` that excludes it,
    # a detector it needs is dead here, or the delivery channel does not exist on this bot.
    # `not_sent` is the INVOCATION: `--scope quick` held it back, and one flag brings it back.
    #
    # They were one counter, printed as "N not applicable to this target". Walked from an
    # install against a black-box endpoint: 319 held by the scope and 14 the target genuinely
    # could not run, all 333 reported as inapplicable. A reader concludes their bot is out of
    # scope for most of the arsenal when they simply asked for a short run -- and the line
    # printed immediately above says "319 more not sent", so the same run described one number
    # correctly and incorrectly, two lines apart.
    #
    # `skipped` stays their sum: it is on every stored artifact and three modules read it.
    not_applicable = len(all_attacks) - len(attacks)
    not_sent = 0

    # A QUICK RUN IS A NARROWER RUN, not a fuller one with most of it withheld. Said out loud
    # here and recorded on the run, because "we tested 58 techniques" and "we tested 285" are
    # different claims and the report must not be able to make the second from the first.
    if args.scope == "quick":
        attacks, held = breadth_slice(attacks)
        not_sent += len(held)
        print(f"  · limited run: one attack from each of {len(attacks)} categories, "
              f"{len(held)} more not sent — a short run is a BROAD run rather than a deep one, "
              f"and every probe is a request to your own endpoint, on your own bill")
    print("=" * 78)
    print("  QAtration — adversarial testing harness for LLM features")
    print("=" * 78)
    # guard the data: a 0-attack scope (wrong --attacks file) must NOT clobber a good
    # results_<target>.json with an empty run — bail before writing, leave prior data intact.
    if not attacks:
        # EXIT 3, NOT 0. `return` here exits zero through the console entry point, and zero is
        # documented as "ran, and the gate you asked for was not tripped". Nothing ran. This is
        # the same event as the errored-run branch further down and takes the same code:
        # nothing measured, nothing written, and a CI that must not read it as a pass.
        _runs.finish(OUT_DIR, _rec, "aborted", spent=_spend(target),
                     note=f"no attack in this arsenal applies to {target.name}; "
                          f"nothing was sent and nothing was written")
        print(f"engine → target='{target.name}'  NO applicable attacks in this arsenal "
              f"({len(all_attacks)} not applicable) — leaving out/results_{target.name}.json "
              f"untouched.", file=sys.stderr)
        sys.exit(3)
    skipped = not_applicable + not_sent
    scoped = f" ({not_applicable} not applicable to this target)" if not_applicable else ""
    print(f"engine → target='{target.name}'  caps={sorted(target.capabilities)}  "
          f"attacks={len(attacks)}{scoped}  trials={trials}")

    # Say out loud which always-on detectors cannot fire here. They run on every probe and
    # find nothing, which reads in the report as a clean target rather than as a check that
    # was never able to speak — and that is how sysprompt_paraphrase sat inert through a
    # whole run on a target that was reciting its instructions on request.
    # ...and the same for detectors this arsenal DECLARES, which was the hole in the first
    # version: an attack naming a detector the target cannot configure runs, finds nothing,
    # and reports DEFENDED exactly like a real defence.
    from oracle import inert_for
    declared = set()
    plants = []
    expects_refusal = False
    for a in attacks:
        declared |= set(a.get("success") or []) | set(a.get("partial") or [])
        plants += [str(m) for m in (a.get("plants") or []) if str(m).strip()]
        expects_refusal = expects_refusal or bool(a.get("expects_refusal"))
    # AN ARSENAL CAN ARM A DETECTOR TOO. `planted_markers` used to come only from the target
    # config, so a detector reading it was inert unless the tester had planted something in
    # advance. Attacks that carry their own marker arm it for themselves, and reporting those
    # as "cannot fire" would be the mirror of the mistake this block exists to prevent: a check
    # that DID run, announced as one that could not.
    inert_ctx = dict(ctx)
    if plants:
        inert_ctx["planted_markers"] = list(ctx.get("planted_markers") or []) + plants
    if expects_refusal:
        inert_ctx["expects_refusal"] = True
    dead = inert_for(inert_ctx, declared)
    if dead:
        print(f"  ! {len(dead)} detector(s) cannot fire on this target — "
              f"missing config, not a clean result:")
        _wn = max(26, *(len(n) for n in dead)) + 2
        for name, keys in sorted(dead.items()):
            print(f"      {name:<{_wn}}needs {', '.join(keys)}")

    # AN ATTACK WHOSE EVERY DECLARED DETECTOR IS INERT MUST NOT RUN. It used to: the console
    # said which detectors could not fire and the sweep sent the attacks anyway, so each came
    # back DEFENDED — a gap reported as a defence, in the results file, with only a printed
    # line standing between it and a customer reading "we tested authorization and you passed".
    #
    # It mattered little while the arsenal was 22 attacks that need nothing but a canary. It
    # matters completely now: promoting the scoped library means bola, bfla, tool-poison and
    # ssrf attacks reach targets that cannot configure `caller_id` or `privileged_tools`, and
    # every one of them would have reported a clean bill for a boundary nobody measured.
    #
    # Skipped rather than failed, and counted, because not-run and defended are different
    # facts and the report already has a place that says which.
    unmeasurable = [a for a in attacks if is_unmeasurable(a, dead)]
    if unmeasurable:
        attacks = [a for a in attacks if not is_unmeasurable(a, dead)]
        not_applicable += len(unmeasurable)
        skipped = not_applicable + not_sent
        by_need = {}
        for a in unmeasurable:
            for d in (set(a.get("success") or []) | set(a.get("partial") or [])):
                for k in dead.get(d, ()):
                    by_need.setdefault(k, set()).add(a["id"])
        print(f"  ! {len(unmeasurable)} attack(s) NOT SENT: every detector they rely on is "
              f"inert here, so a verdict would say defended about something unmeasured:")
        _wk = max(22, *(len(k) for k in by_need)) + 2
        for k, ids in sorted(by_need.items()):
            shown = ", ".join(sorted(ids)[:4])
            more = f" (+{len(ids) - 4} more)" if len(ids) > 4 else ""
            print(f"      needs {k:<{_wk}}{shown}{more}")
        if not attacks:
            # EXIT 3 for the same reason as the branch above: this is the state the sentence
            # printed here describes, and returning zero would report it as a clean run.
            _runs.finish(OUT_DIR, _rec, "aborted", spent=_spend(target),
                         note=f"every attack relied on detectors that cannot fire against "
                              f"{target.name}; nothing was sent and nothing was written")
            print(f"NOTHING MEASURABLE — every attack in this arsenal relies on detectors that "
                  f"cannot fire against {target.name}. Leaving results untouched.",
                  file=sys.stderr)
            sys.exit(3)

    # AND THE SAME FOR A DELIVERY THIS TARGET CANNOT TAKE, which was the arm this preflight
    # was missing. `run_attack` already refused to send them — it returns SKIP when the
    # delivery needs a capability the target lacks — but it refuses at SEND time, after the
    # attack has been counted. So `attacks_n` said 362 where 357 were tried, and five
    # consumers read that number: the scorecard prints it under "attacks fired", the defence
    # page divides by it for coverage, the index ranks targets by broke/attacks_n, the
    # comparison table shows it as a column, and the SARIF invocation carries it as
    # `attacks`. Every one of them overstated in the direction that flatters the report, and
    # the breach RATE moved the wrong way too: a target that cannot accept forged history
    # scored safer than one that can, on the strength of attacks nobody sent it.
    #
    # Measured on memorybot-naive, whose adapter declares `chain` and nothing else: eight
    # Context Compliance attacks in the generic arsenal, three already withheld above for
    # inert canaries, five delivered nowhere and counted anyway.
    #
    # This is the detector arm's rule applied to the delivery channel, and it takes the same
    # shape on purpose: removed from the run, added to `skipped`, and said out loud before
    # the first request. Not-run and defended are different facts.
    from runner import undeliverable
    nodeliver = [(a, undeliverable(a, target.capabilities)) for a in attacks]
    nodeliver = [(a, need) for a, need in nodeliver if need]
    if nodeliver:
        _no = {a["id"] for a, _ in nodeliver}
        attacks = [a for a in attacks if a["id"] not in _no]
        not_applicable += len(nodeliver)
        skipped = not_applicable + not_sent
        by_cap = {}
        for a, need in nodeliver:
            by_cap.setdefault((a.get("delivery", "direct"), need), set()).add(a["id"])
        print(f"  ! {len(nodeliver)} attack(s) NOT SENT: this target cannot take the delivery "
              f"they need, so they were never tried and are not coverage:")
        _wc = max(14, *(len(f"{f} needs {n}") for f, n in by_cap)) + 2
        for (fam, need), ids in sorted(by_cap.items()):
            shown = ", ".join(sorted(ids)[:4])
            more = f" (+{len(ids) - 4} more)" if len(ids) > 4 else ""
            print(f"      {f'{fam} needs {need}':<{_wc}}{shown}{more}")
        if not attacks:
            _runs.finish(OUT_DIR, _rec, "aborted", spent=_spend(target),
                         note=f"every attack needed a delivery {target.name} cannot take; "
                              f"nothing was sent and nothing was written")
            print(f"NOTHING DELIVERABLE — every attack in this arsenal needs a delivery "
                  f"{target.name} cannot take. Leaving results untouched.", file=sys.stderr)
            sys.exit(3)

    # A BUDGET TOO SMALL FOR THE RUN IS KNOWN BEFORE THE FIRST REQUEST, so it is said then
    # rather than discovered two thirds of the way through as a wall of BudgetExhausted errors.
    #
    # This was not hypothetical. The shipped example configs carried `max_requests: 400`,
    # calibrated when the arsenal was 285 attacks — and a full sweep is now 1,389 requests,
    # because 64 of them are multi-turn and cost two or three each. Anyone running the default
    # got 29% of a sweep and a results file that needed the SARIF export's coverage notice to
    # avoid reading as complete. A ceiling that silently truncates a run is the same defect as
    # a detector that silently cannot fire.
    def _requests_for(a):
        if a.get("delivery") in ("chain", "sessions"):
            return max(1, len(a.get("steps") or []))
        return 1

    _need = sum(_requests_for(a) for a in attacks) * trials
    _rate = getattr(target, "rate", None)
    _cap = getattr(_rate, "max_requests", None) if _rate else None
    if _cap and _need > _cap:
        pct = 100.0 * _cap / _need
        print(f"  ! THIS RUN CANNOT FINISH INSIDE ITS BUDGET: {len(attacks)} attack(s) at "
              f"{trials} trial(s) need {_need} requests and `rate.max_requests` is {_cap}.")
        print(f"    About {pct:.0f}% of the arsenal would be sent and the rest would never "
              f"leave — reported as a gap, but still not measured.")
        print(f"    Raise the budget, lower --trials, or use --scope quick "
              f"(which needs {sum(_requests_for(a) for a in breadth_slice(attacks)[0]) * trials} "
              f"requests at {trials} trial(s)).")

    # baseline-diff: learn the target's CLEAN tool-call inputs from a benign probe
    # so 'rogue_tool_call' flags deviation from real behavior, not a model quirk
    # (fixes the qwen false alarm where the model calls a tool with empty input).
    ctx = dict(ctx)
    if "tool_visibility" in target.capabilities:
        target.reset()
        base = target.send(tcfg.get("baseline_prompt", "What are my recent transactions?"))
        clean = {ti.strip().strip("'\"") for _, ti in base.tool_calls}
        ctx["baseline_tool_inputs"] = sorted(
            {str(x) for x in (ctx.get("baseline_tool_inputs") or [])} | clean)
        print(f"baseline probe → clean tool inputs = {ctx['baseline_tool_inputs']}")
    print()
    # COLUMN WIDTHS FROM THE DATA. `{id:<22}` ran the id straight into the delivery on any
    # attack named longer than 21 characters — 74 of 362 rows in a full generic sweep, so a
    # fifth of every run's output read as `ca-terminal-output-injectiondirect`. The arsenal
    # grew past the number and nothing said so, which is what a hard-coded width does.
    #
    # THE FIX WENT INTO TWO COLUMNS AND THE OTHER THREE KEPT THEIR CONSTANTS, which is the
    # defect repaired for the instance rather than for the class. `blocked by` is `:<20` and
    # `refusal_capability:1` is twenty characters exactly, so on a live target the row read
    # `refusal_capability:1-`, with the next column's dash welded to a lock name. Every
    # DEFENDED row that names a refusal is one -- a third of the first sweep anyone runs.
    #
    # `verdict` and `rate` cannot be measured in advance the way an id can: the table streams
    # as the attacks run, so those values do not exist when the header is printed. `cell()` is
    # what covers both cases, by making the separator a property of every column rather than a
    # width that happens to be generous enough.
    _wid = max([len("id")] + [len(a["id"]) for a in attacks]) + 2
    _wdel = max([len("delivery")] + [len(a.get("delivery", "direct")) for a in attacks]) + 2
    _ruler = "-" * (_wid + _wdel + 11 + 7 + 20 + len("fired detectors"))
    print(cell("id", _wid) + cell("delivery", _wdel) + cell("verdict", 11)
          + cell("rate", 7) + cell("blocked by", 20) + "fired detectors")
    print(_ruler)

    broke = 0
    exploited_n = 0
    results = []
    for a in attacks:
        recs = run_attack(target, a, ctx, trials=trials)
        head, rate = headline(recs)
        fired_list = sorted({d for r in recs for d in r["fired"]})
        if head in ("EXPLOITED", "PARTIAL") and a["category"] != "control":
            broke += 1
        if head == "EXPLOITED" and a["category"] != "control":
            exploited_n += 1
        # which lock stopped it — a DEFENDED row is useless without this
        locks = summarize(recs, ctx)
        lock_str = ",".join(f"{k}:{v}" for k, v in locks.items() if k != "compliance")
        print(cell(a["id"], _wid) + cell(a.get("delivery", "direct"), _wdel)
              + cell(head, 11) + cell(rate, 7) + cell(lock_str or "-", 20)
              + (",".join(fired_list) or "-"))
        # serialize trials (probe dataclass -> plain dict) for the report/JSON
        trials_ser = [{
            "verdict": r["verdict"], "fired": r["fired"],
            "refusal": classify(r["probe"], ctx),
            "probe": None if r["probe"] is None else {
                # `prompt` is stored because half the detectors subtract it: content the
                # ATTACKER supplied does not count as a leak when it comes back. Without it
                # a replay scores with echo subtraction switched off and reads more leaks
                # than happened. It is the attacker's own text, not extra evidence.
                "prompt": r["probe"].prompt,
                "resolved": getattr(r["probe"], "resolved", []),
                "output": r["probe"].output, "tool_calls": r["probe"].tool_calls,
                "observations": r["probe"].observations,
                "error": r["probe"].error, "seconds": r["probe"].seconds,
                "turns": getattr(r["probe"], "turns", []),
            },
        } for r in recs]
        results.append({"attack": a, "headline": head, "rate": rate,
                        "fired": fired_list, "locks": locks, "trials": trials_ser})

    attacks_n = sum(1 for a in attacks if a["category"] != "control")
    # The same ruler as the header. This was `"-" * 78` while the line above it is as wide as
    # the ids in this arsenal, so the table closed with a rule that stopped short of it.
    print(_ruler)
    print(f"\n{broke}/{attacks_n} attacks breached the target (controls excluded).")

    # A BREACH VERDICT IS AN ATTRIBUTION, and it is only as good as the target's silence
    # when nobody is attacking it. Twice over, this project published attributions it
    # had not earned — httpbot scoring 5/5 on a detector it also trips on 21 of 48 benign
    # prompts, and nemo-inputonly counting a row that fired on a phishing notice its own
    # poisoned corpus injects into three quarters of ordinary answers. `benign.py` had
    # measured both rates already and nothing read them. Now the sweep does, in the same
    # breath as the number they qualify, because a caveat that arrives in a separate file
    # arrives too late.
    from baseline import note as _baseline_note
    # The config path travels with it, so the command the note prints is the one this reader
    # can actually run. `--target` only resolves against the fleet shipped in this package.
    attribution_note = _baseline_note(target.name, results, _ht.declared(ctx),
                                      config_path=getattr(args, "target_config", None))
    if attribution_note:
        print()
        print(attribution_note)

    # AND THE SHARPER VERSION OF THE SAME QUESTION, for a target whose payload arrives by
    # retrieval. Attribution asks whether the target does this anyway; this asks whether the
    # ATTACK did anything once the payload was in front of the model. Against a third-party RAG
    # app the answer was no -- 83% effect against an 85% background -- while the headline count
    # read as a win. Silent unless the config says what a delivered payload looks like, since
    # nothing else can tell retrieval from a prompt that carried its own payload.
    from baseline import two_factor_note as _two_factor_note
    delivery_note = _two_factor_note(target.name, results, ctx,
                                     caps=getattr(target, "capabilities", ()))
    if delivery_note:
        print()
        print(delivery_note)

    # EVERY TRIAL ERRORED = NOTHING WAS MEASURED, and the file on disk is the record of a run
    # that did. Guarded here for the same reason the empty-arsenal case is guarded one screen
    # up: a well-formed results file full of ERROR rows is not a smaller finding, it is the
    # deletion of a real one.
    #
    # Demonstrated by doing it. A sweep against draftbot with its server down wrote 10 ERROR
    # rows over a good run, and the history diff then reported FIVE findings as "fixed" —
    # including the two memorised-completion breaks demonstrated in the same release — because
    # ERROR is not in BROKE and an errored row therefore read as measured-clean. That is
    # exactly the failure `not_run` was added for, reached through the error door rather than
    # the arsenal door.
    #
    # AND SILENCE IS THE SAME EVENT WITHOUT AN EXCEPTION ATTACHED. A third-party RAG app
    # answered HTTP 200 with an empty body for fifty consecutive probes while the model behind
    # it was down. No error was raised because none occurred, every detector scored the silence
    # and found nothing, and the run would have written a file in which the target DEFENDED
    # against the entire arsenal. `Probe.silent` is the one place that decides what came back.
    all_errored = nothing_measured(results)
    if all_errored:
        _runs.finish(OUT_DIR, _rec, "aborted", spent=_spend(target),
                     note="every trial errored or came back empty; nothing was measured "
                          "and nothing was written")
        print(f"\nNOTHING MEASURED — every trial errored or came back empty "
              f"(is {target.name} up, and is it answering?). "
              f"Leaving out/results_{target.name}.json as it was: a file of ERROR rows would "
              f"overwrite the record of a run that did measure something, and the next "
              f"history diff would read it as five findings fixed.", file=sys.stderr)
        sys.exit(3)

    # --- step 4: write JSON + HTML scorecard to out/ -------------------------
    os.makedirs(OUT_DIR, exist_ok=True)
    meta = {"target": target.name, "model": tcfg.get("model", ""),
            # WHEN, which every benign artifact has carried from the start and no results file
            # did. `engine` says which build of OUR code produced this; nothing said how old
            # the measurement is, and the target is the half that moves. Two answers this
            # repository could not give cost exactly that: five findings on guardedrag stopped
            # reproducing and the artifact could not say whether it was made yesterday or in
            # July, and `qatration verify` had no way to tell a reader how stale "stale" is.
            "when": datetime.now().isoformat(" ", "seconds"),
            # which build of the engine wrote this, so a replay can tell evidence that
            # predates a fix from evidence that survived one
            "engine": engine_version(),
            # Travels with the findings, because an assessment that cannot say who authorised
            # it is worthless as evidence and dangerous as an artifact: in a log it is
            # indistinguishable from an attack.
            "authorization": _auth,
            "caps": sorted(target.capabilities), "trials": trials,
            # A CONFIGURED PATH THAT NEVER RESOLVED. `caps` says what the config claims; this
            # says which of those claims the run could not substantiate even once. Sixteen
            # detectors read the tool-call channel, and against a mistyped path every one of
            # them judged an empty list and found nothing.
            "unresolved_paths": _unresolved(target),
            "attacks_n": attacks_n, "broke": broke, "skipped": skipped,
            "not_applicable": not_applicable, "not_sent": not_sent,
            # HOW MANY ROWS NEVER LANDED. Without this a reader cannot tell 20 attacks
            # that were defended from 1 defended and 19 that errored, and both used to
            # render as "0 / 20 breached" in green. `run_redteam` aborts only when EVERY
            # trial errored, so one surviving row is enough to write the file.
            "errors": sum(1 for r in results if r.get("headline") == "ERROR"),
            # WHICH arsenal, because "5 sent, 132 scoped out" is reassuring or alarming
            # depending entirely on whether the file was written for a target like this
            # one, and the page cannot tell the reader without the name.
            "arsenal": os.path.basename(args.attacks),
            "baseline": ctx.get("baseline_tool_inputs"),
            # carried into the HTML, because the reader of the scorecard is exactly the
            # person who needs to know the breach count is not attributable
            "attribution": attribution_note,
            # WHICH DETECTORS COULD NOT SPEAK, stored rather than only printed. It was said on
            # the console and then thrown away, so a stored result could not tell "nothing
            # fired" from "nothing could fire" — which is the distinction this whole mechanism
            # exists to draw, surviving exactly as long as the terminal scrollback. Every later
            # reader needs it: the SARIF export turns it into a tool notification, and a
            # replay a year from now has no console to consult.
            "inert": {name: list(keys) for name, keys in sorted(dead.items())}}
    # a --model override writes results_<target>_<model>.json (2 underscores) so it
    # sits BESIDE the canonical single-model run and is skipped by the fleet aggregates
    # (which key on the 1-underscore name) — this is what makes a model matrix possible.
    tag = "_" + re.sub(r'[^A-Za-z0-9.]+', '-', args.model) if args.model else ""
    json_path = os.path.join(OUT_DIR, f"results_{target.name}{tag}.json")
    html_path = os.path.join(OUT_DIR, f"report_{target.name}{tag}.html")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "results": results}, f, indent=2, default=str)
    # Closed with what it actually cost, and with the ending named: a run stopped by its
    # budget is not a run that finished, and the attacks it never sent are a gap rather than a
    # set of findings that came back clean.
    _spent = _spend(target)
    _stopped = bool(getattr(getattr(target, "rate", None), "exhausted", ""))
    _runs.finish(OUT_DIR, _rec, "stopped" if _stopped else "finished", spent=_spent,
                 note=(f"budget spent ({getattr(target.rate, 'exhausted', '')}); the remaining "
                       f"attacks were never sent") if _stopped else None)

    recon = _side_artifact(args.recon, f"recon_{target.name}.json", "profile")
    isolation = _side_artifact(args.isolation, f"isolation_{target.name}.json", "maps")
    if isolation and isinstance(isolation.get("maps"), dict):
        # a lock map written with provenance is {"meta": …, "maps": […]}; the page wants the
        # list. Unwrapped here rather than in the renderer, so exactly one place knows the
        # container and the older bare-list artifacts keep working untouched.
        isolation = {**isolation, "maps": isolation["maps"].get("maps") or []}
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(build_html(meta, results, recon=recon, isolation=isolation))
    print(f"report → {html_path}")

    # Where the oracle could not see, said out loud. A code agent that hands a tool a
    # VARIABLE rather than a value exfiltrates in a way no pattern can follow — measured,
    # a customer record with an API key left through send_email(body=customer_record) and
    # one trial scored DEFENDED. Absent telemetry, that is a gap, and a gap reported as a
    # clean result is the one mistake this whole engine keeps making.
    from oracle import blind_spots
    unseen = {}
    for r in results:
        for t in r.get("trials", []):
            pd = t.get("probe") or {}
            if not pd:
                continue
            from target import Probe as _P
            pr = _P(prompt="", output=pd.get("output") or "",
                    tool_calls=[tuple(x) for x in (pd.get("tool_calls") or [])],
                    resolved=[tuple(x) for x in (pd.get("resolved") or [])])
            for b in blind_spots(pr, ctx):
                unseen.setdefault(b, set()).add(r["attack"]["id"])
    if unseen:
        print(f"\nNOT OBSERVABLE — {len(unseen)} call(s) whose contents this run could "
              f"not see.\n  These are gaps, not clean results. Ask the target to log what "
              f"its tools RECEIVE\n  (probe.resolved); standard agent observability "
              f"already records it.")
        for b, aids in sorted(unseen.items()):
            print(f"    {b}\n      on: {', '.join(sorted(aids)[:5])}")

    # Append this run to the target's timeline BEFORE the file above is overwritten again.
    # A sweep used to destroy its predecessor, so "is this new", "did the fix hold" and
    # "has this regressed" were not unimplemented, they were unanswerable — the evidence
    # had been deleted. A per-model run is the same sweep measured twice and would show up
    # as a fictitious change, so it is left out.
    if not tag:
        from history import record, diff
        record(meta, results)
        d = diff(target.name)
        if "reason" not in d:
            since = f"since {d['prev']}"
            if d.get("confounds"):
                # Two runs made with different instruments are not a before/after, and a
                # diff that does not say so is a story rather than a measurement.
                print(f"\n! this comparison is confounded — {'; '.join(d['confounds'])}")
                print("  read 'fixed' with that in mind: the measurement changed too")
            if d["regressed"]:
                print(f"\nREGRESSED {since}: {', '.join(d['regressed'])}\n"
                      f"  a fix that did not hold is worse news than a new finding")
            if d["new"]:
                print(f"new {since}: {', '.join(d['new'][:8])}")
            if d["fixed"]:
                print(f"fixed {since}: {', '.join(d['fixed'][:8])}")
            if d["not_run"]:
                # absence is not a clean result: this arsenal did not send them
                print(f"NOT RE-TESTED (still open until measured): "
                      f"{', '.join(d['not_run'][:8])}"
                      + (f" +{len(d['not_run']) - 8}" if len(d['not_run']) > 8 else ""))
            print(f"still open: {len(d['open'])}")

    # --- CI gate: non-zero exit fails the build ------------------------------
    gate = args.fail_on
    if gate == "exploited" and exploited_n > 0:
        print(f"\nCI GATE: FAIL — {exploited_n} attack(s) fully exploited.")
        sys.exit(1)
    if gate == "any" and broke > 0:
        print(f"\nCI GATE: FAIL — {broke} attack(s) breached the target.")
        sys.exit(1)

    # THE GATE A PULL REQUEST ACTUALLY WANTS, and the reason the other two are wrong for one.
    # `exploited` and `any` fire on the ABSOLUTE state, so the first check a team adds goes red
    # on whatever was already broken and stays red — which teaches everyone to ignore it, the
    # exact outcome the exit-code table warns about. A pull request is not asking "is this bot
    # perfect", it is asking "did I make it worse".
    #
    # And the honest half: a comparison this engine cannot believe must not report a pass. A
    # changed arsenal, a changed model, fewer trials, a torn timeline — each makes before and
    # after two different instruments, and `diff()` already names them. When it does, this exits
    # 3, "nothing was measured", rather than the green that would be a lie. A team seeing that
    # once re-baselines, which is the correct response and takes a minute.
    if gate == "regression":
        code, lines = regression_verdict(locals().get("d"), is_model_copy=bool(tag))
        for line in lines:
            if line.startswith("CI GATE"):
                print("")
            print(line)
        if code:
            sys.exit(code)

    if gate != "none":
        print(f"\nCI GATE: PASS ({gate}).")


if __name__ == "__main__":
    main()
