"""
Tests for the number this project rests on — no model, no network.

`detector_coverage.py` produces the one figure that makes a detector count mean anything:
how many of them have ever caught something on a live target. A defect here does not
produce a wrong log line, it produces a wrong CLAIM, and it had three:

  * the prompt was reconstructed from `attack["text"]`, so a chain or session attack —
    whose turns live in `steps` — replayed with an EMPTY prompt and echo subtraction
    switched off, inflating the very number the tool exists to publish. The same defect
    rejudge had, in a second file;
  * a detector that RAISED on real data was swallowed and landed in "declared only", which
    reads as "no target does this" when the truth is "this one is broken";
  * "never fired" was reported as a single cause, under a sentence claiming no target in
    the fleet exhibits the behaviour — false for any detector whose config is missing
    everywhere.

  * and then the split into causes had the defect it was written to prevent: it asked
    `inert_for(ctx)` without `declared`, which walks only the always-on sets, so the "cannot
    fire as configured" bucket was reachable by nothing that was not always-on. It computed
    to the empty set on the whole fleet. `memorised_completion` — config-gated, supplied by
    no target, declared by no attack — was filed under "no target exhibits this behaviour",
    an assertion about the targets sourced from a detector that could not speak.

    python test_coverage.py      # exits 1 on any failure (CI gate)
"""
import sys, os, json, tempfile, shutil
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import detector_coverage as dc
from oracle import DETECTORS, inert_for, NEEDS_CONFIG
from target import Probe

CANARY = "COV-CANARY-7712"


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- the inflation: a multi-turn attack must replay with its whole attacker side ---
    # The attacker typed the canary in turn one. Counting that as a catch would credit
    # every echo-subtracting detector with a hit it never earned.
    tmp = tempfile.mkdtemp()
    try:
        chain = {"meta": {"target": "cov-fake"},
                 "results": [{"attack": {"id": "c1", "category": "x", "delivery": "chain",
                                         "steps": [f"remember {CANARY}", "what is it?"]},
                              "trials": [{"probe": {"output": f"you said {CANARY}",
                                                    "tool_calls": [], "observations": [],
                                                    "seconds": 0, "turns": []}}]}]}
        with open(os.path.join(tmp, "results_cov-fake.json"), "w", encoding="utf-8") as f:
            json.dump(chain, f)

        real_out, real_ctx = dc.OUT, dc.contexts
        dc.OUT = tmp
        dc.contexts = lambda: {"cov-fake": {"canaries": [CANARY]}}
        hits, where, n, broke, sources = dc.replay()
        dc.OUT, dc.contexts = real_out, real_ctx
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- HOW MUCH EVIDENCE THE CLAIM RESTS ON -------------------------------------------
    #
    # `buckets` asks whether a detector COULD speak, from config keys, and a detector that
    # reads tool arguments needs no key and can still be unable to speak: the probes it was
    # replayed over came from targets with no tools. `secret_material_access` sat under "no
    # target in the fleet exhibits this behaviour" on 127 probes from its own thirteen
    # attacks, ONE of which carried a tool call -- and the fleet's only code agent, the
    # deployment the detector was written for, has never received one of the thirteen.
    #
    # THE RULE IS DERIVED FROM THE DETECTOR, so arm it before trusting it: a `reads_tool_calls`
    # that answered False for everything, or True for everything, would leave the count below
    # printed under the wrong sentence with nothing to notice.
    from oracle import reads_tool_calls as _reads
    check("the rule can tell a detector that reads tool calls", _reads("secret_material_access"))
    check("...from one that reads only the reply", not _reads("divergent_repetition"))
    check("...and answers False for a name that is not a detector", not _reads("no_such_thing"))

    tmp3 = tempfile.mkdtemp()
    try:
        # Two attacks naming one detector, two probes each: one carrying a tool call and one
        # not. The count has to separate them, because "127 probes" and "1 of them could
        # show anything" are different sentences about the same run.
        art = {"meta": {"target": "cov-fake"}, "results": [
            {"attack": {"id": "a1", "category": "x", "success": ["_cov_named"]},
             "trials": [{"probe": {"output": "no", "tool_calls": [], "observations": [],
                                   "seconds": 0, "turns": []}},
                        {"probe": {"output": "no", "tool_calls": [["run", "ls"]],
                                   "observations": [], "seconds": 0, "turns": []}}]},
            {"attack": {"id": "a2", "category": "x", "partial": ["_cov_named"]},
             "trials": [{"probe": {"output": "no", "tool_calls": [], "observations": [],
                                   "seconds": 0, "turns": []}}]},
            {"attack": {"id": "a3", "category": "x", "success": ["_cov_other"]},
             "trials": [{"probe": {"output": "no", "tool_calls": [["run", "ls"]],
                                   "observations": [], "seconds": 0, "turns": []}}]}]}
        with open(os.path.join(tmp3, "results_cov-fake.json"), "w", encoding="utf-8") as f:
            json.dump(art, f)
        real_out, real_ctx = dc.OUT, dc.contexts
        dc.OUT = tmp3
        dc.contexts = lambda: {"cov-fake": {}}
        sup = {}
        dc.replay(support_out=sup)
        dc.OUT, dc.contexts = real_out, real_ctx
    finally:
        shutil.rmtree(tmp3, ignore_errors=True)

    check("a detector's own attacks are counted whether they name it to succeed or partly",
          sup.get("_cov_named", [0, 0])[0] == 3, f"support: {sup}")
    check("...and the probes that carried something it could read are counted apart",
          sup.get("_cov_named", [0, 0])[1] == 1, f"support: {sup}")
    check("...and a detector no attack named gets no credit for another one's probes",
          sup.get("_cov_named", [0, 0]) != sup.get("_cov_other", [0, 0]), f"support: {sup}")
    check("a detector nothing aimed at has no support at all",
          "_cov_unnamed" not in sup, f"support: {sup}")

    check("a multi-step attack replays with every turn the attacker typed", n == 1)
    check("the attacker's own canary is not credited as a catch",
          not hits.get("canary_transformed") and not hits.get("canary_in_tool_call"),
          f"hits: {dict(hits)}")
    # ...but the canary really being in the reply is still a catch: canary_in_output does
    # not subtract the prompt, because a secret shown to the user has left either way.
    check("a canary in the visible reply is still counted",
          hits.get("canary_in_output") == 1, f"hits: {dict(hits)}")

    # --- a detector that throws must be reported, not filed as 'never fired' -----------
    tmp = tempfile.mkdtemp()
    try:
        data = {"meta": {"target": "cov-fake"},
                "results": [{"attack": {"id": "a", "category": "x", "text": "hi"},
                             "trials": [{"probe": {"output": "ok", "tool_calls": [],
                                                   "observations": [], "seconds": 0,
                                                   "turns": []}}]}]}
        with open(os.path.join(tmp, "results_cov-fake.json"), "w", encoding="utf-8") as f:
            json.dump(data, f)

        def boom(probe, ctx):
            raise RuntimeError("this detector is broken")

        DETECTORS["_cov_boom"] = boom
        real_out, real_ctx = dc.OUT, dc.contexts
        dc.OUT = tmp
        dc.contexts = lambda: {"cov-fake": {}}
        try:
            hits2, _, n2, broke2, _s2 = dc.replay()
        finally:
            dc.OUT, dc.contexts = real_out, real_ctx
            del DETECTORS["_cov_boom"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    check("a throwing detector does not take the replay down", n2 == 1)
    check("a throwing detector is counted, not silently filed as never-fired",
          broke2.get("_cov_boom") == 1, str(dict(broke2)))
    check("...and it is not counted as a hit either", not hits2.get("_cov_boom"))

    # --- 'never fired' has three causes, and only one is closed by a new target --------
    # A detector needing config that no target supplies is untested, not exonerated.
    empty = inert_for({}, DETECTORS)
    check("a detector needing config is reported as inert on an empty context",
          "sysprompt_paraphrase" in empty, str(sorted(empty)[:4]))
    check("the same detector is not inert once the config exists",
          "sysprompt_paraphrase" not in inert_for({"system_prompt": "x" * 200}, DETECTORS))

    # The question has to be asked over the same set the replay RUNS, which is all of
    # DETECTORS — not the always-on sets `inert_for` walks by default. Asked over the smaller
    # set, every config-gated detector that is not always-on answers "not inert" and lands in
    # the bucket that claims the fleet does not exhibit the behaviour. `memorised_completion`
    # is that case in the shipping oracle and this is the check that would have caught it.
    missed = sorted(k for k in NEEDS_CONFIG if k not in inert_for({}, DETECTORS))
    check("EVERY config-gated detector is inert on an empty context, always-on or not",
          not missed, f"not reported inert: {missed}")

    # ...and both directions, because a check that passes by calling everything inert is
    # indistinguishable from one that passes on the merits.
    # An entry may be a tuple meaning "any one of these", so flatten before building the
    # fully-configured ctx — a key that is a tuple satisfies nothing.
    def _keys(spec):
        for entry in spec:
            if isinstance(entry, (tuple, list)):
                yield from entry
            else:
                yield entry

    full = {k: (["x" * 40] if k not in ("system_prompt",) else "x" * 200)
            for spec in NEEDS_CONFIG.values() for k in _keys(spec)}
    full["max_output_chars"] = 12000
    still = sorted(k for k in NEEDS_CONFIG if k in inert_for(full, DETECTORS))
    check("...and none of them is inert once every key it names is supplied",
          not still, f"still inert with full config: {still}")

    # --- AN ATTACK THAT HAS NEVER BEEN SENT IS A CLAIM, NOT A CAPABILITY ---------------------
    #
    # This tool has always separated a detector that has caught something from one that has only
    # been written. The same question about the ARSENAL was not being asked, and the arsenal size
    # is a number this project publishes: 357 attacks, 184 of them with a stored trial. Somebody
    # counting the first and reading `out/` would assume the second.
    #
    # The check is that the count is DERIVED — `replay()` collecting real ids out of real
    # artifacts — rather than a number somebody typed. A hardcoded 184 would pass any assertion
    # about its value.
    sent = set()
    _scanned = set()
    dc.replay(None, None, sent, scanned_out=_scanned)
    check("the replay collects the attack ids it has evidence for", len(sent) > 50,
          f"only {len(sent)} distinct attack id(s) found in every stored sweep")
    # AND WHICH TARGETS IT ACTUALLY READ, which is what keeps "no target in the fleet does
    # this" from being said about targets nobody ran. The bucket unit tests above pass a
    # `scanned` set by hand, so they stay green if `replay` quietly stops filling one —
    # measured by mutation: removing the collection put `hallucinated_package` straight back
    # under the fleet claim with every test still passing. This is the half they cannot see.
    check("...and reports which targets it actually read a probe for",
          len(_scanned) > 10 and _scanned <= set(dc.contexts()),
          f"{len(_scanned)} target(s) scanned: {sorted(_scanned)[:5]}")
    import yaml as _y
    arsenal = {a["id"] for a in
               _y.safe_load(open(os.path.join(HERE, "attacks_generic.yaml"),
                                 encoding="utf-8"))}
    check("...and they are real ids from the arsenal, not strings from somewhere else",
          len(sent & arsenal) > 50, f"{len(sent & arsenal)} of {len(sent)} are in the arsenal")
    src = open(os.path.join(HERE, "detector_coverage.py"), encoding="utf-8").read()
    check("...and the tool prints how many were never sent",
          "never sent against anything" in src,
          "the arsenal-coverage line is gone, so the gap is unreported again")

    # --- AND THE OTHER DIRECTION: A DETECTOR MISSING FROM THE TABLE -------------------------
    #
    # Everything above asks whether the detectors ALREADY in NEEDS_CONFIG behave. Nothing asked
    # the question the CONTRIBUTING rule actually states — a detector that needs configuration
    # must be listed — and `inert_for` cannot be used to ask it, because `inert_for` is driven
    # by NEEDS_CONFIG. It is the table interviewing itself. The eleven detectors that rule was
    # written about were found by hand, once, by somebody who went looking.
    #
    # Reading the source was tried and produced noise in both directions: twelve detectors reach
    # their keys through helpers, and `sysprompt_leak` keeps built-in phrases on purpose and
    # degrades rather than going silent, so "reads ctx" is not the property.
    #
    # THE BEHAVIOURAL QUESTION IS: can this detector say anything at all with no configuration?
    # `test_oracle.CASES` already holds, for every detector, a probe that makes it fire and the
    # context it needs — so the firing cases of an undeclared detector get re-run against `{}`.
    # If not one of them still fires, the detector is config-gated in fact and undeclared in the
    # table, and its silence on an unconfigured target would be reported as a defence.
    #
    # It found one on the first run: `refusal_then_comply`, which returns whatever
    # `canary_in_output`, `canary_transformed` or `forced_output` returns and so inherits all
    # three gates while declaring none.
    import test_oracle as _to
    firing = {}
    for case in _to.CASES:
        if case[4]:                                   # (label, detector, probe, ctx, expected)
            firing.setdefault(case[1], []).append((case[0], case[2]))

    check("every detector has at least one case that makes it fire, or the question below "
          "cannot be asked of it",
          not sorted(set(DETECTORS) - set(firing)), str(sorted(set(DETECTORS) - set(firing))))

    mute = []
    for name in sorted(set(DETECTORS) - set(NEEDS_CONFIG)):
        cases = firing.get(name) or []
        if cases and not any(DETECTORS[name](probe, {}) for _label, probe in cases):
            mute.append(name)
    check("a detector that cannot fire without configuration is IN the table",
          not mute, f"config-gated in fact, undeclared: {mute}")

    # ...AND THE CHECK IS SHOWN FAILING, in this process, because one that passes by examining
    # nothing looks identical to one that passes on the merits. A known-gated detector is
    # removed from the table and the check above must find it.
    _saved = NEEDS_CONFIG.pop("canary_in_output")
    try:
        replanted = [n for n in sorted(set(DETECTORS) - set(NEEDS_CONFIG))
                     if (firing.get(n) or [])
                     and not any(DETECTORS[n](p, {}) for _l, p in firing[n])]
        check("...and that check catches a gated detector taken OUT of the table",
              "canary_in_output" in replanted, f"it found {replanted}")
    finally:
        NEEDS_CONFIG["canary_in_output"] = _saved
    check("...and the table is restored afterwards",
          NEEDS_CONFIG.get("canary_in_output") == ["canaries"])

    # THE REVERSE IS NOT A RULE, and asserting it was wrong. Three detectors are declared here
    # and still fire on an empty context, because they are PARTLY gated: `lookalike_domain`
    # catches punycode and mixed-script hosts structurally and needs `allowed_domains` only to
    # judge whether a domain is one of yours; `unbounded_output` falls back to a 12,000-character
    # default; `mass_assignment` carries built-in privileged field names. Declaring them is what
    # lets `inert_for` tell an operator that half a check did not run.
    #
    # The declaration has a cost — `_unmeasurable` refuses to send an attack whose every
    # detector is inert — so it was measured rather than assumed: on a config with no
    # `oracle_context` at all, 76 of 357 attacks are held back, and ZERO of them rely only on
    # these three. The cost is currently nil. This asserts that, so an arsenal change that makes
    # it stop being nil is visible rather than silent.
    _partly = {"lookalike_domain", "mass_assignment", "unbounded_output"}
    import yaml as _yaml
    _atk = _yaml.safe_load(open(os.path.join(HERE, "attacks_generic.yaml"), encoding="utf-8"))
    _dead = set(inert_for({}, DETECTORS))
    _lost = [a["id"] for a in _atk
             if (set(a.get("success") or []) | set(a.get("partial") or []))
             and (set(a.get("success") or []) | set(a.get("partial") or [])) <= _partly]
    check("no attack is held back solely by a detector that would have worked anyway",
          not _lost, f"not sent, but every detector they name still fires unconfigured: {_lost}")

    # --- the bucket split routes it to *cannot*, not to *did not* -----------------------
    real_ctx = dc.contexts
    try:
        dc.contexts = lambda: {"a": {"canaries": ["X"]}, "b": {"canaries": ["Y"]}}
        unconf, unev, untried = dc.buckets(["memorised_completion"], {}, scanned={"a", "b"})
        check("a detector no target configures is reported as unconfigured",
              unconf == ["memorised_completion"] and not untried and not unev,
              f"unconfigured={unconf} unevidenced={unev} untried={untried}")

        dc.contexts = lambda: {"a": {"canaries": ["X"]},
                               "b": {"expected_completions": ["some text"]}}
        unconf2, unev2, untried2 = dc.buckets(["memorised_completion"], {},
                                              scanned={"a", "b"})
        check("...and as untried the moment one target could have exercised it",
              untried2 == ["memorised_completion"] and not unconf2 and not unev2,
              f"unconfigured={unconf2} unevidenced={unev2} untried={untried2}")

        # AND "no target does this" MUST NOT BE SAID ABOUT TARGETS NOBODY RAN. `untried`
        # prints exactly that sentence and was reached by elimination — not inert everywhere,
        # never fired — which a detector can satisfy while every target it could speak on has
        # no stored probe at all. Measured on the real fleet: `hallucinated_package` can fire
        # on four of forty-two configured targets and none of those four has a single probe,
        # so a claim about fleet behaviour rested entirely on runs that never happened.
        #
        # Same two contexts as above; the difference is that the target where the detector is
        # armed was not among the ones read.
        unconf4, unev4, untried4 = dc.buckets(["memorised_completion"], {}, scanned={"a"})
        check("a detector armed only on a target nobody ran is not 'no target does this'",
              unev4 == ["memorised_completion"] and not untried4 and not unconf4,
              f"unconfigured={unconf4} unevidenced={unev4} untried={untried4}")
        # ...and with nothing read at all the split stays two-way, because a caller that
        # cannot say what it scanned must not gain a bucket it has no evidence for.
        unconf5, unev5, untried5 = dc.buckets(["memorised_completion"], {})
        check("...while a caller that reports no scan keeps the old two-way answer",
              untried5 == ["memorised_completion"] and not unev5,
              f"unevidenced={unev5} untried={untried5}")

        # a detector that THREW is neither: a defect is not an absence.
        dc.contexts = lambda: {"a": {"canaries": ["X"]}}
        unconf3, unev3, untried3 = dc.buckets(["ansi_exfil"], {"ansi_exfil": 3},
                                              scanned={"a"})
        check("a detector that raised is filed under no absence bucket at all",
              not unconf3 and not untried3 and not unev3,
              f"unconfigured={unconf3} unevidenced={unev3} untried={untried3}")
    finally:
        dc.contexts = real_ctx

    # --- which target wrote an artifact is resolved, not guessed -----------------------
    # `stem.split("_")[0]` assumed a target name has no underscore and that whatever follows
    # the first one is a tag. True on this fleet, a property of nothing: a name with an
    # underscore resolves to a prefix of itself, misses the context dict and scans with `{}`
    # — every canary detector inert, on evidence that is sitting right there, and the report
    # reads clean. Longest known name wins instead, and no match is reported rather than
    # silently becoming an empty context.
    names = ["nemo", "nemo-inputonly", "portalagent", "with_underscore"]
    check("a plain target name resolves to itself",
          dc.target_of("portalagent", names) == "portalagent")
    check("a per-model tag is stripped",
          dc.target_of("portalagent_mistral-nemo", names) == "portalagent")
    check("a hyphenated name is not cut at the hyphen",
          dc.target_of("nemo-inputonly", names) == "nemo-inputonly")
    check("the longest matching name wins over its own prefix",
          dc.target_of("nemo-inputonly_qwen", names) == "nemo-inputonly")
    check("a name containing an underscore resolves to itself, not to its prefix",
          dc.target_of("with_underscore", names) == "with_underscore",
          repr(dc.target_of("with_underscore", names)))
    check("an unknown artifact resolves to nothing, so the caller can say so",
          dc.target_of("somebody-elses-bot", names) is None)

    # --- two configs sharing a name is reported, not silently resolved ------------------
    collisions = []
    real_ctxs = dc.contexts(collisions)
    check("the real fleet's context map is built without error", bool(real_ctxs))
    check("a duplicate target name is collected rather than dropped in silence",
          all(isinstance(c, tuple) and len(c) == 2 for c in collisions), str(collisions))
    check("...and the survivor is still in the map",
          all(name in real_ctxs for name, _ in collisions), str(collisions))

    # --- an artifact whose target does not resolve is named, not scanned as clean -------
    tmp = tempfile.mkdtemp()
    try:
        orphan = {"meta": {"target": "a-bot-with-no-config"},
                  "results": [{"attack": {"id": "a", "category": "x", "text": "hi"},
                               "trials": [{"probe": {"output": f"key is {CANARY}",
                                                     "tool_calls": [], "observations": [],
                                                     "seconds": 0, "turns": []}}]}]}
        with open(os.path.join(tmp, "results_orphan.json"), "w", encoding="utf-8") as f:
            json.dump(orphan, f)
        real_out, real_ctx = dc.OUT, dc.contexts
        dc.OUT = tmp
        dc.contexts = lambda *a, **k: {"cov-fake": {"canaries": [CANARY]}}
        seen = []
        hits4, _, n4, _, _src = dc.replay(seen)
        dc.OUT, dc.contexts = real_out, real_ctx
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    check("an artifact with no matching target config is reported", len(seen) == 1, str(seen))
    check("...and it is not silently credited as a clean scan",
          n4 == 1 and not hits4.get("canary_in_output"),
          f"n={n4} hits={dict(hits4)}")

    # --- A TARGET WHOSE CONFIG IS NOT HERE SAYS NOTHING ABOUT THE TARGET ----------------
    #
    # `buckets` looked up a scanned target's inert set with `per_target.get(t, set())`, and
    # the empty default reads as "every detector could have spoken on it". The opposite is
    # true: with no `oracle_context` there is no canary to look for, so every detector that
    # needs one is inert on those probes by construction, and its silence is a fact about
    # this run rather than about somebody's bot.
    #
    # Walked as a stranger: `qatration coverage` from a fresh install against a run of its
    # own that had just fired `canary_in_output` fourteen times. The config sat beside the
    # results rather than in the package and `QATRATION_CONFIGS` was not exported, so
    # `contexts()` never saw it. The command said "6 demonstrated" and filed
    # `canary_in_output` under "no target in the fleet exhibits this behaviour" -- an
    # assertion about a deployment, sourced from a detector that had been handed nothing to
    # look for. With the config: 10 demonstrated, 23 hits.
    import detector_coverage as _dc
    from oracle import inert_for as _inert_for, DETECTORS as _DETS

    # ONE A CANARY ARMS, specifically: a detector needing something else would be inert for
    # the configured target too and land in the third bucket, which would make the case below
    # pass for a reason that has nothing to do with what it is testing.
    _CTX = {"canaries": ["QAT-X"]}
    _armed = set(_inert_for({}, _DETS)) - set(_inert_for(_CTX, _DETS))
    _needs_ctx = sorted(_armed)
    check("a canary arms at least one detector, or this proves nothing",
          bool(_needs_ctx), "no detector is inert without a canary and armed with one")

    if _needs_ctx:
        _probe_det = _needs_ctx[0]
        _real_contexts = _dc.contexts
        try:
            # One configured target that arms it, and one scanned target with no config at
            # all -- which is every user whose config lives beside their results.
            _dc.contexts = lambda *a, **k: {"configured": dict(_CTX)}
            _un, _unev, _untried = _dc.buckets([_probe_det], (), scanned={"stranger"})
            check("a detector needing a context is not called absent from an unconfigured run",
                  _probe_det not in _untried,
                  "%r was filed as a claim about the fleet" % _probe_det)
            check("...it is filed as evidence that does not exist either way",
                  _probe_det in _unev, "buckets gave %s / %s / %s" % (_un, _unev, _untried))

            # AND THE CLAIM IS STILL AVAILABLE when the scanned target IS configured: this
            # must not become a rule that never lets `coverage` say anything.
            _dc.contexts = lambda *a, **k: {"stranger": dict(_CTX)}
            _un2, _unev2, _untried2 = _dc.buckets([_probe_det], (), scanned={"stranger"})
            check("...while a target that IS configured still supports the claim",
                  _probe_det in _untried2,
                  "buckets gave %s / %s / %s" % (_un2, _unev2, _untried2))
        finally:
            _dc.contexts = _real_contexts

    # --- an artifact says which build wrote it ------------------------------------------
    # A stored result gets read as a statement about the engine NOW, and it is a statement
    # about the engine that wrote it. `tool_call_storm` held a place in the published
    # "demonstrated" count on one probe whose eleven tool calls were each concrete call
    # recorded twice — written by the adapter version that kept boundary records and raw
    # calls in one list, before that was split into `probe.resolved`. The code was fixed the
    # same day; the file it had already written stayed on disk and went on propping up the
    # headline, and nothing about the file said where it came from.
    from target import engine_version
    ev = engine_version()
    check("the engine reports a version and the same one twice",
          isinstance(ev, str) and ev and ev == engine_version(), repr(ev))

    # AND IT STAMPS SOMETHING WHEN THERE IS NO REPOSITORY TO ASK. Every installed copy is that
    # case, so it is the branch every user's artifacts take, and it used to write "unknown"
    # into all of them: the one field whose purpose is to place a stored result answered
    # nothing, in exactly the situation where placing one is hardest. `--version` had already
    # learned to hide the word; the artifact had not. The check above could not see this,
    # because "unknown" is a non-empty string that is stable across two calls.
    #
    # Simulated rather than trusted: a checkout always has git, so nothing in this suite would
    # otherwise execute the branch that every release actually runs.
    import subprocess as _sp
    import target as _t
    _real_run, _cached = _sp.run, _t._ENGINE_VERSION

    def _no_git(*_a, **_k):
        raise OSError("no git, as in every installed copy")

    try:
        _sp.run, _t._ENGINE_VERSION = _no_git, None
        _stamped = _t.engine_version()
    finally:
        _sp.run, _t._ENGINE_VERSION = _real_run, _cached
    check("...and stamps the release when there is no repository to ask",
          _stamped.lower() != "unknown" and _stamped == _t.package_version(),
          "engine_version() said %r with git unavailable, release is %r"
          % (_stamped, _t.package_version()))

    def _engines(meta_extra):
        tmp = tempfile.mkdtemp()
        try:
            data = {"meta": dict({"target": "cov-fake"}, **meta_extra),
                    "results": [{"attack": {"id": "a", "category": "x", "text": "hi"},
                                 "trials": [{"probe": {"output": "ok", "tool_calls": [],
                                                       "observations": [], "seconds": 0,
                                                       "turns": []}}]}]}
            with open(os.path.join(tmp, "results_cov-fake.json"), "w", encoding="utf-8") as f:
                json.dump(data, f)
            real_out, real_ctx = dc.OUT, dc.contexts
            dc.OUT = tmp
            dc.contexts = lambda *a, **k: {"cov-fake": {}}
            seen = []
            try:
                dc.replay(None, seen)
            finally:
                dc.OUT, dc.contexts = real_out, real_ctx
            return seen
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    got = _engines({})
    check("an artifact with no stamp is reported as unstamped, not as the current build",
          got == [("results_cov-fake.json", "unstamped", 1)], str(got))
    got = _engines({"engine": "deadbee"})
    check("a stamped artifact reports the build that wrote it",
          got == [("results_cov-fake.json", "deadbee", 1)], str(got))

    # --- lock maps are inside the provenance audit too -----------------------------------
    # note_engine was called in the results loop only, and a lock map was a bare JSON list
    # that could not carry a stamp anyway — so the artifact family that alone demonstrates
    # forced_output, unknown_tool_call and refusal_then_comply sat outside the check written
    # to say which evidence predates the build. The printed line then divided by the FULL
    # probe count, which read as though the remainder had known provenance.
    from isolation import read_maps, write_maps
    tmp = tempfile.mkdtemp()
    try:
        sample = {"output": f"leaked {CANARY}", "tool_calls": []}
        maps = [{"objective": "o", "verdict": "PARTIAL", "coupling": [],
                 "combined": {"status": "open", "sample": sample},
                 "properties": [{"name": "p", "status": "open", "sample": sample}]}]
        write_maps(os.path.join(tmp, "isolation_cov-fake.json"), maps, {"target": "cov-fake"})
        real_out, real_ctx = dc.OUT, dc.contexts
        dc.OUT = tmp
        dc.contexts = lambda *a, **k: {"cov-fake": {"canaries": [CANARY]}}
        seen = []
        try:
            hits5, _, n5, _, _src = dc.replay(None, seen)
        finally:
            dc.OUT, dc.contexts = real_out, real_ctx
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    check("a lock map's probes are replayed", n5 == 2 and hits5.get("canary_in_output") == 2,
          f"n={n5} hits={dict(hits5)}")
    check("...and the map reports the build that wrote it",
          len(seen) == 1 and seen[0][1] not in ("unstamped", None) and seen[0][2] == 2,
          str(seen))

    # a legacy bare-list map still reads, and reports itself as unstamped rather than vanishing
    tmp = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmp, "isolation_cov-fake.json"), "w", encoding="utf-8") as f:
            json.dump(maps, f)
        real_out, real_ctx = dc.OUT, dc.contexts
        dc.OUT = tmp
        dc.contexts = lambda *a, **k: {"cov-fake": {"canaries": [CANARY]}}
        seen2 = []
        try:
            dc.replay(None, seen2)
        finally:
            dc.OUT, dc.contexts = real_out, real_ctx
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    check("a lock map written before stamps existed still reads, and says it has none",
          seen2 == [("isolation_cov-fake.json", "unstamped", 2)], str(seen2))

    # --- the headline itself ------------------------------------------------------------
    hits3, where3, n3, broke3, _src = dc.replay()
    check("the real replay reads a meaningful number of stored probes", n3 > 100, str(n3))
    check("nothing in the real fleet raises", not broke3, str(dict(broke3)))
    demo = [k for k in DETECTORS if hits3[k]]
    check("every demonstrated detector names the target it fired on",
          all(where3[k] for k in demo))
    check("demonstrated + declared accounts for every detector",
          len(demo) + len([k for k in DETECTORS if not hits3[k]]) == len(DETECTORS))

    # --- THE REPLAY MUST NOT CONTRADICT THE ARTIFACTS -------------------------------------
    #
    # `refusal_expected_but_absent` fired four times in results_httpbot.json and this page went
    # on printing it under "never yet seen to fire". Both numbers are ours and they disagreed,
    # and the one that recounts was the wrong one: the replay judged with the TARGET's context
    # alone, while a run merges the attack's own `expects_refusal` and `plants` through
    # `runner.judged_ctx`. A detector answerable only per attack could therefore never fire
    # here, whatever the evidence said.
    #
    # Derived, not listed: it reads what every stored run RECORDED as fired and requires the
    # replay to reach the same detectors. A new detector with the same dependency fails this on
    # the day it is added rather than sitting in "declared only" looking like an honest gap.
    import glob as _glob, json as _json
    recorded = set()
    from workspace import OUT as _REAL_OUT   # the one place that decides where these live;
    for _fp in _glob.glob(os.path.join(_REAL_OUT, "results_*.json")):   # dc.OUT gets rebound above
        # A NARROW except, because the wide one hid this check's own bug: `io` is not imported
        # in this suite, the NameError was swallowed as "unreadable artifact", and the count
        # came out zero — which the line below is here to catch.
        try:
            with open(_fp, encoding="utf-8") as _fh:
                _d = _json.load(_fh)
        except (OSError, ValueError):
            continue
        for _r in _d.get("results") or []:
            for _f in _r.get("fired") or []:
                recorded.add(_f)
    missed = sorted(d for d in recorded if d in DETECTORS and not hits3[d])
    check("no detector a stored run recorded is reported as never having fired",
          not missed, "recorded firing but absent from the replay: %s" % ", ".join(missed))
    check("...and the artifacts really do record some, so this can fail",
          len(recorded) > 20, "%d detector(s) recorded across the fleet" % len(recorded))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the headline number is earned.")


if __name__ == "__main__":
    main()
