"""
Which detectors have actually caught something, and which are only declared.

A detector with a green unit test and no live hit is a claim, not a capability — the same
thing this tool says about an untested guardrail, turned on itself. A count of detectors
says how many were written. This says how many have ever fired against a live target, which is
the only one of the two that describes a capability.

It replays every stored artifact (sweeps AND lock maps) through the current oracle, so it
costs no GPU and stays honest as both sides change: a new detector starts as declared, and
a new target is what moves it to demonstrated.

    qatration coverage
    ... --json out/detector_coverage.json
"""
import sys, os, glob, json, argparse, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from workspace import OUT as WORKSPACE_OUT, target_of, read_artifact
from isolation import read_maps
ROOT = os.path.dirname(HERE)
OUT = WORKSPACE_OUT
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import yaml
from target import Probe, target_configs
from oracle import DETECTORS, inert_for
from target import engine_version
from rejudge import _prompt_of


def contexts(collisions=None):
    """target name -> oracle_context, first config wins, and it SAYS when one did.

    Two configs may legitimately describe the same bot scoped to different questions —
    `targets_nemo.yaml` carries the staff key and the RAG poison for a sweep, and a key
    search wants one canary at a time or a hit on the poison credits the wrong frame. The
    name is shared because the target is. What is not legitimate is `setdefault` quietly
    choosing between them: the replay then scores one config's stored probes against the
    other's canary list, which can only ever ADD hits to a number whose whole value is that
    it is allowed to go down. Pass a list to collect the collisions and print them.
    """
    out = {}
    for fp in target_configs(HERE):
        cfg = yaml.safe_load(open(fp, encoding="utf-8")) or {}
        name = cfg.get("name") or os.path.basename(fp)[len("targets_"):-len(".yaml")]
        if name in out:
            if collisions is not None:
                collisions.append((name, os.path.basename(fp)))
            continue
        out[name] = cfg.get("oracle_context", {})
    return out


def replay(unresolved=None, engines=None, attacks=None, unreadable_out=None):
    """-> (hits, targets per detector, probes scanned, detectors that threw).

    `unresolved` collects artifacts whose target could not be matched to any config. They
    used to fall back to an empty context, which reads as a clean scan of real evidence.
    `attacks` collects every attack id that has a stored trial, for the arsenal line — an
    out-parameter like the other two, so the return shape stays what every caller expects.
    """
    ctxs = contexts()
    hits, where, n = collections.Counter(), collections.defaultdict(set), 0
    # ARTIFACTS THAT WOULD NOT PARSE. Collected rather than skipped, because a replay
    # missing a file it could not read publishes a coverage number over less evidence
    # than it claims — and this tool's entire output is that number.
    unreadable = []
    broke = collections.Counter()
    # WHAT KIND of evidence demonstrated each detector. A fire under attack and a fire on
    # traffic nobody attacked both prove the detector works, and they say opposite things
    # about the target, so the bucket has to carry which.
    sources = collections.defaultdict(set)

    def note_engine(d, artifact, n_probes):
        if engines is not None and n_probes:
            engines.append((artifact, (d.get("meta") or {}).get("engine") or "unstamped",
                            n_probes))

    def ctx_for(name, artifact):
        hit = target_of(name, ctxs)
        if hit is None and unresolved is not None:
            unresolved.append((artifact, name))
        return ctxs.get(hit, {})

    def scan(pr, ctx, target, source="attack"):
        nonlocal n
        n += 1
        for name, fn in DETECTORS.items():
            try:
                if fn(pr, ctx):
                    hits[name] += 1
                    where[name].add(target)
                    sources[name].add(source)
            except Exception:
                # A detector that throws on real data must not take the report down with
                # it — and it must not vanish either. Swallowed silently it lands in
                # "declared only", which reads as "no target does this" when the truth is
                # "this one is broken". Counted and printed instead.
                broke[name] += 1

    for fp in glob.glob(os.path.join(OUT, "results_*.json")):
        d, _why = read_artifact(fp)
        if _why:
            unreadable.append((os.path.basename(fp), _why))
            continue
        tgt = d["meta"]["target"]
        ctx = ctx_for(tgt, os.path.basename(fp))
        before = n
        for r in d.get("results", []):
            if attacks is not None:
                _a = r.get("attack") or {}
                attacks.add(_a.get("id") if isinstance(_a, dict) else _a)
            for t in r.get("trials", []):
                pd = t.get("probe") or {}
                if not pd:
                    continue
                # The whole attacker side, not just `text`: a chain or session attack
                # keeps its turns in `steps`, so reading `text` left the prompt EMPTY and
                # echo subtraction switched off — the same defect rejudge had, in a second
                # file, and here it inflates the headline number this tool exists to
                # publish. Prefer what was actually stored, reconstruct only for the older
                # files that predate it.
                scan(Probe(prompt=_prompt_of(r["attack"], pd.get("prompt")),
                           output=pd.get("output") or "",
                           tool_calls=[tuple(x) for x in (pd.get("tool_calls") or [])],
                           observations=pd.get("observations") or [],
                           turns=pd.get("turns") or [], error=pd.get("error"),
                           seconds=pd.get("seconds") or 0), ctx, tgt)
        note_engine(d, os.path.basename(fp), n - before)

    # THE BENIGN CORPUS WAS NOT READ AT ALL, and it is the larger body of evidence: 1,392
    # probes against 29 targets. A detector demonstrated only there was reported under "never
    # yet seen to fire — no target in the fleet exhibits this behaviour", which is false twice
    # over: it has fired, and a target does do it. `tool_call_storm` was the case that showed
    # it, sitting in DECLARED ONLY while benign.py's own roll-up printed a fire for it on
    # foreign-code. Two tools in this repo contradicting each other about the same artifact,
    # because one of them derived its bucket from a filtered set rather than from everything
    # that happened.
    for fp in glob.glob(os.path.join(OUT, "benign_*.json")):
        d, _why = read_artifact(fp)
        if _why:
            unreadable.append((os.path.basename(fp), _why))
            continue
        tgt = (d.get("meta") or {}).get("target") or os.path.basename(fp)[7:-5]
        ctx = ctx_for(tgt, os.path.basename(fp))
        before = n
        for r in d.get("rows") or []:
            pd = r.get("probe") or {}
            if not pd:
                continue
            scan(Probe(prompt=pd.get("prompt") or "", output=pd.get("output") or "",
                       tool_calls=[tuple(x) for x in (pd.get("tool_calls") or [])],
                       observations=pd.get("observations") or [],
                       turns=pd.get("turns") or [], error=pd.get("error"),
                       resolved=[tuple(x) for x in (pd.get("resolved") or [])] or None,
                       seconds=pd.get("seconds") or 0), ctx, tgt, source="benign")
        note_engine(d, os.path.basename(fp), n - before)

    for fp in glob.glob(os.path.join(OUT, "isolation_*.json")):
        stem = os.path.basename(fp)[len("isolation_"):-len(".json")]
        ctx = ctx_for(stem, os.path.basename(fp))
        tgt = target_of(stem, ctxs) or stem
        # Lock maps were outside the provenance audit entirely: `note_engine` was called in
        # the results loop only, and the artifacts were a bare JSON list that could not carry
        # a stamp anyway. Three detectors — forced_output, unknown_tool_call and
        # refusal_then_comply — are demonstrated ONLY by one of these, so their whole evidence
        # sat outside the check written to say which evidence predates the build.
        iso_maps, iso_meta = read_maps(fp)
        before = n
        for m in iso_maps:
            for p in list(m.get("properties") or []) + [m.get("combined") or {}]:
                s = p.get("sample") or {}
                if s.get("output") is None:
                    continue
                scan(Probe(prompt="", output=s.get("output") or "",
                           tool_calls=[tuple(x) for x in (s.get("tool_calls") or [])]),
                     ctx, tgt)
        note_engine({"meta": iso_meta}, os.path.basename(fp), n - before)
    if unreadable_out is not None:
        unreadable_out.extend(unreadable)
    return hits, where, n, broke, sources


def buckets(declared, broke=()):
    """Split "never fired" into *cannot* and *did not*, over EVERY detector the replay runs.

    "Never fired" has three causes and they need different answers, so reporting them as one
    line said "no target in the fleet does this" — a claim, and a wrong one for any detector
    whose config is missing everywhere, or one that throws on every probe.

    The split then had the defect it was written to prevent, in the module that publishes the
    headline: it asked `inert_for(ctx)` with no `declared`, and that function only walks the
    always-on sets. So the "cannot fire as configured" bucket was reachable only by always-on
    detectors, whose config is satisfied on some target by construction — it computed to the
    empty set on the whole fleet, and always would have. This repo's own "a guard only covers
    where it looks", aimed at the number it exists to publish.

    The casualty was `memorised_completion`. It needs `expected_completions`; no target on the
    fleet supplies it and no attack declares it, so it returned False on all 1,180 stored
    probes for want of a config key — and the report filed that under "no target in the fleet
    exhibits this behaviour", which is an assertion about the targets sourced from a detector
    that was never able to speak. `inert_for`'s own docstring names this detector and this
    exact fact; the fix reached `judge()` through `declared` and never reached the report.

    `replay()` runs every detector in DETECTORS on every probe regardless of what declares it,
    so DETECTORS is the set the inert question has to be asked over. Same set, both places.
    """
    inert = set(DETECTORS)
    for ctx in contexts().values():
        inert &= set(inert_for(ctx, DETECTORS))   # inert on EVERY target, not merely on one
    unconfigured = sorted(k for k in declared if k in inert)
    untried = sorted(k for k in declared if k not in inert and k not in broke)
    return unconfigured, untried


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    unresolved, collisions, engines = [], [], []
    contexts(collisions)
    sent = set()
    _unreadable_seen = []
    hits, where, n, broke, sources = replay(unresolved, engines, sent, _unreadable_seen)
    demo = sorted(k for k in DETECTORS if hits[k])
    # Demonstrated ONLY on traffic nobody attacked is a different claim from demonstrated by
    # an attack, and the difference is the interesting one: the detector works, and what it
    # caught was the target doing it unprompted. Said rather than folded in.
    benign_only = sorted(k for k in demo if sources[k] == {"benign"})
    declared = sorted(k for k in DETECTORS if not hits[k])
    unconfigured, untried = buckets(declared, broke)

    for _name, _why in _unreadable_seen:
        print(f"  ! {_name} could not be read ({_why}). Its probes are NOT in the "
              f"numbers below.", file=sys.stderr)
    print(f"{len(DETECTORS)} detectors · {len(demo)} demonstrated · {len(declared)} declared "
          f"only   (replayed {n} stored probes, no model calls)")

    # THE SAME QUESTION ABOUT THE ARSENAL, and nothing was asking it. This tool has always
    # separated a detector that has caught something from one that has only been written, on
    # the grounds that the second is a claim rather than a capability. An attack that has never
    # been SENT is the same claim, and the arsenal size is a number this project publishes.
    #
    # Free to compute here: the artifacts are already open and already indexed by attack id.
    try:
        import yaml as _yaml
        _arsenal = {a["id"] for a in
                    (_yaml.safe_load(open(os.path.join(HERE, "attacks_generic.yaml"),
                                          encoding="utf-8")) or [])}
        _sent = sent & _arsenal
        print(f"{len(_arsenal)} attacks in the portable arsenal · {len(_sent)} with a stored "
              f"trial · {len(_arsenal - _sent)} never sent against anything")
    except Exception as _e:
        # Said, not swallowed: a count that failed to compute must not read as a count of zero.
        print(f"(the arsenal count could not be computed: {type(_e).__name__}: {_e})")
    print()
    print("DEMONSTRATED — caught something on a live target")
    for k in sorted(demo, key=lambda x: -hits[x]):
        tg = ", ".join(sorted(where[k])[:3])
        more = f" +{len(where[k]) - 3}" if len(where[k]) > 3 else ""
        tag = "  [clean traffic only]" if k in benign_only else ""
        print(f"  {k:<24}{hits[k]:>5}   {tg}{more}{tag}")
    if benign_only:
        print("")
        print(f"  {len(benign_only)} of these fired ONLY on traffic nobody attacked. The")
        print("  detector is demonstrated and no attack has yet needed it — which is a")
        print("  statement about the arsenal, not a clean bill for the detector:")
        print("    " + ", ".join(benign_only))

    print("\nDECLARED ONLY — implemented and unit-tested, never yet seen to fire")
    if untried:
        print("  no target in the fleet exhibits this behaviour:")
        for k in untried:
            print(f"    {k}")
    if unconfigured:
        print("  cannot fire on any target as configured — untested, not exonerated:")
        for k in unconfigured:
            print(f"    {k}")
    if broke:
        print("  RAISED on real data, which is a defect rather than an absence:")
        for k, c in broke.most_common():
            print(f"    {k:<24}{c} probe(s)")
    print("\nOnly the first group is closed by a new target. The second needs config, the\n"
          "third needs a fix, and collapsing them into one line hides two of the three.")

    # Neither of these changes a count. Both change what a count is allowed to mean, so they
    # are printed in the same breath rather than left for someone to notice.
    if collisions:
        print("\nTWO CONFIGS, ONE TARGET NAME — the first was used and the others were not:")
        for name, fp in collisions:
            print(f"    {name:<24}{fp}")
        print("    (their stored probes are scored against the first config's oracle_context)")
    # A stored result is a statement about the engine that WROTE it, and it gets read as one
    # about the engine now. `tool_call_storm` sat in the demonstrated column on a probe whose
    # eleven tool calls were each concrete call recorded twice, by an adapter fixed the same
    # day — the fix landed, the file it had already written did not move, and nothing here
    # could tell. This does not fail anything: it says which evidence predates the build.
    #
    # Two states, kept apart for the usual reason: "I do not know which build wrote this" and
    # "I know, and it was that one" are different answers, and one line for both says neither.
    now = engine_version()
    unstamped = [(a, c) for a, e, c in engines if e == "unstamped"]
    earlier = [(a, e, c) for a, e, c in engines if e not in ("unstamped", now)]
    if unstamped or earlier:
        print(f"\nENGINE PROVENANCE — replayed against build {now}. The oracle applied here is"
              f"\ncurrent; what these probes RECORDED is whatever the adapter of the day stored,"
              f"\nand that is not re-derivable without running the target again.")
    if unstamped:
        # `X of n` used to read as though the remaining probes had known provenance. They did
        # not: nothing on disk carried a stamp, and the difference was the isolation
        # artifacts, which this loop could not ask. Both numbers are named now.
        stamped = n - sum(c for _, c in unstamped)
        print(f"  no stamp, written before results carried one:  "
              f"{sum(c for _, c in unstamped)} of {n} probes, {len(unstamped)} artifact(s)"
              + (f"  ({stamped} probe(s) carry one)" if stamped else "  (none carry one)"))
    for a, e, c in sorted(earlier, key=lambda x: -x[2]):
        print(f"  earlier build {e:<16}{a:<42}{c} probe(s)")
    if unresolved:
        print("\nARTIFACTS WHOSE TARGET DID NOT RESOLVE — scanned with an empty context, so\n"
              "every detector needing one was inert on them:")
        for fp, stem in unresolved:
            print(f"    {fp}  (looked for a target named {stem!r})")

    if args.json:
        path = args.json if os.path.isabs(args.json) else os.path.join(ROOT, args.json)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"probes": n, "demonstrated": {k: hits[k] for k in demo},
                       "declared_only": declared,
                       "targets": {k: sorted(v) for k, v in where.items()}},
                      f, indent=2)
        print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
