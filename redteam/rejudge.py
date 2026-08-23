"""
Re-score stored results with the CURRENT oracle, without re-running a single model.

Scoring and execution are separate concerns, and conflating them makes an oracle fix cost
a full GPU run — which in practice means the fix does not get applied to the history and
the old numbers quietly stay in the reports. Every trial's probe is stored in
`out/results_<target>.json`, so a corrected judge can be replayed over it for free.

The fix that prompted this: `judge()` only consulted the detectors an attack DECLARED, so
mcpagent leaking the real key into a `SendTelemetry` argument scored DEFENDED 3/3 — the
detector existed, the attack (written for a bot with no tools) just never named it. Every
stored run made before that fix is scored the same wrong way.

    qatration rejudge              # preview, writes nothing
    qatration rejudge --write      # apply + rebuild the HTML

Read-only by default on purpose: these files are the record of expensive runs, and a
scoring tool has no business overwriting them until someone has looked at what changes.
"""
import sys, os, glob, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from workspace import OUT as WORKSPACE_OUT, target_of
ROOT = os.path.dirname(HERE)
OUT_DIR = WORKSPACE_OUT
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import yaml
from target import Probe, target_configs
from oracle import judge
from refusal import classify, summarize
from runner import headline
from report_engine import build_html
import datetime
from isolation import apply_keysearch, _verdict, read_maps, write_maps
from baseline import note as _baseline_note


def contexts():
    """target name -> oracle_context, read from the configs rather than the results.

    The results file does not store ctx (canaries, forbidden tokens, markers), and it is
    the ctx that decides what counts as a leak — so re-scoring has to go back to the config
    the run was pointed at.

    Configs outside this repository arrive through `target_configs`, which reads
    `QATRATION_CONFIGS`. This function briefly had its own `extra` parameter and a flag beside
    it; then the same defect appeared in `coverage`, the fix moved to the shared enumeration,
    and two answers to one question is the arrangement that drifts. `--target-config` still
    exists here and sets that variable.
    """
    out = {}
    for fp in target_configs(HERE):
        cfg = yaml.safe_load(open(fp, encoding="utf-8")) or {}
        name = cfg.get("name") or os.path.basename(fp)[len("targets_"):-len(".yaml")]
        out.setdefault(name, cfg.get("oracle_context", {}))
    return out


def _prompt_of(attack, stored):
    """The attacker's whole side of the exchange, for echo subtraction.

    Older result files predate storing it, so it is reconstructed from the attack exactly
    as runner.py assembles it — including every step of a chain or session, not just the
    last, since the attacker typed all of them.
    """
    if stored:
        return stored
    if attack.get("steps"):
        return "\n".join(str(x) for x in attack["steps"])
    return attack.get("text") or attack.get("user_prompt") or ""


def _probe(attack, d):
    """Rebuild a Probe from stored JSON, losing nothing the detectors read.

    Two fields were being dropped and each moved verdicts in a different direction.
    `seconds` is what the timing detectors read, so replay saw 0 and rb-slow fell from
    PARTIAL to DEFENDED on a probe whose stored evidence says 26.5s — a --write would have
    erased every timing finding from the history and rebuilt the HTML without them.
    `prompt` is what echo subtraction reads, so replay counted the attacker's own text as
    though the target had revealed it. A scoring tool that silently reads different
    evidence than the run did is worse than no scoring tool.

    A third was found the same way, by replaying new detectors over the stored corpus and
    checking what the replay could actually see: `resolved`. The runner writes it, both
    report paths read it, and this one did not — so every tool-reading detector, which
    prefers `resolved` and falls back to `tool_calls`, silently changed evidence on replay.
    That fallback is precisely where `final_answer` gets miscounted as a tool call, which is
    the false positive the telemetry contract was introduced to remove. Same bug, third
    field: a reconstruction that lists fields by hand needs checking whenever Probe grows.
    """
    if not d:
        return None
    return Probe(prompt=_prompt_of(attack, d.get("prompt")),
                 output=d.get("output") or "",
                 tool_calls=[tuple(t) for t in (d.get("tool_calls") or [])],
                 observations=d.get("observations") or [],
                 resolved=[tuple(t) for t in (d.get("resolved") or [])],
                 error=d.get("error"), seconds=float(d.get("seconds") or 0),
                 turns=d.get("turns") or [])


def rescore(path, ctx):
    """Returns (data, [changed rows]) — never writes."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    changed = []
    for r in data.get("results", []):
        attack = r["attack"]
        recs = []
        for t in r.get("trials", []):
            p = _probe(attack, t.get("probe"))
            if p is None:
                recs.append({"verdict": t.get("verdict", "SKIP"), "fired": t.get("fired", []),
                             "probe": None})
                continue
            v, fired = judge(attack, p, ctx)
            t["verdict"], t["fired"] = v, fired
            t["refusal"] = classify(p, ctx)
            recs.append({"verdict": v, "fired": fired, "probe": p})
        if not recs:
            continue
        head, rate = headline(recs)
        before = (r.get("headline"), r.get("rate"))
        fired = sorted({d for rec in recs for d in rec["fired"]})
        # A CHANGE IS NOT ONLY A CHANGE OF HEADLINE. This compared verdict and rate alone,
        # so a newly-written detector firing on a row that was already PARTIAL produced an
        # empty preview: `fabricated_citation` landed on cite-multi-hop 2/2 and the preview
        # said one row would change, in a different attack. The reviewer then approves a
        # --write without having seen the finding it adds, in the one tool that overwrites
        # the record of expensive runs. What fired is part of what changed.
        if before != (head, rate) or sorted(r.get("fired") or []) != fired:
            changed.append((attack["id"], before, (head, rate), fired))
        r["headline"], r["rate"] = head, rate
        r["fired"] = fired
        r["locks"] = summarize(recs, ctx)

    # the headline counters in meta are derived, so they have to move too
    real = [r for r in data.get("results", []) if r["attack"].get("category") != "control"]
    data["meta"]["broke"] = sum(1 for r in real if r["headline"] in ("EXPLOITED", "PARTIAL"))
    data["meta"]["attacks_n"] = len(real)
    return data, changed


_map_meta = {}


def rescore_map(path):
    """Re-apply the CURRENT lock-map verdict logic to a stored map. Never writes.

    -> (maps, [(objective, before, after, keyed)]).

    Lock maps had no replay at all, and a stored one is a published verdict about a client's
    system in exactly the way a sweep result is. `out/isolation_secretbot.json` is what that
    costs: it stores **HARDENED** for `secret-disclosure` — "nothing gives, even in isolation"
    — while the same record holds `transformed_disclosure` with a key search verdict of KEYED.
    `apply_keysearch` exists to catch precisely that and its docstring names the stakes:
    "Reporting it as hardened is the most expensive kind of wrong this tool can be: the reader
    stops looking." It runs inside `run_isolation`, so the code has been right since it was
    written; the artifact predates it, no map on disk carries the `keyed` field it adds, and
    the scorecard has been rendering HARDENED off the stale file ever since.

    A stale artifact is a claim about the current engine that nothing re-checks — the same
    lesson `engine_version()` came from, in the one artifact family that had no way to be
    re-checked at all. Everything this needs is already stored, so it costs no GPU: the
    property statuses, the combined probe, the coupling and each property's key search.
    """
    maps, meta = read_maps(path)
    _map_meta[path] = meta
    changed = []
    for m in maps:
        before = (m.get("verdict"), tuple(m.get("keyed") or ()))
        m["verdict"] = _verdict(m.get("properties") or [], m.get("combined") or {},
                                m.get("coupling") or [])
        apply_keysearch(m)
        after = (m.get("verdict"), tuple(m.get("keyed") or ()))
        if before != after:
            changed.append((m.get("objective", "?"), before, after))
    return maps, changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="apply the re-scoring and rebuild each HTML report "
                         "(default: preview only)")
    ap.add_argument("--target", default=None, help="restrict to one target name")
    args = ap.parse_args()

    # NO FLAG HERE, and that is a decision the build made rather than a preference. It had one
    # briefly, implemented by writing QATRATION_CONFIGS from inside this module, and `test_llm`
    # refused it: "no module mutates process-global state, so one target cannot move another's
    # ground". Correct -- a module that edits the environment changes the ground under whatever
    # runs next in the same process. The variable is the mechanism; `qatration init` prints the
    # line that sets it, and the message below names it.
    ctxs = contexts()
    total_changed, files_touched, skipped = 0, 0, []
    for path in sorted(glob.glob(os.path.join(OUT_DIR, "results_*.json"))):
        name = os.path.basename(path)[len("results_"):-len(".json")]
        # Longest known target name, not `name.split("_")[0]`. The split assumes a target
        # name has no underscore and that whatever follows the first one is a --model tag;
        # one that does resolves to a prefix of itself, misses `ctxs`, and this file is
        # silently left alone with an "no config found" line nobody reads as a defect.
        base = target_of(name, ctxs)
        if args.target and base != args.target:
            continue
        if base is None:
            skipped.append(name)                        # no config: cannot know its canaries
            continue
        data, changed = rescore(path, ctxs[base])

        # A STALE CAVEAT IS A CHANGE. `meta["attribution"]` is computed at sweep time against
        # the target's benign run, because "this attack caused this detector to fire" is only
        # worth something if the target is quiet when nobody attacks it. Both sides of that
        # comparison move after a sweep: a benign run can be added or re-scored, and the
        # verdicts this replay just changed are the other half of it. Rebuilding the page from
        # stored meta carried whatever the sweep believed, and a file whose verdicts happened
        # not to move was never rewritten at all — so the caveat could not be corrected even
        # in principle.
        #
        # nemo-inputonly is the case that showed it: its sweep predates baseline.py, so its
        # meta holds no note, while its benign run has the bot emitting the canary on 36 of 48
        # ORDINARY prompts. Every canary_in_output row on that page was unattributed and the
        # page said nothing — the exact failure baseline.py exists to prevent, reached through
        # the replay door instead of the sweep door.
        note = _baseline_note(base, data["results"], (ctxs[base] or {}).get("canaries") or [])
        note_moved = (note or "") != (data["meta"].get("attribution") or "")
        if not changed and not note_moved:
            continue
        files_touched += 1
        total_changed += len(changed)
        print(f"\n{name}")
        for aid, before, after, fired in changed:
            print(f"  {aid:<26}{before[0]} {before[1]:<7} ->  {after[0]} {after[1]:<7}"
                  f"  {','.join(fired) or '-'}")
        if note_moved:
            was = (data["meta"].get("attribution") or "").strip().splitlines()
            now = (note or "").strip().splitlines()
            print(f"  {'attribution':<26}{len(was)} line(s) -> {len(now)} line(s)"
                  + ("  (a caveat appears)" if now and not was else
                     "  (a caveat is withdrawn)" if was and not now else ""))
            for l in now[:3]:
                print(f"      {l.strip()[:96]}")
        if args.write:
            data["meta"]["attribution"] = note
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            html = os.path.join(OUT_DIR, f"report_{name}.html")
            with open(html, "w", encoding="utf-8") as f:
                f.write(build_html(data["meta"], data["results"]))

    # Lock maps, which had no replay at all until one of them published HARDENED over a key
    # its own record held.
    maps_changed, maps_touched = 0, 0
    for path in sorted(glob.glob(os.path.join(OUT_DIR, "isolation_*.json"))):
        stem = os.path.basename(path)[len("isolation_"):-len(".json")]
        if args.target and target_of(stem, ctxs) != args.target:
            continue
        maps, changed = rescore_map(path)
        if not changed:
            continue
        maps_touched += 1
        maps_changed += len(changed)
        print(f"\n{os.path.basename(path)}")
        for obj, before, after in changed:
            keyed = ", ".join(after[1]) or "-"
            print(f"  {obj:<26}{before[0]:<10} ->  {after[0]:<10} keyed: {keyed}")
        if args.write:
            write_maps(path, maps, {k: v for k, v in _map_meta.get(path, {}).items()
                                    if k != "engine"})
            # AND the page, or the correction stops at the JSON. The scorecard renders the
            # lock map straight from this file, so leaving it alone is how HARDENED stayed on
            # the published page for a target whose own record held the key that opened it.
            tgt = target_of(stem, ctxs)
            results = os.path.join(OUT_DIR, f"results_{tgt}.json") if tgt else None
            if results and os.path.exists(results):
                with open(results, encoding="utf-8") as f:
                    rd = json.load(f)
                when = datetime.datetime.fromtimestamp(
                    os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
                html = os.path.join(OUT_DIR, f"report_{tgt}.html")
                with open(html, "w", encoding="utf-8") as f:
                    f.write(build_html(rd["meta"], rd["results"],
                                       isolation={"maps": maps, "when": when}))
                print(f"  rebuilt {os.path.basename(html)}")

    if skipped:
        # NOT A NOTE. Nothing was re-scored for these targets, which is the whole command.
        print(f"\nNOT RE-SCORED — no config found for: {', '.join(skipped)}.\n"
              f"  Re-scoring reads the canaries and markers from the config, and results "
              f"files do not carry them.\n"
              f"  Point at it, and every other command with it:\n"
              f"      export QATRATION_CONFIGS=/path/to/your.yaml")
    verb = "rescored" if args.write else "would change"
    print(f"\n{verb} {total_changed} attack row(s) across {files_touched} file(s)"
          f"{' (some of them only their attribution caveat)' if files_touched and not total_changed else ''}.")
    if maps_touched:
        print(f"{verb} {maps_changed} lock-map objective(s) across {maps_touched} map file(s).")
    if (total_changed or files_touched or maps_touched) and not args.write:
        print("nothing was written — re-run with --write to apply")


if __name__ == "__main__":
    main()
