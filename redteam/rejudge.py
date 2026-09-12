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
import workspace
from workspace import OUT as WORKSPACE_OUT, no_results_note, target_of, BROKE
from runner import judged_ctx   # one definition of "what did this attack declare"
ROOT = os.path.dirname(HERE)
OUT_DIR = WORKSPACE_OUT
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from target import Probe
from oracle import judge
from refusal import classify, summarize
from runner import headline
from report_engine import build_html
import datetime
from isolation import (apply_keysearch, _verdict, read_maps, write_maps,
                       map_target as _map_target)
from baseline import note as _baseline_note
from baseline import two_factor_note as _two_factor_note


# target name -> oracle_context, read from the configs rather than the results. The results
# file does not store ctx (canaries, forbidden tokens, markers), and it is the ctx that
# decides what counts as a leak, so re-scoring has to go back to the config the run was
# pointed at.
#
# Configs outside this repository arrive through `target_configs`, which reads
# `QATRATION_CONFIGS`. This briefly had its own `extra` parameter and a flag beside it; then
# the same defect appeared in `coverage`, the fix moved to the shared enumeration, and two
# answers to one question is the arrangement that drifts. `--target-config` still exists
# here and sets that variable.
#
# THEN THE MAP ITSELF MOVED, for the same reason one more time: this one used `setdefault`
# and said nothing, so when two configs name one target the loser's stored rows were
# re-scored against the winner's canaries -- and this is the command that WRITES that back.
# `coverage` collected the collisions and printed them; the two were the same question and
# only one of them answered it. What was left here was a two-line wrapper identical to the
# one in `coverage`, which is a second implementation with a shorter body: the import binds
# the name instead.
from workspace import oracle_contexts as contexts


def _prompt_of(attack, stored):
    """The attacker's whole side of the exchange, for echo subtraction.

    Older result files predate storing it, so it is reconstructed -- through
    `runner.attacker_side`, which is the function `run_attack` itself uses, rather than
    through a second copy here. The copy said it reconstructed "exactly as runner.py
    assembles it" and did not: it joined the raw `steps` with neither `payload()` nor the
    attack's `encode:` applied, and ignored a forged transcript entirely.

    That fails in the direction that manufactures a finding. Subtracting the plain words of
    an encoded attack subtracts almost nothing, so the encoded payload coming back in the
    reply reads as the target revealing it.
    """
    if stored:
        return stored
    from runner import attacker_side
    return attacker_side(attack)


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
                 turns=d.get("turns") or [],
                 retries=int(d.get("retries") or 0))


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
            # THE CONTEXT THE RUN JUDGED AGAINST, not the target's half of it. `runner` scores
            # with `judged_ctx(attack, ctx)`, which merges what the ATTACK declared —
            # `plants` and `expects_refusal` — and this replay passed the bare target config.
            # So every attack armed by its own declaration was re-scored with that declaration
            # missing, and came back clean: previewed on httpbot, seven EXPLOITED 3/3 rows
            # became DEFENDED 0/3, all of them `rf-*` and `doc-*`. A tool whose whole purpose
            # is applying an oracle fix to stored history would have deleted seven confirmed
            # breaches, silently, in the direction that flatters the target.
            #
            # `detector_coverage` had this defect and fixed it, with the comment "one
            # definition of what did this attack declare" over the import. This was the third
            # module asking the question and the only one still answering it alone.
            v, fired = judge(attack, p, judged_ctx(attack, ctx))
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
    data["meta"]["broke"] = sum(1 for r in real if r["headline"] in BROKE)
    # A SKIP ROW IS NOT AN ATTACK THAT FIRED. Older artifacts can carry them — the sweep only
    # started withholding an undeliverable attack up front — and counting them here would put
    # the overstatement back into a file that had been rescored to remove it.
    data["meta"]["attacks_n"] = sum(1 for r in real if r["headline"] != "SKIP")
    # AND THE ERRORED COUNT, which is as derived as the two above it and was not in the
    # list. `workspace.measured` -- the denominator the scorecard, the defence page, the
    # fleet index and the SARIF export all share -- reads it, so a re-score moved
    # `attacks_n` and left `errors` describing the rows before it. Measured: a file whose
    # every row was rewritten came back with the count it was handed.
    data["meta"]["errors"] = sum(1 for r in real if r["headline"] == "ERROR")
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
    # THE ONE SPELLING, from the table this command is listed in. A bare parser
    # here printed the flags and left `--help` silent about the job.
    from cli import parser as _cli_parser
    ap = _cli_parser("rejudge")
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
    _collisions = []
    ctxs = contexts(collisions=_collisions)
    # SAID BEFORE ANYTHING IS REWRITTEN, rather than found afterwards in a diff. `coverage`
    # printed this and this did not, and of the two commands it is this one that overwrites
    # the stored verdict and the page built from it.
    if _collisions:
        print("TWO CONFIGS, ONE TARGET NAME - the first was used, the others were not:")
        for _cn, _cf in _collisions:
            print(f"    {_cn:<24}{_cf}")
        print("    (their stored rows are re-scored against the first "
              "config's oracle_context)")
    # HOW MANY ARTIFACTS WERE READ, which is a different number from how many CHANGED and the
    # difference is the whole exit code. `files_touched` counts files this command rewrote, so
    # "would change 0 attack row(s) across 0 file(s)" was printed both when every stored score
    # was already correct and when there was nothing on disk to score at all -- and returned 0
    # either way. A CI step reads that as "scoring is up to date".
    examined = 0
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
        examined += 1
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
        import honeytoken as _ht
        note = _baseline_note(base, data["results"], _ht.declared(ctxs[base] or {}))
        # AND THE SHARPER CAVEAT, THROUGH THE SAME DOOR. Splitting a breach into "the payload
        # reached the model" and "the model acted on it" needs nothing but the stored replies,
        # so every run already on disk can answer it — including the ones that predate the
        # measurement, which is every run there is. `caps` comes from the run's own meta: a
        # target that was seedable then is refused now, rather than compared against a baseline
        # that never met the payload.
        delivery = _two_factor_note(base, data["results"], ctxs[base] or {},
                                    caps=(data.get("meta") or {}).get("caps") or ())
        note_moved = ((note or "") != (data["meta"].get("attribution") or "")
                      or (delivery or "") != (data["meta"].get("delivery") or ""))
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
        if delivery and delivery != (data["meta"].get("delivery") or ""):
            for l in delivery.strip().splitlines()[:4]:
                print(f"      {l.strip()[:96]}")
        if args.write:
            data["meta"]["attribution"] = note
            data["meta"]["delivery"] = delivery
            # THE BUILD IS THE ORACLE THAT PRODUCED THESE VERDICTS, and after this line
            # that is the one running now -- the rule `write_maps` states and applies to
            # the lock map a hundred lines down, in this same command, on the same run.
            # `when` is untouched for the opposite reason: the probes were measured
            # whenever they were measured.
            from target import judged_now as _judged_now
            data["meta"] = _judged_now(data["meta"])
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            html = workspace.artifact(f"report_{name}.html", root=OUT_DIR)
            # WITH THE PANELS THE RUN PUT THERE. This rebuilt the page from the results
            # alone, so re-scoring a stored run silently deleted the recon fingerprint and
            # the isolation lock map from it -- ten targets here ship one or both, and the
            # command that removed them exists to keep the scores current. Same reader as
            # `run`, so the two cannot render the same page from different inputs.
            _recon = workspace.side_artifact(
                None, f"recon_{name}.json", "profile", root=OUT_DIR)
            _iso = workspace.side_artifact(
                None, f"isolation_{name}.json", "maps", root=OUT_DIR)
            with open(html, "w", encoding="utf-8") as f:
                f.write(build_html(data["meta"], data["results"],
                                   recon=_recon, isolation=_iso))

    # Lock maps, which had no replay at all until one of them published HARDENED over a key
    # its own record held.
    maps_changed, maps_touched = 0, 0
    # READ IS NOT CHANGED, and the exit code is the difference. This loop counted only
    # the files it REWROTE, and `examined` below counts only results files, so a
    # directory holding lock maps and no sweep exited 3 — `nothing was
    # measured` — after re-scoring every map in it. See the note at the bottom.
    maps_examined = 0
    for path in sorted(glob.glob(os.path.join(OUT_DIR, "isolation_*.json"))):
        stem = os.path.basename(path)[len("isolation_"):-len(".json")]
        maps, changed = rescore_map(path)
        # THE MAP'S OWN RECORD OF WHICH TARGET IT IS ABOUT, which means reading it before
        # deciding whether `--target` wants it. Resolved from the filename alone, three of
        # the maps stored here read as two other targets, and this is the command that
        # rewrites the published page for whatever it resolves to. One rule, in `isolation`,
        # so `coverage` and this cannot file the same artifact under different targets.
        tgt = _map_target(stem, _map_meta.get(path) or {}, ctxs)
        if args.target and tgt != args.target:
            continue
        maps_examined += 1
        if not changed:
            continue
        maps_touched += 1
        maps_changed += len(changed)
        print(f"\n{os.path.basename(path)}")
        for obj, before, after in changed:
            keyed = ", ".join(after[1]) or "-"
            # A STORED MAP MAY CARRY NO VERDICT AT ALL, and `None` is not a string: the
            # format spec raised `TypeError` out of the print, which is a crash in the
            # command whose whole job is to re-score what is stored. Named as unset,
            # because a map that never said is a fact worth seeing in the diff.
            _was = before[0] if before[0] is not None else "(unset)"
            _now = after[0] if after[0] is not None else "(unset)"
            print(f"  {obj:<26}{_was:<10} ->  {_now:<10} keyed: {keyed}")
        if args.write:
            # THE DATE SURVIVES AND THE BUILD DOES NOT, because they answer opposite
            # questions: the probes were measured whenever they were measured, and the
            # verdicts in this file were produced by the oracle running now. Dropping
            # `when` here would leave `write_maps` to invent one, which it refuses to.
            write_maps(path, maps, {k: v for k, v in _map_meta.get(path, {}).items()
                                    if k != "engine"})
            # AND the page, or the correction stops at the JSON. The scorecard renders the
            # lock map straight from this file, so leaving it alone is how HARDENED stayed on
            # the published page for a target whose own record held the key that opened it.
            results = os.path.join(OUT_DIR, f"results_{tgt}.json") if tgt else None
            if results and os.path.exists(results):
                with open(results, encoding="utf-8") as f:
                    rd = json.load(f)
                # THE SAME RULE AS `run`'s panel: the artifact's own date where it has
                # one, and marked as the filesystem's where it does not.
                from workspace import dated as _dated_fn
                when, _msaid = _dated_fn(_map_meta.get(path) or {}, path)
                html = os.path.join(OUT_DIR, f"report_{tgt}.html")
                # AND THE RECON PANEL TOO. This branch restored the lock map and dropped
                # the fingerprint, which is the same deletion pointed the other way.
                _recon2 = workspace.side_artifact(
                    None, f"recon_{tgt}.json", "profile", root=OUT_DIR)
                with open(html, "w", encoding="utf-8") as f:
                    f.write(build_html(rd["meta"], rd["results"], recon=_recon2,
                                       isolation={"maps": maps, "when": when}))
                print(f"  rebuilt {os.path.basename(html)}")

    if skipped:
        # NOT A NOTE. Nothing was re-scored for these targets, which is the whole command.
        print(f"\nNOT RE-SCORED — no config found for: {', '.join(skipped)}.\n"
              f"  Re-scoring reads the canaries and markers from the config, and results "
              f"files do not carry them.\n"
              f"  Point at it, and every other command with it:\n"
              f'      export QATRATION_CONFIGS="/path/to/your.yaml"')
    verb = "rescored" if args.write else "would change"
    print(f"\n{verb} {total_changed} attack row(s) across {files_touched} file(s)"
          f"{' (some of them only their attribution caveat)' if files_touched and not total_changed else ''}.")
    if maps_touched:
        print(f"{verb} {maps_changed} lock-map objective(s) across {maps_touched} map file(s).")
    if (total_changed or files_touched or maps_touched) and not args.write:
        print("nothing was written — re-run with --write to apply")
    # NOT A PASS. Nothing was re-scored because there was nothing to re-score, which is
    # the question going unanswered rather than answered well. `docs/ci.md` gives that
    # code 3; returning 0 told a pipeline the stored scores had been checked.
    #
    # AND A LOCK MAP IS AN ARTIFACT THIS COMMAND RE-SCORES. `examined` counted results
    # files only, so a directory with lock maps and no sweep — which is what
    # `qatration isolation --target x` alone leaves — got `no results, run a
    # sweep first` and exit 3 AFTER this command had corrected those maps and written them
    # back. The case that proved it is the one `rescore_map` was written for: a stored
    # HARDENED replaced with EXPLOITED, the file rewritten, and the number a pipeline reads
    # saying nothing happened. That docstring calls the verdict the most expensive kind of
    # wrong this tool can be, and the correction for it was published as an absence.
    if not examined and not maps_examined:
        print(no_results_note(OUT_DIR) if not skipped else
              "no artifact could be re-scored: every results file found is for a target with "
              "no config, and re-scoring reads the canaries from the config.")
        return 3
    # AND SAY WHICH HALF DID NOT HAPPEN, rather than letting one 0 stand for both. A lock
    # map carries no attack rows and no attribution caveat, so a directory with maps alone
    # has had its objectives re-scored and its sweep verdicts not looked at.
    if not examined:
        print("\nNO SWEEP RESULT WAS RE-SCORED, and %d lock map(s) were. Re-scoring an "
              "attack row reads the canaries from the config; a lock map needs none."
              % maps_examined)
        if not skipped:
            print(no_results_note(OUT_DIR))
    return 0


if __name__ == "__main__":
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
