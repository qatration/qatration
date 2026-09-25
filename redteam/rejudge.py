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
    qatration rejudge --pages      # rebuild the HTML only, touching no record

Read-only by default on purpose: these files are the record of expensive runs, and a
scoring tool has no business overwriting them until someone has looked at what changes.
"""
import sys, os, glob, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import workspace
from workspace import OUT as WORKSPACE_OUT, no_results_note, target_of, BROKE
from workspace import point_at_configs
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
from isolation import restate_combined_inert
from isolation import (apply_keysearch, _verdict, read_maps, write_maps,
                       map_target as _map_target, restate_unmeasured)
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


def _number(value, default):
    """A stored number, or the default. Never an exception.

    `float(d.get("seconds") or 0)` reads the field the timing detectors judge, and a record
    holding a string there ended the command rather than the probe. The same rule as the
    tool-call normaliser beside it: a stored artifact is evidence, not a promise.
    """
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return float(default)


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
    # THROUGH THE SAME NORMALISER THE RUN USED. `[tuple(t) for t in ...]` trusts the stored
    # shape, and a stored record is not a trusted input: `tool_calls: 7` is not iterable,
    # `[None]` is not a pair, and either one came out of here as a TypeError that cost the
    # WHOLE command -- no scores, no pages, for one field of one probe. Measured on a planted
    # artifact: three shapes out of six killed `qatration rejudge` outright.
    #
    # `_pairs` is where this engine already decides what a tool call is, with a docstring
    # saying an unusable shape is reported rather than guessed at. It is idempotent over the
    # pairs a run stores, so a replay reads what the run read -- which is the property this
    # whole function exists for.
    from targets_http import _pairs as _pairs_r
    return Probe(prompt=_prompt_of(attack, d.get("prompt")),
                 output=d.get("output") or "",
                 tool_calls=_pairs_r(d.get("tool_calls")),
                 observations=d.get("observations") or [],
                 resolved=_pairs_r(d.get("resolved")),
                 error=d.get("error"), seconds=_number(d.get("seconds"), 0.0),
                 turns=d.get("turns") or [],
                 retries=int(_number(d.get("retries"), 0)),
                 reply_bytes=(int(_number(d["reply_bytes"], 0))
                              if d.get("reply_bytes") is not None else None))


def rescore(path, ctx, why=None):
    """Returns (data, [changed rows]) — never writes. (None, []) for a record it cannot read.

    THROUGH `read_artifact`, which is the one reader for this directory and exists because
    of what the other way costs: "a single truncated artifact took every one of them down
    with a raw JSONDecodeError". This read was `with open(...): json.load(f)`, a shape the
    gate against raw reads could not see, so it was the one left -- and it is the command
    that reads the most records. Measured: one truncated `results_*.json` in a workspace of
    three ended `qatration rejudge` with a traceback, and the two good files were not
    re-scored either.

    `why` is an out-parameter, the idiom this package uses where a caller has to say what
    went wrong: the reason is appended, and the caller names the file.
    """
    data, _err = workspace.read_artifact(path)
    if _err is not None:
        if why is not None:
            why.append(_err)
        return None, []
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
            changed.append((workspace.attack_name(attack), before, (head, rate), fired))
        r["headline"], r["rate"] = head, rate
        r["fired"] = fired
        r["locks"] = summarize(recs, ctx)

    # the headline counters in meta are derived, so they have to move too
    real = [r for r in data.get("results", []) if r["attack"].get("category") != "control"]
    data["meta"]["broke"] = sum(1 for r in real if r["headline"] in BROKE)
    # A SKIP ROW IS NOT AN ATTACK THAT FIRED. Older artifacts can carry them — the sweep only
    # started withholding an undeliverable attack up front — and counting them here would put
    # the overstatement back into a file that had been rescored to remove it.
    # PLUS WHAT THE RUN NEVER REACHED, which left no row to count and which `measured`
    # subtracts: recounting from the rows alone took them off twice, and a no-op rejudge of a
    # stopped run lowered what it had measured. Found by an independent review.
    data["meta"]["attacks_n"] = (sum(1 for r in real if r["headline"] != "SKIP")
                                 + (data["meta"].get("unreached") or 0))
    # AND THE ERRORED COUNT, which is as derived as the two above it and was not in the
    # list. `workspace.measured` -- the denominator the scorecard, the defence page, the
    # fleet index and the SARIF export all share -- reads it, so a re-score moved
    # `attacks_n` and left `errors` describing the rows before it. Measured: a file whose
    # every row was rewritten came back with the count it was handed.
    # Through `error_split`, the sweep's own rule: a row the budget never sent is not errored.
    data["meta"]["errors"], data["meta"]["never_sent"] = workspace.error_split(real)
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
        # THE STORED STATUSES FIRST, where the tallies beside them say they measured nothing.
        for _row in (m.get("properties") or []) + [m.get("combined")]:
            restate_unmeasured(_row)
        restate_combined_inert(m)
        m["verdict"] = _verdict(m.get("properties") or [], m.get("combined") or {},
                                m.get("coupling") or [])
        apply_keysearch(m)
        after = (m.get("verdict"), tuple(m.get("keyed") or ()))
        if before != after:
            changed.append((m.get("objective", "?"), before, after))
    return maps, changed


def write_page(name, data):
    """Rebuild `report_<name>.html` from one stored record. Writes nothing else.

    WITH THE PANELS THE RUN PUT THERE. An earlier version built the page from the results
    alone, so re-scoring a stored run silently deleted the recon fingerprint and the
    isolation lock map from it -- ten targets here ship one or both, and the command that
    removed them exists to keep the scores current. Same reader as `run`, so the two cannot
    render one page from different inputs.

    A FUNCTION BECAUSE TWO COMMANDS NEED IT. `--write` rebuilds the page as a consequence of
    re-scoring; `--pages` rebuilds it and nothing else.
    """
    html = workspace.artifact(f"report_{name}.html", root=OUT_DIR)
    _recon = workspace.side_artifact(None, f"recon_{name}.json", "profile", root=OUT_DIR)
    _iso = workspace.side_artifact(None, f"isolation_{name}.json", "maps", root=OUT_DIR)
    with workspace.atomic_write(html) as f:
        f.write(build_html(data["meta"], data["results"], recon=_recon, isolation=_iso))


def no_such_target(target, what):
    """-> the sentence for a `--target` no stored results answer to, or None.

    A NAME THAT MATCHED NOTHING IS NOT AN EMPTY WORKSPACE. Both modes of this command ended on
    `no_results_note` -- "no results in out/ -- run a sweep first" -- over a directory holding
    results for other targets, so a mistyped name read as lost evidence and sent the reader to
    spend a sweep. `runs --target` names the targets it has; this does too.
    """
    if not target:
        return None
    _names = contexts()
    here = sorted({target_of(s, _names) or s
                   for s in (os.path.basename(p)[len("results_"):-len(".json")]
                             for p in glob.glob(os.path.join(OUT_DIR, "results_*.json")))})
    if not here or target in here:
        return None
    return ("no stored results for target %r in %s. The targets with results here: %s. "
            "Nothing was %s." % (target, OUT_DIR, ", ".join(here), what))


def rebuild_pages(only=None):
    """Every committed report page, rebuilt from the record exactly as it is stored.

    THE RECORD IS NOT TOUCHED, and that is the whole reason this exists beside `--write`.
    Rebuilding a page used to cost the provenance of the run it describes: the write branch
    stamps `judged_by` with the build running now and recomputes the attribution caveat, so
    the only way to bring a page up to date with the renderer was to rewrite forty-five
    stored records into saying they were judged today.

    They needed it. `report_engine` grew a `Which trial` block -- which of the trials the
    reply on the page came from, and how many of them broke -- and the committed pages
    predate it, so every one of them shows a reply with no way to tell whether it was the
    run that broke or the two that held. Nothing rebuilt them, because the gate that keeps a
    committed page honest drives the four commands that have no side effects.

    -> the names rebuilt, so a caller can say how many rather than that it went well.
    """
    done = []
    # `--target` MEANT TWO THINGS IN ONE COMMAND. The re-score below resolves each file to the
    # target that wrote it, so `--target mybot` takes `results_mybot.json` and its per-model
    # copies `results_mybot_alpha.json`, `..._beta.json`; this compared the file's own stem,
    # so `--pages --target mybot` rebuilt one page of the three, and `--pages --target
    # mybot_alpha` rebuilt a page the re-score answered with "no results -- run a sweep
    # first". One rule, the re-score's. A file whose target has no config is its own name,
    # because a page needs no oracle to be drawn.
    _names = contexts() if only else {}
    for path in sorted(glob.glob(os.path.join(OUT_DIR, "results_*.json"))):
        name = os.path.basename(path)[len("results_"):-len(".json")]
        if only and (target_of(name, _names) or name) != only:
            continue
        # THROUGH `read_artifact`, which is the one reader for this directory: five modules
        # opened it themselves once and a single truncated file took all five down with a
        # raw JSONDecodeError, naming nothing. A command that rewrites every page must not
        # be the one that stops at the first bad file and leaves the rest stale.
        data, why = workspace.read_artifact(path)
        if why is not None:
            print(f"  ! {os.path.basename(path)} could not be read ({why}); its page is "
                  f"left as it stands")
            continue
        if not isinstance(data, dict) or "results" not in data:
            print(f"  ! {os.path.basename(path)} holds no results; its page is left as it "
                  f"stands")
            continue
        write_page(name, data)
        done.append(name)
    return done


def main():
    # THE ONE SPELLING, from the table this command is listed in. A bare parser
    # here printed the flags and left `--help` silent about the job.
    from cli import parser as _cli_parser
    ap = _cli_parser("rejudge")
    ap.add_argument("--write", action="store_true",
                    help="apply the re-scoring and rebuild each HTML report "
                         "(default: preview only)")
    ap.add_argument("--target", default=None, help="restrict to one target name")
    # REBUILDING A PAGE SHOULD NOT COST THE PROVENANCE OF THE RUN. `--write` stamps every
    # record it rewrites with the build doing the stamping, which is right for a re-score
    # and wrong as the price of re-rendering.
    ap.add_argument("--pages", action="store_true",
                    help="rebuild each HTML report from the stored record and write "
                         "nothing else")
    args = ap.parse_args()
    # TWO ANSWERS TO ONE QUESTION, and `--pages` returned first. `--pages --write` rebuilt the
    # pages from the records as stored, said "no record was changed" and exited 0: the re-score
    # the reader asked for by name was never run, in a sentence that reads as it having found
    # nothing to change.
    if args.pages and args.write:
        ap.error("--pages rebuilds the pages from the records as they are; --write re-scores the "
                 "records and rebuilds the pages from the new scores. They are different jobs: "
                 "run one. Nothing was written.")

    if args.pages:
        _built = rebuild_pages(args.target)
        # NOTHING REBUILT IS NOT A SUCCESS. An empty `out/` and a directory whose every page
        # is current print the same sentence otherwise, and this command exists to be run
        # after a change to the renderer.
        #
        # AND IT SAYS WHAT TO DO, through the sentence every other command that reads this
        # directory already uses. Walked on an empty workspace, all twelve of them ended on a
        # command to type -- and this one, added last, ended on "rebuilt 0 page(s)", which
        # reads like a report on work done rather than on a directory with nothing in it.
        if not _built:
            print(no_such_target(args.target, "rebuilt") or no_results_note(OUT_DIR))
            return 3
        print("rebuilt %d page(s) from stored records; no record was changed"
              % len(_built))
        return 0

    # NO FLAG HERE, and that is a decision the build made rather than a preference. It had one
    # briefly, implemented by writing QATRATION_CONFIGS from inside this module, and `test_llm`
    # refused it: "no module mutates process-global state, so one target cannot move another's
    # ground". Correct -- a module that edits the environment changes the ground under whatever
    # runs next in the same process. The variable is the mechanism; `qatration init` prints the
    # line that sets it, and the message below names it.
    _collisions = []
    ctxs = contexts(collisions=_collisions)
    from workspace import configs_by_name as _configs_by_name
    # `realpath`, the same spelling `run` writes: see the note there about macOS symlinks.
    _config_paths = {n: os.path.realpath(fp) for n, (fp, _c) in _configs_by_name().items()}
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
    examined, rows_examined = 0, 0
    total_changed, files_touched, skipped, unreadable = 0, 0, [], []
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
        _why_r = []
        data, changed = rescore(path, ctxs[base], why=_why_r)
        if data is None:
            # NAMED AND PASSED OVER, not raised and not skipped in silence. Counted apart
            # from `examined`, because a file this could not read was not examined, and the
            # closing line says so rather than folding it into a count of files it did.
            print(f"\n  ! {os.path.basename(path)} could not be read ({_why_r[0]}); it is "
                  f"NOT re-scored and its page is left as it stands")
            unreadable.append(os.path.basename(path))
            continue
        examined += 1
        rows_examined += len(data.get("results") or [])

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
        # WITH THE CONFIG IT RESOLVED, when it resolved one. This passed none, so the note's
        # remedy became `--target-config <the config you swept>` even with QATRATION_CONFIGS
        # naming the config -- and a sweep's note, which carries the real path, read as
        # changed: walked, a fresh `run` then `rejudge` offered to replace the exact command
        # with the placeholder, on a run that had nothing to re-score.
        note = _baseline_note(base, data["results"], _ht.declared(ctxs[base] or {}),
                              config_path=_config_paths.get(base),
                              as_of=(data.get("meta") or {}).get("when") or "")
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
            with workspace.atomic_write(path) as f:
                json.dump(data, f, indent=2, default=str)
            write_page(name, data)

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
        # A TORN LOCK MAP IS NAMED AND PASSED OVER, like a torn results file above. `read_maps`
        # raises through the one reader now, and this was the caller that did not catch it.
        try:
            maps, changed = rescore_map(path)
        except ValueError as _e_m:
            print(f"\n  ! {os.path.basename(path)} could not be read ({_e_m}); it is NOT "
                  f"re-scored and its page is left as it stands")
            unreadable.append(os.path.basename(path))
            continue
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
                # THE SAME READER, for the same reason: this rebuilds the page from the
                # results file, and a truncated one ended the command here too.
                rd, _rd_why = workspace.read_artifact(results)
                if _rd_why is not None:
                    print(f"  ! {os.path.basename(results)} could not be read ({_rd_why}); "
                          f"the lock map is corrected but its page is left as it stands")
                    continue
                # THE SAME RULE AS `run`'s panel: the artifact's own date where it has
                # one, and marked as the filesystem's where it does not.
                from workspace import dated as _dated_fn
                when, _msaid = _dated_fn(_map_meta.get(path) or {}, path)
                html = os.path.join(OUT_DIR, f"report_{tgt}.html")
                # AND THE RECON PANEL TOO. This branch restored the lock map and dropped
                # the fingerprint, which is the same deletion pointed the other way.
                _recon2 = workspace.side_artifact(
                    None, f"recon_{tgt}.json", "profile", root=OUT_DIR)
                with workspace.atomic_write(html) as f:
                    f.write(build_html(rd["meta"], rd["results"], recon=_recon2,
                                       isolation={"maps": maps, "when": when}))
                print(f"  rebuilt {os.path.basename(html)}")

    if skipped:
        # NOT A NOTE. Nothing was re-scored for these targets, which is the whole command.
        print(f"\nNOT RE-SCORED — no config found for: {', '.join(skipped)}.\n"
              f"  Re-scoring reads the canaries and markers from the config, and results "
              f"files do not carry them.\n"
              f"  Point at it, and every other command with it:\n"
              + "\n".join(point_at_configs(indent="      ")))
    # "CHANGED", NOT "RESCORED": the sentence below ends "having re-scored N", and on a stranger's
    # first `--write` it read "rescored 0 attack row(s) ... having re-scored 46" -- the same
    # word for the rows that moved and the rows that were looked at.
    verb = "changed" if args.write else "would change"
    # A COUNT OVER THE FILES IT COULD READ, printed as one over the directory, is the gap
    # this whole engine is named after. The files it could not read are named beside it.
    if unreadable:
        print(f"\nNOT RE-SCORED — could not be read: {', '.join(unreadable)}.")
    # AND SAY HOW MUCH WAS LOOKED AT, in the sentence and not only in the exit code. "would
    # change 0 attack row(s) across 0 file(s)" was printed over three results files that had
    # all been read and were all current, and over a filter that matched none of them: a
    # reader at a terminal saw the same line for both. `benign --rejudge` wrote this rule
    # down ("0 rows would change reads as a clean bill") and applied it to its own sentence.
    print(f"\n{verb} {total_changed} attack row(s) across {files_touched} file(s)"
          f"{' (some of them only their attribution caveat)' if files_touched and not total_changed else ''}"
          f", having re-scored {rows_examined} across {examined} results file(s).")
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
    # `qatration isolation --target-config x.yaml` alone leaves — got `no results, run a
    # sweep first` and exit 3 AFTER this command had corrected those maps and written them
    # back. The case that proved it is the one `rescore_map` was written for: a stored
    # HARDENED replaced with EXPLOITED, the file rewritten, and the number a pipeline reads
    # saying nothing happened. That docstring calls the verdict the most expensive kind of
    # wrong this tool can be, and the correction for it was published as an absence.
    if not examined and not maps_examined:
        # AND NOT "RUN A SWEEP FIRST" OVER A DIRECTORY THAT HOLDS ONE. A workspace whose only
        # results file is unreadable is not an empty one, and the advice for it is different.
        print(no_such_target(args.target, "re-scored") or
              no_results_note(OUT_DIR) if not (skipped or unreadable) else
              "no artifact could be re-scored: every results file found is unreadable or "
              "for a target with no config, and re-scoring reads the canaries from the config."
              if skipped else
              "no artifact could be re-scored: every results file found is unreadable, and "
              "is named above.")
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
