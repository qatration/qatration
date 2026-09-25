"""
Entry point for the lock-isolation harness: map a target's defences per objective
before spending a sweep on payloads.

    qatration isolation --trials 3
    ... --target-config redteam/targets_guardbot.yaml --json out/isolation.json

Reads objectives from YAML (properties + combined payload), runs each property in
isolation, then the combination, and prints one map per objective. Reuses the same
target adapters, detectors and ctx as run_redteam.py — this is a different question
asked of the same engine, not a second engine.
"""
import sys, os, re, argparse, json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import yaml
from isolation import (run_isolation, format_map, apply_keysearch, prop_ctx, write_maps,
                       would_lose_a_measurement)
from keysearch import search, format_search, load_frames
from compose import compose, format_compose


from run_redteam import load_target as _build_target
from workspace import (OUT as WORKSPACE_OUT, safe_target_name,
                       refuse_to_overwrite_evidence, OVERWRITE_HELP)


def load_target(cfg_path, model=None):
    """Reuse run_redteam's adapter registry and target config verbatim — one place
    to add a target, both entry points get it."""
    from workspace import load_yaml_or_refuse as _load_yaml
    tcfg = _load_yaml(cfg_path, "target config", "isolation")
    from workspace import refuse_unusable_config as _refuse
    _refuse(tcfg, "isolation")
    # AUTHORISATION FIRST, before a target is even built. Isolation sends real traffic — a
    # separate probe per defence, several trials each — so it is exactly as much somebody
    # else's system as a sweep is. The gate lived in the sweep and the benign run and not
    # here, while the documentation said "any non-local target".
    from authorization import gate as _auth_gate
    _auth_gate(tcfg, "isolation")
    from workspace import apply_model_override as _amo
    _amo(tcfg, model, "isolation")
    target = _build_target(tcfg)
    if tcfg.get("name"):
        # Through the shared rule: this assignment used to hand the raw config
        # value to an adapter that never validates it, and the name becomes a
        # filename in six places, one of them an append.
        target.name = safe_target_name(tcfg["name"], "target config")
    from workspace import oracle_context_of as _octx
    # AND THE CANARY THE OBJECTIVES LOOK FOR IS THERE, which `run` refuses without: with the
    # honeytoken snippet reverted, the canary objective read HARDENED, exit 0 -- a lock that
    # held against a secret the target no longer had. Found by an independent review.
    import honeytoken as _ht_i
    _pre = _ht_i.precondition(target, _octx(tcfg))
    if _pre is not None:
        print("ABORT — %s\n  nothing was sent and nothing was written." % _pre[2],
              file=sys.stderr)
        sys.exit(_pre[0])
    return target, _octx(tcfg)


def objectives_path(name):
    """Where a relative `--objectives` points: beside the reader, the workspace, the package.

    IT RESOLVED AGAINST THE PACKAGE ALONE. So an operator who wrote objectives beside their
    own config and passed the name got a FileNotFoundError naming a path inside
    `site-packages` -- and `generate` had to WRITE there for its output to be reachable,
    which it did, on every fresh install, into the installed package.

    THE PACKAGE STAYS IN THE LIST AND STAYS LAST. `isolation_example.yaml` and the per-bot
    objectives are package data and `--objectives` defaults to one of them.

    A FUNCTION so the refusal can be reached without building a target and sending traffic:
    the same reason `gate_verdict` and `regression_verdict` are functions. Resolution is not
    a decision anyone should have to spend a run to check.
    """
    if os.path.isabs(name) or os.path.exists(name):
        return name
    for base in (WORKSPACE_OUT, HERE):
        candidate = os.path.join(base, name)
        if os.path.exists(candidate):
            return candidate
    raise SystemExit(
        "isolation: no objectives file at %r. Looked beside you, in %s, and in the "
        "objectives this package ships.\n"
        "  `qatration generate --target-config <cfg>` writes one into the workspace."
        % (name, WORKSPACE_OUT))


def main():
    # THE ONE SPELLING, from the table this command is listed in. A bare parser
    # here printed the flags and left `--help` silent about the job.
    from cli import parser as _cli_parser
    ap = _cli_parser("isolation")
    # NO DEFAULT TARGET. This pointed at a practice bot shipped inside the package,
    # so `qatration isolation` from an install aimed at the author's LangChain agent
    # rather than at the user's deployment, and the optional extra that bot needs is
    # not installed by default: the command ended in a raw ModuleNotFoundError
    # traceback and exit 1, which the exit-code contract reserves for "the target was
    # exploited or breached". `benign`, `run` and `matrix` all ask for the config and
    # exit 2; these two were the ones that did not.
    ap.add_argument("--target-config", required=True, help="the YAML describing the target")
    ap.add_argument("--overwrite-evidence", action="store_true", help=OVERWRITE_HELP)
    ap.add_argument("--objectives", default="isolation_example.yaml",
                    help="the objectives file naming what to isolate, one defence at a time")
    from workspace import trial_count as _trial_count
    ap.add_argument("--trials", type=_trial_count, default=3,
                    help="repeats per probe — one trial cannot tell a wall from noise")
    ap.add_argument("--only", default=None, help="run a single objective id")
    ap.add_argument("--model", default=None,
                    help="override the target's model — the way to ask whether a finding "
                         "is a property of the technique or of the model size")
    ap.add_argument("--keys", action="store_true",
                    help="for every locked property, search frames.yaml for a framing "
                         "that opens it (costs trials x frames per locked property)")
    # COUNTED FROM THE LIBRARY, not written here. This said "all 16" over a library of
    # thirteen families and the control: a number in a help text is a claim nothing keeps
    # true, and this one had stopped being true without anything noticing.
    _families = sorted({str(f.get("family")) for f in load_frames()} - {"control"})
    ap.add_argument("--frame-families", default=None,
                    help="comma-separated families to search (default: all %d in the "
                         "library: %s). The whole library runs per LOCKED property per "
                         "trial, so this is the knob for when that budget matters; the bare "
                         "control always runs" % (len(_families), ", ".join(_families)))
    ap.add_argument("--stop-on-hit", action="store_true",
                    help="stop a property's search at the first frame that opens it — "
                         "cheaper, but you lose which OTHER families also work, which is "
                         "the evidence about the target")
    ap.add_argument("--frames", default=None, help="an alternative frame library")
    ap.add_argument("--compose", action="store_true",
                    help="after the key search, reassemble the keys into one payload and "
                         "test the whole objective (implies --keys)")
    ap.add_argument("--json", default=None,
                    help="write the raw maps here (default $QATRATION_OUT/isolation_<target>.json, "
                         "which `qatration run` picks up into the report)")
    args = ap.parse_args()
    if args.compose:
        args.keys = True          # composition needs the keys the search finds
    # AND THE THREE FLAGS THAT ONLY STEER THE SEARCH imply it the same way. Without `--keys`
    # they were dropped in silence: walked, `--frame-families authority --stop-on-hit --frames
    # <a broken library>` ran the plain map, never opened the library it was pointed at,
    # printed two locked properties as HARDENED and exited 0 -- a family search asked for by
    # name, reported as a wall nothing had searched.
    _steer = [_f for _f, _on in (("--frame-families", args.frame_families is not None),
                                 ("--frames", args.frames is not None),
                                 ("--stop-on-hit", args.stop_on_hit)) if _on]
    if _steer and not args.keys:
        args.keys = True
        print("isolation: %s only steer%s the key search, so the search runs: --keys is "
              "implied, as it is by --compose.\n"
              % (" and ".join(_steer), "s" if len(_steer) == 1 else ""))

    path = objectives_path(args.objectives)
    from workspace import load_yaml_or_refuse as _load_yaml
    objectives = _load_yaml(path, "objectives file", "isolation")
    # The same rule, on the corpus where a typo is worst: an unknown name leaves nothing to
    # evaluate, every trial misses, and an objective whose properties are all locked reads as
    # HARDENED — the strongest claim this command makes.
    # SHAPE BEFORE SPELLING, the order `refuse_unknown_detectors` already keeps inside
    # itself, and the half that was missing out here: that rule asks what the DETECTOR
    # NAMES are, and an objectives file whose entries are not objectives reached
    # `scoped_to` and the probe loop as a traceback. `run --attacks mine.yaml` has had
    # `unusable_entries` at its door since the day a customer's arsenal could reach one.
    from lint_arsenal import refuse_unknown_detectors, unusable_objectives
    _unusable = unusable_objectives(objectives, os.path.basename(path))
    if _unusable:
        print("isolation: %d objective(s) in %s cannot be used. Nothing was sent."
              % (len(_unusable), path), file=sys.stderr)
        for _u in _unusable[:8]:
            print("    " + _u, file=sys.stderr)
        # 2: the invocation was refused. Not 1, which is a finding about the target.
        return 2
    refuse_unknown_detectors(objectives, "isolation", path, nested=True)

    target, ctx = load_target(args.target_config, args.model)
    # SCOPING IS ONE RULE IN ONE PLACE. `run_redteam` had the same expression written out
    # again, and the hazard they share does not survive being copied: an `applies_to`
    # without brackets is a string, and `name in "guardbot"` is a substring test. The
    # shape itself is refused a few lines up, by `refuse_unknown_detectors`.
    from workspace import scoped_to as _scoped
    # THE IDS AS LOADED, kept before scoping: the filter below runs on what is left, and
    # reporting "it has: none" about a corpus that has three -- all of them for another bot
    # -- answers the wrong question.
    _all_ids = [str(o.get("id")) for o in objectives]
    objectives = [o for o in objectives if _scoped(o, target.name)]
    if args.only:
        # AN ID NOBODY HAS IS A TYPO, NOT AN ANSWER ABOUT THE TARGET. This narrowed to
        # nothing and fell into the branch below, which says "no objectives apply to target
        # 'x' -- nothing was measured" -- a sentence about `applies_to` scoping and about the
        # target, sending a reader to look at two files when one character of the flag is
        # wrong. `tools/check.py` refuses an unmatched suite pattern for the same reason:
        # "a typo that silently runs nothing is a green build that checked nothing. Refuse
        # rather than narrow."
        _named = [o for o in objectives if o.get("id") == args.only]
        if not _named and args.only in _all_ids:
            # IT EXISTS AND IS FOR ANOTHER BOT, which is a different mistake from a typo and
            # has a different remedy: the reader has the right id and the wrong target.
            print("isolation: --only %r is an objective in %s, but its `applies_to` "
                  "excludes %r, so it was scoped out before the filter ran. Nothing was "
                  "sent." % (args.only, path, target.name), file=sys.stderr)
            return 2
        if not _named:
            print("isolation: --only %r matches no objective in %s. It has: %s."
                  % (args.only, path, ", ".join(_all_ids) or "none"),
                  file=sys.stderr)
            # 2: the invocation was refused. Not 3, which says the target was asked and
            # could not answer.
            return 2
        objectives = _named
    if not objectives:
        # 3, NOT 0. No objective ran, so nothing was measured, and returning None made
        # `cli` exit 0 -- which a pipeline reads as a clean lock map. `run` already exits
        # 3 for the same situation on its own side, and `test_end_to_end` asserts it:
        # `an arsenal with no applicable attack exits 3, not 0`.
        print(f"no objectives apply to target '{target.name}' — nothing was measured, "
              f"which is not the same as nothing being open")
        return 3

    # THE DESTINATION BEFORE THE PROBES, as in `recon`: both refusals below read only the path
    # -- the reader's flag, or the target's name and the objectives file's -- and were made
    # after every probe and every key search had been sent.
    # The artifact name follows the OBJECTIVES, not just the target: a run of generated
    # objectives used to overwrite the results of the curated ones for the same bot, which
    # is a silent loss of the more expensive artifact of the two.
    stem = os.path.splitext(os.path.basename(path))[0]
    tag = re.sub(r"^isolation_", "", stem)
    tag = re.sub(rf"_?{re.escape(target.name)}$", "", tag)     # no guardbot_…_guardbot
    tag = "" if tag in ("", target.name, "example", "more") else "_" + tag
    # A PATH THE READER TYPED IS THEIRS, relative to where they typed it. This joined it onto
    # the directory this module is installed in, so `--json x.json` from a workspace landed
    # beside site-packages -- and the next CI step, reading `x.json`, found nothing.
    out = os.path.abspath(args.json or os.path.join(WORKSPACE_OUT,
                                                    f"isolation_{target.name}{tag}.json"))
    # THE SAME REFUSAL `run` AND `benign` MAKE. `refuse_to_overwrite_evidence` was
    # written after a `--attacks` run replaced a full sweep's `results_httpbot.json`
    # with eight rows and `coverage` reported 958 fewer probes. It was then wired into
    # two of the five commands that write evidence into `out/`, and this is one of the
    # other three: the repository tracks 11 isolation maps, each a record of a real
    # target's replies that `run` folds into a report.
    #
    # An untracked file is still overwritten in silence, which is the point: a person
    # re-running their own sweep is not asked permission.
    _refusal = refuse_to_overwrite_evidence(
        out, force=getattr(args, "overwrite_evidence", False))
    if _refusal:
        # 2, THE SAME AS `run`: the invocation was refused and nothing was measured,
        # so a pipeline must not read it as a finding.
        print(_refusal, file=sys.stderr)
        return 2
    from workspace import writable_path as _writable
    out = _writable(out, "maps", "isolation", replaces=("a lock map",))

    print(f"target: {target.name}   objectives: {len(objectives)}   "
          f"trials: {args.trials}\n")
    fams = args.frame_families.split(",") if args.frame_families else None
    frames = load_frames(args.frames, fams) if args.keys else None
    if frames:
        scope = f" (families: {args.frame_families})" if fams else ""
        print(f"frame library: {len(frames)} frames{scope}\n")
    maps = []
    for obj in objectives:
        result = run_isolation(target, obj, ctx, trials=args.trials)
        maps.append(result)
        print(format_map(result))
        print()

        by_name = {p["name"]: p for p in obj["properties"]}
        if args.keys:
            # only locked properties are worth a search — an open one has nothing to open,
            # and a `task` is required because a frame wraps the bare ask, not a full probe
            # ...and the properties an empty reply left unmeasured: see `isolation.searchable`.
            from isolation import searchable as _searchable
            locked = [p for p in result["properties"] if _searchable(p)]
            for p in locked:
                spec = by_name.get(p["name"], {})
                task = spec.get("task")
                if not task:
                    print(f"  (no 'task' for '{p['name']}' — add one to search frames)\n")
                    continue
                # alternative phrasings a frame may require (task_self, ...) travel
                # with the property, so content stays in the objective file
                alts = {k: v for k, v in spec.items()
                        if k.startswith("task") or k == "frame_vars"}
                # judged under the property's own narrowing, same as the solo probe was
                #
                # `found`, NOT `out`: `out` is the artifact path, settled before the probes, and
                # this name used to reuse it -- harmless while the path was computed after the
                # loop, a crash in `write_maps` the moment it moved above it (d040215).
                found = search(target, task, spec.get("success", []), prop_ctx(spec, ctx),
                               frames=frames, trials=args.trials,
                               stop_on_hit=args.stop_on_hit, tasks=alts,
                               require_all=bool(spec.get("require_all")))
                p["keysearch"] = {k: v for k, v in found.items() if k != "results"}
                print(format_search(p["name"], found))
                print()
            # the map's verdict predates the search; a found key can invalidate it
            apply_keysearch(result)
            if result.get("keyed"):
                print(f"  verdict now {result['verdict']}: a frame opened "
                      f"{', '.join(result['keyed'])} — not hardened, keyed\n")

        # keys in hand, put them back together — the step where a by-hand red-teamer
        # reliably goes wrong, and the only way to tell "the combination is the wall"
        # apart from "nothing works"
        if args.compose and result["verdict"] != "EXPLOITED":
            parts, missing = compose_parts(result, by_name)
            if missing:
                # composing around a property that never opened would produce a failure
                # that proves nothing — say so instead of running it
                print(f"  compose skipped — nothing to compose from: {', '.join(missing)}\n")
            else:
                cout = compose(target, obj, parts, ctx, trials=args.trials)
                result["compose"] = {k: v for k, v in cout.items() if k != "best"}
                print(format_compose(cout))
                print()

    counts = {}
    for m in maps:
        counts[m["verdict"]] = counts.get(m["verdict"], 0) + 1
    print("summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    coupled = [m["objective"] for m in maps if m["verdict"] == "COUPLED"]
    if coupled:
        print("coupled objectives (locks open alone, blocked together): "
              + ", ".join(coupled))

    # (`out` and both refusals of it are settled above, before the probes.)
    if out:
        # AND A RUN THAT MEASURED NOTHING DOES NOT REPLACE ONE THAT DID. `run` refuses the
        # same trade in as many words, `benign` refuses it, `recon` refuses it; this wrote.
        # The rule lives in `isolation` beside the writer it guards.
        _lost = would_lose_a_measurement(out, maps)
        if _lost:
            print("\n" + _lost, file=sys.stderr)
        else:
        # through write_maps, so the artifact carries the build that produced it — lock maps
        # were a bare list with no meta and could not be stamped even in principle
        # THE MOMENT THIS MEASURED, said here because this is what knows it. `write_maps`
        # will not invent one: `rejudge --write` rewrites these files for probes recorded
        # weeks earlier, and a default would stamp today onto that evidence.
            import datetime as _dt_i
            write_maps(out, maps,
                       {"target": target.name, "objectives": os.path.basename(path)},
                       when=_dt_i.datetime.now().isoformat(" ", "seconds")[:16])
            print(f"\nwrote {out}")

    # 3 WHEN NOTHING WAS MEASURED, WHICH THE VERDICT ALREADY KNEW. `_verdict` learned to
    # answer UNMEASURED after a dead target came back HARDENED, and the exit code was left
    # at 0: pointed at an endpoint that refuses every connection this printed
    # `summary: UNMEASURED 1`, wrote the artifact, and told the shell it had succeeded. A
    # pipeline reads that as the locks holding, which is the strongest claim this command
    # makes, made from nothing. `recon` and `benign` both exit 3 for the same outage.
    #
    # The map is still WRITTEN. It is an honest record that a run happened and learned
    # nothing, and `coverage` and the report both read it; the exit code is the part a
    # pipeline acts on, and it was the part that was wrong.
    #
    # AND THE REASON IS THE ONE THE MAP RECORDS. This said "every property errored on every
    # trial" for every UNMEASURED run, and told the reader to check the endpoint. Walked on a
    # bot that answered every probe: its properties rested on `bfla_call` and
    # `forced_output`, which cannot fire on a config with no tools and no forbidden text, so
    # each came back `unmeasured` with no error at all -- and the reader was sent to debug a
    # server that was up, when what was missing was in their own config.
    if maps and all(m["verdict"] == "UNMEASURED" for m in maps):
        _n = len(maps)
        _which = "the objective" if _n == 1 else "none of the %d objectives" % _n
        _unm = [p for m in maps for p in (m.get("properties") or [])
                if p.get("status") == "unmeasured"]
        _deaf = {}
        for p in _unm:
            for _d, _w in (p.get("inert") or {}).items():
                _deaf.setdefault(_d, _w)
        _dead = [p for p in _unm if not p.get("inert") and not p.get("unscored")]
        _unscored = [p for p in _unm if p.get("unscored")]
        print("\nNOTHING MEASURED - so %s above says nothing about %s." % (_which, target.name))
        if _deaf:
            print("  %d propert%s could not be scored on this config: every detector %s "
                  "on cannot fire here, and the oracle_context lacks what each needs -- %s. "
                  "That is the config, not the endpoint: it answered, and nothing could "
                  "have judged the answer."
                  % (len(_unm) - len(_dead), "y" if len(_unm) - len(_dead) == 1 else "ies",
                     "it relies" if len(_unm) - len(_dead) == 1 else "they rely",
                     "; ".join("%s: %s" % (_d, " and ".join(map(str, _w))
                                           if isinstance(_w, (list, tuple)) else _w)
                               for _d, _w in sorted(_deaf.items()))))
        if _dead:
            print("  %d propert%s errored or came back empty on every trial. Check the "
                  "endpoint is up and answering, then run this again."
                  % (len(_dead), "y" if len(_dead) == 1 else "ies"))
        if _unscored:
            print("  %d propert%s declare no `success:` of %s own, so %s solo probe%s could "
                  "not be judged; only the combined test reads the objective's list."
                  % (len(_unscored), "y" if len(_unscored) == 1 else "ies",
                     "its" if len(_unscored) == 1 else "their",
                     "its" if len(_unscored) == 1 else "their",
                     "" if len(_unscored) == 1 else "s"))
        _skip = [p for m in maps for p in (m.get("properties") or [])
                 if p.get("status") == "skipped"]
        if _skip:
            print("  %d propert%s not sent: %s."
                  % (len(_skip), "y was" if len(_skip) == 1 else "ies were",
                     "; ".join(sorted({str(p.get("note") or "no reason recorded")
                                       for p in _skip}))))
        print("  Nothing measured is not the same as nothing open.")
        return 3


def compose_parts(result, by_name):
    """-> (parts to compose, [why a property was left out]) for one objective's map.

    OPEN, OR OPENED BY A KEY -- and nothing else. This excluded `locked` alone, so an
    `unmeasured` property (errored, silent, or unscored) and a `skipped` one went into the
    ladder with their bare ask, and a zero-hit ladder printed COUPLED, "every property was
    reachable on its own". Found by an independent review. A function so the rule can be
    asked without a target.
    """
    parts, missing = [], []
    for p in result["properties"]:
        spec = by_name.get(p["name"], {})
        task = (spec.get("task") or "").strip()
        keys = ((p.get("keysearch") or {}).get("keys") or [])
        if not task:
            missing.append(f"{p['name']} (no 'task')")
            continue
        if p["status"] not in ("open", "noisy") and not keys:
            missing.append(f"{p['name']} ({p['status']}, no key found)")
            continue
        parts.append({"name": p["name"], "task": task,
                      "frame_template": keys[0]["template"] if keys else None})
    return parts, missing


if __name__ == "__main__":
    # The return value is the answer; `main()` alone drops it. Stated where `build_index`
    # states it, because five modules here computed a code and threw it away for anybody
    # who ran the file rather than the `qatration` entry point.
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
