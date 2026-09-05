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
from isolation import run_isolation, format_map, apply_keysearch, prop_ctx, write_maps
from keysearch import search, format_search, load_frames
from compose import compose, format_compose


from run_redteam import load_target as _build_target
from workspace import OUT as WORKSPACE_OUT, safe_target_name


def load_target(cfg_path, model=None):
    """Reuse run_redteam's adapter registry and target config verbatim — one place
    to add a target, both entry points get it."""
    with open(cfg_path, encoding="utf-8") as f:
        tcfg = yaml.safe_load(f) or {}
    # AUTHORISATION FIRST, before a target is even built. Isolation sends real traffic — a
    # separate probe per defence, several trials each — so it is exactly as much somebody
    # else's system as a sweep is. The gate lived in the sweep and the benign run and not
    # here, while the documentation said "any non-local target".
    from authorization import gate as _auth_gate
    _auth_gate(tcfg, "isolation")
    if model:
        tcfg["model"] = model
    target = _build_target(tcfg)
    if tcfg.get("name"):
        # Through the shared rule: this assignment used to hand the raw config
        # value to an adapter that never validates it, and the name becomes a
        # filename in six places, one of them an append.
        target.name = safe_target_name(tcfg["name"], "target config")
    return target, tcfg.get("oracle_context", {})


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
    ap = argparse.ArgumentParser()
    # NO DEFAULT TARGET. This pointed at a practice bot shipped inside the package,
    # so `qatration isolation` from an install aimed at the author's LangChain agent
    # rather than at the user's deployment, and the optional extra that bot needs is
    # not installed by default: the command ended in a raw ModuleNotFoundError
    # traceback and exit 1, which the exit-code contract reserves for "the target was
    # exploited or breached". `benign`, `run` and `matrix` all ask for the config and
    # exit 2; these two were the ones that did not.
    ap.add_argument("--target-config", required=True)
    ap.add_argument("--objectives", default="isolation_example.yaml")
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
    ap.add_argument("--frame-families", default=None,
                    help="comma-separated families to search (default: all 16). The whole "
                         "library runs per LOCKED property per trial, so this is the knob "
                         "for when that budget matters; the bare control always runs")
    ap.add_argument("--stop-on-hit", action="store_true",
                    help="stop a property's search at the first frame that opens it — "
                         "cheaper, but you lose which OTHER families also work, which is "
                         "the evidence about the target")
    ap.add_argument("--frames", default=None, help="an alternative frame library")
    ap.add_argument("--compose", action="store_true",
                    help="after the key search, reassemble the keys into one payload and "
                         "test the whole objective (implies --keys)")
    ap.add_argument("--json", default=None,
                    help="write the raw maps here (default out/isolation_<target>.json, "
                         "which run_redteam.py picks up into the report)")
    args = ap.parse_args()
    if args.compose:
        args.keys = True          # composition needs the keys the search finds

    path = objectives_path(args.objectives)
    with open(path, encoding="utf-8") as f:
        objectives = yaml.safe_load(f) or []
    # The same rule, on the corpus where a typo is worst: an unknown name leaves nothing to
    # evaluate, every trial misses, and an objective whose properties are all locked reads as
    # HARDENED — the strongest claim this command makes.
    from lint_arsenal import refuse_unknown_detectors
    refuse_unknown_detectors(objectives, "isolation", path)

    target, ctx = load_target(args.target_config, args.model)
    objectives = [o for o in objectives
                  if not o.get("applies_to") or target.name in o["applies_to"]]
    if args.only:
        objectives = [o for o in objectives if o.get("id") == args.only]
    if not objectives:
        print(f"no objectives apply to target '{target.name}'")
        return

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
            locked = [p for p in result["properties"] if p["status"] == "locked"]
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
                out = search(target, task, spec.get("success", []), prop_ctx(spec, ctx),
                             frames=frames, trials=args.trials,
                             stop_on_hit=args.stop_on_hit, tasks=alts)
                p["keysearch"] = {k: v for k, v in out.items() if k != "results"}
                print(format_search(p["name"], out))
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
            parts, missing = [], []
            for p in result["properties"]:
                spec = by_name.get(p["name"], {})
                task = (spec.get("task") or "").strip()
                keys = ((p.get("keysearch") or {}).get("keys") or [])
                if not task:
                    missing.append(f"{p['name']} (no 'task')")
                    continue
                if p["status"] == "locked" and not keys:
                    missing.append(f"{p['name']} (locked, no key found)")
                    continue
                parts.append({"name": p["name"], "task": task,
                              "frame_template": keys[0]["template"] if keys else None})
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

    # The artifact name follows the OBJECTIVES, not just the target: a run of generated
    # objectives used to overwrite the results of the curated ones for the same bot, which
    # is a silent loss of the more expensive artifact of the two.
    stem = os.path.splitext(os.path.basename(path))[0]
    tag = re.sub(r"^isolation_", "", stem)
    tag = re.sub(rf"_?{re.escape(target.name)}$", "", tag)     # no guardbot_…_guardbot
    tag = "" if tag in ("", target.name, "example", "more") else "_" + tag
    out = args.json or os.path.join(WORKSPACE_OUT, f"isolation_{target.name}{tag}.json")
    if out:
        out = out if os.path.isabs(out) else os.path.join(ROOT, out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        # through write_maps, so the artifact carries the build that produced it — lock maps
        # were a bare list with no meta and could not be stamped even in principle
        write_maps(out, maps, {"target": target.name, "objectives": os.path.basename(path)})
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
