"""
Entry point for generation: turn a recon profile into objectives for that target.

    qatration generate --target-config redteam/targets_guardbot.yaml

Reads `out/recon_<target>.json` (run run_recon.py first) and writes
`redteam/isolation_generated_<target>.yaml`, which run_isolation.py can take straight away:

    ... run_isolation.py --target-config <cfg> --objectives isolation_generated_<target>.yaml --keys

Read the file before running it. The source is the bot's own wording, so a vague rule makes
a vague ask, and each objective carries the sentence it came from precisely so that check is
possible. Anything whose detector was inferred rather than named is marked in the file.
"""
import sys, os, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import yaml
from generate import objectives_from_profile, prohibitions, to_yaml
from workspace import OUT as WORKSPACE_OUT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-config", default=os.path.join(HERE, "targets_dvla.yaml"))
    ap.add_argument("--recon", default=None,
                    help="profile to read (default out/recon_<target>.json)")
    ap.add_argument("--out", default=None,
                    help="where to write (default redteam/isolation_generated_<target>.yaml)")
    ap.add_argument("--print", dest="show", action="store_true",
                    help="print the objectives instead of writing them")
    args = ap.parse_args()

    with open(args.target_config, encoding="utf-8") as f:
        tcfg = yaml.safe_load(f) or {}
    name = tcfg.get("name") or os.path.basename(args.target_config)[len("targets_"):-len(".yaml")]
    ctx = tcfg.get("oracle_context", {})

    prof_path = args.recon or os.path.join(WORKSPACE_OUT, f"recon_{name}.json")
    if not os.path.exists(prof_path):
        print(f"no recon profile at {prof_path}\n"
              f"run: run_recon.py --target-config {args.target_config}")
        return
    with open(prof_path, encoding="utf-8") as f:
        profile = json.load(f)

    rules = prohibitions(profile)
    objs, skipped = objectives_from_profile(profile, ctx, name)
    print(f"target: {name}   rules found: {len(rules)}   "
          f"objectives: {len(objs)}   unscoreable: {len(skipped)}\n")
    for o in objs:
        mark = "  [detector inferred]" if o.get("inferred_detector") else ""
        print(f"  + {o['properties'][0]['probe'][:64]:<66}{o['success']}{mark}")
    for s in skipped:
        # naming what the config is missing is the point: this is a fixable gap, not a
        # verdict about the target
        print(f"  - {s['ask'][:64]:<66}dropped, {s['why']}")

    if not objs:
        print("\nnothing to write.")
        return
    if args.show:
        print("\n" + to_yaml(objs, name))
        return

    out = args.out or os.path.join(HERE, f"isolation_generated_{name}.yaml")
    with open(out, "w", encoding="utf-8") as f:
        f.write(to_yaml(objs, name))
    print(f"\nwrote {out}")
    print(f"next: run_isolation.py --target-config {args.target_config} "
          f"--objectives {os.path.basename(out)} --keys")


if __name__ == "__main__":
    main()
