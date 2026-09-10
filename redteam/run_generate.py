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
    # THE ONE SPELLING, from the table this command is listed in. A bare parser
    # here printed the flags and left `--help` silent about the job.
    from cli import parser as _cli_parser
    ap = _cli_parser("generate")
    # REQUIRED, like `onboard`'s. This defaulted to `targets_dvla.yaml`, a practice bot that
    # ships with the package -- so the command with no arguments pointed at a target the caller
    # never chose, in a tool whose neighbours send real attacks. Nothing depends on the default:
    # the docs and the fleet both pass it.
    ap.add_argument("--target-config", required=True,
                    help="the target config to generate objectives for")
    ap.add_argument("--recon", default=None,
                    help="profile to read (default out/recon_<target>.json)")
    ap.add_argument("--out", default=None,
                    help="where to write (default "
                         "$QATRATION_OUT/isolation_generated_<target>.yaml)")
    ap.add_argument("--print", dest="show", action="store_true",
                    help="print the objectives instead of writing them")
    args = ap.parse_args()

    # A CLEAR REFUSAL RATHER THAN A TRACEBACK. `--target` is an unambiguous prefix of
    # `--target-config`, so argparse accepts it and hands a target NAME to something that opens
    # a path -- and a stack trace tells the reader the tool is broken rather than that they
    # typed the wrong flag.
    # THROUGH THE ONE READER. This refusal was written out here, and separately inside
    # `run` as a closure, while five siblings had neither and crashed.
    from workspace import load_yaml_or_refuse as _load_yaml
    tcfg = _load_yaml(args.target_config, "target config", "generate") or {}
    from workspace import refuse_unusable_config as _refuse
    _refuse(tcfg, "generate")
    # AUTHORISATION FIRST, before a single probe. This sends real traffic to whatever the
    # config names, so it is exactly as much somebody else's system as a sweep is. The gate
    # was in the sweep and the benign run and not here, while the documentation said "any
    # non-local target" and this is the command the documentation says to run first.
    from authorization import gate as _auth_gate
    _auth_gate(tcfg, "generate")


    from workspace import config_name as _config_name
    name = _config_name(args.target_config, tcfg)
    ctx = tcfg.get("oracle_context", {})

    prof_path = args.recon or os.path.join(WORKSPACE_OUT, f"recon_{name}.json")
    if not os.path.exists(prof_path):
        # 3, NOT 0. The input this command works from is not there, so nothing was
        # generated and nothing was measured, and returning None made `cli` exit 0 --
        # which a pipeline reads as `asked and answered`. `compare_recon` reached the
        # same conclusion for the same situation and wrote it down there.
        #
        # AND THE REMEDY IS A COMMAND, not a path. `run_recon.py` exists in a checkout of
        # this repository and nowhere in an installed package, so the line telling a
        # reader what to do next was the one thing on the page they could not run.
        print(f"no recon profile at {prof_path} - profile the target first:"
              f"\n    qatration recon --target-config {args.target_config}")
        return 3
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
        # 0, AND THE DIFFERENCE FROM THE BRANCH ABOVE IS THE POINT. The profile was read
        # and states no prohibitions: an answer about the target rather than a missing
        # input, and this command did the work it was asked to do.
        print("\nnothing to write: this profile states no prohibitions to turn into "
              "objectives, which is an answer about the target rather than a failure.")
        return 0
    if args.show:
        print("\n" + to_yaml(objs, name))
        return

    # THE WORKSPACE, NOT THE PACKAGE. This defaulted to `HERE`, which in a checkout is
    # `redteam/` and in an installed copy is `site-packages/qatration/` -- so walking the
    # documented chain from a fresh install deposited the operator's generated objectives
    # inside the installed package. Three things wrong with that and none of them announce
    # themselves: site-packages is read-only on plenty of installs (a system Python, a
    # container layer, a locked prefix), so the command simply fails for those users; nobody
    # has any reason to look there for their own file; and `pip install -U qatration` replaces
    # that directory, taking the file with it.
    #
    # Every other artifact this tool writes goes to `$QATRATION_OUT`, and this is a generated
    # artifact like the rest of them.
    out = args.out or os.path.join(WORKSPACE_OUT, f"isolation_generated_{name}.yaml")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(to_yaml(objs, name))
    print(f"\nwrote {out}")
    # THE COMMAND, NOT THE FILE. `run_isolation.py` exists in a checkout of this repository
    # and nowhere in an installed package, and this line is the one a first-time reader
    # copies. Same defect `compare_recon` carried, in the sibling that hands off to it.
    print(f"next: qatration isolation --target-config {args.target_config} "
          f"--objectives {os.path.basename(out)} --keys")


if __name__ == "__main__":
    # The return value is the answer; `main()` alone drops it. Stated where `build_index`
    # states it, because five modules here computed a code and threw it away for anybody
    # who ran the file rather than the `qatration` entry point.
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
