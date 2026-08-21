"""
Entry point for recon: profile a target before attacking it.

    qatration recon --target-config redteam/targets_guardbot.yaml
    ... --json out/recon_guardbot.json

Run this FIRST on any new target. It costs ~a dozen benign probes and it answers the
questions a sweep silently assumes: does reset() clear memory, do tool calls actually run,
what does this bot's refusal sound like, which forbidden tokens are hard-blocked, what
shape are its answers. It ends with a paste-ready `oracle_context` fragment.

Nothing is written into the target config automatically. A regex learned from one refusal
sentence and a marker paraphrased from the bot's own words are proposals — landing them is
a decision about what counts as a breach on this target, which stays with the tester.
"""
import sys, os, argparse, json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import yaml
from recon import fingerprint, format_profile, suggest_config
from workspace import OUT as WORKSPACE_OUT, safe_target_name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-config", default=os.path.join(HERE, "targets_dvla.yaml"))
    ap.add_argument("--model", default=None, help="override the target's model")
    ap.add_argument("--tool-prompt", default=None,
                    help="a benign request that SHOULD make the target use a tool "
                         "(defaults to the config's baseline_prompt)")
    ap.add_argument("--max-tokens", type=int, default=4,
                    help="how many forbidden_tokens to bare-echo test")
    ap.add_argument("--json", default=None,
                    help="write the raw profile here (default out/recon_<target>.json, "
                         "which run_redteam.py picks up into the report)")
    args = ap.parse_args()

    with open(args.target_config, encoding="utf-8") as f:
        tcfg = yaml.safe_load(f) or {}
    # AUTHORISATION FIRST, before a single probe. This sends real traffic to whatever the
    # config names, so it is exactly as much somebody else's system as a sweep is. The gate
    # was in the sweep and the benign run and not here, while the documentation said "any
    # non-local target" and this is the command the documentation says to run first.
    from authorization import gate as _auth_gate
    _auth_gate(tcfg, "recon")


    if args.model:
        tcfg["model"] = args.model
    ctx = tcfg.get("oracle_context", {})

    from run_redteam import load_target        # one adapter registry, three entry points
    target = load_target(tcfg)                 # (this chdir's into the target)
    if tcfg.get("name"):
        # Through the shared rule: this assignment used to hand the raw config
        # value to an adapter that never validates it, and the name becomes a
        # filename in six places, one of them an append.
        target.name = safe_target_name(tcfg["name"], "target config")

    print(f"recon → target='{target.name}' model='{tcfg.get('model', '')}' "
          f"(benign probes only)\n")
    profile = fingerprint(target, ctx,
                          tool_prompt=args.tool_prompt or tcfg.get("baseline_prompt"),
                          max_tokens=args.max_tokens)
    print(format_profile(profile))

    frag = suggest_config(profile)
    if frag:
        print("\n--- proposed additions to " + os.path.basename(args.target_config) +
              " (review, then paste) ---")
        print(frag)

    out = args.json or os.path.join(WORKSPACE_OUT, f"recon_{target.name}.json")
    if out:
        out = out if os.path.isabs(out) else os.path.join(ROOT, out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False)
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
