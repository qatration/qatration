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
from workspace import (OUT as WORKSPACE_OUT, safe_target_name,
                       refuse_to_overwrite_evidence, OVERWRITE_HELP)


def main():
    ap = argparse.ArgumentParser()
    # NO DEFAULT TARGET. This pointed at a practice bot shipped inside the package,
    # so `qatration recon` from an install aimed at the author's LangChain agent
    # rather than at the user's deployment, and the optional extra that bot needs is
    # not installed by default: the command ended in a raw ModuleNotFoundError
    # traceback and exit 1, which the exit-code contract reserves for "the target was
    # exploited or breached". `benign`, `run` and `matrix` all ask for the config and
    # exit 2; these two were the ones that did not.
    ap.add_argument("--target-config", required=True)
    ap.add_argument("--overwrite-evidence", action="store_true", help=OVERWRITE_HELP)
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
    from workspace import refuse_unusable_config as _refuse
    _refuse(tcfg, "recon")
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

    # NOTHING LANDED IS NOT A PROFILE. Every field above already refuses to guess from an
    # errored probe — `token_lock_state` has a third state for it, `_out` collapses silence
    # rather than inventing a reply — and the result was a complete-LOOKING profile of a
    # target that was down: `recon_<name>.json` written to the workspace, exit 0, and
    # `profiles` reading that file afterwards like any other.
    #
    # `run` refuses the same trade in the same words: "NOTHING MEASURABLE ... Leaving results
    # untouched." Walked against a dead port before this existed, and the profile it wrote said
    # `tool channel: unobservable`, `memory: not measured`, four refusal probes at `error` —
    # every line honest, and the file on disk regardless.
    _probes, _errors = profile.get("probes") or 0, profile.get("errors") or 0
    if _probes and _errors >= _probes:
        print("\nNOTHING MEASURED: all %d recon probe(s) errored or came back empty, so none "
              "of the profile above rests on an answer. This is an outage to fix rather than "
              "a target to read. Leaving the workspace untouched." % _probes)
        return 3
    if _errors:
        print("\n  ! %d of %d recon probe(s) did not land; the fields they feed read as "
              "unmeasured above rather than as a result." % (_errors, _probes))

    frag = suggest_config(profile)
    if frag:
        print("\n--- proposed additions to " + os.path.basename(args.target_config) +
              " (review, then paste) ---")
        print(frag)

    out = args.json or os.path.join(WORKSPACE_OUT, f"recon_{target.name}.json")
    if out:
        out = out if os.path.isabs(out) else os.path.join(ROOT, out)
        # THE SAME REFUSAL `run` AND `benign` MAKE. `refuse_to_overwrite_evidence` was
        # written after a `--attacks` run replaced a full sweep's `results_httpbot.json`
        # with eight rows and `coverage` reported 958 fewer probes. It was then wired into
        # two of the five commands that write evidence into `out/`. This is one of the
        # other three: the repository tracks 11 recon profiles, 11 isolation maps and 3
        # adaptive transcripts, every one of them a record of a real target's replies that
        # something else recounts -- `compare_recon` builds the fleet page from these, and
        # `run` folds them into a report.
        #
        # An untracked file is still overwritten in silence, which is the whole point: a
        # person re-running their own sweep is not asked permission.
        _refusal = refuse_to_overwrite_evidence(
            out, force=getattr(args, "overwrite_evidence", False))
        if _refusal:
            # 2, THE SAME AS `run`: the invocation was refused, nothing was measured, and
            # a pipeline must not read it as a finding.
            print(_refusal, file=sys.stderr)
            return 2
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False)
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
