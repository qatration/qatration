"""Is what the last report claims still true? Re-send only the rows that claim something.

A shipped artifact is a set of claims about a live system, and a live system moves. On
2026-08-28 `out/results_guardedrag.json` was still reporting five breaches that had stopped
reproducing: the artifact was twelve days old, every report built from it carried those five,
and the way it surfaced was somebody sending two of them by hand.

Nothing measured that. `history diff` compares two runs, so it needs a second full sweep before
it can say anything. `rejudge` replays the ORACLE over stored probes and never touches the
target, so a target that changed underneath is exactly what it cannot see. The cheap question --
"do the findings we published still happen" -- had no command.

    qatration verify --target-config redteam/targets_guardedrag.yaml

WHAT IT SENDS: the attacks the stored artifact records as breaches, and nothing else. On
guardedrag that is five attacks rather than the arsenal's ten, and against a real deployment it
is usually a handful out of hundreds. The cost of an answer should match the size of the claim.

WHAT IT WILL NOT DO: write. A verification is one trial deep by default and a sweep is three,
so letting this overwrite `results_<target>.json` would replace a measurement with a spot check.
It prints, it exits with a code, and it leaves the evidence alone.

WHAT IT DOES NOT COVER, said here because a list of what a check protects reads as the complete
list: the rows that were DEFENDED. A target that got WORSE since the artifact was written is a
full sweep's question, and this command says so rather than implying it looked.

AND A FLAKY ATTACK IS NOT A STALE CLAIM. An attack the artifact recorded at 1 of 3 will fail to
reproduce two times in three by chance alone, and calling that "no longer reproduces" would turn
noise into a finding. Only a row that the artifact recorded on EVERY trial, and that reproduces
on none of this run's, is reported as stale. Everything else is printed with both rates beside
it and no verdict attached.
"""
import argparse
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import yaml
from workspace import OUT as WORKSPACE_OUT, safe_target_name, BROKE

OUT_DIR = WORKSPACE_OUT


def claimed(results):
    """-> [(attack, hits, trials)] for the rows a stored run reports as breaches.

    The rate travels with the claim because it decides what a failure to reproduce means. A
    row recorded 3 of 3 and a row recorded 1 of 3 are different claims and a spot check that
    treats them alike is measuring its own sample size.
    """
    out = []
    for r in results or []:
        if r.get("headline") not in BROKE:
            continue
        rate = str(r.get("rate") or "")
        try:
            hits, trials = (int(x) for x in rate.split("/"))
        except (ValueError, TypeError):
            hits, trials = 0, 0
        out.append((r.get("attack") or {}, hits, trials))
    return out


def verdict(before_hits, before_trials, now_hits, now_trials):
    """-> ("stale" | "holds" | "unclear", one sentence).

    Deliberately reluctant. "stale" is the only word that accuses the artifact of being wrong,
    and it is reserved for the case where nothing else fits: the claim was made on every trial
    and reproduced on none.
    """
    if not now_trials:
        return "unclear", "nothing was sent"
    if now_hits:
        return "holds", "reproduced %d of %d" % (now_hits, now_trials)
    if before_trials and before_hits == before_trials:
        return "stale", ("recorded %d of %d, reproduced 0 of %d"
                         % (before_hits, before_trials, now_trials))
    return "unclear", ("recorded %d of %d, so 0 of %d is within what that rate predicts"
                       % (before_hits, before_trials, now_trials))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-config", default=os.path.join(HERE, "targets_dvla.yaml"))
    ap.add_argument("--trials", type=int, default=3,
                    help="attempts per claimed breach (default 3, matching a sweep). One is "
                         "cheaper and makes 'unclear' the usual answer for a flaky row")
    ap.add_argument("--results", default=None,
                    help="the artifact to verify (default out/results_<target>.json)")
    args = ap.parse_args()

    with io.open(args.target_config, encoding="utf-8") as f:
        tcfg = yaml.safe_load(f) or {}

    # AUTHORISATION FIRST, before a single probe. This sends real traffic to whatever the
    # config names, exactly as a sweep does, and a cheaper command is not a less authorised one.
    from authorization import gate as _auth_gate
    _auth_gate(tcfg, "verify")

    from run_redteam import load_target
    from runner import run_attack, headline, judged_ctx
    target = load_target(tcfg)
    if tcfg.get("name"):
        target.name = safe_target_name(tcfg["name"], "target config")
    ctx = tcfg.get("oracle_context", {})

    path = args.results or os.path.join(OUT_DIR, "results_%s.json" % target.name)
    if not os.path.exists(path):
        print("no stored results at %s — there is no claim to verify. Run a sweep first."
              % path, file=sys.stderr)
        return 2
    with io.open(path, encoding="utf-8") as f:
        stored = json.load(f)

    rows = claimed(stored.get("results") or [])
    print("verify → target='%s'  %d claimed breach(es) in %s  trials=%d"
          % (target.name, len(rows), os.path.basename(path), args.trials))
    if not rows:
        print("\nnothing in that artifact claims a breach, so there is nothing to re-send.")
        print("This checks published FINDINGS. Whether the target got worse is a sweep's "
              "question, not this one.")
        return 0

    print()
    print("%-30s %-10s %-10s %s" % ("attack", "recorded", "now", "verdict"))
    stale, sent = [], 0
    for attack, hits, trials in rows:
        recs = run_attack(target, attack, judged_ctx(attack, ctx), trials=args.trials)
        real = [r for r in recs if r.get("verdict") != "SKIP"]
        # `headline` returns (verdict, rate); the verdict is what decides a breach, and
        # reading the tuple as a string here would have made every row look clean.
        now_hits = sum(1 for r in real if headline([r])[0] in BROKE)
        sent += len(real)
        v, why = verdict(hits, trials, now_hits, len(real))
        if v == "stale":
            stale.append((attack.get("id"), why))
        print("  %-28s %-10s %-10s %s"
              % (str(attack.get("id"))[:28], "%d/%d" % (hits, trials),
                 "%d/%d" % (now_hits, len(real)), v))

    # NOTHING SENT IS NOT A PASS, and it is the failure this command is most likely to hit:
    # it exists because a target changed, and a target that is simply down changes nothing.
    if not sent:
        print("\nNOTHING MEASURED — every claimed row was skipped or refused delivery. "
              "Is %s up? The artifact is untouched and unverified." % target.name,
              file=sys.stderr)
        return 3

    print()
    if stale:
        print("%d claim(s) no longer reproduce:" % len(stale))
        for aid, why in stale:
            print("   %-28s %s" % (aid, why))
        print("\nThe artifact overstates what this target does today. Re-run the sweep to "
              "replace it, and read the difference as a change in the TARGET only after "
              "checking that nothing changed here.")
    else:
        print("every claimed breach still reproduces.")
    print("\nNot checked: the %d row(s) this artifact records as defended. A target that got "
          "worse is a sweep's question." % (len(stored.get("results") or []) - len(rows)))
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
