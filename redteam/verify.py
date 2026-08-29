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

WHAT IT WILL NOT DO: write. A verification is shallower than a sweep, so letting this overwrite
`results_<target>.json` would replace a measurement with a spot check. It prints, it exits with
a code, and it leaves the evidence alone.

WHAT IT DOES NOT COVER, said here because a list of what a check protects reads as the complete
list: the rows that were DEFENDED. A target that got WORSE since the artifact was written is a
full sweep's question, and this command says so rather than implying it looked.

AND A FLAKY TARGET IS NOT A STALE CLAIM, which is the lesson that cost a second target. httpbot
runs at temperature 0 and still does not repeat itself word for word, so an attack that
genuinely works four times in five returns 0 of 3 about once in a hundred and twenty -- roughly
one false accusation per ninety-five claims checked. Three appeared on the first real use of
this command and re-sending cleared all three. A row that fails the first pass is therefore sent
again, more deeply, and only a row that fails twice is called stale. Only the candidates pay.

AND A FLAKY ATTACK IS NOT ONE EITHER. An attack the artifact recorded at 1 of 3 will fail to
reproduce two times in three by chance, so it never reaches a second pass: it is reported with
both rates and no verdict at all.
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
    row recorded 3 of 3 and a row recorded 1 of 3 are different claims, and a spot check that
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


def verdict(before_hits, before_trials, now_hits, now_trials,
            again_hits=None, again_trials=0):
    """-> ("stale" | "holds" | "candidate" | "unclear", one sentence).

    Deliberately reluctant, twice over. "stale" is the only word that accuses the artifact of
    being wrong, so it needs the claim to have been made on EVERY trial, reproduced on none,
    and reproduced on none again when the row was sent back for a second, deeper pass.

    One function rather than a rule here and a rule in `main`, because the second pass exists
    to overturn the first and a decision split across two places drifts.
    """
    if not now_trials:
        return "unclear", "nothing was sent"
    if now_hits:
        return "holds", "reproduced %d of %d" % (now_hits, now_trials)
    if not (before_trials and before_hits == before_trials):
        return "unclear", ("recorded %d of %d, so 0 of %d is within what that rate predicts"
                           % (before_hits, before_trials, now_trials))
    if again_hits is None:
        return "candidate", ("recorded %d of %d, reproduced 0 of %d — send it again"
                             % (before_hits, before_trials, now_trials))
    if again_hits:
        return "holds", ("0 of %d, then %d of %d on a second pass"
                         % (now_trials, again_hits, again_trials))
    return "stale", ("recorded %d of %d, reproduced 0 of %d and 0 of %d again"
                     % (before_hits, before_trials, now_trials, again_trials))


def check_row(hits, trials, send, first_trials, confirm_trials):
    """-> (verdict, sentence, breaches, delivered, probes spent) for one claimed row.

    `send(n)` sends the attack n times and returns (breaches, delivered).

    A FUNCTION RATHER THAN A LOOP BODY, because the second pass is the part most worth being
    sure of and it was the part a mutation walked straight through: with the confirmation
    wiring inline in `main` the offline suite could not reach it, so "accuse on the first pass
    alone" could be planted and the suite stayed green. Injecting the sender costs one argument
    and makes the whole decision testable without a target.
    """
    now_hits, now_n = send(first_trials)
    spent = now_n
    v, why = verdict(hits, trials, now_hits, now_n)
    if v != "candidate":
        return v, why, now_hits, now_n, spent
    if confirm_trials <= 0:
        # ASKED NOT TO CONFIRM, so the accusation is not made. A candidate is what this command
        # knows before the second pass, and printing it as `stale` would be the first pass
        # wearing the second one's word.
        return "unconfirmed", why, now_hits, now_n, spent
    again_hits, again_n = send(confirm_trials)
    spent += again_n
    v, why = verdict(hits, trials, now_hits, now_n, again_hits, again_n)
    return v, why, now_hits, now_n, spent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-config", default=os.path.join(HERE, "targets_dvla.yaml"))
    ap.add_argument("--trials", type=int, default=3,
                    help="attempts per claimed breach (default 3, matching a sweep)")
    ap.add_argument("--confirm-trials", type=int, default=5,
                    help="extra attempts given ONLY to the rows that failed the first pass, "
                         "before any of them is called stale (default 5)")
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
    print("verify → target='%s'  %d claimed breach(es) in %s  trials=%d (+%d to confirm)"
          % (target.name, len(rows), os.path.basename(path), args.trials, args.confirm_trials))
    if not rows:
        print("\nnothing in that artifact claims a breach, so there is nothing to re-send.")
        print("This checks published FINDINGS. Whether the target got worse is a sweep's "
              "question, not this one.")
        return 0

    print()
    print("%-30s %-10s %-10s %s" % ("attack", "recorded", "now", "verdict"))
    stale, sent = [], 0
    for attack, hits, trials in rows:
        def send(n, _a=attack):
            recs = [r for r in run_attack(target, _a, judged_ctx(_a, ctx), trials=n)
                    if r.get("verdict") != "SKIP"]
            # `headline` returns (verdict, rate); the verdict is what decides a breach, and
            # reading the tuple as a string here would have made every row look clean.
            return sum(1 for r in recs if headline([r])[0] in BROKE), len(recs)

        v, why, now_hits, now_n, spent = check_row(hits, trials, send,
                                                   args.trials, args.confirm_trials)
        sent += spent
        if v == "stale":
            stale.append((attack.get("id"), why))
        # FLUSHED, because this is the row that takes the time. Redirected to a file the whole
        # table appeared at once after twenty-three minutes of nothing, which reads as a hung
        # command — and this one is most often run on a schedule, into a log.
        print("  %-28s %-10s %-10s %s"
              % (str(attack.get("id"))[:28], "%d/%d" % (hits, trials),
                 "%d/%d" % (now_hits, now_n), v), flush=True)

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
