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

AND `1` MEANS SOMETHING ELSE HERE THAN IT DOES ANYWHERE ELSE. The exit table reserves it for
"this change introduced or reopened a finding", and this command cannot introduce one: it
re-sends what a report already claims. It exits `1` when a claim NO LONGER REPRODUCES -- the
finding is in the artifact, not in the target -- and a build reading the table's row alone would
conclude the opposite. `docs/ci.md` says so beside the table; said here too, because the code is
returned from this file.

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
from workspace import (OUT as WORKSPACE_OUT, safe_target_name, BROKE,
                       NOT_MEASURED, results_files, target_of)

OUT_DIR = WORKSPACE_OUT


def measured(rec):
    """Did this attempt learn anything? A dead target must not read as a fixed one.

    THE BUG THIS EXISTS TO PREVENT, and it would have arrived with the fleet-wide mode. A
    target whose server is down answers every probe with an ERROR, no detector fires, and the
    rows come back 0 of 3 -- so every claim it ever made would be re-sent, fail, fail again on
    the confirmation, and be reported as no longer reproducing. An audit of forty targets would
    have turned each unreachable one into a page of false accusations.

    Same rule as everywhere else in this repository: `NOT_MEASURED` for the verdicts, and an
    empty reply for the silence that carries no exception with it.
    """
    if rec.get("verdict") in NOT_MEASURED:
        return False
    pr = rec.get("probe")
    if pr is None:
        return False
    # TWO SHAPES, AND THE SUITE ONLY EVER SAW ONE. A stored artifact holds a dict; a live run
    # hands back the `Probe` object itself, and this walked into `AttributeError` on the first
    # target of the first fleet audit. The offline checks passed because every fixture was a
    # dict, which is the shape that comes off disk.
    if not isinstance(pr, dict):
        return not (getattr(pr, "error", None) or pr.silent())
    if pr.get("error"):
        return False
    return bool((pr.get("output") or "").strip() or pr.get("tool_calls")
                or pr.get("turns") or pr.get("observations"))


def tally(recs, verdict_of):
    """-> (breaches, attempts that measured something), from one attack's records.

    Two lines, extracted, because they were inside a closure that needs a live target and a
    mutation walked through them: swapping `measured` back for the old "not a SKIP" filter left
    the suite green while turning every unreachable target into a page of stale claims.
    """
    kept = [r for r in recs if measured(r)]
    return sum(1 for r in kept if verdict_of(r) in BROKE), len(kept)


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


def age_note(meta, now=None, path=None):
    """-> a sentence about how old the measurement being checked is.

    "Stale" is a claim about time and this command could not say how much. Sweeps stamp `when`
    from 2026-08-28; every artifact written before that says nothing, and saying nothing is the
    answer that must be printed rather than a zero or a guess. Two questions in this repository
    have already died on a missing date.

    AND SAYING NOTHING WAS ITSELF THE GAP, on 44 of the 45 shipped artifacts. This is the one
    command whose verdict word is `stale`, and on all but one stored run it printed that how
    stale a stale row is cannot be said -- while `workspace.measured_when`, written for this
    exact question and read by the SARIF export, the fleet page and the report panel, answers
    it from the file and marks that it did.

    THE FILE'S MTIME IS NOT WHEN THE RUN HAPPENED, which is why that helper flags it and why
    it was right not to be reached for blindly. But it only ever moves the wrong way ONCE: a
    clone, a `cp` or a `rejudge --write` pushes it forward and nothing pushes it back, so
    mtime >= the write >= the run and the age it yields is a FLOOR. The measurement is at
    least that old and may be older, which is a bound in the safe direction -- it can
    understate staleness and cannot invent freshness -- and a floor said out loud beats a
    sentence saying nothing is knowable.

    Through `workspace.measured_when` and `baseline.days_between` rather than a second date
    reader kept here. The one this replaced counted elapsed 24-hour periods where every other
    surface counts calendar days, so an artifact written at 23:00 and checked at 01:00 read as
    `0 days` here and `1 day` on the page; and one stamped two hours ahead by a clock that
    disagreed -- a sweep run on a UTC box, verified on a machine west of it -- came out
    `dated in the future`, which withholds the age entirely over a skew a date comparison
    does not even see.
    """
    from datetime import datetime
    import baseline
    import workspace
    when, said = workspace.measured_when(meta or {}, path)
    if not when:
        return ("this artifact carries no date and there is no file to date it by, so how "
                "stale a stale row is cannot be said — sweeps stamp one from 2026-08-28")
    days = baseline.days_between(when, (now or datetime.now()).isoformat(" ", "seconds"))
    if days is None:
        return "this artifact's date is unreadable (%r)" % ((meta or {}).get("when"),)
    if days < 0:
        return "this artifact is dated in the future (%s), so its age says nothing" % when
    ago = "%d day%s ago" % (days, "" if days == 1 else "s")
    if said:
        return "measured %s, %s" % (when, ago)
    return ("the run recorded no date, so this is the file's: last written %s, %s. A copy, a "
            "clone or a `rejudge --write` moves that forward and never back, so the "
            "measurement is AT LEAST that old and may be older" % (when, ago))


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


def note_verdict(note):
    """-> (exit code, one line) for a target that was not verified. "" means it was.

    THE DEFAULT IS THE REFUSAL, and it was the reassurance. `main` handled four notes by name
    and fell through everything else to "every claimed breach still reproduces" — so pointing
    the command at `guardedrag-weak` while the server ran GUARD=on, which the build check
    correctly caught, printed a clean bill of health after sending no probes at all. An
    unhandled state must not be able to read as a pass, and a table of known cases with no
    default is exactly the shape that lets it.
    """
    if not note:
        return 0, ""
    if note == "nothing claimed":
        return 0, ("nothing in that artifact claims a breach, so there is nothing to re-send. "
                   "This checks published FINDINGS; whether the target got worse is a sweep's "
                   "question.")
    if note == "no stored results":
        # 3, NOT 2. The invocation was fine and the config was fine; this command read
        # the workspace and found nothing in it, which is what the table gives 3 for --
        # "rejudge with no stored artifact to re-score" is the same sentence. 2 is
        # "the config or the invocation was refused", and neither was.
        return 3, "no stored results - there is no claim to verify. Run a sweep first."
    if note.startswith("unreachable"):
        return 3, ("NOTHING MEASURED - every claimed row errored or came back empty. "
                   "The artifact is untouched and unverified.")
    return 2, ("NOT VERIFIED - %s. The artifact is untouched and nothing was measured." % note)


def _clipped(text, width):
    """A note cut at a word, with a mark, rather than in the middle of one.

    `which is not vendored in thi` is what a fixed slice produces, and a sentence that
    stops mid-word reads as a bug in the tool rather than as a message about the target.
    The same lesson as `format_map`'s column widths one module over: a truncated map is a
    misread map.
    """
    text = " ".join(str(text or "").split())
    if len(text) <= width:
        return text
    cut = text[:width].rsplit(" ", 1)[0] or text[:width]
    return cut.rstrip(" ,.;:") + "\u2026"


def verify_target(tcfg, path, trials, confirm_trials, quiet=False,
                  build_check=None):
    """-> a summary dict for one target. Prints its own table unless `quiet`.

    Split out for the fleet-wide mode, and the split is the point: an audit that dies on the
    first target it cannot load has audited nothing, so every failure here becomes a row in a
    table rather than a traceback.
    """
    from authorization import gate as _auth_gate
    from run_redteam import load_target
    from runner import run_attack, headline, judged_ctx

    out = {"target": tcfg.get("name") or "?", "claims": 0, "holds": 0, "unclear": 0,
           "stale": 0, "stale_ids": [], "note": "", "sent": 0}
    # IS THERE A CLAIM TO VERIFY, before anything is built. This sat below the loader, so
    # a workspace with no artifact for this target still constructed one — and where
    # the adapter could not be imported the answer came back as `not loaded`, which is a
    # true sentence about the wrong question. Building a target is not inert either: the
    # HTTP adapter expands `${VAR}` in its headers in the constructor and the practice
    # adapters start processes there, which `run_redteam` already moved its own gate above
    # for exactly this reason.
    if not os.path.exists(path):
        out["note"] = "no stored results"
        return out
    try:
        _auth_gate(tcfg, "verify")
    except SystemExit as e:
        out["note"] = "not loaded: %s" % _clipped(str(e).splitlines()[0], 70)
        return out

    # THE WRONG BUILD ANSWERING IS NOT A STALE CLAIM, and the fleet audit was about to publish
    # five of them. Six configs point at one guardedrag port and differ only by an environment
    # variable, so checking `guardedrag-weak` against a server running GUARD=on compares claims
    # made under one build with the behaviour of another — and every row would come back 0 of 3
    # and be called stale. The sweep has refused to run against the wrong build since the day a
    # guard-on/guard-off diff turned out to compare two runs of the same build; this command
    # sends the same traffic and had no such check.
    # INJECTED so the wiring can be exercised without a server. The rule itself lives in
    # `run_redteam` and is not copied here; what a test needs to reach is the branch that acts
    # on it, which is where today's other two wiring bugs were.
    if build_check is None:
        from run_redteam import _build_mismatch as build_check
    wrong = build_check(tcfg)
    if wrong:
        out["note"] = "wrong build: %s" % _clipped(wrong, 70)
        return out

    # AND ONLY NOW IS A TARGET BUILT. This sat above the build check, so a run refused for
    # answering from the wrong build had already constructed the thing it refused to talk
    # to — and building is not inert: the HTTP adapter expands `${VAR}` in its headers in
    # the constructor, and the practice adapters start processes there. The same ordering
    # was wrong twice in `run_redteam` and once in `benign`, each time for the same reason:
    # a gate placed after the thing it guards is a record of a decision rather than a
    # control. Authorisation stays first, because that is the one that must precede
    # everything.
    try:
        target = load_target(tcfg)
    except SystemExit as e:
        out["note"] = "not loaded: %s" % _clipped(str(e).splitlines()[0], 70)
        return out
    except Exception as e:
        out["note"] = "not loaded: %s: %s" % (type(e).__name__, _clipped(str(e), 50))
        return out
    if tcfg.get("name"):
        target.name = safe_target_name(tcfg["name"], "target config")
    out["target"] = target.name
    ctx = tcfg.get("oracle_context", {})

    with io.open(path, encoding="utf-8") as f:
        stored = json.load(f)
    rows = claimed(stored.get("results") or [])
    out["claims"] = len(rows)
    if not quiet:
        print("verify -> target='%s'  %d claimed breach(es) in %s  trials=%d (+%d to confirm)"
              % (target.name, len(rows), os.path.basename(path), trials, confirm_trials))
        print("  %s" % age_note(stored.get("meta"), path=path))
    if not rows:
        out["note"] = "nothing claimed"
        return out
    if not quiet:
        print()
        print("%-30s %-10s %-10s %s" % ("attack", "recorded", "now", "verdict"))

    for attack, hits, was in rows:
        def send(n, _a=attack):
            # `headline` returns (verdict, rate); the verdict is what decides a breach, and
            # reading the tuple as a string here would have made every row look clean.
            return tally(run_attack(target, _a, judged_ctx(_a, ctx), trials=n),
                         lambda r: headline([r])[0])

        # A TARGET THAT THROWS IS A ROW, NOT A TRACEBACK, which is the whole reason this
        # function was split out and was not honoured for the sending half: the first fleet
        # audit died on its first target and audited nothing.
        try:
            v, why, now_hits, now_n, spent = check_row(hits, was, send, trials, confirm_trials)
        except Exception as e:
            out["note"] = "failed on %s: %s: %s" % (attack.get("id"), type(e).__name__,
                                                    str(e)[:60])
            return out
        out["sent"] += spent
        out[v if v in ("holds", "stale") else "unclear"] += 1
        if v == "stale":
            out["stale_ids"].append((attack.get("id"), why))
        if not quiet:
            # FLUSHED, because this is the row that takes the time. Redirected to a file the
            # whole table arrived at once after twenty-three minutes of silence, which reads as
            # a hung command, and this is one people run on a schedule into a log.
            print("  %-28s %-10s %-10s %s"
                  % (str(attack.get("id"))[:28], "%d/%d" % (hits, was),
                     "%d/%d" % (now_hits, now_n), v), flush=True)

    if not out["sent"]:
        # NOTHING SENT IS NOT A PASS, and it is the failure this command is most likely to
        # meet: it exists because a target changed, and a target that is simply down changes
        # nothing. Counted as unreachable, never as a page of stale claims.
        out["note"] = "unreachable: nothing was measured"
        out["stale"], out["holds"], out["unclear"], out["stale_ids"] = 0, 0, 0, []
    return out


def audit(trials, confirm_trials):
    """Every target that has an artifact, one table. Unreachable is its own answer."""
    from target import target_configs
    cfgs = {}
    for fp in target_configs(HERE):
        try:
            with io.open(fp, encoding="utf-8") as f:
                d = yaml.safe_load(f) or {}
        except Exception:
            continue
        from workspace import config_name as _config_name
        nm = _config_name(fp, d)
        d["name"] = nm
        cfgs[nm] = d

    jobs = []
    for fp in results_files(OUT_DIR):
        stem = os.path.basename(fp)[len("results_"):-len(".json")]
        nm = target_of(stem, cfgs)
        if nm:
            jobs.append((cfgs[nm], fp))
    print("verify --all -> %d artifact(s) with a config, trials=%d (+%d to confirm)\n"
          % (len(jobs), trials, confirm_trials), flush=True)
    if not jobs:
        # NOTHING TO VERIFY IS NOT EVERY CLAIM HOLDING. Over an empty workspace this
        # printed `0 of 0 targets reachable, 0 claims re-sent` and then `every claim on
        # every reachable target still reproduces`, and returned 0 — a clean bill
        # over nothing, which is the sentence this whole repository is named after. Every
        # other read-only command answers 3 in that state.
        from workspace import no_results_note as _no_results
        print(_no_results(OUT_DIR))
        print("Nothing was re-sent, so nothing here says whether a stored claim still "
              "holds.")
        return 3

    rows, total_stale = [], []
    for tcfg, fp in jobs:
        r = verify_target(tcfg, fp, trials, confirm_trials, quiet=True)
        rows.append(r)
        total_stale += [(r["target"], a, w) for a, w in r["stale_ids"]]
        print("  %-26s %s" % (r["target"],
                              r["note"] or "%d claims: %d hold, %d unclear, %d stale"
                              % (r["claims"], r["holds"], r["unclear"], r["stale"])),
              flush=True)

    reached = [r for r in rows if not r["note"]]
    print("\n%d of %d targets reachable, %d claims re-sent"
          % (len(reached), len(rows), sum(r["claims"] for r in reached)))
    if total_stale:
        print("\n%d claim(s) no longer reproduce:" % len(total_stale))
        for t, aid, why in total_stale:
            print("   %-18s %-26s %s" % (t, aid, why))
    else:
        print("\nevery claim on every reachable target still reproduces.")
    # UNREACHABLE IS NEITHER A PASS NOR A FAILURE, and rounding it into either is the one thing
    # this command must not do. It gets its own line and no exit code of its own.
    missed = [r for r in rows if r["note"]]
    if missed:
        print("\nnot checked (%d): %s" % (len(missed),
              ", ".join("%s (%s)" % (r["target"], r["note"].split(":")[0])
                        for r in missed[:8])))
    return 1 if total_stale else 0


def main():
    # THE ONE SPELLING, from the table this command is listed in. A bare parser
    # here printed the flags and left `--help` silent about the job.
    from cli import parser as _cli_parser
    ap = _cli_parser("verify")
    # NO DEFAULT TARGET. This defaulted to `targets_dvla.yaml`, a practice config inside
    # this package, so `qatration verify` typed with no arguments verified somebody else's
    # demo bot — and answered `NOT VERIFIED - not loaded: targets_dvla needs the DVLA
    # practice app, which is not vendored`, about a target the reader never named, in a
    # workspace that may hold none of their own. Every other command that sends traffic
    # asks for the config; `benign` refuses in as many words. This one chose for them.
    ap.add_argument("--target-config", default=None)
    ap.add_argument("--all", action="store_true",
                    help="every target that has a stored artifact, in one table. A target that "
                         "cannot be reached is reported as unreachable, never as stale")
    ap.add_argument("--trials", type=int, default=3,
                    help="attempts per claimed breach (default 3, matching a sweep)")
    ap.add_argument("--confirm-trials", type=int, default=5,
                    help="extra attempts given ONLY to the rows that failed the first pass, "
                         "before any of them is called stale (default 5)")
    ap.add_argument("--results", default=None,
                    help="the artifact to verify (default out/results_<target>.json)")
    args = ap.parse_args()

    if args.all:
        return audit(args.trials, args.confirm_trials)
    if not args.target_config:
        # NAMED, AND WITH THE OTHER DOOR NAMED TOO. `--all` is the form that needs no
        # config at all: it verifies what is in the workspace, which is the only subject
        # this command can pick on its own.
        ap.error("--target-config is required, or --all to verify every target that has a "
                 "stored artifact in this workspace")

    from workspace import load_yaml_or_refuse as _load_yaml
    tcfg = _load_yaml(args.target_config, "target config", "verify") or {}
    from workspace import refuse_unusable_config as _refuse
    _refuse(tcfg, "verify")
    if not tcfg.get("name"):
        from workspace import config_name as _config_name
        tcfg["name"] = _config_name(args.target_config, {})
    path = args.results or os.path.join(OUT_DIR, "results_%s.json" % tcfg["name"])
    r = verify_target(tcfg, path, args.trials, args.confirm_trials)

    code, line = note_verdict(r["note"])
    if r["note"]:
        where = sys.stderr if code else sys.stdout
        print()
        print(line, file=where)
        return code

    print()
    if r["stale_ids"]:
        print("%d claim(s) no longer reproduce:" % len(r["stale_ids"]))
        for aid, why in r["stale_ids"]:
            print("   %-28s %s" % (aid, why))
        print("\nThe artifact overstates what this target does today. Re-run the sweep to "
              "replace it, and read the difference as a change in the TARGET only after "
              "checking that nothing changed here.")
    else:
        print("every claimed breach still reproduces.")
    print("\nNot checked: the rows this artifact records as defended. A target that got worse "
          "is a sweep's question.")
    return 1 if r["stale_ids"] else 0


if __name__ == "__main__":
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
