"""
Memory across runs — the difference between a scan and a monitor.

Every sweep used to overwrite `out/results_<target>.json` and destroy what was there. The
engine could therefore answer only one question, "what is broken now", and none of the ones
that matter on the second run against the same system:

    is this finding NEW, or was it here last month?
    did the fix we shipped actually close it?
    is this a REGRESSION of something we already closed?
    how long has this been open?

Those are the whole back half of ongoing testing, and they were not merely unimplemented,
they were impossible: the evidence had been deleted. That matters more here than for a
classic scanner, because an AI feature changes weekly — a prompt edit, a model bump, a new
tool — and each of those can reopen something quietly.

The design keeps the blast radius at zero. `results_<target>.json` stays exactly as it was,
so every existing report keeps reading it; history is APPENDED to `out/history/<target>.jsonl`,
one compact line per run. Append-only on purpose: a history that can be rewritten answers
"has this regressed" with whatever the last writer believed.

    qatration history                 # every target, latest diff
    qatration history --target dvla   # one target, full timeline
    qatration history --backfill      # seed from today's results
"""
import sys, os, re, json, glob, argparse, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from workspace import (OUT as WORKSPACE_OUT, results_files, read_artifact,
                       NOT_MEASURED)
ROOT = os.path.dirname(HERE)
OUT = WORKSPACE_OUT
HIST = os.path.join(OUT, "history")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from workspace import BROKE   # one definition of what counts as a breach


def _path(target):
    return os.path.join(HIST, f"{target}.jsonl")


def snapshot(meta, results, when=None, note=None):
    """One run, reduced to what a later comparison needs and nothing else."""
    rows = {}
    for r in results:
        if r["attack"].get("category") == "control":
            continue                       # a control is a false-alarm check, not a finding
        rows[r["attack"]["id"]] = {"v": r["headline"], "rate": r.get("rate", ""),
                                   "fired": sorted(r.get("fired") or [])}
    return {"run": when or datetime.datetime.now().isoformat(" ", "seconds"),
            "target": meta.get("target"), "model": meta.get("model", ""),
            "trials": meta.get("trials"), "attacks": len(rows),
            "broke": sum(1 for x in rows.values() if x["v"] in BROKE),
            "note": note, "rows": rows}


def _append(snap):
    """Write one prepared snapshot. Split out so `backfill` can inspect before appending."""
    os.makedirs(HIST, exist_ok=True)
    with open(_path(snap["target"]), "a", encoding="utf-8") as f:
        f.write(json.dumps(snap, ensure_ascii=False) + "\n")
    return snap


def record(meta, results, when=None, note=None):
    """Append one run. Never rewrites a line, so a regression cannot be edited away.

    NOT DEDUPED, deliberately. A live run that reproduces the previous result exactly is a
    fact worth keeping: it is the second data point that turns "fixed" into "fixed and it
    held". Only `backfill` dedupes, and only because it is re-reading a run the timeline may
    already hold.
    """
    return _append(snapshot(meta, results, when, note))


def same_run(a, b):
    """Is this the same run, recorded twice?

    THE CLOCK CANNOT ANSWER THIS AND WAS ASKED TO. `backfill` skipped a results file when
    some timeline entry carried the same `run` string, comparing a file mtime against a
    stamp `record` took from `datetime.now()` when the snapshot was built. Those are two
    different clocks reading two different moments -- the second is when the sweep finished
    writing, the first is whenever the file was last touched -- so the strings differ and the
    guard never fired. Measured on this repository: 28 of the 35 targets with a timeline
    would be re-seeded, and every mtime involved reads 2026-08-20 16:08:13, because a bulk
    file operation touched them all. The key was not merely the wrong clock, it was a clock
    that no longer records anything about the run.

    What that costs is not a duplicate line. `diff()` compares `runs[-2]` against `runs[-1]`,
    so a re-seeded run is compared against its own copy: no new, no fixed, no regressed,
    nothing flagged -- which reads as a stable target and is in fact nothing having been
    compared. Sharper still after `rejudge`, which rewrites results in place and bumps the
    mtime, so the phantom entry carries re-scored verdicts against the originals and an
    oracle change surfaces as target findings that no run measured.

    So identity is the RUN, not the moment: the model, the trial count and the finding set.
    Two snapshots agreeing on all three say the same thing about the same target, and a
    timeline holding both learns nothing from the second.
    """
    return (a.get("model") == b.get("model")
            and a.get("trials") == b.get("trials")
            and a.get("rows") == b.get("rows"))


def load(target, unreadable=None):
    """The timeline for one target, newest last. Corrupt lines are skipped and COUNTED.

    One unreadable line must not lose the whole timeline — a truncated write from a killed
    run should cost the run it recorded and nothing else. But skipping it in silence makes
    the timeline shorter than it is, and this file is what answers "is this new, did the fix
    hold, has it regressed, how long has it been open". A diff computed across a gap is a
    confident answer over evidence that is missing, which is the one thing this repo will not
    do quietly. Pass a list to collect what could not be read.
    """
    p = _path(target)
    if not os.path.exists(p):
        return []
    out = []
    for n, line in enumerate(open(p, encoding="utf-8"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception as e:
            if unreadable is not None:
                unreadable.append((n, f"{type(e).__name__}: {e}"))
    return out


def broke_every_trial(row):
    """Did this row break on EVERY attempt: True, False, or None when it cannot say.

    `snapshot()` has written `rate` as "1/3" since the day it was written, and `diff()` threw
    it away: the comparison read the verdict alone, so 0/3 -> 1/3 and 0/3 -> 3/3 were the same
    event. They are not. The first is one sample of a coin the target was already flipping,
    and the gate below turns events into somebody's build going red.

    Measured, not supposed: two runs of this engine against one endpoint, nothing changed
    between them but the sampler, moved ten attacks. Six became "introduced or reopened" and
    four became "fixed", and not one of the ten broke on all three attempts in either run.

    None rather than False when the rate is missing or unreadable, because a row that cannot
    say is not a row that says no. The caller keeps such rows out of the counted buckets and
    names them, which understates the diff. That is the allowed direction here.
    """
    m = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*$", str((row or {}).get("rate") or ""))
    if not m:
        return None
    hits, trials = int(m.group(1)), int(m.group(2))
    if trials <= 0:
        return None
    return hits >= trials


def diff(target):
    """Latest run against the one before it.

    FIVE states, and the fifth is the one that matters most for being right.

      new       broken now, clean in the previous run           -> triage
      fixed     broken before, MEASURED clean now               -> verify and close
      regressed clean in the previous run, broken now, and broken at some point before
                that -> the fix did not hold, which is worse news than a new finding
      open      broken in both                                  -> still owed
      not_run   broken before, ABSENT from this run             -> not tested, not fixed

    That last one exists because the first real sweep after this was written reported eight
    findings as fixed when the run had simply used a different arsenal and never sent them.
    Absence read as a clean result — the same "not measured is not measured clean" mistake
    this repo has now made in four separate places, and the only one where it would have
    reported somebody's vulnerabilities as closed.

    AND THEN IT WAS MADE AGAIN HERE, one run later and in the opposite direction. `state()`
    returns None for an attack a run did not send, with a comment saying it says nothing
    either way — and the branch below read that None as False, i.e. as *measured clean*. So
    an attack broken now, absent from the previous run and broken in some earlier one was
    labelled REGRESSED, whose whole meaning is "the fix did not hold", when nothing had ever
    measured it fixed. `not_run` protects absent-NOW; nothing protected absent-BEFORE.

    A previous state of absence is now its own case. Broken now, never seen broken before,
    not measured last time is `new` — it is the first sighting, which is what new means.
    Broken now, broken in some earlier run, not measured last time is `open`: it has been
    owed since that earlier break and no run since has shown it closed. Neither can be
    `regressed`, because a regression is a claim that something was measured clean in
    between, and the ids where that claim would have been made are returned in
    `assumed_clean` so the caller can say the comparison rests on an absence.
    """
    torn = []
    runs = load(target, torn)
    if len(runs) < 2:
        return {"runs": len(runs), "reason": "need two runs to compare"}
    prev, cur = runs[-2], runs[-1]

    def state(run, aid):
        row = run["rows"].get(aid)
        if row is None:
            return None                    # not attempted: says nothing either way
        if row.get("v") in NOT_MEASURED:
            # ATTEMPTED OR NOT, MEASURED NOTHING — either way. SKIP was missing, and it is
            # the worse of the two: `"SKIP" in BROKE` is False, which is the value that means
            # MEASURED CLEAN, so an attack that broke last week and was not delivered this
            # week came back as FIXED. That is the one direction the docstring above calls
            # out as the reason this whole function exists, reached through a verdict the
            # branch simply did not name.
            #
            # A target losing `history:` from its config is enough to do it: every forged
            # transcript attack turns to SKIP, and the diff closes each one it had open.
            return None
        return row["v"] in BROKE

    ids = sorted(set(cur["rows"]) | set(prev["rows"]))
    new, fixed, regressed, still, untested, assumed = [], [], [], [], [], []
    unstable = []
    for aid in ids:
        now, before = state(cur, aid), state(prev, aid)
        if now is None:
            if before:
                untested.append(aid)       # was broken, and this run did not check
            continue
        earlier = any(state(r, aid) for r in runs[:-2])
        # A FLIP THE TRIALS DO NOT AGREE ON IS NOT A CHANGE IN THE TARGET. Every branch below
        # decides whether somebody's build goes red, and 0/3 -> 1/3 says only that a coin the
        # target was already flipping came up the other way. So a counted move has to break on
        # every attempt on the side making the claim: now, for a finding introduced or
        # reopened; before, for one called fixed. The rest are real rows with real verdicts,
        # listed rather than dropped, but they are not the change this gate was asked about.
        steady_now = broke_every_trial(cur["rows"].get(aid))
        steady_before = broke_every_trial(prev["rows"].get(aid))
        if now and before is None:
            # The previous run never sent it, so nothing measured it clean and REGRESSED is
            # not available: a fix that did not hold requires a fix that was seen to hold.
            assumed.append(aid)
            if earlier:
                still.append(aid)
            else:
                (new if steady_now else unstable).append(aid)
        elif now and not before:
            # A regression is a repeat, not a first sighting: it has to have been broken
            # in some run before the one that showed it clean.
            if not steady_now:
                unstable.append(aid)
            else:
                (regressed if earlier else new).append(aid)
        elif before and not now:
            # Measured in both, and it stopped breaking -- if it had been breaking reliably.
            # The confound below already says that a flaky attack given FEWER chances reads as
            # a fix. Given the same number and a different seed, it reads as one just as well.
            (fixed if steady_before else unstable).append(aid)
        elif now and before:
            still.append(aid)
    # Two runs made with different instruments are not comparable, and saying so is the
    # difference between a diff and a story. Caught on the first real use: httpbot's
    # previous run used three trials and the new one two, and seven attacks moved to
    # "fixed" — nearly all of them the encoded ones, a cluster too tidy to be behaviour.
    # A flaky attack that broke once in three has fewer chances in two, so the change was
    # in the measurement rather than the target. The comparison is still worth showing;
    # presenting it as a clean before/after is not.
    confounds = []
    if prev.get("trials") != cur.get("trials"):
        confounds.append(f"trials {prev.get('trials')} → {cur.get('trials')}: fewer "
                         f"attempts give a flaky attack fewer chances, which reads as a fix")
    if (prev.get("model") or "") != (cur.get("model") or ""):
        confounds.append(f"model {prev.get('model')!r} → {cur.get('model')!r}")
    if prev["attacks"] != cur["attacks"]:
        confounds.append(f"arsenal {prev['attacks']} → {cur['attacks']} attacks")
    if torn:
        # A gap in the timeline is not a gap in the diff's confidence unless it is said to be.
        confounds.append(f"{len(torn)} line(s) of this target's timeline could not be read "
                         f"(line {torn[0][0]}: {torn[0][1]}) — the history behind this "
                         f"comparison is incomplete")
    if assumed:
        confounds.append(f"{len(assumed)} row(s) the previous run never sent: "
                         f"{', '.join(assumed[:4])}{' …' if len(assumed) > 4 else ''} — "
                         f"broken now, and nothing measured them clean in between")
    return {"runs": len(runs), "prev": prev["run"], "cur": cur["run"],
            "new": new, "fixed": fixed, "regressed": regressed, "open": still,
            "not_run": untested, "assumed_clean": assumed, "unstable": unstable,
            "confounds": confounds}


def first_seen(target):
    """attack id -> the run that first showed it broken, for anything still broken.

    An open finding's AGE is the number people react to. "Critical" is an opinion;
    "critical and open since the 3rd" is a fact about how the team responds to them.
    """
    runs = load(target)
    seen, out = {}, {}
    for r in runs:
        for aid, row in r["rows"].items():
            if row["v"] in BROKE and aid not in seen:
                seen[aid] = r["run"]
    if runs:
        for aid, row in runs[-1]["rows"].items():
            if row["v"] in BROKE:
                out[aid] = seen.get(aid, runs[-1]["run"])
    return out


def backfill():
    """Seed the timeline from the results already on disk, stamped with their file time.

    Without this the feature is useless until someone re-runs everything, which is the
    cost that stopped it being built. A backfilled entry is marked as such, because its
    run time is a file's mtime rather than something the engine recorded.
    """
    made = 0
    for fp in results_files(OUT):   # per-model copies are the same run, twice
        d, why = read_artifact(fp)
        if why:
            # A run that cannot be read is not a run with no findings. Recording it as one
            # would put a false "everything fixed" step into the timeline.
            print(f"  ! {os.path.basename(str(fp))} could not be read ({why}); no timeline "
                  f"entry was written for it.", file=sys.stderr)
            continue
        target = (d.get("meta") or {}).get("target")
        if not target:
            continue
        when = datetime.datetime.fromtimestamp(
            os.path.getmtime(fp)).isoformat(" ", "seconds")
        # ON THE RUN, NOT ON THE CLOCK. See `same_run`: this compared the file's mtime
        # against a stamp `record` took from `datetime.now()`, so it never matched and
        # re-seeded 28 of the 35 targets that already had a timeline.
        snap = snapshot(d["meta"], d["results"], when=when,
                        note="backfilled from results file")
        if any(same_run(snap, r) for r in load(target)):
            continue                       # already seeded; append-only must stay honest
        _append(snap)
        made += 1
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=None)
    ap.add_argument("--backfill", action="store_true")
    args = ap.parse_args()

    if args.backfill:
        n = backfill()
        print(f"seeded {n} timeline(s) from stored results.\n"
              f"Their run times are file mtimes, not engine records, and each entry says so.")
        return

    targets = ([args.target] if args.target
               else sorted(os.path.basename(p)[:-len(".jsonl")]
                           for p in glob.glob(os.path.join(HIST, "*.jsonl"))))
    if not targets:
        # A FLAG BELONGS TO A COMMAND. `--backfill` on its own is advice the reader cannot
        # act on without guessing which of twenty commands takes it.
        print("no history yet — run a sweep, or read what is already stored:\n"
              "    qatration run --target-config <your-config>.yaml\n"
              "    qatration history --backfill")
        # NOT A PASS, for the reason `build_index` records.
        return 3

    for t in targets:
        runs = load(t)
        d = diff(t)
        print(f"\n{t}  ({len(runs)} run(s))")
        if args.target:
            for r in runs:
                mark = " (backfilled)" if r.get("note") else ""
                print(f"  {r['run']}  {r['broke']:>3}/{r['attacks']} broken  "
                      f"{r.get('model') or ''}{mark}")
        if "reason" in d:
            print(f"  {d['reason']} — a single run is a snapshot, not a trend")
            continue
        for label, key in (("REGRESSED", "regressed"), ("new", "new"),
                           ("fixed", "fixed"), ("still open", "open"),
                           ("NOT RUN", "not_run"), ("unsteady", "unstable")):
            if d[key]:
                shown = ", ".join(d[key][:6]) + (f" +{len(d[key]) - 6}" if len(d[key]) > 6 else "")
                print(f"  {label:<11}{len(d[key]):>3}  {shown}")
        if d.get("confounds"):
            print(f"  ! NOT A CLEAN BEFORE/AFTER — {'; '.join(d['confounds'])}")
        ages = first_seen(t)
        if ages:
            oldest = min(ages.values())
            print(f"  oldest open finding first seen {oldest}")


if __name__ == "__main__":
    main()
