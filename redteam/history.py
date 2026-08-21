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
import sys, os, json, glob, argparse, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from workspace import OUT as WORKSPACE_OUT, results_files, read_artifact
ROOT = os.path.dirname(HERE)
OUT = WORKSPACE_OUT
HIST = os.path.join(OUT, "history")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BROKE = ("EXPLOITED", "PARTIAL")


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


def record(meta, results, when=None, note=None):
    """Append one run. Never rewrites a line, so a regression cannot be edited away."""
    os.makedirs(HIST, exist_ok=True)
    snap = snapshot(meta, results, when, note)
    with open(_path(snap["target"]), "a", encoding="utf-8") as f:
        f.write(json.dumps(snap, ensure_ascii=False) + "\n")
    return snap


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
        if row.get("v") == "ERROR":
            return None                    # attempted, measured nothing: also either way
        return row["v"] in BROKE

    ids = sorted(set(cur["rows"]) | set(prev["rows"]))
    new, fixed, regressed, still, untested, assumed = [], [], [], [], [], []
    for aid in ids:
        now, before = state(cur, aid), state(prev, aid)
        if now is None:
            if before:
                untested.append(aid)       # was broken, and this run did not check
            continue
        earlier = any(state(r, aid) for r in runs[:-2])
        if now and before is None:
            # The previous run never sent it, so nothing measured it clean and REGRESSED is
            # not available: a fix that did not hold requires a fix that was seen to hold.
            assumed.append(aid)
            (still if earlier else new).append(aid)
        elif now and not before:
            # A regression is a repeat, not a first sighting: it has to have been broken
            # in some run before the one that showed it clean.
            (regressed if earlier else new).append(aid)
        elif before and not now:
            fixed.append(aid)              # measured in both, and it stopped breaking
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
            "not_run": untested, "assumed_clean": assumed, "confounds": confounds}


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
        if any(r["run"] == when for r in load(target)):
            continue                       # already seeded; append-only must stay honest
        record(d["meta"], d["results"], when=when, note="backfilled from results file")
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
        print("no history yet — run a sweep, or --backfill from what is already stored")
        return

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
                           ("NOT RUN", "not_run")):
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
