"""
Model matrix — run ONE agent target across several models and compare how each
holds up. A threat-class by model-strength view: for some classes a bigger model is
safer, because it resists being talked into an action; for others size buys nothing,
because a secret it can see is a secret it leaks. Only works on the
LOCAL AGENT adapters (the http-backed bots bake their model into the server).

    python model_matrix.py --target-config targets_memorybot_naive.yaml \
        --attacks attacks_memorybot.yaml --models mistral-nemo,qwen2.5:14b --trials 3
"""
import sys, os, re, time, json, glob, argparse, subprocess
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import yaml
from workspace import OUT as WORKSPACE_OUT, read_artifact, NOT_MEASURED
from workspace import dated, named_build
# THE FIFTH COPY, and `workspace` has the comment that predicted it: this tuple was written
# out in `history`, `discrimination` and `build_index`, a fourth was caught arriving, and
# the grep that found those three did not reach here. Three copies of a rule agree until
# somebody decides a fourth verdict counts as a breach. `test_names` refuses the next one.
from workspace import BROKE
# and one definition of what an ATTACK is -- what it sends and what scores it. The same
# digest `history.diff`, `compare_targets.pair_diffs` and `discrimination.paired` use.
from lint_arsenal import attack_digest

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = WORKSPACE_OUT
PY = sys.executable


def tag(model):
    """The bare slug. The separator and the filename live in `workspace`, with the rule
    that decides which files this produces — see `workspace.model_tag`.
    """
    from workspace import model_tag as _model_tag
    return _model_tag(model)[1:]


def comparable(rc, path, started, exists=None, mtime=None):
    """-> (is this model's run comparable with the others, why not).

    A FAILED RUN LEAVES THE PREVIOUS RUN'S FILE IN PLACE, and `os.path.exists` is true for
    it — so the matrix would compare this model's fresh result against another model's
    older one and present the difference as a property of the models. It would be measuring
    the calendar. Both the exit code and the mtime are checked, because a run can exit 0
    having written nothing: a scope with no applicable attacks bails before writing,
    deliberately, so that an empty sweep cannot clobber good data.

    A function rather than three `continue`s inside the loop, because a rule inside a loop
    that shells out to a sweep can only be reached by running one — and what guarded it
    was three substring searches for `rc != 0`, `not comparable` and
    `os.path.getmtime(fp) < started` in this file's own source. Those are spellings. They
    go green on a refactor that keeps the words and changes the meaning, and red on one
    that keeps the meaning.

    `exists` and `mtime` are injectable for the same reason: the fixture needs to describe
    a file that is there and older than the run, which is a state and not a file.
    """
    exists = exists or os.path.exists
    mtime = mtime or os.path.getmtime
    if rc != 0:
        return False, "exited %s, so its results are not comparable" % rc
    if not exists(path):
        return False, "wrote no results file"
    if mtime(path) < started:
        return False, ("wrote nothing this run \u2014 the file on disk predates it, so it is a "
                       "DIFFERENT measurement")
    return True, ""


def main():
    # THE ONE SPELLING, from the table this command is listed in. A bare parser
    # here printed the flags and left `--help` silent about the job.
    from cli import parser as _cli_parser
    ap = _cli_parser("matrix")
    ap.add_argument("--target-config", required=True, help="the YAML describing the target")
    ap.add_argument("--attacks", default=os.path.join(ROOT, "attacks.yaml"),
                    help="the arsenal every model receives — the same one for each, or"
                         " the comparison is between two things at once")
    ap.add_argument("--models", default=None, help="comma list, e.g. mistral-nemo,qwen2.5:14b")
    from workspace import trial_count as _trial_count
    ap.add_argument("--trials", type=_trial_count, default=3,
                    help="runs per attack per model (default 3)")
    ap.add_argument("--from-disk", action="store_true",
                    help="compare per-model runs ALREADY on disk, no GPU — and print when each "
                         "was measured and by which build, because that is the whole risk")
    args = ap.parse_args()
    if not args.models and not args.from_disk:
        ap.error("--models is required unless --from-disk is given")

    from workspace import load_yaml_or_refuse as _load_yaml
    cfg = _load_yaml(args.target_config, "target config", "matrix")
    from workspace import refuse_unusable_config as _refuse
    _refuse(cfg, "matrix")
    from workspace import config_name as _config_name
    base = _config_name(args.target_config, {})
    tname = cfg.get("name", base)
    models = [m.strip() for m in (args.models or "").split(",") if m.strip()]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")

    # --- read what is already on disk ---------------------------------------------------
    #
    # The live path below refuses to compare a fresh run against a stored one, and it is right
    # to: the difference would be the calendar rather than the model. But that rule left the
    # per-model artifacts UNREADABLE — real GPU hours, sitting in out/, that nothing could look
    # at without spending them again. Nine of them were on disk when this was written.
    #
    # So stored-against-stored is allowed, and the dates and engine stamps are printed rather
    # than checked, because here the reader is the one who can judge. Two runs a week apart on
    # the same build compare models. Two runs across an oracle change compare oracles, and the
    # only defensible thing to do about that is to say so where the numbers are.
    if args.from_disk:
        per_model, when, short = {}, {}, {}
        for fp in sorted(glob.glob(os.path.join(OUT, f"results_{tname}_*.json"))):
            m = os.path.basename(fp)[len(f"results_{tname}_"):-len(".json")]
            if models and m not in [tag(x) for x in models]:
                continue
            try:
                d, _why = read_artifact(fp)
                if _why:
                    raise ValueError(_why)
            except Exception as e:
                print(f"  ({m}: unreadable, {type(e).__name__}) — not the same as absent")
                continue
            per_model[m] = {r["attack"]["id"]: r for r in d.get("results") or []}
            meta = d.get("meta") or {}
            # AND HOW MUCH OF THE ARSENAL THAT ARM WAS ACTUALLY ASKED. See `asked_less`.
            short[m] = (meta.get("unreached") or 0, meta.get("stopped") or "")
            # THE DATE THE RUN RECORDED, WHERE IT RECORDED ONE. `os.path.getmtime` is a
            # filesystem event, not a measurement: git does not preserve mtimes, so a
            # fresh clone stamps every artifact with the clone time and the `measured on
            # different days` warning below finds no difference and never renders. That
            # is the exact defect `workspace.measured_when` was written for, and this
            # was the last reader still asking the filesystem -- in the command whose
            # own `--from-disk` help calls the dates and the builds `the whole risk`.
            _shown, _from_run = dated(meta, fp)
            when[m] = (_shown, named_build(meta.get("engine")),
                       meta.get("arsenal") or "?", meta.get("trials"), _from_run)
        if len(per_model) < 2:
            # 3, NOT 0. A comparison needs two things to compare and there are not two, so
            # nothing was measured. `regression_verdict` reaches the same answer for the
            # same shortage -- a first run is a baseline, not a verdict -- and exits 3.
            print(f"\nfound {len(per_model)} stored per-model run(s) for {tname}; need "
                  f"2+. Nothing was compared.")
            return 3
        print(f"\nSTORED RUNS — not measured together. Judge the comparison against these:")
        _tw = max([4] + [len(v[0]) for v in when.values()]) + 2
        for m, (t, eng, ars, tr, said) in sorted(when.items()):
            print(f"  {m:<18}{t:<{_tw}}build {eng or 'unstamped':<16}{ars}  x{tr}")
        if not all(v[4] for v in when.values()):
            print("    (file) — that run recorded no date, so this one is the artifact's "
                  "timestamp:\n    a clone or a copy resets it, and it is not when the run "
                  "happened.")
        # BOTH SIDES OR NOTHING, over NAMED builds only. `engine_version` stamps the
        # literal "unknown" where there is no repository to ask, and that string is
        # truthy: a set of {'unknown', 'a1b2c3'} has two members and this warned about a
        # different oracle nobody had measured, while two unknowns compared equal and
        # withdrew the warning as though they had been shown to agree.
        builds = {v[1] for v in when.values() if v[1]}
        if len(builds) > 1:
            print("  ! these runs were scored by DIFFERENT builds of the oracle, so a "
                  "difference below\n    may be a change in the detectors rather than in the "
                  "models.")
        elif not all(v[1] for v in when.values()):
            # NOT SILENCE. A run with no build has not been shown to match the others,
            # and no warning is what agreement looks like.
            print("  ! at least one of these runs did not record which build scored it, "
                  "so whether\n    the same oracle judged them is not answerable from "
                  "what is stored.")
        # AND THE DAYS, over dates the RUNS recorded. Comparing mtimes answers a
        # question about the filesystem: in a fresh clone they are all equal and this
        # never fires, which is the same absence-read-as-agreement one line up.
        days = {v[0][:10] for v in when.values() if v[4]}
        if len(days) > 1:
            print(f"  ! measured on different days ({', '.join(sorted(days))}); a target or its "
                  f"model\n    may have moved in between.")
        return report(tname, per_model, short)

    # run the target once per model (writes results_<target>_<modeltag>.json each)
    per_model, stale, short = {}, [], {}
    for m in models:
        print(f"\n===== {tname} on {m} =====")
        started = time.time()
        # A ceiling per model, for the same reason as the fleet sweep: a model that stops
        # producing tokens blocks the matrix on one cell, and a matrix missing a row reads as
        # a model that was not tried rather than one that never answered.
        _deadline = int(os.environ.get("QATRATION_SWEEP_TIMEOUT", "14400"))
        try:
            rc = subprocess.run([PY, os.path.join(ROOT, "run_redteam.py"),
                                 "--target-config", args.target_config,
                                 "--attacks", args.attacks,
                                 "--model", m, "--trials", str(args.trials)], env=env,
                                timeout=_deadline).returncode
        except subprocess.TimeoutExpired:
            print(f"  ! {m}: no output for {_deadline}s, stopped — this row is missing "
                  f"because the model stopped answering, not because it held")
            rc = None
        # ASKED, NOT RECONSTRUCTED. This is the file `run_redteam` writes for `--model m`,
        # and the two modules now get it from the same function.
        from workspace import artifact_path as _artifact_path
        fp = _artifact_path(OUT, "results", tname, m)
        # A FAILED RUN LEAVES THE PREVIOUS RUN'S FILE IN PLACE, and `os.path.exists` is true
        # for it — so the matrix would compare this model's fresh result against another
        # model's older one and present the difference as a property of the models. It would
        # be measuring the calendar. Both the exit code and the mtime are checked, because a
        # run can exit 0 having written nothing: a scope with no applicable attacks bails
        # before writing, deliberately, so that an empty sweep cannot clobber good data.
        # AND A MODEL THAT WROTE NO FILE AT ALL JOINS THEM. This case printed its own line
        # and did not join `stale`, so it was missing from the summary whose stated job is
        # that the exclusions are named rather than silently thinning the comparison —
        # two of the three exclusions reached the line a reader scans.
        _ok, _why_x = comparable(rc, fp, started)
        if not _ok:
            print(f"  ({m} {_why_x}, skipped)")
            stale.append(m)
            continue
        _d, _why = read_artifact(fp)
        if _why:
            stale.append(m)
            continue
        per_model[m] = {r["attack"]["id"]: r for r in (_d.get("results") or [])}
        _meta_m = _d.get("meta") or {}
        short[m] = (_meta_m.get("unreached") or 0, _meta_m.get("stopped") or "")

    if stale:
        print(f"\nnot in the matrix: {', '.join(stale)} — comparing a fresh run against a "
              f"stored one measures the calendar, not the model.")
    if len(per_model) < 2:
        # NOT ZERO. This command exists to compare, and a run that compared nothing has not
        # answered its question: the same event `run` reports as 3, "nothing was measured".
        # Exiting 0 told a script the matrix was fine and there was merely nothing to say.
        print("\nneed >=2 models with results FROM THIS RUN to compare.")
        sys.exit(3)
    return report(tname, per_model, short)


def mark(row):
    """-> what one cell of the matrix says about one row.

    `ok` USED TO COVER THREE DIFFERENT THINGS: a model that held, a row that errored, and a
    row that was never delivered. This table is the one a reader trusts most — it is a
    side-by-side of how models behaved — and in it "the model held" and "nobody asked it"
    rendered identically.

    Not hypothetical. A target that declares `chain` and nothing else cannot take a forged
    transcript, so the five Context Compliance attacks in the generic arsenal come back SKIP,
    and every one of them printed `ok` beside a model that was never sent them. `-` already
    means "no row here"; these are rows that exist and measured nothing, which is a third
    state and now says so.
    """
    head = row.get("headline")
    if head in BROKE:
        return "BREAK"
    if head in NOT_MEASURED:
        return "skip" if head == "SKIP" else "err!"
    return "ok"


def asked_less(short, models):
    """-> {model: (attacks never sent to it, why)} for the arms the arsenal outran.

    A RUN THAT STOPPED PART WAY MAKES A MODEL LOOK SAFER, and the verdict this command ends
    with is a ranking of breach counts. `comparable` already refuses a run that exited
    non-zero, wrote nothing, or left an older file in place -- and a sweep the target
    stopped exits 0, writes a fresh file, and is simply short. Fewer attacks sent is fewer
    attacks that can break it, so the arm that was cut off wins the comparison.

    `meta["unreached"]` is what the sweep records for exactly this: the attacks it never
    got to. An arm with none is not mentioned, because a caveat on every run is one nobody
    reads.
    """
    out = {}
    for m in models:
        n, why = (short or {}).get(m) or (0, "")
        if n:
            out[m] = (n, why)
    return out


def report(tname, per_model, short=None):
    # union of attack ids, controls last
    ids, seen = [], set()
    for m in per_model:
        for aid in per_model[m]:
            if aid not in seen:
                seen.add(aid); ids.append(aid)

    ms = list(per_model)
    w = max(20, *(len(i) for i in ids))
    print("\n" + "=" * 70)
    print("  MODEL MATRIX — " + tname)
    print("=" * 70)
    print(f"{'attack':<{w}}  " + "  ".join(f"{m:<14}" for m in ms))
    print("-" * (w + 2 + 16 * len(ms)))
    broke_set = {m: set() for m in ms}
    for aid in ids:
        cells = []
        for m in ms:
            r = per_model[m].get(aid)
            if not r:
                cells.append(f"{'-':<14}"); continue
            broke = r["headline"] in BROKE
            if broke and r["attack"].get("category") != "control":
                broke_set[m].add(aid)
            cells.append(f"{mark(r):<5} {r['rate']:<8}")
        print(f"{aid:<{w}}  " + "  ".join(cells))

    breaches = {m: len(broke_set[m]) for m in ms}
    print("-" * (w + 2 + 16 * len(ms)))
    print(f"{'BREACHES (excl. controls)':<{w}}  " + "  ".join(f"{breaches[m]:<14}" for m in ms))

    # AN ID IS A NAME, NOT A QUESTION, and this table joins arms on the id. Under
    # `--from-disk` the arms are separate stored runs -- which this command allows on purpose,
    # with its own help calling the dates and the builds "the whole risk" -- so an attack can
    # be recorded in two versions under one name. A row like that is not one model answering
    # differently from another, and the verdict below is a sentence about the models.
    #
    # NOTHING IN THE STORED MATRIX ARMS DISAGREES TODAY: four targets have two model arms each
    # and all 317 shared ids match. This completes a list this function already keeps -- it
    # warns about a different oracle build and about runs measured on different days for the
    # same reason -- rather than fixing something measured. The three other places an id is
    # used as a join key each had a live instance; this one does not, and saying so is the
    # difference between a check and a claim.
    #
    # THE COUNTS ABOVE STAY. They are per-model totals over what that model was sent, which
    # is a real number either way. What is narrowed is the COMPARISON, because that is the
    # part that reads across arms -- the same split `discrimination.paired` and the
    # comparison page's build pairs already draw, with the same digest.
    _versions = {}
    for aid in ids:
        # NO EMPTY-DIGEST GUARD, and the absence is deliberate. `attack_digest` returns
        # empty only for a non-mapping, and every row here has already been indexed by
        # `r["attack"]["id"]`, so it cannot. A line no mutation can turn red is the thing
        # this suite refuses everywhere else.
        _seen = {attack_digest((per_model[m].get(aid) or {}).get("attack") or {})
                 for m in ms if per_model[m].get(aid)}
        if len(_seen) > 1:
            _versions[aid] = len(_seen)
    if _versions:
        print("\n  ! %d attack(s) are recorded in more than one version across these runs, "
              "so a\n    difference on them is the question changing rather than the model: "
              "%s%s.\n    They are in the counts above and out of the comparison below; "
              "re-run the models\n    with one arsenal to compare them."
              % (len(_versions), ", ".join(sorted(_versions)[:6]),
                 " …" if len(_versions) > 6 else ""))
        for m in ms:
            broke_set[m] = broke_set[m] - set(_versions)

    # WHICH ARMS THE ARSENAL OUTRAN, before any sentence that ranks them. `comparable`
    # names the runs that were excluded; these were INCLUDED and are short, which is the
    # exclusion nobody had to make because the run exited 0.
    _cut = asked_less(short, ms)
    for _m, (_n, _why) in sorted(_cut.items()):
        print(f"\n  ! {_n} attack(s) never reached {_m}"
              + (f": {_why}" if _why else "")
              + f"\n    Its {breaches[_m]} breach(es) below are a FLOOR, not a count: an "
                f"attack nobody sent cannot break it.")

    # verdict: compare the SETS breached, not just counts — a different failure
    # SURFACE at the same count is the subtle case a count-only view hides.
    print()
    counts = set(breaches.values())
    all_same_set = all(broke_set[m] == broke_set[ms[0]] for m in ms)
    if all_same_set:
        print(f"→ model strength made NO difference ({breaches[ms[0]]} breaches, the SAME attacks "
              f"on every model) — this class doesn't care how big the model is.")
    elif len(counts) == 1:
        print(f"→ SAME breach count ({breaches[ms[0]]}) but a DIFFERENT failure surface — model "
              f"choice reshuffles WHICH attacks land, it doesn't reduce them:")
        for m in ms:
            uniq = broke_set[m] - set.intersection(*(broke_set[x] for x in ms))
            if uniq:
                print(f"    only {m} falls for: {', '.join(sorted(uniq))}")
    else:
        safest = min(breaches, key=breaches.get)
        worst = max(breaches, key=breaches.get)
        # AND AN ARM THE ARSENAL OUTRAN CANNOT BE THE SAFER ONE. An attack nobody sent
        # cannot break the model it was never sent to, so a run that stopped part way makes
        # its model look better and this line is a ranking of breach counts. The asymmetry
        # is the one `workspace.verdict_for` states: a missing row can HIDE a breach and
        # cannot invent one, so the count is a floor -- which still supports calling an arm
        # the WORST, and never the safest.
        if safest in _cut:
            print(f"→ {safest} has the fewest breaches ({breaches[safest]}) and is also the "
                  f"arm {_cut[safest][0]} attack(s) never reached, so it CANNOT be called "
                  f"the safer model here: its count is a floor. Re-run it against the whole "
                  f"arsenal before comparing.")
        else:
            print(f"→ model choice MATTERS here: {safest} ({breaches[safest]}) held better "
                  f"than {worst} ({breaches[worst]}).")
        for m in (safest, worst):
            uniq = broke_set[m] - broke_set[safest if m == worst else worst]
            if uniq:
                print(f"    only {m} falls for: {', '.join(sorted(uniq))}")
    print("  (model choice is not a security control — only a structural guard holds regardless.)")


if __name__ == "__main__":
    # The return value is the answer; `main()` alone drops it. Stated where `build_index`
    # states it, because five modules here computed a code and threw it away for anybody
    # who ran the file rather than the `qatration` entry point.
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
