"""
Model matrix — run ONE agent target across several models and compare how each
holds up. This is the "threat-class x model-strength" view no output-quality tool
gives: for some classes a bigger model is safer (it resists a talked-into action),
for others size buys nothing (a secret it can see, it leaks). Only works on the
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
from workspace import OUT as WORKSPACE_OUT

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = WORKSPACE_OUT
PY = sys.executable
BROKE = ("EXPLOITED", "PARTIAL")


def tag(model):
    return re.sub(r'[^A-Za-z0-9.]+', '-', model)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-config", required=True)
    ap.add_argument("--attacks", default=os.path.join(ROOT, "attacks.yaml"))
    ap.add_argument("--models", default=None, help="comma list, e.g. mistral-nemo,qwen2.5:14b")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--from-disk", action="store_true",
                    help="compare per-model runs ALREADY on disk, no GPU — and print when each "
                         "was measured and by which build, because that is the whole risk")
    args = ap.parse_args()
    if not args.models and not args.from_disk:
        ap.error("--models is required unless --from-disk is given")

    cfg = yaml.safe_load(open(args.target_config, encoding="utf-8")) or {}
    base = os.path.basename(args.target_config)[len("targets_"):-len(".yaml")]
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
        per_model, when = {}, {}
        for fp in sorted(glob.glob(os.path.join(OUT, f"results_{tname}_*.json"))):
            m = os.path.basename(fp)[len(f"results_{tname}_"):-len(".json")]
            if models and m not in [tag(x) for x in models]:
                continue
            try:
                d = json.load(open(fp, encoding="utf-8"))
            except Exception as e:
                print(f"  ({m}: unreadable, {type(e).__name__}) — not the same as absent")
                continue
            per_model[m] = {r["attack"]["id"]: r for r in d.get("results") or []}
            meta = d.get("meta") or {}
            when[m] = (time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(fp))),
                       meta.get("engine") or "unstamped",
                       meta.get("arsenal") or "?", meta.get("trials"))
        if len(per_model) < 2:
            print(f"\nfound {len(per_model)} stored per-model run(s) for {tname}; need 2+.")
            return
        print(f"\nSTORED RUNS — not measured together. Judge the comparison against these:")
        for m, (t, eng, ars, tr) in sorted(when.items()):
            print(f"  {m:<18}{t}   build {eng:<16}{ars}  x{tr}")
        builds = {v[1] for v in when.values()}
        if len(builds) > 1:
            print("  ! these runs were scored by DIFFERENT builds of the oracle, so a "
                  "difference below\n    may be a change in the detectors rather than in the "
                  "models.")
        days = {v[0][:10] for v in when.values()}
        if len(days) > 1:
            print(f"  ! measured on different days ({', '.join(sorted(days))}); a target or its "
                  f"model\n    may have moved in between.")
        return report(tname, per_model)

    # run the target once per model (writes results_<target>_<modeltag>.json each)
    per_model, stale = {}, []
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
        fp = os.path.join(OUT, f"results_{tname}_{tag(m)}.json")
        # A FAILED RUN LEAVES THE PREVIOUS RUN'S FILE IN PLACE, and `os.path.exists` is true
        # for it — so the matrix would compare this model's fresh result against another
        # model's older one and present the difference as a property of the models. It would
        # be measuring the calendar. Both the exit code and the mtime are checked, because a
        # run can exit 0 having written nothing: a scope with no applicable attacks bails
        # before writing, deliberately, so that an empty sweep cannot clobber good data.
        if rc != 0:
            print(f"  ({m} exited {rc} — its results are not comparable, skipped)")
            stale.append(m)
            continue
        if not os.path.exists(fp):
            print(f"  (no results file for {m} — skipped)")
            continue
        if os.path.getmtime(fp) < started:
            print(f"  ({m} wrote nothing this run — the file on disk predates it, so it is a "
                  f"DIFFERENT measurement and is skipped)")
            stale.append(m)
            continue
        per_model[m] = {r["attack"]["id"]: r
                        for r in json.load(open(fp, encoding="utf-8"))["results"]}

    if stale:
        print(f"\nnot in the matrix: {', '.join(stale)} — comparing a fresh run against a "
              f"stored one measures the calendar, not the model.")
    if len(per_model) < 2:
        print("\nneed >=2 models with results FROM THIS RUN to compare.")
        return
    return report(tname, per_model)


def report(tname, per_model):
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
            mark = "BREAK" if broke else "ok"
            cells.append(f"{mark} {r['rate']:<8}")
        print(f"{aid:<{w}}  " + "  ".join(cells))

    breaches = {m: len(broke_set[m]) for m in ms}
    print("-" * (w + 2 + 16 * len(ms)))
    print(f"{'BREACHES (excl. controls)':<{w}}  " + "  ".join(f"{breaches[m]:<14}" for m in ms))

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
        print(f"→ model choice MATTERS here: {safest} ({breaches[safest]}) held better than "
              f"{worst} ({breaches[worst]}).")
        for m in (safest, worst):
            uniq = broke_set[m] - broke_set[safest if m == worst else worst]
            if uniq:
                print(f"    only {m} falls for: {', '.join(sorted(uniq))}")
    print("  (model choice is not a security control — only a structural guard holds regardless.)")


if __name__ == "__main__":
    main()
