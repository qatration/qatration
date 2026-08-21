"""
One command to run the whole fleet: discover every targets_*.yaml, run each
through the engine (multi-trial by default), SKIP any whose backing server is
down (so one dead bot doesn't poison the sweep with ERROR rows), then regenerate
the aggregate defense + fleet reports.

    python run_all.py [--trials N] [--attacks attacks.yaml] [--only a,b]

Needs Ollama running (+ OLLAMA_MODELS set) for the agent adapters, and the local
bot servers up for the url-backed ones (httpbot:8099, nemo:8100, guardedrag:8200,
localrag:8000) — the ones that are down are simply skipped and named at the end.
"""
import sys, os, glob, socket, subprocess, argparse
from target import target_configs
from urllib.parse import urlparse
try:                                    # line_buffering so our prints interleave correctly
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable                      # same interpreter/venv that launched us


# Ceilings, not schedules. A sweep stops itself on its config's own `max_seconds` budget;
# these catch a process that is not running any more — a server that accepted a connection and
# never answered, a model that stopped producing tokens — which without them blocks this loop
# for as long as anybody lets it, with the fleet run looking like it is still working.
SWEEP_DEADLINE = int(os.environ.get("QATRATION_SWEEP_TIMEOUT", "14400"))   # 4h per target
TOOL_DEADLINE = int(os.environ.get("QATRATION_TOOL_TIMEOUT", "600"))       # offline, seconds


def server_up(url, timeout=2.0):
    """TCP-connect probe — 'is anything listening on host:port', no HTTP semantics."""
    p = urlparse(url)
    host = p.hostname or "localhost"
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=None,
                    help="passthrough to run_redteam (default: its own 3 / per-config)")
    ap.add_argument("--attacks", default=os.path.join(ROOT, "attacks.yaml"))
    ap.add_argument("--only", default=None,
                    help="comma list of config basenames or target names to include")
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",")} if args.only else None
    configs = target_configs(ROOT)
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    ran, skipped, failed = [], [], []

    # pre-flight: lint the arsenal FIRST — a bad detector ref would silently under-test
    # every target, so refuse to sweep on a broken arsenal.
    print("pre-flight: linting arsenal…")
    try:
        _lint_rc = subprocess.run([PY, os.path.join(ROOT, "lint_arsenal.py")], env=env,
                                  timeout=TOOL_DEADLINE).returncode
    except subprocess.TimeoutExpired:
        print("ABORT — the arsenal lint did not finish in %ds. It reads files and calls no "
              "model, so this is a wedge rather than slow work." % TOOL_DEADLINE)
        sys.exit(1)
    if _lint_rc != 0:
        print("ABORT — arsenal failed lint (see errors above); fix before sweeping.")
        sys.exit(1)

    print("=" * 60)
    print(f"  QAtration fleet sweep — {len(configs)} target configs found")
    print("=" * 60)
    for cfg_path in configs:
        base = os.path.basename(cfg_path)[len("targets_"):-len(".yaml")]
        cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
        name = cfg.get("name", base)
        if only and base not in only and name not in only:
            continue
        # A config can be a TEMPLATE rather than a member of the fleet — the generic adapter
        # ships one, and sweeping it would put a second copy of an existing bot into every
        # aggregate under a different name. Declared in the config so the sweep does not have
        # to guess, and honoured here rather than in the readers, which would each need their
        # own copy of the rule.
        if cfg.get("skip_in_fleet"):
            print(f"SKIP  {name:<22} template config (skip_in_fleet), run it explicitly")
            continue
        url = cfg.get("url")
        if url and not server_up(url):
            print(f"SKIP  {name:<22} server down at {url}")
            skipped.append(name)
            continue
        cmd = [PY, os.path.join(ROOT, "run_redteam.py"),
               "--target-config", cfg_path, "--attacks", args.attacks]
        if args.trials is not None:
            cmd += ["--trials", str(args.trials)]
        print(f"\n----- RUN {name} " + "-" * (48 - len(name)))
        try:
            rc = subprocess.run(cmd, env=env, timeout=SWEEP_DEADLINE).returncode
        except subprocess.TimeoutExpired:
            # Counted as failed, and SAID, because the alternative is a fleet run that stops
            # here forever while printing nothing: every target after this one goes unswept
            # and the pages keep whatever they had, which reads as a fleet that was measured.
            print(f"  ! {name}: no output for {SWEEP_DEADLINE}s, stopped. Its results are "
                  f"whatever the last completed run left, and the rest of the fleet follows.")
            rc = None
        (ran if rc == 0 else failed).append(name)

    print("\n" + "=" * 60)
    print("  regenerating aggregate reports")
    print("=" * 60)
    for script in ("defense_report.py", "compare_targets.py", "build_index.py"):
        try:
            subprocess.run([PY, os.path.join(ROOT, script)], env=env, timeout=TOOL_DEADLINE)
        except subprocess.TimeoutExpired:
            print(f"  ! {script} did not finish in {TOOL_DEADLINE}s; its page is whatever it "
                  f"was before this sweep")

    print("\n" + "=" * 60)
    print("  discrimination self-audit")
    print("=" * 60)
    # Its exit code is the credibility gate — it is 1 when a control fired on a target whose
    # benign traffic does not explain it, which is this tool crying wolf. That was being
    # discarded, so a sweep printed "sweep done" over a failed self-audit and the pages were
    # published anyway. A gate whose result nothing reads is not a gate.
    try:
        audit_rc = subprocess.run([PY, os.path.join(ROOT, "discrimination.py")], env=env,
                                  timeout=TOOL_DEADLINE).returncode
    except subprocess.TimeoutExpired:
        # Not zero. This exit code IS the credibility gate, and an audit that did not run is
        # the one thing it must never be read as passing.
        print("  ! the discrimination self-audit did not finish in %ds; treating it as failed, "
              "because an audit that did not run has not cleared anything" % TOOL_DEADLINE)
        audit_rc = 1

    print("\n" + "=" * 60)
    print(f"  sweep done — ran {len(ran)}, skipped {len(skipped)}, failed {len(failed)}")
    print("=" * 60)
    if ran:
        print(f"ran     : {', '.join(ran)}")
    if skipped:
        # A SKIPPED TARGET STILL HAS A PAGE. Its results file from an earlier run is on disk,
        # so the aggregates above include it and a reader has no way to tell it apart from
        # something this sweep measured. The staleness bar catches it only when the dates
        # differ enough to notice; this says it outright.
        print(f"skipped : {', '.join(skipped)}  (server down — start it and re-run)")
        print(f"          their pages come from an EARLIER run and are in the aggregates "
              f"above as though this sweep had measured them.")
    if failed:
        print(f"FAILED  : {', '.join(failed)}  (non-zero exit — check its output above)")

    # The exit code carries all of it, or a scheduled sweep is green whatever happened.
    if failed:
        print(f"\nEXIT 1 — {len(failed)} target(s) failed to run.")
        sys.exit(1)
    if audit_rc:
        print("\nEXIT 1 — the discrimination self-audit failed: a control fired on a target "
              "whose benign traffic does not explain it.")
        sys.exit(audit_rc)


if __name__ == "__main__":
    main()
