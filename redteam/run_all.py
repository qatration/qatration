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

# NO CLI DOOR, ON PURPOSE, and said here rather than in the gate: a list of exempt
# modules living in the check is a second copy of this judgement, and the next module
# added would join it by whoever happened to be editing the check.
NO_CLI_DOOR = "sweeps the practice fleet, which only exists inside this repository"


ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable                      # same interpreter/venv that launched us


# Ceilings, not schedules. A sweep stops itself on its config's own `max_seconds` budget;
# these catch a process that is not running any more — a server that accepted a connection and
# never answered, a model that stopped producing tokens — which without them blocks this loop
# for as long as anybody lets it, with the fleet run looking like it is still working.
from workspace import sweep_deadline as _sweep_deadline, env_int as _env_int
SWEEP_DEADLINE = _sweep_deadline()                                          # 4h per target
TOOL_DEADLINE = _env_int("QATRATION_TOOL_TIMEOUT", 600, 1,                  # offline, seconds
                         "it is the seconds an offline step may run before it is stopped")


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


def fleet_plan(only=None, root=None):
    """-> [(name, path, config, skip reason or "")] — who this sweep will run, and who it
    will not.

    A FUNCTION BECAUSE NOTHING COULD ASK. Every decision here was inline in `main`, between
    two `print`s and a `subprocess.run` that sends real traffic to every practice bot, so
    the only way to find out who a sweep would touch was to run one. The rest of this
    repository has been through the same move -- `gate_verdict`, `verify.fleet_configs`,
    `benign.adjudicated` -- with the same sentence: a decision rendered inside a print block
    is a decision nothing can read.

    THROUGH THE ONE ENUMERATION. This parsed each config itself and then asked whatever came
    back for `name`, so a config reading `- name: listy` ended the fleet sweep with an
    `AttributeError` before a single target was touched.

    BOTH HALVES OF `--only`, because it matches either: the filename stem, which is what
    somebody types for a config that declares no name, and the name the config declares. The
    map answers the second and the path answers the first.

    A TEMPLATE IS NOT A MEMBER OF THE FLEET. The generic adapter ships one, and sweeping it
    would put a second copy of an existing bot into every aggregate under a different name --
    one run counted twice, which is the arithmetic the per-model-copy rule exists to prevent.
    Declared in the config so the sweep does not have to guess, and honoured here rather than
    in the readers, which would each need their own copy of the rule.
    """
    from workspace import configs_by_name as _by_name, config_name as _config_name
    out = []
    for name, (cfg_path, cfg) in sorted(_by_name(root or ROOT).items()):
        base = _config_name(cfg_path, {})
        if only and base not in only and name not in only:
            continue
        why = ("template config (skip_in_fleet), run it explicitly"
               if cfg.get("skip_in_fleet") else "")
        out.append((name, cfg_path, cfg, why))
    return out


def main():
    ap = argparse.ArgumentParser()
    from workspace import trial_count as _trial_count
    ap.add_argument("--trials", type=_trial_count, default=None,
                    help="passthrough to run_redteam (default: its own 3 / per-config)")
    ap.add_argument("--attacks", default=os.path.join(ROOT, "attacks.yaml"))
    ap.add_argument("--only", default=None,
                    help="comma list of config basenames or target names to include")
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",")} if args.only else None
    configs = target_configs(ROOT)   # counted for the banner; read through the map below
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
    for name, cfg_path, cfg, why in fleet_plan(only, ROOT):
        if why:
            print(f"SKIP  {name:<22} {why}")
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
    # A PAGE THAT FAILED TO BUILD IS A FAILURE: only a timeout was said, and a report script
    # exiting 1 left its page stale under a green run. Found by an independent review.
    pages_failed = []
    for script in ("defense_report.py", "compare_targets.py", "build_index.py"):
        try:
            _prc = subprocess.run([PY, os.path.join(ROOT, script)], env=env,
                                  timeout=TOOL_DEADLINE).returncode
        except subprocess.TimeoutExpired:
            print(f"  ! {script} did not finish in {TOOL_DEADLINE}s; its page is whatever it "
                  f"was before this sweep")
            _prc = None
        if _prc != 0:
            pages_failed.append(script)

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
    # NOTHING RAN IS NOT A PASS: every named server down, or a typo in `--only`, printed
    # "ran 0" and exited 0. Found by an independent review.
    if not ran and not failed:
        print("\nEXIT 3 — nothing was swept: %s. The pages above are from earlier runs."
              % ("every target named was down" if skipped else "no target matched"))
        sys.exit(3)
    if pages_failed:
        print(f"\nEXIT 1 — {', '.join(pages_failed)} did not rebuild its page, so what it "
              f"shows is from before this sweep.")
        sys.exit(1)
    if failed:
        print(f"\nEXIT 1 — {len(failed)} target(s) failed to run.")
        sys.exit(1)
    if audit_rc:
        print("\nEXIT 1 — the discrimination self-audit failed: a control fired on a target "
              "whose benign traffic does not explain it.")
        sys.exit(audit_rc)


if __name__ == "__main__":
    main()
