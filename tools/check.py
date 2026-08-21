"""Run the offline suites. One command for a person and for CI, so they cannot diverge.

Every `redteam/test_*.py` is a standalone script that exits non-zero on failure — no pytest, no
plugins, no collection rules, and nothing between a failing assertion and a red exit code. That
is worth keeping, but it left "run the tests" as a shell loop that everyone rewrote slightly
differently, and a CI whose loop differs from the one a developer runs is a CI that tests
something else.

    python tools/check.py                    # everything
    python tools/check.py oracle benign      # just those (prefix match, no test_ needed)
    python tools/check.py --list

Every suite here is offline: no model, no network, no practice fleet. That is the property that
lets this run on a runner with no GPU, and it is asserted rather than assumed — a suite that
starts needing a fleet will fail here first, which is the right place to find out.
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SUITES = os.path.join(ROOT, "redteam")

# One suite per line of output would hide the failures among the passes, so only failures print
# their tail. This is how much of it to show: enough to see the assertion, not the whole run.
TAIL = 25


# How long one suite may take before it is called hung.
#
# Measured, not guessed: on this machine `end_to_end` takes 116.9s and the next slowest is
# `contract` at 5.8s — one dominant suite and a twentyfold gap to the rest. 600s is about five
# times the observed maximum, which leaves room for a CI runner two or three times slower
# without ever tripping on a healthy run. A deadline that fires on a slow machine teaches
# people to raise it without looking, and after that it is not a deadline.
#
# The runner prints the slowest suite and this margin at the end of every run, so the next
# person to change this number has the evidence rather than a guess to re-guess. The job-level
# `timeout-minutes: 30` in both workflows sits above it as the backstop for what a per-suite
# deadline cannot reach.
DEADLINE = int(os.environ.get("QATRATION_SUITE_TIMEOUT", "600"))


def suites(patterns):
    names = sorted(f for f in os.listdir(SUITES)
                   if f.startswith("test_") and f.endswith(".py"))
    if not patterns:
        return names
    chosen, unmatched = [], []
    for p in patterns:
        stem = p[5:] if p.startswith("test_") else p
        stem = stem[:-3] if stem.endswith(".py") else stem
        hits = [n for n in names if stem in n]
        if not hits:
            unmatched.append(p)
        chosen.extend(h for h in hits if h not in chosen)
    if unmatched:
        # A typo that silently runs nothing is a green build that checked nothing, which is the
        # failure this whole repository is about. Refuse rather than narrow.
        print("no suite matches: %s" % ", ".join(unmatched), file=sys.stderr)
        print("try: python tools/check.py --list", file=sys.stderr)
        raise SystemExit(2)
    return chosen


def main(argv):
    if "--list" in argv:
        for n in suites([]):
            print("  " + n[5:-3])
        return 0

    names = suites([a for a in argv if not a.startswith("-")])
    started = time.time()
    failed = []

    slowest = (0.0, "")
    for name in names:
        t0 = time.time()
        try:
            proc = subprocess.run([sys.executable, os.path.join(SUITES, name)],
                                  capture_output=True, text=True, cwd=ROOT,
                                  timeout=DEADLINE)
        except subprocess.TimeoutExpired as e:
            # A HANG IS A RESULT AND IT HAS A NAME. Without the deadline this call blocks
            # until the CI job's own limit — six hours by default on GitHub Actions — and the
            # run reports as "cancelled", which names no suite. Several suites here bind
            # sockets and start server threads, so a hang is the likely shape of a failure
            # rather than an exotic one.
            secs = time.time() - t0
            failed.append(name)
            print("  HUNG %-28s %5.1fs   (killed at the %ds deadline)"
                  % (name[5:-3], secs, DEADLINE))
            tail = (e.stdout or b"") if isinstance(e.stdout, bytes) else (e.stdout or "")
            if isinstance(tail, bytes):
                tail = tail.decode("utf-8", "replace")
            lines = str(tail).rstrip().splitlines()
            if lines:
                for line in lines[-TAIL:]:
                    print("       | " + line)
                print("       | it stopped producing output here")
            else:
                # Nothing captured is the usual case and it is worth saying why, or the
                # reader concludes the suite printed nothing rather than that its buffer
                # died with it. Run the suite directly to see where it gets to.
                print("       | no output survived: a killed process takes its unflushed")
                print("       | buffer with it. Run it on its own to watch where it stops:")
                print("       |     python redteam/%s" % name)
            continue
        secs = time.time() - t0
        if secs > slowest[0]:
            slowest = (secs, name[5:-3])
        if proc.returncode == 0:
            print("  ok   %-28s %5.1fs" % (name[5:-3], secs))
            continue
        failed.append(name)
        print("  FAIL %-28s %5.1fs" % (name[5:-3], secs))
        out = ((proc.stdout or "") + (proc.stderr or "")).rstrip().splitlines()
        for line in out[-TAIL:]:
            print("       | " + line)

    print("\n%d suite(s), %d failed, %.0fs" % (len(names), len(failed), time.time() - started))
    # Printed so the deadline stays a measured number. Somebody raising it should be able to
    # see how much headroom the slowest suite actually has, rather than doubling a guess.
    if slowest[1]:
        print("slowest: %s at %.1fs, against a %ds deadline" %
              (slowest[1], slowest[0], DEADLINE))
    if failed:
        print("failed: %s" % ", ".join(n[5:-3] for n in failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
