"""Run the offline suites. One command for a person and for CI, so they cannot diverge.

Every `redteam/test_*.py` is a standalone script that exits non-zero on failure — no pytest, no
plugins, no collection rules, and nothing between a failing assertion and a red exit code. That
is worth keeping, but it left "run the tests" as a shell loop that everyone rewrote slightly
differently, and a CI whose loop differs from the one a developer runs is a CI that tests
something else.

    python tools/check.py                    # everything
    python tools/check.py oracle benign      # just those (prefix match, no test_ needed)
    python tools/check.py --list

A NAMED SUBSET IS NOT ENOUGH WHEN YOU ADD OR REMOVE A CHECK. The README publishes how many
assertions this suite carries and `readme` recounts it, so any commit that changes the number
of checks -- in any file -- turns that suite red. Run `readme` alongside whatever you touched,
or run everything. This is written here because it was learned the other way: a commit that
added five checks to `test_onboard` passed its own suites and failed CI on all four platforms.

Every suite here is offline: no model, no network, no practice fleet. That is the property that
lets this run on a runner with no GPU, and it is asserted rather than assumed — a suite that
starts needing a fleet will fail here first, which is the right place to find out.
"""

import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SUITES = os.path.join(ROOT, "redteam")

# HOW A SUITE SAYS WHAT IT RAN, in every form the suites here actually use. Derived from
# them rather than imposed, by running all fifty-one and reading what came out:
#
#   `61/61 passed`                  forty-eight of them, sometimes behind a prefix --
#                                   `oracle tests: 843/843 passed · 66/66 detectors`
#   `packaging: 24 checks`          announced before the functions it found by name run
#   the `PASS ` lines themselves    `unguarded` prints those and no summary at all
#
# THE LAST ONE IS WHY THIS RETURNS A NUMBER RATHER THAN None. A suite that prints neither
# a summary nor a single per-check line has reported ZERO, and zero is the answer: output
# nobody can count is indistinguishable from a run that did nothing, which is the sentence
# the `0/0 passed` literal already carried for one of the three forms.
_COUNT_FORMS = (
    re.compile(r"(\d+)\s*/\s*\d+\s+passed\b"),
    re.compile(r"^\s*[A-Za-z_][A-Za-z_0-9]*:\s*(\d+)\s+checks?\b"),
)


def checks_reported(text):
    """-> how many checks a suite says it ran. Zero means it said nothing countable."""
    lines = text.splitlines()
    # THE PER-CHECK LINES ARE A COUNT IN THEMSELVES, and for `unguarded` they are the only
    # one it prints. Counted here rather than noticed in the loop below and counted again
    # underneath it, which is how a first version of this had the same rule twice and a
    # mutation of either half changed no answer.
    best = sum(1 for l in lines if l.startswith("PASS") or l.startswith("FAIL"))
    for line in lines:
        for pat in _COUNT_FORMS:
            m = pat.search(line)
            if m:
                best = max(best, int(m.group(1)))
    return best


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

# And how long a suite that was killed may take to hand over what it printed. A dead process
# hands its buffer over at once; this is the ceiling on waiting for one that cannot.
DRAIN = int(os.environ.get("QATRATION_DRAIN_TIMEOUT", "20"))


def kill_tree(proc):
    """Kill the suite AND whatever it started, because the deadline is worthless otherwise.

    `subprocess.run(capture_output=True, timeout=N)` kills the suite at N and then reads its
    pipes to end-of-file. The suite is dead and holds nothing, but a SERVER it started inherited
    the same pipe and is still alive, so end-of-file never comes and the call blocks. Measured
    here rather than reasoned about: with a five-second deadline it had not returned after two
    minutes. The job then dies at the workflow's `timeout-minutes: 30` and reports "cancelled",
    naming no suite -- exactly the outcome this deadline exists to prevent, in exactly the case
    it was written for. Several suites bind sockets and start servers, so that is the likely
    shape of a hang here rather than an exotic one.
    """
    if os.name == "nt":
        # The only tree-kill Windows offers without a dependency.
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.kill()
    except OSError:
        pass


OFFLINE = os.path.join(HERE, "_offline")


def child_env():
    """The environment a suite runs in, with the offline rule armed.

    The docstring at the top of this file says these suites are offline "asserted rather than
    assumed". It was assumed. `_offline/sitecustomize.py` is imported by every child on
    startup because this puts its directory on PYTHONPATH, and it refuses a connection to
    anywhere but this machine — loopback stays open, because nine suites drive their own HTTP
    server on 127.0.0.1 and blocking those would delete the checks rather than the dependency.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = OFFLINE + os.pathsep + env.get("PYTHONPATH", "")
    return env


def run_suite(path):
    """-> (returncode, output, hung, orphaned). returncode is None when it had to be killed."""
    # Its own process group, so one signal reaches everything it started. The cost is that
    # Ctrl-C no longer reaches the suite on its own, which is why the interrupt is caught here
    # and turned into the same tree kill.
    opts = {} if os.name == "nt" else {"start_new_session": True}
    # UTF-8, SAID RATHER THAN INHERITED. `text=True` alone decodes with whatever
    # `locale.getpreferredencoding` returns on the machine, and every suite here writes UTF-8
    # -- each one opens with `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`.
    # The two agree wherever the machine's locale already is UTF-8, and they do not on
    # the Windows CI runner: `test_payload` prints a fullwidth prompt whose UTF-8 contains
    # byte 0x81, which cp1252 has no character for. What reached this process there was not
    # what the suite printed, and the line it needed -- `31/31 passed` -- was not in it, so
    # the suite that ran thirty-one checks was reported as one that ran none.
    #
    # `errors="replace"` for the same reason the suites use it: a byte this cannot render is
    # a reason to show a placeholder, never a reason to lose the output around it.
    proc = subprocess.Popen([sys.executable, path], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", cwd=ROOT, env=child_env(), **opts)
    try:
        out, err = proc.communicate(timeout=DEADLINE)
        return proc.returncode, (out or "") + (err or ""), False, False
    except subprocess.TimeoutExpired:
        pass
    except KeyboardInterrupt:
        kill_tree(proc)
        raise
    kill_tree(proc)
    try:
        out, err = proc.communicate(timeout=DRAIN)
        return None, (out or "") + (err or ""), True, False
    except subprocess.TimeoutExpired:
        # ABANDONED RATHER THAN CLOSED. A reader thread is still blocked on that pipe and
        # closing it underneath that thread is not safe. They are daemon threads and go when
        # this process does; the tree is already dead, so nothing is left running.
        return None, "", True, True


def skipped(text):
    """-> the SKIP lines a suite printed, so a green run still says what it did not check.

    A convention rather than a mechanism: a suite that steps over something prints a line
    beginning with SKIP and explains itself. This surfaces those lines and nothing else,
    because a passing suite's ordinary output is noise and its refusals are not.
    """
    return [ln.rstrip() for ln in text.splitlines() if ln.strip().startswith("SKIP")]


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


def refuse_if_empty(names):
    """The same rule as above, for the case it did not cover: NO suites at all.

    The refusal beside `unmatched` is written against a typo in an argument. Run with no
    arguments in a tree where the suites are not where this expects them -- a renamed
    directory, an sdist built without them, a checkout half-done -- and `names` comes back
    empty, the loop runs zero times, and this printed "0 suite(s), 0 failed" and exited 0.

    That is a green build that ran nothing, produced by the command every other check in this
    repository is run through, and it is the failure the file's own comment four lines up
    names. One rule; it was implemented once and needed twice.
    """
    if not names:
        print("no suites found in %s — nothing was run, and nothing is not a pass.\n"
              "  This directory should hold the `test_*.py` files. If the tree moved, say\n"
              "  where: python tools/check.py --list" % SUITES, file=sys.stderr)
        raise SystemExit(2)
    return names


def main(argv):
    if "--list" in argv:
        for n in refuse_if_empty(suites([])):
            print("  " + n[5:-3])
        return 0

    names = refuse_if_empty(suites([a for a in argv if not a.startswith("-")]))
    started = time.time()
    failed = []

    slowest = (0.0, "")
    for name in names:
        t0 = time.time()
        rc, text, hung, orphaned = run_suite(os.path.join(SUITES, name))
        if hung:
            # A HANG IS A RESULT AND IT HAS A NAME. Without this the run blocks until the CI
            # job's own limit and reports as "cancelled", which names no suite.
            failed.append(name)
            print("  HUNG %-28s %5.1fs   (killed at the %ds deadline)"
                  % (name[5:-3], time.time() - t0, DEADLINE))
            if orphaned:
                # WORTH ITS OWN LINE: it says the suite leaked a process, which is a second
                # defect and the reason the deadline used to be unable to fire at all.
                print("       | it left something running that held the output pipe open, so")
                print("       | nothing it printed survived. The whole tree has been killed.")
            lines = text.rstrip().splitlines()
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
        # A SUITE THAT PRINTS FAILURES AND EXITS 0 IS NOT A PASS. The exit code was the
        # only signal, and `capture_output=True` discards the output on success, so
        # nobody would ever see it. Every suite here exits correctly today; nothing made
        # that true of the next one.
        lied = [ln for ln in text.splitlines() if ln.strip().startswith("FAIL")]
        # AND A SUITE THAT RAN NOTHING IS NOT A PASS EITHER, which this asked as a literal:
        # `0/0 passed`. Fifty of the fifty-one suites end that way and one does not --
        # `packaging` prints `packaging: 24 checks` and runs twenty-four functions it finds
        # by name. Measured by breaking that name: the list came back empty, the suite
        # printed `packaging: 0 checks` and `all packaging checks passed`, exited 0, and
        # this runner said `ok packaging 0.1s` against a normal 110 seconds. The rule was
        # right and the SET it read was one output format wide.
        if rc == 0 and checks_reported(text) == 0:
            lied.append("it reported 0 checks: a run that did nothing reads exactly like "
                        "a run that did everything, so this is not a pass")
            # AND WHAT IT DID SAY, because `it reported 0` is a verdict and not evidence.
            # The first time this fired on CI it named the suite and nothing else, and the
            # cause was in the output nobody was shown: the runner had mangled it reading
            # UTF-8 as cp1252. A reader of a failed build should not have to guess that.
            _tail = [l.rstrip() for l in text.splitlines() if l.strip()][-3:]
            lied += ["    it printed: " + l[:120] for l in _tail] or \
                    ["    it printed nothing at all"]
        if rc == 0 and not lied:
            print("  ok   %-28s %5.1fs" % (name[5:-3], secs))
            # AND WHAT IT DID NOT CHECK. Output from a passing suite is discarded, so a suite
            # that skipped half of itself and passed the rest reported exactly like one that
            # ran everything. Several suites here skip on purpose -- no shell on this machine,
            # no interpreter by that name -- and they say so, into a buffer nobody reads.
            #
            # Found by asking whether the Windows leg had really run a launcher check or
            # quietly stepped over it. The answer took a stopwatch and a local comparison to
            # infer, which is the wrong way to learn what a green build covered.
            for line in skipped(text):
                print("       | " + line)
            continue
        if rc == 0:
            failed.append(name)
            # THE CAUSE, NOT ONE OF THE TWO. A suite can exit 0 while printing failures and
            # a suite can exit 0 having run nothing, and a reader who sees the wrong sentence
            # goes looking in the wrong place.
            print("  LIED %-28s %5.1fs  exited 0 %s"
                  % (name[5:-3], secs,
                     "while reporting failures"
                     if any(l.strip().startswith("FAIL") for l in lied)
                     else "without running what it claims to"))
            for line in lied[:TAIL]:
                print("       | " + line)
            continue
        failed.append(name)
        print("  FAIL %-28s %5.1fs" % (name[5:-3], secs))
        out = text.rstrip().splitlines()
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
