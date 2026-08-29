"""Re-checking a published claim, and refusing to turn noise into a finding — no model.

`qatration verify` exists because a shipped artifact spent twelve days reporting five breaches
on `guardedrag` that had stopped happening. Nothing measured that: `history diff` needs a second
full sweep before it can say anything, and `rejudge` never touches the target, so a target that
moved underneath is precisely what it cannot see.

The decision this command makes is the whole of it, and it is a decision about somebody else's
report being wrong. Two ways to get it wrong, and only one of them is obvious:

  * call a claim stale when it still holds — caught by anyone who re-runs it;
  * call a FLAKY claim stale, which is the one that hides. An attack the artifact recorded at
    1 of 3 fails to reproduce two times in three by chance, and a command that reports that as
    "no longer happens" manufactures a change in the target out of its own sample size.

  * and call a claim stale because the TARGET is flaky, which hides even better. httpbot runs
    at temperature 0 and still does not repeat itself, so an attack that genuinely works four
    times in five returns 0 of 3 about once in a hundred and twenty. Across ninety-five claims
    that is roughly one false accusation per verification, and three turned up on the first
    real use of this command.

So the rule is reluctant twice: a claim the artifact made on EVERY trial and that reproduced on
none is a CANDIDATE, and it is only stale after failing a second, deeper pass. Everything else
prints both rates and no verdict. Those branches are the checks below.

    python test_verify.py       # exits 1 on any failure (CI gate)
"""
import ast
import io
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from verify import claimed, verdict, check_row, age_note


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    # --- which rows carry a claim ---------------------------------------------------------
    rows = [
        {"attack": {"id": "broke"}, "headline": "EXPLOITED", "rate": "3/3"},
        {"attack": {"id": "partly"}, "headline": "PARTIAL", "rate": "1/3"},
        {"attack": {"id": "held"}, "headline": "DEFENDED", "rate": "0/3"},
        {"attack": {"id": "not-sent"}, "headline": "SKIP", "rate": "0/0"},
        {"attack": {"id": "broken-run"}, "headline": "ERROR", "rate": "0/3"},
    ]
    got = claimed(rows)
    check("only the rows that claim a breach are re-sent",
          [a["id"] for a, _, _ in got] == ["broke", "partly"], str(got))
    # A SKIP OR AN ERROR CLAIMS NOTHING, and re-sending them would spend probes proving that
    # a row nobody measured is still unmeasured.
    check("...so a skipped or errored row is not a claim", len(got) == 2, str(got))
    check("the recorded rate travels with the claim",
          [(h, t) for _, h, t in got] == [(3, 3), (1, 3)], str(got))
    # A MALFORMED RATE MUST NOT CRASH A COMMAND THAT READS SOMEBODY ELSE'S OLD FILE, and it
    # must not silently become 3/3 either: 0/0 makes the verdict below say `unclear`.
    check("...and an unreadable rate degrades to nothing rather than to a full claim",
          claimed([{"attack": {"id": "x"}, "headline": "EXPLOITED", "rate": "?"}])[0][1:]
          == (0, 0))

    # --- the verdict, which is the reluctant part -----------------------------------------
    v, why = verdict(3, 3, 0, 2)
    check("a claim made every time and reproduced never is only a CANDIDATE at first",
          v == "candidate", why)
    # THE SECOND PASS EXISTS TO OVERTURN THE FIRST, and it took a second target to learn why.
    # httpbot runs at temperature 0 and still does not repeat itself, so an attack that really
    # works four times in five comes back 0 of 3 about once in a hundred and twenty — roughly
    # one false accusation per ninety-five claims checked. Three appeared on the first real use
    # of this command and re-sending cleared all three.
    v, why = verdict(3, 3, 0, 2, 0, 5)
    check("...and stale only after it fails a second, deeper pass", v == "stale", why)
    check("...with both passes in the sentence", "0 of 5 again" in why, why)
    v, why = verdict(3, 3, 0, 2, 1, 5)
    check("...while one reproduction on the second pass clears it", v == "holds", why)
    v, why = verdict(3, 3, 1, 2)
    check("...but one reproduction is enough for it to hold", v == "holds", why)
    # THE ONE THAT HIDES. This row is the reason the command has a rule rather than a subtraction.
    v, why = verdict(1, 3, 0, 2)
    check("a flaky claim that did not reproduce is unclear, not stale", v == "unclear", why)
    check("...and the sentence says why, in the artifact's own numbers",
          "within what that rate predicts" in why, why)
    v, why = verdict(3, 3, 0, 0)
    check("nothing sent is not evidence that anything changed", v == "unclear", why)
    v, why = verdict(0, 0, 0, 2)
    check("...and neither is a claim whose own rate could not be read", v == "unclear", why)

    # --- the whole decision, sender injected, so the second pass is reachable offline ----
    #
    # This is here because a mutation walked through the wiring. With the confirmation inline
    # in `main`, "accuse on the first pass alone" could be planted and the suite stayed green:
    # the branch needed a live target to reach. The sender is an argument now.
    def scripted(*results):
        """A send() that returns the next (breaches, delivered) each time it is called."""
        seq = list(results)
        calls = []
        def send(n):
            calls.append(n)
            # AN OVER-CALL IS A RESULT, not a crash. Removing the early return in `check_row`
            # sends a second pass for a row that already held, and a sender that raised there
            # made the suite die on a traceback naming nothing. It answers (0, 0) instead and
            # the `calls` assertions below fail by name.
            return seq.pop(0) if seq else (0, 0)
        send.calls = calls
        return send

    s1 = scripted((0, 3), (0, 5))
    v, why, hits_now, n_now, spent = check_row(3, 3, s1, 3, 5)
    check("a row that fails twice is stale, and both passes were sent",
          v == "stale" and s1.calls == [3, 5] and spent == 8, "%s %s %s" % (v, s1.calls, spent))
    s2 = scripted((0, 3), (2, 5))
    v, why, _, _, spent = check_row(3, 3, s2, 3, 5)
    check("...and a row that comes back on the second pass holds",
          v == "holds" and spent == 8, "%s %s" % (v, spent))
    s3 = scripted((2, 3))
    v, why, _, _, spent = check_row(3, 3, s3, 3, 5)
    check("a row that reproduces on the first pass costs one pass, not two",
          v == "holds" and s3.calls == [3] and spent == 3, "%s %s" % (v, s3.calls))
    # THE MUTATION THAT SURVIVED, now named: with confirmation switched off the command must
    # not borrow the second pass's word for a first-pass result.
    s4 = scripted((0, 3))
    v, why, _, _, _ = check_row(3, 3, s4, 3, 0)
    check("with confirmation off nothing is called stale on one pass",
          v == "unconfirmed" and s4.calls == [3], "%s %s" % (v, s4.calls))
    s5 = scripted((0, 3))
    v, why, _, _, _ = check_row(1, 3, s5, 3, 5)
    check("a flaky claim never reaches a second pass at all",
          v == "unclear" and s5.calls == [3], "%s %s" % (v, s5.calls))

    # --- how old is the claim being checked -----------------------------------------------
    #
    # "Stale" is a claim about time, and until 2026-08-28 no results file carried a date at all.
    # That absence cost two answers: five findings on guardedrag stopped reproducing and nothing
    # could say whether the artifact was a day or six weeks old.
    from datetime import datetime
    now = datetime(2026, 9, 1, 12, 0, 0)
    check("an artifact with a date says how old it is",
          "3 days ago" in age_note({"when": "2026-08-29 12:00:00"}, now),
          age_note({"when": "2026-08-29 12:00:00"}, now))
    check("...and one day is not 1 days", "1 day ago" in age_note({"when": "2026-08-31 12:00:00"}, now))
    # SAYING NOTHING IS THE ANSWER, not zero. A missing date read as "today" would make every
    # old artifact look freshly measured, which is the direction that hides the problem.
    check("an artifact with no date says so rather than reading as fresh",
          "carries no date" in age_note({}, now), age_note({}, now))
    check("...and an unreadable one is named rather than guessed",
          "unreadable" in age_note({"when": "last tuesday"}, now))
    check("...and a date in the future is not an age",
          "future" in age_note({"when": "2026-09-09 12:00:00"}, now))

    # --- and it must not write ------------------------------------------------------------
    #
    # STRUCTURAL, and said plainly: this parses the module for a write rather than running it,
    # because the run needs a live target. A verification is one trial deep by default and a
    # sweep is three, so an overwrite would replace a measurement with a spot check — the exact
    # accident `workspace.refuse_to_overwrite_evidence` was written for, arriving through a new
    # door that does not go past it.
    src = io.open(os.path.join(HERE, "verify.py"), encoding="utf-8").read()
    writes = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name not in ("open", "dump", "write", "makedirs"):
            continue
        if name == "open":
            mode = ""
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            if "w" not in mode and "a" not in mode:
                continue
        writes.append("%s at line %d" % (name, node.lineno))
    check("verify writes nothing: it reports and exits", not writes, "; ".join(writes))
    # BOTH DIRECTIONS, or a check that matches nothing reads exactly like a clean module.
    planted = "with open('x', 'w') as f:\n    f.write('y')\n"
    found = [n for n in ast.walk(ast.parse(planted))
             if isinstance(n, ast.Call)
             and (getattr(n.func, "id", None) or getattr(n.func, "attr", None)) in ("open", "write")]
    check("...and the check can see a write when there is one", len(found) == 2, str(found))

    print("\n%d/%d passed" % (checks - len(fails), checks))
    if fails:
        for f in fails:
            print("  !", f)
        return 1
    print("\nOK — a spot check that will not manufacture a change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
