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

So the rule is reluctant: `stale` is reserved for a claim the artifact made on EVERY trial and
that reproduced on none. Everything else prints both rates and no verdict. Those branches are
the checks below.

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

from verify import claimed, verdict


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
    check("a claim made every time and reproduced never is stale", v == "stale", why)
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
