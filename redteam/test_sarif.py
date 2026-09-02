"""The SARIF export, checked on the thing it exists to get right.

Anyone can serialise findings into SARIF. The reason this file is long is the demotion: a
breach that cannot be told apart from a target's ordinary traffic must not arrive in somebody's
pull request as a red error, and a detector that could not fire must arrive as a notification
rather than as a silence. Both are easy to write and easy to lose, and losing either turns the
most visible surface this tool has into a confident lie.

Offline. Fixtures only, no model, no fleet, no stored evidence.
"""

import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import baseline  # noqa: E402
import sarif  # noqa: E402

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS  " + label)
    else:
        FAIL += 1
        print("FAIL  " + label + (("  " + detail) if detail else ""))


def row(aid, headline, fired, category="injection", rate="2/2"):
    return {"attack": {"id": aid, "category": category, "text": "..."},
            "headline": headline, "fired": list(fired), "rate": rate, "locks": {}}


def results(rows, **meta):
    m = {"target": "fixture", "engine": "abc1234", "attacks_n": len(rows),
         "broke": sum(1 for r in rows if r["headline"] != "DEFENDED")}
    m.update(meta)
    return {"meta": m, "results": rows}


def build(rows, ambient, config="cfg.yaml", **meta):
    """Build a SARIF log with `ambient` standing in for the benign baseline.

    The rate is injected rather than read from disk, because the whole point under test is what
    happens at 0%, at 3% and at 30%, and no fixture fleet produces those on demand.
    """
    real = baseline.rates
    baseline.rates = lambda target, out_dir=None: ambient
    try:
        # `config` is a parameter because one check needs there to be none: a finding must
        # carry no location rather than a location assembled from the target's name.
        return sarif.build(results(rows, **meta), target_config=config)
    finally:
        baseline.rates = real


def levels(log):
    out = {}
    for r in log["runs"][0]["results"]:
        out[r["level"]] = out.get(r["level"], 0) + 1
    return out


def notifications(log):
    return log["runs"][0]["invocations"][0].get("toolExecutionNotifications", [])


# --- the shape a consumer needs ---------------------------------------------------------
log = build([row("a1", "EXPLOITED", ["canary_in_output"])], {"canary_in_output": 0.0})
check("SARIF 2.1.0 with a schema, a driver and a version",
      log["version"] == "2.1.0" and log["$schema"].endswith("sarif-2.1.0.json")
      and log["runs"][0]["tool"]["driver"]["name"] == "QAtration")
one = log["runs"][0]["results"][0]
check("a finding carries a rule, a level, a message and a location",
      one["ruleId"] == "canary_in_output" and one["level"]
      and one["message"]["text"] and one["locations"][0]["physicalLocation"]
      ["artifactLocation"]["uri"] == "cfg.yaml")
# --- AND NEVER AT A FILE THAT DOES NOT EXIST ---------------------------------------------
#
# This module's comment says a made-up source location would be "a fabricated fact in the one
# field a reviewer trusts most", and the line under it made one up: `redteam/targets_<name>.yaml`
# assembled from a naming convention whenever no config was passed. On a real export that was 88
# findings anchored at a path on no disk.
_no_cfg = build([row("a1", "EXPLOITED", ["canary_in_output"])], {"canary_in_output": 0.0},
                config=None)
check("with no config to point at, a finding carries no location rather than a false one",
      _no_cfg["runs"][0]["results"][0].get("locations") == [],
      "a location was invented for a config nobody named")
check("...and the finding is still emitted, not dropped",
      len(_no_cfg["runs"][0]["results"]) == 1,
      "losing the finding is not the fix; losing the false anchor is")

_src = io.open(os.path.join(HERE, "sarif.py"), encoding="utf-8").read()
check("no path is assembled from the target's name",
      'targets_%s.yaml' not in _src,
      "a uri is still being built from a naming convention rather than found on a disk")

check("every rule referenced by a result is declared in the driver",
      {r["ruleId"] for r in log["runs"][0]["results"]}
      <= {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]})

# --- the demotion, which is the reason this file exists ---------------------------------
quiet = build([row("a1", "EXPLOITED", ["canary_in_output"])], {"canary_in_output": 0.0})
check("a breach on a detector that is silent on benign traffic is an error",
      levels(quiet) == {"error": 1}, str(levels(quiet)))

noisy = build([row("a1", "EXPLOITED", ["canary_in_output"])], {"canary_in_output": 0.30})
check("...the same breach on a detector that fires on 30% of benign traffic is NOT an error",
      levels(noisy) == {"note": 1}, str(levels(noisy)))
check("...and the message says the rate that demoted it",
      "30%" in noisy["runs"][0]["results"][0]["message"]["text"]
      and "NOT ATTRIBUTABLE" in noisy["runs"][0]["results"][0]["message"]["text"])

weak = build([row("a1", "EXPLOITED", ["canary_in_output"])], {"canary_in_output": 0.03})
check("...a small ambient rate weakens it to a warning rather than erasing it",
      levels(weak) == {"warning": 1}, str(levels(weak)))

# `None` and `{}` are different answers, and the difference is the whole of baseline.py.
never = build([row("a1", "EXPLOITED", ["canary_in_output"])], None)
check("no baseline ever run is a warning, not an error and not a clean pass",
      levels(never) == {"warning": 1}, str(levels(never)))
check("...and it says so, rather than showing a confident finding",
      "UNMEASURED" in never["runs"][0]["results"][0]["message"]["text"])
check("...and the run is flagged as unattributable as a whole",
      any("baseline" in n["descriptor"]["id"] for n in notifications(never)))

measured_silent = build([row("a1", "EXPLOITED", ["canary_in_output"])], {})
check("a baseline that was run and found nothing is the STRONGEST case, so: error",
      levels(measured_silent) == {"error": 1}, str(levels(measured_silent)))

# A row is judged on its best detector — the same rule baseline.attribution applies, asserted
# here because the export is where getting it backwards would be most expensive.
mixed = build([row("a1", "EXPLOITED", ["canary_in_output", "session_leak"])],
              {"canary_in_output": 0.30, "session_leak": 0.0})
check("one quiet detector rescues a row that also fired a noisy one",
      levels(mixed) == {"error": 1}, str(levels(mixed)))

# --- what must NOT appear ---------------------------------------------------------------
defended = build([row("a1", "DEFENDED", []), row("a2", "EXPLOITED", ["canary_in_output"])],
                 {"canary_in_output": 0.0})
check("a defended attack is not a finding",
      len(defended["runs"][0]["results"]) == 1
      and defended["runs"][0]["results"][0]["ruleId"] == "canary_in_output")

# --- inert detectors are notifications, not silence -------------------------------------
blind = build([row("a1", "DEFENDED", [])], {},
              inert={"sysprompt_paraphrase": ["system_prompt"], "bfla_call": ["privileged_tools"]})
ids = [n["descriptor"]["id"] for n in notifications(blind)]
check("a detector that could not fire is reported as a tool notification",
      "inert/sysprompt_paraphrase" in ids and "inert/bfla_call" in ids, str(ids))
check("...and says its silence is a gap rather than a defence",
      all("not a defence" in n["message"]["text"]
          for n in notifications(blind) if n["descriptor"]["id"].startswith("inert/")))

recorded_none = build([row("a1", "DEFENDED", [])], {}, inert={})
check("a run that recorded NO inert detectors says nothing about inertness",
      not [n for n in notifications(recorded_none)
           if n["descriptor"]["id"].startswith("inert/")])

# The distinction this project is named after: absent evidence is not evidence of absence.
old = build([row("a1", "DEFENDED", [])], {})
check("a result predating the inert field says it is UNKNOWN, not none",
      any(n["descriptor"]["id"] == "inert/unrecorded" for n in notifications(old)))

# --- fingerprints must survive a rerun ---------------------------------------------------
a = build([row("a1", "EXPLOITED", ["canary_in_output"])], {"canary_in_output": 0.0})
b = build([row("a1", "EXPLOITED", ["canary_in_output"], rate="3/3")], {"canary_in_output": 0.02})
check("the same attack keeps its fingerprint when its rate and level change",
      a["runs"][0]["results"][0]["partialFingerprints"]
      == b["runs"][0]["results"][0]["partialFingerprints"])
check("...and the level really did change, so the fingerprint is not just constant",
      a["runs"][0]["results"][0]["level"] != b["runs"][0]["results"][0]["level"])

# --- the file it writes is JSON a consumer can read --------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    src = os.path.join(tmp, "results_fixture.json")
    with io.open(src, "w", encoding="utf-8") as f:
        json.dump(results([row("a1", "EXPLOITED", ["canary_in_output"])]), f)
    dest = os.path.join(tmp, "out.sarif")
    argv = sys.argv
    sys.argv = ["sarif", "--results", src, "--out", dest]
    try:
        rc = sarif.main()
    finally:
        sys.argv = argv
    check("the command writes a file and exits 0", rc in (0, None) and os.path.isfile(dest))
    with io.open(dest, encoding="utf-8") as f:
        check("...and what it wrote parses as JSON", json.load(f)["version"] == "2.1.0")

    sys.argv = ["sarif", "--results", os.path.join(tmp, "nope.json")]
    try:
        check("a missing results file exits non-zero rather than writing an empty log",
              sarif.main() == 2)
    finally:
        sys.argv = argv

# --- A RUN THAT SENT NOTHING IS NOT A CLEAN SCAN --------------------------------------------
#
# Everything else here reasons from rows: an attack that errored or was skipped leaves one
# behind, and `unrun` catches it. A sweep whose arsenal came out empty leaves none, so `unrun`
# was empty, `executionSuccessful` was True, and the export was zero findings with no
# notification at all — a green code-scanning tab for a run that tried nothing. That is
# absence rendered as the best possible result, in the one artifact a CI acts on with nobody
# reading it.
#
# `workspace.verdict_for` already answers this and was never asked. Both directions are
# checked, because a rule that fails everything is as useless as one that fails nothing.
_ZERO = {"meta": {"target": "acme", "attacks_n": 0, "errors": 0, "broke": 0}, "results": []}
_ERRORED = {"meta": {"target": "acme", "attacks_n": 5, "errors": 5, "broke": 0},
            "results": [{"headline": "ERROR", "attack": {"id": "a", "category": "x"},
                         "trials": [{"error": "boom"}], "fired": []}]}
_CLEAN = {"meta": {"target": "acme", "attacks_n": 5, "errors": 0, "broke": 0},
          "results": [{"headline": "DEFENDED", "attack": {"id": "a", "category": "x"},
                       "trials": [{}], "fired": []}]}
_BROKE = {"meta": {"target": "acme", "attacks_n": 5, "errors": 0, "broke": 1},
          "results": [{"headline": "EXPLOITED", "attack": {"id": "a", "category": "x"},
                       "trials": [{}], "fired": ["canary_in_output"]}]}


def _inv(doc):
    return sarif.build(doc)["runs"][0]["invocations"][0]


def _notes(doc):
    return [n["descriptor"]["id"] for n in _inv(doc).get("toolExecutionNotifications", [])]


# --- A FINDING ANCHORED NOWHERE SAYS SO -----------------------------------------------------
#
# Without a config to point at, every finding exports with `"locations": []` and this printed
# the identical "wrote ... 20 finding(s)" line either way. On the page whose whole job is to put
# a finding next to a file, that is the quietest possible failure: a reviewer clicks a finding,
# lands nowhere, and concludes the tool is broken.
#
# Met on a first run, not imagined. `init` writes mybot.yaml in the working directory and prints
# the QATRATION_CONFIGS export that makes it findable, four lines below the canary block
# everyone is reading. Skipping it anchored 0 of 20; setting it anchored 20 of 20; the output
# was the same both times.
_UNANCHORED = {"meta": {"target": "nowhere-bot", "attacks_n": 1, "errors": 0, "broke": 1},
               "results": [{"headline": "EXPLOITED", "rate": "1/1",
                            "attack": {"id": "a", "category": "x"},
                            "fired": ["canary_in_output"], "locks": {}, "trials": [{}]}]}
_anch = sarif.build(_UNANCHORED)["runs"][0]
check("a finding with no config to anchor to is exported anyway",
      len(_anch["results"]) == 1, "the finding itself must not be dropped")
check("...and the log says why it points nowhere",
      "anchor/no-config" in [n["descriptor"]["id"]
                             for n in _anch["invocations"][0].get(
                                 "toolExecutionNotifications", [])],
      str([n["descriptor"]["id"]
           for n in _anch["invocations"][0].get("toolExecutionNotifications", [])]))
# ...and the note is absent when there IS an anchor, or it becomes furniture nobody reads.
_ok = sarif.build(_UNANCHORED, target_config="mybot.yaml")["runs"][0]
check("...and an anchored export carries no such note",
      "anchor/no-config" not in [n["descriptor"]["id"]
                                 for n in _ok["invocations"][0].get(
                                     "toolExecutionNotifications", [])]
      and all(r.get("locations") for r in _ok["results"]),
      "the note fires even when the findings are anchored")

check("a sweep that sent nothing is not a successful invocation",
      _inv(_ZERO)["executionSuccessful"] is False,
      "zero attacks exported as a clean scan")
check("...and it says so, rather than exporting an empty list in silence",
      "coverage/nothing-measured" in _notes(_ZERO), str(_notes(_ZERO)))
check("...while a run whose attacks all errored keeps its own notification",
      _inv(_ERRORED)["executionSuccessful"] is False
      and "coverage/incomplete" in _notes(_ERRORED), str(_notes(_ERRORED)))
check("a real clean run is still successful", _inv(_CLEAN)["executionSuccessful"] is True)
check("...and so is one that found a breach and reported it",
      _inv(_BROKE)["executionSuccessful"] is True)
check("...neither of which carries the nothing-measured notification",
      "coverage/nothing-measured" not in _notes(_CLEAN) + _notes(_BROKE))

print("\n%d/%d passed" % (PASS, PASS + FAIL))
if FAIL:
    sys.exit(1)
print("\nOK — findings that cannot be attributed do not arrive as errors.")
