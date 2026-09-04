"""Stored results as SARIF 2.1.0, so findings land in a code-scanning tab instead of a console.

A security tool that cannot fail a build is not in anybody's pipeline, and one that fails it
with an exit code alone makes every engineer open a log to find out why. SARIF is what GitHub,
GitLab and the rest already read: upload it and each finding appears on the pull request, with
its rule, its severity and its explanation, next to whatever else scans that repository.

    qatration sarif --results out/results_mybot.json --out qatration.sarif

TWO THINGS THIS FILE SAYS THAT A PLAIN DUMP DOES NOT, and they are the reason it is worth
more than thirty lines:

**An unattributable breach is not reported as an error.** A detector that fires on a fifth of
ordinary traffic has not demonstrated anything when it fires under attack, and `baseline.py`
already knows which those are. Emitting them at `error` would be the most flattering possible
lie in the most visible possible place — a red mark on somebody's pull request that a day of
work cannot reproduce. They come out at `note`, carrying the ambient rate that demoted them.

**A detector that could not fire is a tool notification, not a silence.** SARIF has a place for
"the tool could not complete a check", and that is precisely what an inert detector is. Without
it a run with eleven blind detectors and no findings renders as a clean scan, which is this
project's own defect class arriving in someone else's dashboard.

Levels, and why they are not the obvious mapping:

    EXPLOITED, attributed      error       a demonstrated breach nobody can explain away
    EXPLOITED, weakened        warning     real, but a detector that also fires on benign traffic
    EXPLOITED, unattributable  note        cannot be told apart from this target's noise floor
    EXPLOITED, unmeasured      warning     no baseline was ever run; the honest answer is unknown
    PARTIAL                    warning     something moved, short of the full objective
    DEFENDED                   (omitted)   SARIF results are findings, not a transcript
"""

import json
import os
import re

import yaml

import baseline
import runs
import workspace
from target import target_configs

# Qualifiers this export does not carry, and why. See `workspace.QUALIFIERS`.
QUALIFIERS_NOT_CARRIED = {
    "arsenal": "SARIF describes one run; there is no second run in it to be comparable with",
    "trials": "the rate rides on each finding's message rather than the invocation summary",
    "when": "the consumer stamps its own upload time, and a second date invites the wrong one",
    "run_id": "the id itself is noise in a code-scanning tab, which has no way to open a run "
              "record -- but the record's ENDING is read, and an unfinished run makes the "
              "invocation unsuccessful. The exemption was right about the field and was "
              "quietly covering not asking the question",
}


SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/qatration/qatration"

# headline -> level before attribution is considered.
BASE_LEVEL = {"EXPLOITED": "error", "PARTIAL": "warning"}

# attribution verdict -> the level it may not exceed. `attributed` caps at nothing.
CEILING = {"unattributable": "note", "weakened": "warning", "unmeasured": "warning"}

_ORDER = {"none": 0, "note": 1, "warning": 2, "error": 3}


def _cap(level, verdict):
    ceiling = CEILING.get(verdict)
    if ceiling and _ORDER[ceiling] < _ORDER[level]:
        return ceiling
    return level


def _detector_help(name):
    """The first line of a detector's docstring, or nothing.

    Read from the live oracle rather than from a table kept beside it, because a table would be
    a second description to drift out of step with the code — and a rule help text that
    describes a detector's old behaviour is worse than one that describes none.
    """
    try:
        import oracle
        fn = oracle.DETECTORS.get(name)
        doc = (fn.__doc__ or "").strip() if fn else ""
        return doc.splitlines()[0].strip() if doc else ""
    except Exception:
        return ""


def _uri(path):
    r"""A path as SARIF wants it: forward slashes, and absolute ones as a `file:` URI.

    `--target-config C:\Users\me\mybot.yaml` was emitted verbatim, and a backslash is not a
    separator in a URI reference (SARIF 2.1.0 3.4.3) — so the one field a code-scanning UI uses
    to take a reviewer to the thing that failed silently pointed nowhere. The natural Windows
    invocation produced it, and a POSIX-only helper misses exactly that case.
    """
    text = str(path).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", text):
        return "file:///" + text
    if text.startswith("/"):
        return "file://" + text
    return text


def _message(row, verdict, noisy):
    a = row.get("attack") or {}
    parts = ["%s: %s (%s)" % (row.get("headline", "?"),
                              a.get("id", "?"), a.get("category", "uncategorised"))]
    if row.get("rate"):
        parts.append("fired on %s trials" % row["rate"])
    if row.get("fired"):
        parts.append("detectors: %s" % ", ".join(row["fired"]))
    if verdict == "unattributable":
        parts.append("NOT ATTRIBUTABLE — %s of this target's own ordinary traffic, so this "
                     "breach cannot be told apart from its noise floor"
                     % ", ".join("%s fires on %.0f%%" % (d, r * 100) for d, r in noisy))
    elif verdict == "weakened":
        parts.append("attribution weakened — %s"
                     % ", ".join("%s fires on %.0f%% of benign traffic" % (d, r * 100)
                                 for d, r in noisy))
    elif verdict == "unmeasured":
        parts.append("attribution UNMEASURED — no benign baseline exists for this target, so "
                     "nothing here rules out an ambient false positive")
    return " · ".join(parts)


def build(results, target_config=None, out_dir=None):
    """A SARIF log for one results file. `results` is the parsed JSON, not a path."""
    meta = results.get("meta") or {}
    rows = results.get("results") or []
    target = meta.get("target") or "target"

    # Where the finding is anchored. SARIF wants a file, and the honest file is the config that
    # describes the thing under test — not a source line, because no line of the operator's
    # code is what failed. Anchoring at a made-up source location would be a fabricated fact in
    # the one field a reviewer trusts most.
    #
    # AND THE LINE BELOW USED TO DO EXACTLY THAT. Without `--target-config` it emitted
    # `redteam/targets_<name>.yaml`, a path assembled from a naming convention rather than
    # found on a disk. Measured on an export from a config `qatration init` wrote: 88 findings,
    # every one anchored at a file that exists nowhere. A reviewer who follows a wrong link
    # concludes the tool is broken; one who finds no link goes and looks.
    #
    # So: the named config, else a config of that name that actually exists — `target_configs`
    # reads QATRATION_CONFIGS, so one kept outside this package resolves too — else nothing.
    def _config_for(name):
        for fp in target_configs():
            try:
                cfg = yaml.safe_load(open(fp, encoding="utf-8")) or {}
            except Exception:
                continue
            # THROUGH `workspace.config_name`, which is where this rule lives. Comparing
            # `cfg["name"]` alone meant the eleven shipped configs that omit the key could
            # never match, so every finding for those targets exported with no location at
            # all - 95 of 95 on httpbot - while the comment above says the fallback exists
            # precisely so a reviewer gets a file that is really there.
            if workspace.config_name(fp, cfg) == name:
                return fp
        return None

    anchor = target_config or _config_for(target)
    uri = _uri(anchor) if anchor else None
    # AND IF THERE IS NO CONFIG TO POINT AT, SAY SO. Without one every finding exports with
    # `"locations": []`, and this printed the same "wrote ... 20 finding(s)" line either way.
    # A reader uploading that to code scanning gets twenty findings anchored nowhere and no
    # hint why, which on a page whose whole job is to put a finding next to a file is the
    # quietest possible failure.
    #
    # Met on a first run: `init` writes mybot.yaml in the working directory and prints the
    # `QATRATION_CONFIGS` export needed to make it findable. Skip that line -- it is four
    # lines below the canary block everyone is reading -- and `sarif` anchors 0 of 20. With
    # the variable set, 20 of 20. The difference was invisible in the output.
    unanchored_note = None
    if not uri:
        unanchored_note = (
            "No config was found for %s, so every finding below is exported without a "
            "location. Pass --target-config, or point QATRATION_CONFIGS at the file "
            "`qatration init` wrote. The findings are real; only the anchor is missing."
            % target)

    ambient = baseline.rates(target, out_dir=out_dir or workspace.OUT)

    rules, seen, sarif_results = [], set(), []
    unrun = []
    for row in rows:
        head = row.get("headline", "")
        # AN ATTACK THAT NEVER RAN IS NOT A DEFENDED ATTACK. `ERROR` and `SKIP` used to fall
        # through the same `continue` as `DEFENDED`, so a run that exhausted its request budget
        # a third of the way through — 285 attacks at 3 trials is 855 requests against a
        # `max_requests: 400` config — exported the handful that got sent and rendered as a
        # complete, clean scan. This module's whole argument is that a detector which could not
        # fire is a notification rather than a silence; an attack that was never sent is the
        # same claim one level up, and it was the one place the argument was not applied.
        # `workspace.NOT_MEASURED`, not a literal of the same two names. The set is decided
        # in one place -- it grew from ("ERROR",) to ("SKIP", "ERROR") once already, because
        # an attack that was never delivered reads as one that held -- and a second copy here
        # would keep the older answer without anything noticing.
        if head in workspace.NOT_MEASURED:
            unrun.append(row)
            continue
        level = BASE_LEVEL.get(head)
        if not level:                       # DEFENDED, and anything the engine may add later
            continue
        verdict, noisy = baseline.attribution(row.get("fired"), ambient)
        level = _cap(level, verdict)

        fired = row.get("fired") or []
        rule_id = fired[0] if fired else "breach"
        if rule_id not in seen:
            seen.add(rule_id)
            rule = {"id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": "QAtration detector: %s" % rule_id},
                    "defaultConfiguration": {"level": "error"}}
            helptext = _detector_help(rule_id)
            if helptext:
                rule["fullDescription"] = {"text": helptext}
            rules.append(rule)

        attack = row.get("attack") or {}
        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": _message(row, verdict, noisy)},
            # NO LOCATION RATHER THAN A FALSE ONE. SARIF 2.1.0 allows a result with no
            # physical location, and that is the honest shape when the config this run was
            # pointed at cannot be found from here.
            "locations": ([{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 1}}}] if uri else []),
            # Stable across runs so a code-scanning tab can tell a finding that persists from
            # one that is new. Keyed on the attack rather than on the message, because the
            # message carries rates that move between runs and a fingerprint that moves with
            # them would report every finding as new on every run.
            "partialFingerprints": {
                "qatration/v1": "%s:%s:%s" % (target, attack.get("id", "?"), rule_id)},
            "properties": {"attribution": verdict,
                           "headline": head,
                           "category": attack.get("category", ""),
                           "trials": row.get("rate", "")},
        })

    # What the run could not measure. SARIF's own concept for "a check did not complete", which
    # is exactly what an inert detector is — and the alternative, leaving it out, renders a
    # blind run as a clean one.
    notifications = []
    inert = meta.get("inert")
    # THREE STATES, NOT TWO. A dict with entries names the blind detectors; an EMPTY dict says
    # the run looked and found none; absent — or an explicit null — says nobody ever looked.
    # The first version tested `if inert:` then `elif "inert" not in meta:`, so a stored null
    # fell through both and emitted nothing at all, which reads exactly like the empty-dict
    # case. That is the distinction this whole block exists to draw, lost to a falsy value.
    if unanchored_note:
        notifications.append({
            "level": "warning",
            "message": {"text": unanchored_note},
            "descriptor": {"id": "anchor/no-config"}})
    if inert is None:
        notifications.append({
            "level": "note",
            "message": {"text": "This result predates inert-detector recording, so whether any "
                                "detector was unable to fire is unknown for this run — not "
                                "known to be none."},
            "descriptor": {"id": "inert/unrecorded"}})
    elif inert:
        for name, keys in sorted(inert.items()):
            notifications.append({
                "level": "warning",
                "message": {"text": "%s could not fire on this target: missing %s. Its silence "
                                    "is a gap, not a defence." % (name, ", ".join(keys))},
                "descriptor": {"id": "inert/%s" % name}})

    # `ambient is None` ALONE. This used to also require `meta["baseline"] is None`, on the
    # assumption that the key held the benign baseline. It does not — `run_redteam` writes
    # `ctx["baseline_tool_inputs"]` there, the clean tool-call arguments learned from a probe.
    # So any target reporting tool calls had a non-None value, the conjunct was False, and the
    # one run-level statement that NOTHING in the log can be attributed was suppressed on 23 of
    # the 40 stored runs — silenced precisely where the target is richest and the finding
    # heaviest. Two different things named "baseline", and the wrong one was consulted.
    if ambient is None:
        notifications.append({
            "level": "warning",
            "message": {"text": "No benign baseline exists for %s, so no finding here can be "
                                "attributed: an ambient false positive and a breach look the "
                                "same. Run `qatration benign` against it." % target},
            "descriptor": {"id": "baseline/missing"}})

    # Attacks that were sent and errored, or were never sent at all. Reported as a run-level
    # notification AND as an unsuccessful invocation, because a reader who sees a short list of
    # findings has no other way to learn that the list is short because the run stopped.
    skipped = meta.get("skipped") or 0
    if unrun or skipped:
        reasons = {}
        for row in unrun:
            for t in row.get("trials") or []:
                err = str((t or {}).get("error") or "").split(":")[0].strip()
                if err:
                    reasons[err] = reasons.get(err, 0) + 1
        detail = ("; ".join("%s x%d" % (k, v) for k, v in sorted(reasons.items()))
                  or "no error recorded")
        parts = []
        if unrun:
            parts.append("%d attack(s) produced no measurement (%s)" % (len(unrun), detail))
        if skipped:
            # "SCOPED OUT OR UNMEASURABLE" NAMED BOTH CAUSES AND SEPARATED NEITHER, which is
            # as far as one counter could go. The run records them apart now, and a reader in
            # a code-scanning tab can act on the difference: one is a config to extend, the
            # other is a flag to drop.
            _na, _ns = meta.get("not_applicable"), meta.get("not_sent")
            if isinstance(_na, int) and isinstance(_ns, int) and _ns:
                parts.append("%d attack(s) were never sent: %d not applicable to this target, "
                             "%d held back by the scope this run was given"
                             % (skipped, _na, _ns))
            else:
                parts.append("%d attack(s) were never sent (scoped out or unmeasurable on "
                             "this target)" % skipped)
        notifications.append({
            "level": "error" if unrun else "warning",
            "message": {"text": ". ".join(parts) + ". These are gaps in coverage, not clean "
                                "results: nothing below rules out a breach among them."},
            "descriptor": {"id": "coverage/incomplete"}})

    # AND A RUN THAT SENT NOTHING AT ALL, which has no rows to be `unrun`. Everything above
    # reasons from rows: an attack that errored or was skipped leaves one behind and is caught.
    # A sweep whose arsenal came out empty — scoped to nothing, filtered to nothing, or stopped
    # before its first send — leaves none, so `unrun` was empty, `executionSuccessful` was True
    # and the export was zero findings, no notification, a green code-scanning tab. Absence
    # rendered as the best possible result, in the one artifact a CI acts on without a human
    # reading it.
    #
    # `workspace.verdict_for` already owns this rule and says "Not measured" for it, in the
    # words of its own docstring: zero breaches out of zero attacks is not a defence. It was
    # never consulted here; `meta["attacks_n"]` was read only to fill in `properties`.
    unmeasured = workspace.verdict_for(meta) == "Not measured"
    if unmeasured and not (unrun or skipped):
        notifications.append({
            "level": "error",
            "message": {"text": "This run measured nothing: %s attack(s) were sent against %s. "
                                "There are no findings below because nothing was tried, which "
                                "is not the same as nothing being found."
                                % (meta.get("attacks_n") or 0, target)},
            "descriptor": {"id": "coverage/nothing-measured"}})

    # AND WHETHER THE RUN FINISHED AT ALL, which this never asked. Everything above reasons
    # from ROWS: an attack that errored leaves one behind. A run stopped by its BUDGET does
    # not -- `run_redteam` writes the results file and then closes the record as "stopped",
    # noting that the remaining attacks were never sent -- so a truncated sweep with no
    # errored row exported `executionSuccessful: true`. Measured: a record saying `stopped`,
    # 350 attacks never sent, one finding, and the field a code-scanning tab reads to decide
    # whether the analysis completed said it had.
    #
    # `docs/ci.md` promises the opposite in as many words, and so does the comment forty lines
    # up in this file. Neither was the code.
    #
    # NONE IS NOT NO. `record_for` returns None for an artifact written before run records
    # existed, and "cannot say" is not "it did not finish" -- flipping on None would mark
    # every one of those unsuccessful. Only a record that exists and does not say `finished`.
    _rec = runs.record_for(meta, out_dir or workspace.OUT)
    _unfinished = bool(_rec) and _rec.get("state") != "finished"
    if _unfinished:
        notifications.append({
            "level": "error",
            "message": {"text": (runs.unfinished_note(meta, out_dir or workspace.OUT)
                                 or "the run behind this evidence did not finish")
                        + ". The findings below are what it reached, not what it looked for."},
            "descriptor": {"id": "run/unfinished"}})

    invocation = {"executionSuccessful": not unrun and not unmeasured and not _unfinished}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "QAtration",
                                "informationUri": INFO_URI,
                                "version": meta.get("engine") or "unknown",
                                "rules": rules}},
            "results": sarif_results,
            "invocations": [invocation],
            "properties": {"target": target,
                           "attacks": meta.get("attacks_n"),
                           "breached": meta.get("broke")},
        }],
    }


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Convert stored QAtration results into SARIF 2.1.0 for code scanning.")
    ap.add_argument("--results", required=True,
                    help="a results_<target>.json written by `qatration run`")
    ap.add_argument("--out", default=None,
                    help="where to write the SARIF (default: beside the results file)")
    ap.add_argument("--target-config", default=None,
                    help="the config the findings are anchored to, for the code-scanning UI")
    args = ap.parse_args()

    if not os.path.isfile(args.results):
        print("no such results file: %s" % args.results)
        return 2
    # A REFUSAL, NOT A TRACEBACK. This file is named on the command line, so unlike the tools
    # that scan the whole directory there is nothing to carry on with — but a decode error out
    # of the json module tells a CI operator nothing about what to do, and an empty or missing
    # SARIF upload reads to a code-scanning dashboard as a clean scan. Truncation is what an
    # interrupted write leaves, which is the state a stopped sweep is in.
    from workspace import read_artifact
    results, why = read_artifact(args.results)
    if why:
        print("%s could not be read (%s). Nothing was exported: an absent SARIF upload reads "
              "as a clean scan, so this fails rather than producing one." % (args.results, why))
        return 2

    log = build(results, target_config=args.target_config,
                out_dir=os.path.dirname(os.path.abspath(args.results)))
    dest = args.out or os.path.splitext(args.results)[0] + ".sarif"
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    run = log["runs"][0]
    levels = {}
    for r in run["results"]:
        levels[r["level"]] = levels.get(r["level"], 0) + 1
    notes = len(run["invocations"][0].get("toolExecutionNotifications", []))
    print("wrote %s — %d finding(s)%s%s" % (
        dest, len(run["results"]),
        (" [" + ", ".join("%d %s" % (n, l) for l, n in sorted(levels.items())) + "]")
        if levels else "",
        ", %d notification(s) about what could not be measured" % notes if notes else ""))
    # ON STDOUT AS WELL AS IN THE FILE, because the person running this command is not the
    # person who opens the SARIF. A CI step writes it and uploads it; the anchor being missing
    # is discovered days later by a reviewer clicking a finding that goes nowhere, if at all.
    # This line is the only chance to catch it while somebody is still looking at a terminal.
    if not any(r.get("locations") for r in run["results"]) and run["results"]:
        print("  ! every finding above is anchored to no file. Pass --target-config, or point "
              "QATRATION_CONFIGS\n    at the config `qatration init` wrote, and re-run: the "
              "findings are the same, the link is not.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
