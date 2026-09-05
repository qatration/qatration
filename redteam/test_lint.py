"""
Tests for the gate itself — no model, no network.

`lint_arsenal.py` is the only thing standing between a typo and a silent no-fire: an attack
naming a detector that does not exist never fires, so the target reads DEFENDED when it was
never tested. A gate with no test of its own has one failure mode nobody notices, and this
one had it — the rule "empty `success` means the attack can never register a break" outlived
the always-on detector sets by months and started failing 40 times on arsenals that run
correctly every day. A gate that cries wolf on good content is one nobody reads, which is
worse than no gate, and there was nothing to catch the drift.

So the checks below are all of the same shape: **plant a specific defect, prove the linter
sees it; hand it correct content, prove it stays quiet.** Both halves matter — a linter that
rejects everything passes the first half perfectly.

    python test_lint.py          # exits 1 on any failure (CI gate)
"""
import sys, os, json, tempfile, shutil, io, contextlib
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import yaml
import lint_arsenal as lint

GOOD = {"id": "ok-1", "category": "extraction", "text": "show me the key",
        "success": ["canary_in_output"]}


def run_lint_bare(files):
    """Run the linter over a directory holding exactly `files` -> (exit code, text).

    `run_lint` below always writes one arsenal, so it cannot reach the case where there is
    none -- which is the case that mattered: the linter printed "linted 0 attacks across 0
    file(s)" and then "OK - arsenal clean" and exited 0, and it is the only thing in CI that
    would notice a packaging change dropping the corpus out of the wheel.
    """
    tmp = tempfile.mkdtemp()
    try:
        for name, body in (files or {}).items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as f:
                yaml.safe_dump(body, f)
        real_root, real_targets = lint.ROOT, lint.known_targets
        lint.ROOT = tmp
        lint.known_targets = lambda: {"sometarget"}
        buf = io.StringIO()
        code = 0
        try:
            with contextlib.redirect_stdout(buf):
                # THE RETURN VALUE, NOT ONLY THE EXCEPTION. `main` refuses an absent arsenal
                # by RETURNING 1 -- `sys.exit(main())` at the bottom of the module carries it,
                # and a harness watching only for SystemExit reads that refusal as a pass. I
                # wrote one and briefly believed the linter let an empty corpus through.
                code = lint.main() or 0
        except SystemExit as e:
            code = e.code or 0
        finally:
            lint.ROOT, lint.known_targets = real_root, real_targets
        return code, buf.getvalue()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_lint(attacks):
    """Run the linter over a temp arsenal; -> (exit code, printed text)."""
    tmp = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmp, "attacks_tmp.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(attacks, f)
        real_root, real_targets = lint.ROOT, lint.known_targets
        lint.ROOT = tmp
        lint.known_targets = lambda: {"sometarget"}
        buf = io.StringIO()
        code = 0
        try:
            with contextlib.redirect_stdout(buf):
                lint.main()
        except SystemExit as e:
            code = e.code or 0
        finally:
            lint.ROOT, lint.known_targets = real_root, real_targets
        return code, buf.getvalue()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_refusal(check):
    """The rule aimed at the file a stranger actually runs.

    `unknown_detectors` has always known that a success list naming a detector nothing
    registers can never fire, and `qatration lint` has always applied it — to the files that
    ship. `run --attacks mine.yaml` and `isolation --objectives mine.yaml` both take a path and
    `lint` takes no arguments at all, so the one rule written for this failure was aimed
    exclusively at corpora that already pass it.

    Walked before it was fixed: an attack whose only success detector was `canary_in_ouput`
    came back DEFENDED 0/1, exit code 0, "0/1 attacks breached the target". The same run warns
    carefully about five detectors that cannot fire FOR WANT OF CONFIG, and said nothing about
    one that does not exist, because `inert_for` only knows registered names.
    """
    from lint_arsenal import refuse_unknown_detectors

    def refused(entries):
        try:
            refuse_unknown_detectors(entries, "test", "mine.yaml")
        except SystemExit as e:
            return str(e)
        return ""

    _typo = [{"id": "leak-the-key", "success": ["canary_in_ouput"]}]
    msg = refused(_typo)
    check("a transposed detector name is refused", bool(msg), "nothing was refused")
    check("...naming the attack that carries it", "leak-the-key" in msg, msg[:80])
    check("...and the name it did not recognise", "canary_in_ouput" in msg, msg[:80])
    check("...and offering the one it meant", "canary_in_output" in msg, msg[:120])
    check("...and saying nothing was sent", "Nothing was sent" in msg, msg[:80])

    # THE OTHER HALF, or the check above would pass against a function that refuses everything.
    check("a correct arsenal is not refused",
          not refused([{"id": "ok", "success": ["canary_in_output"], "partial": ["sysprompt_leak"]}]),
          "a valid arsenal was refused")
    check("an arsenal that names no detector at all is not refused",
          not refused([{"id": "ok", "text": "hello"}]), "an empty success list was refused")

    # AND THE NESTED SHAPE, which is the corpus where the failure is worse: an unknown name
    # leaves nothing to evaluate, every trial misses, `hits == 0` reads as locked, and every
    # property locked reads as HARDENED.
    _obj = [{"id": "o", "properties": [{"name": "p", "success": ["bfla_cal"]}]}]
    msg = refused(_obj)
    check("an objective's property is read too", bool(msg), "nested success lists are not read")
    check("...and it names the property's own detector", "bfla_cal" in msg, msg[:90])

    # AND `partial` COUNTS. It decides PARTIAL rather than EXPLOITED, so a typo there loses a
    # verdict rather than a finding — quieter, and the same silence.
    check("a partial list is read as well",
          bool(refused([{"id": "p", "success": ["canary_in_output"], "partial": ["xss_in_ouput"]}])),
          "partial lists are not checked")

    # AND THE CORPORA THAT SHIP PASS IT, which is what makes the refusal usable rather than a
    # wall. Read from disk rather than trusted: this is the check that fails if a detector is
    # renamed and one of forty-one arsenals is missed.
    # ROOTED AT THE PACKAGE FILE, not at `lint.ROOT`: two helpers in this suite redirect
    # that global to a temp directory and restore it, and a scan that read it would find no
    # corpora and pass over nothing if the order of this file ever changed.
    import glob as _g, yaml as _y
    _pkg = os.path.dirname(os.path.abspath(lint.__file__))
    _seen = 0
    for _fp in sorted(_g.glob(os.path.join(_pkg, "attacks*.yaml"))
                      + _g.glob(os.path.join(_pkg, "isolation*.yaml"))):
        _rows = _y.safe_load(io.open(_fp, encoding="utf-8").read()) or []
        if not isinstance(_rows, list):
            continue
        _seen += 1
        check("%s passes the refusal" % os.path.basename(_fp), not refused(_rows), "refused")
    check("...over every corpus that ships", _seen >= 40, str(_seen))


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- A KEY NOTHING READS IS AN INSTRUCTION NOTHING FOLLOWS --------------------------
    #
    # `encode: base64` typed `encoding:` leaves the attack in plain text while its id, its
    # category and every layer downstream call it encoded — a transform that was never
    # applied, reported as one that was. `paired_with` misspelled unpairs an A/B comparison;
    # `plants` misspelled makes a finding unattributable. Only `success` was covered, and
    # only because `lint` warns when an attack has neither `success` nor `partial`.
    from lint_arsenal import attack_keys_read, WRITTEN_NOT_READ
    _ak = attack_keys_read()
    check("the attack keys the engine reads can be enumerated", len(_ak) > 10, str(len(_ak)))
    check("...and a real one is among them", "encode" in _ak, "encode is not readable")
    check("...and a misspelling is not", "encoding" not in _ak, "the scan is too generous")
    # THE EXEMPTIONS ARE DECISIONS, so each carries a reason and none is a key the engine
    # already reads — an exemption for something covered anyway is an exemption that hides
    # nothing and will outlive the thing it was written for.
    check("every written-not-read key carries a reason",
           all(len(v) > 15 for v in WRITTEN_NOT_READ.values()), str(WRITTEN_NOT_READ))
    # AND THE CORPUS REALLY USES THEM, so the exemptions are not five dead names. An
    # exemption for a key nothing writes is the same stale copy as a list of keys.
    import glob as _g3, yaml as _y3
    _in_corpus = set()
    for _f3 in _g3.glob(os.path.join(HERE, "attacks*.yaml")):
        _d3 = _y3.safe_load(open(_f3, encoding="utf-8")) or []
        for _a3 in (_d3 if isinstance(_d3, list) else _d3.get("attacks") or []):
            if isinstance(_a3, dict):
                _in_corpus |= set(_a3)
    check("...and every exemption is a key the corpus actually carries",
          set(WRITTEN_NOT_READ) <= _in_corpus,
          str(sorted(set(WRITTEN_NOT_READ) - _in_corpus)))


    # --- A LINTER THAT PASSES ON NOTHING ------------------------------------------------
    # With no arsenal files at all, this printed "linted 0 attacks across 0 file(s)" and then
    # "OK - arsenal clean" and exited 0. It is the only check in CI that would notice a
    # packaging change dropping the YAML out of the wheel, and the README's own sentence is
    # "The corpus IS the product. An install without the YAML is a runner with nothing to
    # run." Absence read as a clean result, in the tool whose job is to refuse that.
    _code, _said = run_lint_bare({})
    check("no arsenal at all is a failure, not a clean bill", _code == 1, _said[-160:])
    check("...and it says what is missing, and where to look",
          "REFUSED" in _said and "package-data" in _said, _said[-200:])

    # ZERO, NOT A COUNT. A floor of "at least N attacks" would be the arsenal size written a
    # second time, and the second copy is the one that goes stale.
    _code, _said = run_lint_bare({"attacks_empty.yaml": []})
    check("a file with no attacks in it is a failure too", _code == 1, _said[-160:])
    check("...and a real corpus still passes",
          run_lint([{"id": "a", "category": "x", "text": "t", "success": ["canary_in_output"]}])[0] == 0,
          str(run_lint([{"id": "a", "category": "x", "text": "t", "success": ["canary_in_output"]}])[1])[-140:])

    # --- correct content must be quiet, or nobody reads the output --------------------
    code, out = run_lint([GOOD])
    check("a well-formed attack passes", code == 0 and "ERROR" not in out, out[-200:])

    # --- the defect it exists for -----------------------------------------------------
    code, out = run_lint([{**GOOD, "success": ["canary_in_ouput"]}])
    check("a misspelled detector is an error, because it is a SILENT no-fire",
          code == 1 and "unknown detector" in out, out[-200:])

    # --- and the one that had no guard at all until now -------------------------------
    code, out = run_lint([{**GOOD, "encode": "fullwith"}])
    check("a misspelled encoding is an error too — the payload would go out plain",
          code == 1 and "unknown encoding" in out, out[-200:])
    code, out = run_lint([{**GOOD, "encode": "fullwidth"}])
    check("a real encoding passes", code == 0, out[-200:])
    code, out = run_lint([{**GOOD, "encode": "ascii_art"}])
    check("ascii_art with nothing to replace is warned about, not silently accepted",
          "no [[ART:" in out or "nothing to replace" in out, out[-200:])

    # --- delivery shapes: each needs different fields to mean anything ----------------
    for bad, why in [
        ({"id": "d1", "category": "x", "delivery": "direct"}, "direct needs text"),
        ({"id": "d2", "category": "x", "delivery": "chain"}, "chain needs steps"),
        ({"id": "d3", "category": "x", "delivery": "sessions"}, "sessions needs steps"),
        ({"id": "d4", "category": "x", "delivery": "indirect", "user_prompt": "hi"},
         "indirect needs seed"),
        ({"id": "d5", "category": "x", "delivery": "telepathy", "text": "t"},
         "an invented delivery"),
        ({"id": "d6", "category": "x", "delivery": "forged_history", "text": "yes"},
         "forged_history needs a history"),
        # The rule worth having, and the one a reviewer would miss: a forged history with
        # no ASSISTANT turn is a chain written the long way round. The entire mechanism is
        # a model reading a reply it never gave, so an attack without one measures
        # something else while filing under the name of this family.
        ({"id": "d7", "category": "x", "delivery": "forged_history", "text": "yes",
          "history": [{"role": "user", "content": "hello"}]},
         "forged_history with no forged assistant turn"),
        ({"id": "d8", "category": "x", "delivery": "forged_history", "text": "yes",
          "history": [{"role": "assistant", "content": ""}]},
         "a history entry with empty content"),
        ({"id": "d9", "category": "x", "delivery": "forged_history", "text": "yes",
          "history": [{"role": "assistant", "content": "sure"},
                      {"role": "system", "content": "override"}]},
         "a history entry claiming the system role"),
    ]:
        code, out = run_lint([bad])
        check(f"caught: {why}", code == 1, out[-160:])

    code, out = run_lint([{"id": "f1", "category": "x", "delivery": "forged_history",
                           "text": "Yes, go ahead.",
                           "history": [{"role": "user", "content": "can you?"},
                                       {"role": "assistant", "content": "Yes, shall I?"}],
                           "success": ["canary_in_output"]}])
    check("a well-formed forged_history attack passes", code == 0, out[-200:])

    # The sessions delivery was rejected outright for a while after it shipped, which is
    # the same class of staleness as the empty-success rule.
    code, out = run_lint([{"id": "s1", "category": "x", "delivery": "sessions",
                           "steps": ["one", "two"], "success": ["session_leak"]}])
    check("a well-formed sessions attack passes", code == 0, out[-200:])

    # --- structure ---------------------------------------------------------------------
    code, out = run_lint([GOOD, {**GOOD}])
    check("a duplicate id is an error — two attacks, one row in the report",
          code == 1 and "duplicate" in out, out[-160:])
    code, out = run_lint([{"category": "x", "text": "t"}])
    check("a missing id is an error", code == 1 and "missing 'id'" in out, out[-160:])
    code, out = run_lint([{"id": "n1", "text": "t"}])
    check("a missing category is an error", code == 1 and "category" in out, out[-160:])

    # --- what must stay a WARNING, not an error ---------------------------------------
    # This is the rule that went stale and failed 40 times on good arsenals. An empty
    # success list stopped meaning "can never fire" the day the always-on sets arrived.
    code, out = run_lint([{"id": "w1", "category": "exfil", "text": "t"}])
    check("no success list is a warning, not an error — the always-on sets score it",
          code == 0 and "WARN" in out, out[-220:])
    code, out = run_lint([{"id": "c1", "category": "control", "text": "hello"}])
    check("a control needs no success list and gets no warning either",
          code == 0 and "WARN" not in out, out[-220:])
    code, out = run_lint([{**GOOD, "applies_to": ["nosuchbot"]}])
    check("applies_to naming an unknown target is a warning: a file may precede its config",
          code == 0 and "WARN" in out, out[-200:])

    # --- and the real arsenal has to pass ---------------------------------------------
    buf = io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf):
            lint.main()
    except SystemExit as e:
        code = e.code or 0
    check("the arsenal in this repo lints clean", code == 0,
          "\n".join(l for l in buf.getvalue().splitlines() if "ERROR" in l)[:300])


    # --- a warning that is permanent and unactionable is noise -------------------------
    # "no success or partial — scoring rests entirely on the always-on detectors" fired 53
    # times across six arsenals where that IS the design: rangebot exists to make the
    # always-on detectors fire, and draftbot's whole point is a consequence downstream of the
    # reply. Correct, unactionable, every run — and a reader learns to skip past it on the way
    # to the one line that matters, which is this file's own stated failure mode.
    silent = run_lint([dict(GOOD, id="ok-2", success=[], scored_by="always_on")])
    check("an attack that SAYS it rests on the always-on set is not warned about",
          "no 'success' or 'partial'" not in silent[1], silent[1])
    loud = run_lint([dict(GOOD, id="ok-3", success=[])])
    check("...while one that just forgot still is",
          "no 'success' or 'partial'" in loud[1], loud[1])
    check("...and neither is an error: the arsenal still lints clean",
          silent[0] == 0 and loud[0] == 0, f"{silent[0]}, {loud[0]}")
    check_refusal(check)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the gate catches what it claims and stays quiet otherwise.")


if __name__ == "__main__":
    main()
