"""The front door, checked against a scripted endpoint — no model, no network beyond localhost.

Onboarding exists for one failure above all others: a `response.reply` path that does not match
the endpoint's shape. It is the most expensive kind of wrong this system can produce, because
it does not fail. An unmapped reply is an empty reply, an empty reply fires no detector, and no
detector firing is a target that held. A whole run comes back clean and the operator is told
their bot is safe.

So the checks below care less about the happy path than about that one, and about whether the
message a customer gets is actionable: naming the path that DOES hold their text, rather than
telling them a field was empty and leaving them to guess a second time.

    python test_onboard.py       # exits 1 on any failure (CI gate)
"""
import sys, os, io, json, shutil, subprocess, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import onboard
import jobqueue as q


class Bot(BaseHTTPRequestHandler):
    """Answers in the OpenAI shape, which is not the shape the first config will ask for."""

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        out = json.dumps({"choices": [{"message": {
            "content": "Of course, I can help with your recent order. What is the order "
                       "number?"}}], "id": "cmpl-1", "model": "scripted"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


CFG = """adapter: http
name: {name}
url: "http://127.0.0.1:{port}/v1/chat/completions"
request:
  model: scripted
  messages: [{{role: user, content: "{{prompt}}"}}]
response:
  reply: "{path}"
{extra}"""


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- A KEY NOTHING READS IS A DETECTOR NOBODY ARMED ---------------------------------
    #
    # `canaries` misspelled `canarys` parses, sweeps, and disarms every canary detector in
    # the oracle — a clean bill for checks that could not fire, out of the one file an
    # operator edits by hand. This command exists to catch a config that would otherwise
    # produce a clean report from a broken mapping, and it read the reply path only.
    from workspace import context_keys_read as _keys_read

    _known = _keys_read()
    check("the engine's context keys can be enumerated", len(_known) > 20, str(len(_known)))
    check("...and a real key is among them", "canaries" in _known, sorted(_known)[:6])
    check("...and a misspelling is not", "canarys" not in _known, "the scan is too generous")

    check("a misspelled context key is named",
          onboard.unread_context_keys({"oracle_context": {"canarys": ["X"]}}) == ["canarys"],
          str(onboard.unread_context_keys({"oracle_context": {"canarys": ["X"]}})))
    check("...and a real one is not",
          onboard.unread_context_keys({"oracle_context": {"canaries": ["X"]}}) == [],
          str(onboard.unread_context_keys({"oracle_context": {"canaries": ["X"]}})))
    check("a config with no oracle_context is not accused of anything",
          onboard.unread_context_keys({}) == [], "an empty config produced a complaint")
    # AND A BROKEN SCAN ACCUSES NOTHING. If the source scan ever comes back empty — a
    # packaging change, a rename, a read that fails — every key in every config would look
    # unknown and the note would be worse than useless. The guard for that is unreachable in
    # a healthy tree, so it is reached here on purpose.
    import workspace as _wsk
    _real = _wsk.context_keys_read
    _wsk.context_keys_read = lambda root=None: set()
    try:
        check("a scan that came back empty accuses no key",
              onboard.unread_context_keys({"oracle_context": {"canarys": ["X"]}}) == [],
              "an empty scan reported every key as unknown")
    finally:
        _wsk.context_keys_read = _real

    # AND THE SHIPPED CONFIGS ARE CLEAN, which is the half that protects this repository's own
    # fleet: a typo in one of forty-three configs would disarm a detector on that target and
    # the sweep would report a clean bill for it.
    import glob as _g, yaml as _y
    _bad = {}
    for _f in sorted(_g.glob(os.path.join(HERE, "targets_*.yaml"))):
        try:
            _c = _y.safe_load(io.open(_f, encoding="utf-8").read()) or {}
        except Exception:
            continue
        _u = onboard.unread_context_keys(_c)
        if _u:
            _bad[os.path.basename(_f)] = _u
    # AND THERE HAVE TO BE CONFIGS. A universal claim over an empty set is satisfied by the
    # set being empty, and the `except Exception: continue` above makes an unparseable file
    # disappear from it silently -- so the count is asserted beside the claim.
    _seen_cfgs = sorted(_g.glob(os.path.join(HERE, "targets_*.yaml")))
    check("there are shipped configs to check", len(_seen_cfgs) >= 20, str(len(_seen_cfgs)))
    check("no shipped config declares a context key nothing reads", not _bad, str(_bad))

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Bot)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    work = tempfile.mkdtemp()

    def write(name, path, extra=""):
        p = os.path.join(work, f"targets_{name}.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(CFG.format(name=name, port=port, path=path, extra=extra))
        return p

    try:
        # --- THE ONE THAT MATTERS: a wrong reply path -------------------------------------
        wrong = write("wrongpath", "message.content")
        ok, rep = onboard.check(wrong)
        check("a config whose reply path matches nothing does not pass", not ok)
        prob = " ".join(rep["problems"])
        check("...and is called a mapping problem, not a connectivity one",
              "mapping problem" in prob, prob[:160])
        check("...and says WHY it would not have failed the run on its own",
              "held" in prob, prob[:200])
        notes = " ".join(rep["notes"])
        check("...and names the path that actually holds the text",
              "choices.0.message.content" in notes, notes[:200])
        check("...and shows what the endpoint really returned, so it can be checked",
              "What is the order" in notes or "help with your recent order" in notes,
              notes[:240])

        # --- AND A PATH THAT RESOLVES TO THE WRONG FIELD ----------------------------------
        #
        # The check above asks whether `response.reply` resolved to ANYTHING. A mapping
        # pointed at `id` or `model` resolves perfectly, and every probe of the sweep then
        # comes back as `cmpl-1` or `scripted`: no detector can fire on that, so the run
        # reports the target as having held against the whole arsenal, and this command
        # said `ready to queue`. Walked against this same scripted endpoint before the fix:
        # three wrong mappings, three clean bills.
        for _bad_path, _got in (("id", "cmpl-1"), ("model", "scripted")):
            _wrongfield = write("wrongfield_%s" % _bad_path, _bad_path)
            _ok2, _rep2 = onboard.check(_wrongfield)
            check("a reply path that resolves to %r does not pass" % _got, not _ok2,
                  str(_rep2.get("problems")))
            _p2 = " ".join(_rep2["problems"])
            check("...quoting what it actually resolved to", _got in _p2, _p2[:200])
            check("...and saying the sweep would have reported the target as holding",
                  "held against the whole arsenal" in _p2, _p2[:240])
            _n2 = " ".join(_rep2["notes"])
            check("...and naming the path that does hold the answer",
                  "choices.0.message.content" in _n2, _n2[:200])

        # AND A TERSE ENDPOINT IS NOT REFUSED, which is the other direction and the one that
        # would make this rule unusable. The judgement is on the EVIDENCE: refuse only when
        # the same body holds something that reads like an answer and the mapping missed it.
        class _Terse(Bot):
            def do_POST(self):
                _n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(_n)
                _o = json.dumps({"status": "ok"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(_o)))
                self.end_headers()
                self.wfile.write(_o)

        _tsrv = ThreadingHTTPServer(("127.0.0.1", 0), _Terse)
        threading.Thread(target=_tsrv.serve_forever, daemon=True).start()
        try:
            _tp = os.path.join(work, "targets_terse.yaml")
            with open(_tp, "w", encoding="utf-8") as _f:
                _f.write(CFG.format(name="terse", port=_tsrv.server_address[1],
                                    path="status", extra=""))
            _ok3, _rep3 = onboard.check(_tp)
            check("a terse endpoint with nothing better to point at is not refused", _ok3,
                  str(_rep3.get("problems")))
            check("...but is told where to look if everything comes back DEFENDED",
                  any("terse endpoint" in n for n in _rep3["notes"]),
                  str(_rep3["notes"]))
        finally:
            _tsrv.shutdown()

        # AND THE BODY STAYS OFF THE PROBE. `targets_http` attaches the raw response to a
        # FAILED probe on purpose and to nothing else: "a raw payload the oracle could read
        # would be a second, unaudited channel into every judgement in this repo". The body
        # onboard now reads is kept on the TARGET, which a detector is never handed, and only
        # when a caller asks. Both halves are checked, because the safe half is the one that
        # would be quietly lost.
        _rsrc = io.open(os.path.join(HERE, "run_redteam.py"), encoding="utf-8").read()
        _isrc = io.open(os.path.join(HERE, "run_isolation.py"), encoding="utf-8").read()
        _bsrc = io.open(os.path.join(HERE, "benign.py"), encoding="utf-8").read()
        check("no command that judges probes asks the adapter to keep response bodies",
              "_keep_last_raw" not in (_rsrc + _isrc + _bsrc), "a sweep asked for the body")
        _hp = write("probeclean", "choices.0.message.content")
        import yaml as _yaml
        _cfg9 = _yaml.safe_load(io.open(_hp, encoding="utf-8"))
        from targets_http import HttpConfiguredTarget as _HCT
        _tg = _HCT(**{k: v for k, v in _cfg9.items()
                      if k not in onboard.CONFIG_ONLY_KEYS})
        _pb = _tg.send("Hello, I have a question about my recent order.")
        check("...and a successful probe carries no raw body for a detector to read",
              getattr(_pb, "raw", None) is None, repr(getattr(_pb, "raw", None))[:80])
        check("...while the target it came from did not keep one either, unasked",
              getattr(_tg, "_last_raw", None) is None,
              repr(getattr(_tg, "_last_raw", None))[:80])

        # --- the happy path, and what it derives ------------------------------------------
        right = write("rightpath", "choices.0.message.content")
        ok, rep = onboard.check(right)
        check("a correct config passes", ok, str(rep.get("problems")))
        check("...and shows the reply, so a human can see it is really their bot",
              "recent order" in (rep.get("reply") or ""), str(rep.get("reply"))[:80])
        check("...and reports what it cost in seconds", rep.get("seconds") is not None)

        # Capabilities are DERIVED from the config, and their absence deletes whole classes of
        # attack from the run without failing anything. That has to be said at onboarding,
        # because a narrower run and a weaker verdict look identical in the report.
        notes = " ".join(rep["notes"])
        check("a config with no history block is warned that multi-turn will be SKIPPED",
              "SKIPPED" in notes and "chain" in notes, notes[:200])
        check("...and told that a run without them is narrower, not weaker",
              "narrower" in notes, notes[:220])
        check("a config with no canaries is warned that a leak would be invisible",
              "canaries" in notes and "invisible" in notes, notes[:300])

        multi = write("multiturn", "choices.0.message.content",
                      extra=("history:\n  field: messages\n  mode: splice\n"
                             "  insert_before: 1\noracle_context:\n  canaries: [\"K-1\"]\n"))
        ok, rep = onboard.check(multi)
        check("declaring history derives the multi-turn deliveries", ok and
              "chain" in (rep.get("capabilities") or []), str(rep.get("capabilities")))
        check("...and forged_history with it, since both need a transcript",
              "forged_history" in (rep.get("capabilities") or []),
              str(rep.get("capabilities")))
        notes = " ".join(rep["notes"])
        check("...and the multi-turn and canary warnings are then gone",
              "SKIPPED" not in notes and "invisible" not in notes, notes[:200])

        # --- a budget that cannot hold the run is said BEFORE the run ---------------------
        tight = write("tight", "choices.0.message.content",
                      extra="rate:\n  max_requests: 20\n  max_seconds: 1800\n")
        ok, rep = onboard.check(tight)
        notes = " ".join(rep["notes"])
        check("a budget too small for a default run is flagged up front", ok and
              "STOP part way" in notes, notes[:220])
        check("...and the unsent attacks are named a gap rather than rows that held",
              "gap rather than rows that held" in notes, notes[:260])

        # AND THE MINUTES IN IT ARE THE ARSENAL'S, NOT A LITERAL'S. `_arsenal()` exists
        # because a hard-coded 19 had been true of a nineteen-attack arsenal and nothing
        # re-read it; the request estimate above got that fix and the TIME estimate three
        # lines away kept the 19, so the sentence named the real count while the arithmetic
        # used a twentieth of it. A warning that understates stays quiet exactly when it
        # should speak: at a 3s reply it reported 3 minutes against a real 57.
        # READ FROM THE SOURCE, and the reason is itself worth recording: the note is guarded
        # by `if rep["seconds"] and ...`, and a local fixture answers fast enough that
        # `round(elapsed, 1)` is 0.0, which is falsy. So on this bench the estimate never runs
        # and a functional check here would pass by never reaching the arithmetic -- the shape
        # this repository calls a check that cannot fail. What can be asserted is that the
        # multiplier is the arsenal and not a number somebody remembered.
        import re as _re
        _src = io.open(os.path.join(HERE, "onboard.py"), encoding="utf-8").read()
        _est = _re.search(r'if rep\["seconds"\] and rate\.max_seconds:.*?\n\s*need = ([^\n]+)',
                          _src, _re.S)
        check("the time estimate exists to be checked", bool(_est), "no `need =` after the guard")
        if _est:
            _expr = _est.group(1)
            check("...and it multiplies by the arsenal, not by a literal",
                  "need_req" in _expr and not _re.search(r"\*\s*\d\d\s*\*", _expr), _expr.strip())
            check("...and the sentence beside it names the same count",
                  "{need_att} attacks x 3" in _src, "the note does not name need_att")

        # --- AND A CHAIN COSTS ONE REQUEST PER STEP -------------------------------------
        #
        # A budget is spent on REQUESTS and this counted ATTACKS: 379 x 3 = 1,137 where the
        # run sends 1,464, because 69 of the arsenal are chains. `docs/ci.md` prices the same
        # sweep at 1,464 and `test_readme` recounts that table, so the doc and its gate have
        # always agreed; the check an operator reads BEFORE spending the money had its own
        # arithmetic. It understated, which in a warning whose whole sentence is `it will
        # STOP part way` is silence exactly where it should speak.
        #
        # Driven at the boundary rather than asserted about the source, because the old
        # number is a budget that must now warn and the new one is a budget that must not.
        from runner import requests_for as _rf
        _atk = onboard._arsenal()
        _need, _old_sum = _rf(_atk, 3), len(_atk) * 3
        check("a chain makes a sweep cost more requests than it has attacks",
              _need > _old_sum, "%d requests for %d attacks" % (_need, _old_sum))
        _budget = write("oldsum", "choices.0.message.content",
                        extra="rate:\n  max_requests: %d\n  max_seconds: 999999\n" % _old_sum)
        _ok2, _rep2 = onboard.check(_budget)
        _n2 = " ".join(_rep2["notes"])
        check("a budget the size of attacks x trials is too small, and is told so",
              "STOP part way" in _n2, _n2[:200])
        check("...and the sentence says a chain is counted by its steps",
              "counting a chain by its steps" in _n2, _n2[:220])
        check("...and it names the request count, not the attack count",
              str(_need) in _n2, _n2[:220])
        _budget = write("enough", "choices.0.message.content",
                        extra="rate:\n  max_requests: %d\n  max_seconds: 999999\n" % _need)
        _ok3, _rep3 = onboard.check(_budget)
        check("...while a budget that covers every step is not warned about",
              "STOP part way" not in " ".join(_rep3["notes"]),
              " ".join(_rep3["notes"])[:200])

        # AND ONE ARITHMETIC, NOT TWO. `docs/ci.md`'s cost table is recounted in
        # `test_readme` with the same rule; if that gate keeps its own copy of it the two
        # can drift apart again in the direction nobody watches.
        _rsrc = io.open(os.path.join(HERE, "test_readme.py"), encoding="utf-8").read()
        check("the cost table is recounted with the engine's own turn rule",
              "from runner import turns" in _rsrc,
              "test_readme keeps its own copy of the turn rule")
        # A three-step chain is three and a plain attack is one, pinned to a fixture so the
        # shared function cannot answer both callers the same wrong way.
        from runner import turns as _turns_f
        check("a three-step chain costs three requests",
              _turns_f({"delivery": "chain", "steps": ["a", "b", "c"]}) == 3,
              str(_turns_f({"delivery": "chain", "steps": ["a", "b", "c"]})))
        check("...a plain attack costs one",
              _turns_f({"text": "hi"}) == 1, str(_turns_f({"text": "hi"})))
        check("...and an empty or malformed steps list is one, not zero",
              _turns_f({"steps": []}) == 1 and _turns_f({"steps": "abc"}) == 1,
              "%s %s" % (_turns_f({"steps": []}), _turns_f({"steps": "abc"})))

        # --- an unreachable endpoint --------------------------------------------------------
        dead = os.path.join(work, "targets_dead.yaml")
        with open(dead, "w", encoding="utf-8") as f:
            f.write(CFG.format(name="dead", port=1, path="choices.0.message.content", extra=""))
        ok, rep = onboard.check(dead)
        check("an endpoint that cannot be reached does not pass", not ok)
        check("...and is reported as a connection failure, not as a quiet bot",
              any("could not be reached" in p or "error" in p for p in rep["problems"]),
              str(rep["problems"])[:200])
        # AND THE HEADER MUST AGREE WITH IT. `render` printed the elapsed time under the
        # word "answered" whenever a probe came back at all, so a refused connection read
        # "answered in 4.1s" three lines above "the endpoint returned an error". Both lines
        # were about the same probe and only one of them was true.
        _out = io.StringIO()
        _stdout, sys.stdout = sys.stdout, _out
        try:
            onboard.render(ok, rep)
        finally:
            sys.stdout = _stdout
        printed = _out.getvalue()
        check("...and the header does not say the endpoint answered", "answered" not in printed,
              printed[:200])
        check("...it says there was no answer, and after how long",
              "no answer" in printed, printed[:200])

        # --- nothing is queued for a config that failed the check --------------------------
        # A job submitted against an unreachable target is an hour of queue time spent to
        # produce the sentence this command already printed.
        qroot = os.path.join(work, "queue")
        def submit(cfg):
            # Under the runner's per-suite deadline, so a hang here is reported as this
            # step rather than as the whole suite.
            return subprocess.run(
                [sys.executable, os.path.join(HERE, "onboard.py"), "--config", cfg,
                 "--submit", "--root", qroot], capture_output=True, text=True, timeout=120)

        r = submit(dead)
        check("--submit on a failed check exits non-zero", r.returncode != 0,
              (r.stdout + r.stderr)[-200:])
        check("...and queues nothing", not q.listing(qroot), str(q.listing(qroot)))

        r = submit(multi)
        rc = r.returncode
        jobs = q.listing(qroot)
        check("--submit on a passing check queues exactly one job",
              rc == 0 and len(jobs) == 1, f"rc={rc} n={len(jobs)} " + (r.stdout + r.stderr)[-400:])
        check("...carrying the authorization the gate produced",
              jobs and "authorization" in jobs[0])
        check("...and the config path the worker will need",
              jobs and os.path.isabs(jobs[0]["config"]), str(jobs and jobs[0]["config"]))
        # THE TARGET-AGNOSTIC ARSENAL, not the engine's default. attacks.yaml scopes almost
        # every attack `applies_to` a specific practice bot, so the first job that went through
        # this door sent 5 of 137 and skipped 132 — a 3% assessment presented as an assessment.
        check("...and the arsenal written to run against anything",
              jobs and "generic" in os.path.basename(jobs[0]["attacks"] or ""),
              str(jobs and jobs[0].get("attacks")))

        # --- a config for a built-in target is not an onboarding config --------------------
        builtin = os.path.join(work, "targets_builtin.yaml")
        with open(builtin, "w", encoding="utf-8") as f:
            f.write("name: builtin\nmodule: draftbot\n")
        ok, rep = onboard.check(builtin)
        check("a non-http config is refused with a reason rather than crashing",
              not ok and "adapter" in " ".join(rep["problems"]), str(rep["problems"])[:140])
    finally:
        srv.shutdown()
        shutil.rmtree(work, ignore_errors=True)

    # --- TWO DOORS INTO THE QUEUE, ONE RULE ---------------------------------------------
    #
    # `intake.submit` refuses a nameless config and says why: the name becomes
    # `results_<name>.json`, `report_<name>.html` and `history/<name>.jsonl`, so a default
    # means every unnamed target writes the same files. `onboard --submit` reaches the same
    # queue and invented `(unnamed)`, printed it, and answered `ready to queue`.
    #
    # The invented default was not even the name the run would use: a nameless
    # `adapter: http` config constructs as `http-target`, so the queue recorded one target
    # and the artifacts were written under another.
    #
    # ASKED THROUGH `check()`, the function both the report and `--submit` go through, so
    # this cannot pass by testing a helper the door does not call.
    import tempfile as _tf8, shutil as _sh8, yaml as _y8
    _d8 = _tf8.mkdtemp()
    try:
        def _write(cfg):
            _p8 = os.path.join(_d8, "c.yaml")
            with open(_p8, "w", encoding="utf-8") as _f8:
                _y8.safe_dump(cfg, _f8)
            return _p8

        _base = {"adapter": "http", "url": "http://127.0.0.1:9/chat",
                 "request": {"body": {"message": "{prompt}"}},
                 "response": {"reply": "reply"}}
        _ok8, _rep8 = onboard.check(_write(dict(_base)))
        # ONE PROBLEM, AND IT IS THE NAME. `not _ok8` alone passes for the wrong reason:
        # this config points at port 9, so a door that ignored the name would still refuse
        # it on connectivity. The property is that it is refused BEFORE anything is sent,
        # which is the reasoning `intake` wrote down for its own door.
        check("a config with no name is refused before the endpoint is touched",
              not any("endpoint" in p for p in _rep8.get("problems") or [])
              and "reply" not in _rep8, str(_rep8.get("problems")))
        check("...and the refusal says the name is required",
              any("`name` is required" in p for p in _rep8.get("problems") or []),
              str(_rep8.get("problems")))

        # THE OTHER DIRECTION, or the check above is satisfied by a door that refuses
        # everything. This config is unreachable on purpose -- port 9 -- so the run gets
        # as far as the endpoint and no further; what matters is that the NAME is not what
        # it complains about.
        _ok9, _rep9 = onboard.check(_write(dict(_base, name="acme-bot")))
        check("...and a named config gets past the name check",
              not any("`name`" in p for p in _rep9.get("problems") or []),
              str(_rep9.get("problems")))
        check("...and keeps the name it was given", _rep9.get("name") == "acme-bot",
              repr(_rep9.get("name")))

        # AND THE REST OF THE RULE, not only the empty case: a name that cannot be part of
        # a filename was accepted here too.
        _okA, _repA = onboard.check(_write(dict(_base, name="../../etc/passwd")))
        check("...and a name that is a path is refused", not _okA,
              str(_repA.get("problems")))
    finally:
        _sh8.rmtree(_d8, ignore_errors=True)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a misconfiguration is caught before it can report as a defence.")


if __name__ == "__main__":
    main()
