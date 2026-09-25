"""The starting config has to be a config the tool accepts. Checked by building it.

`qatration init` exists because the door had homework on it: the quickstart told a stranger to
run `onboard --target-config mybot.yaml` and nothing in the tool produced `mybot.yaml`. A
command that writes one is only worth having if what it writes actually works, and "actually
works" here has a precise meaning that a human reading the template cannot verify.

DERIVED, NOT LISTED, and in this suite that is the whole design. The template is not compared
against a copy of the expected keys — a copy would be a second description of a valid config,
free to drift from the adapter that decides. It is parsed and fed to `HttpConfiguredTarget`
through exactly the expression `onboard` uses, so the adapter itself is the judge. Add a
required field to the adapter and this fails; the template cannot quietly fall behind.

That matters more than usual here because of how this adapter fails on a bad key. An unknown
key is fatal on purpose: `respones:` for `response:` once produced a target with no reply
mapping, and an unmapped reply is an empty reply, and an empty reply scores as a bot that held.
The failure mode of a wrong config is a clean report, which is this project's own defect class.
Hand-authoring the file is precisely where that typo came from.

    python test_init.py             # exits 1 on any failure (CI gate)
"""
import io
import os
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import yaml                                                                 # noqa: E402
import honeytoken as ht                                                     # noqa: E402
import init_config                                                          # noqa: E402
from targets_http import HttpConfiguredTarget, CONFIG_ONLY_KEYS             # noqa: E402

fails = []
checks = 0


def check(label, ok, detail=""):
    global checks
    checks += 1
    print(("PASS  " if ok else "FAIL  ") + label)
    if not ok:
        fails.append("%s: %s" % (label, detail))


def _placeholder_checks():
    """The template's own words, and who notices when they are still there.

    `DEFAULT_MODEL` is written to be rejected -- the comment above it says a plausible id
    "reads as configured and gets sent", so this one "cannot be mistaken for an answer".
    That holds on an API that VALIDATES the field, and Ollama, LM Studio, vLLM and any
    hand-written `request:` shape do not. Walked from a fresh `init` against an endpoint
    that answers: the body went out as `{"model": "YOUR-MODEL-ID", ...}`, `onboard` printed
    the reply and `ready to queue`, and nothing said the field was never filled in.

    `workspace.config_model` reads `request.model`, so the run's artifact, its scorecard,
    its SARIF export and `history`'s model confound would every one of them have recorded
    YOUR-MODEL-ID as the model tested -- a report that cannot say what it was about.
    """
    import init_config as _ic
    _fresh = {"request": {"model": _ic.DEFAULT_MODEL}}
    check("the template's own model placeholder is recognised when it is still there",
          _ic.placeholders_left(_fresh) == [("request.model", _ic.DEFAULT_MODEL)],
          str(_ic.placeholders_left(_fresh)))
    check("...and a config somebody filled in carries none",
          _ic.placeholders_left({"request": {"model": "llama3.2:3b"}}) == [],
          str(_ic.placeholders_left({"request": {"model": "llama3.2:3b"}})))
    check("...and a config with no request block is not accused of anything",
          _ic.placeholders_left({}) == [], str(_ic.placeholders_left({})))
    check("...nor is one whose model is empty, which is a different mistake",
          _ic.placeholders_left({"request": {"model": ""}}) == [],
          str(_ic.placeholders_left({"request": {"model": ""}})))
    # AND WHAT `init` ACTUALLY WRITES IS WHAT THE RULE LOOKS FOR, or the two drift and the
    # rule is about a string nothing produces.
    _written = yaml.safe_load(_ic.render(secret="QAT-CANARY-AAAA1111BBBB2222",
                                         verify="QAT-VERIFY-AAAA1111")) or {}
    check("...and the config this template writes is one of them",
          bool(_ic.placeholders_left(_written)), str(_ic.placeholders_left(_written)))

    # AND BOTH COMMANDS THAT SEND TRAFFIC ASK. `onboard` answers "what is wrong with my
    # config" and `run` writes the artifact that records the model; a reader can skip the
    # first, so the second cannot rely on it.
    # AS A CALL, NOT AS A SUBSTRING. Written as `is the name in the source`, this passed on
    # a module that imported the rule and then iterated an empty list -- the name was there
    # and the function was not being used, which is the shape this repository has already
    # been caught by once.
    import ast as _ast_i
    for _mod in ("onboard.py", "run_redteam.py"):
        _tree = _ast_i.parse(io.open(os.path.join(HERE, _mod), encoding="utf-8").read())
        # THE LOCAL NAME, because both callers import it under an alias. A check written
        # against the original spelling looks at a name neither file uses.
        _bound = {(_a.asname or _a.name) for _n in _ast_i.walk(_tree)
                  if isinstance(_n, _ast_i.ImportFrom) and _n.module == "init_config"
                  for _a in _n.names if _a.name == "placeholders_left"}
        _calls = [_n for _n in _ast_i.walk(_tree)
                  if isinstance(_n, _ast_i.Call)
                  and getattr(_n.func, "id", "") in _bound and _n.args]
        check("%s asks which placeholders are left" % _mod,
              bool(_bound) and bool(_calls),
              "bound as %s, %d call(s) with an argument" % (sorted(_bound), len(_calls)))

    # --- AND THE NOTE CLAIMED A MEASUREMENT NOBODY HAD MADE -------------------------------
    #
    # Both callers said "Your endpoint answered anyway, so it is ignoring the field", and
    # neither had asked. Walked from a fresh `init` with nothing listening, following this
    # tool's own printed instructions:
    #
    #     PROBLEM   the endpoint returned an error: URLError: ... actively refused it
    #     note      request.model is still 'YOUR-MODEL-ID' ... Your endpoint answered anyway
    #
    # Two lines apart and the second contradicts the first. `run` was worse: its copy prints
    # in the pre-flight block, before a probe leaves the machine, so the claim was
    # unconditional.
    check("an endpoint that answered is said to be ignoring the field",
          "answered anyway" in _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, True),
          _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, True))
    check("...one that did not answer leaves it unmeasured",
          "unmeasured" in _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, False),
          _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, False))
    check("...and before anything is sent, nothing is claimed about it at all",
          "Nothing has been sent yet"
          in _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, None),
          _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, None))
    for _state in (True, False, None):
        _said = _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, _state)
        # THE CONSEQUENCE IS CERTAIN IN ALL THREE, which is what makes the note worth
        # printing at all: `workspace.config_model` reads `request.model` and nothing else.
        check("the cost of leaving it is stated whatever the endpoint did (%r)" % _state,
              "as the model that was tested" in _said, _said)
        check("...and the placeholder itself is named (%r)" % _state,
              _ic.DEFAULT_MODEL in _said, _said)
    # AND NOT THE CLAIM, IN THE TWO STATES THAT HAVE NOT EARNED IT.
    for _state in (False, None):
        check("nothing answered is not reported as an answer (%r)" % _state,
              "answered anyway"
              not in _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, _state),
              _ic.placeholder_note("request.model", _ic.DEFAULT_MODEL, _state))

    # AND THE CALLERS, DRIVEN, because the sentence was right in a function and wrong in the
    # two places that printed it. `onboard` against a port nothing is listening on is the
    # walk that found it; `run` is the copy that never asked at all.
    import subprocess as _sp_p
    import tempfile as _tf_p
    _pw = _tf_p.mkdtemp()
    _penv = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8",
                 QATRATION_OUT=_tf_p.mkdtemp())
    _sp_p.run([sys.executable, os.path.join(HERE, "cli.py"), "init"],
              capture_output=True, text=True, env=_penv, cwd=_pw, timeout=180)
    _cfgp = os.path.join(_pw, "mybot.yaml")
    check("`init` wrote a config to walk", os.path.isfile(_cfgp), _pw)
    # PORT 9 IS discard/, which nothing serves: the connection is refused rather than hanging.
    _txt = io.open(_cfgp, encoding="utf-8").read().replace(
        'url: "http://localhost:8000/chat"', 'url: "http://127.0.0.1:9/chat"')
    io.open(_cfgp, "w", encoding="utf-8", newline="").write(_txt)
    _p = _sp_p.run([sys.executable, os.path.join(HERE, "cli.py"), "onboard",
                    "--target-config", _cfgp],
                   capture_output=True, text=True, env=_penv, cwd=_pw, timeout=180)
    _out = (_p.stdout or "") + (_p.stderr or "")
    check("onboard against a dead endpoint still says the placeholder is there",
          "YOUR-MODEL-ID" in _out and "placeholder" in _out, _out[-300:])
    check("...and does not say the endpoint answered",
          "answered anyway" not in _out,
          [l for l in _out.splitlines() if "answered anyway" in l][:1] or _out[-200:])
    check("...and the header does not call it an answer either",
          "answered    in" not in _out,
          [l for l in _out.splitlines() if "answered" in l][:2])

    # AND THE STATE A BOOLEAN COULD NOT HOLD, reached the way a reader reaches it: a remote
    # url with no `authorization:` block is refused BEFORE the probe, so there is no elapsed
    # time and nothing came back. `rep.get("answered", True)` defaults to the word `answered`
    # for an endpoint nobody has spoken to, which is what the third state is for.
    _txt2 = io.open(_cfgp, encoding="utf-8").read().replace(
        'url: "http://127.0.0.1:9/chat"', 'url: "https://not-a-real-bot.example.com/chat"')
    io.open(_cfgp, "w", encoding="utf-8", newline="").write(_txt2)
    _p2 = _sp_p.run([sys.executable, os.path.join(HERE, "cli.py"), "onboard",
                     "--target-config", _cfgp],
                    capture_output=True, text=True, env=_penv, cwd=_pw, timeout=180)
    _out2 = (_p2.stdout or "") + (_p2.stderr or "")
    check("a config refused before the probe says nothing has been sent",
          "Nothing has been sent yet" in _out2,
          [l for l in _out2.splitlines() if "placeholder" in l][:1] or _out2[-200:])
    check("...and does not report an answer it never waited for",
          "answered" not in _out2, [l for l in _out2.splitlines() if "answered" in l][:2])

    # AND `run` PASSES THE STATE IT IS IN, which is the one this gate cannot reach by driving:
    # reaching that line needs a live endpoint and a planted honeytoken. Read as the ARGUMENT
    # of the call: `run` prints this in its pre-flight block, before a probe leaves the
    # machine, so the only state it can honestly pass is the one that claims nothing.
    _rr_tree = _ast_i.parse(io.open(os.path.join(HERE, "run_redteam.py"),
                                    encoding="utf-8").read())
    _nb = {(_a.asname or _a.name) for _n in _ast_i.walk(_rr_tree)
           if isinstance(_n, _ast_i.ImportFrom) and _n.module == "init_config"
           for _a in _n.names if _a.name == "placeholder_note"}
    _ncalls = [_n for _n in _ast_i.walk(_rr_tree)
               if isinstance(_n, _ast_i.Call) and getattr(_n.func, "id", "") in _nb]
    check("`run` says the placeholder note itself", bool(_nb) and bool(_ncalls),
          "bound as %s, %d call(s)" % (sorted(_nb), len(_ncalls)))
    check("...and tells it that nothing has been sent",
          bool(_ncalls) and all(len(_c.args) >= 3 and isinstance(_c.args[2], _ast_i.Constant)
                                and _c.args[2].value is None for _c in _ncalls),
          str([_ast_i.dump(_c)[:80] for _c in _ncalls]))

    # AND THE PLACEHOLDER HAS TO LOOK LIKE ONE. The comment above `DEFAULT_MODEL` is the
    # whole argument for its value: "a plausible one reads as configured and gets sent, and
    # the endpoint's rejection then looks like the tool rather than the placeholder. This
    # one cannot be mistaken for an answer." Nothing kept it that way, so the value could
    # become `gpt-4o` with every check here green -- and a reader would then see a real
    # model id in their config and take it for a decision somebody made.
    check("the placeholder cannot be mistaken for a model somebody meant",
          "YOUR" in _ic.DEFAULT_MODEL.upper(), _ic.DEFAULT_MODEL)


def main():
    _placeholder_checks()
    text = init_config.render(out="mybot.yaml", url="https://bot.example.com/chat",
                              name="mybot")

    try:
        cfg = yaml.safe_load(text)
        parsed = isinstance(cfg, dict)
    except Exception as e:
        cfg, parsed = {}, False
        check("what init writes is valid YAML", False, "%s: %s" % (type(e).__name__, e))
    if parsed:
        check("what init writes is valid YAML", True)

    # THE CHECK THIS SUITE EXISTS FOR. Same expression as `onboard.check`, so the adapter is
    # the authority and not a list kept here.
    built, why = None, ""
    try:
        built = HttpConfiguredTarget(**{k: v for k, v in cfg.items()
                                        if k not in CONFIG_ONLY_KEYS})
    except SystemExit as e:
        why = str(e)
    check("...and the adapter builds a real target out of it", built is not None,
          "the config init writes would be refused by onboard: " + why)

    check("onboard's own path is the one used above",
          "CONFIG_ONLY_KEYS})" in io.open(os.path.join(HERE, "onboard.py"),
                                          encoding="utf-8").read(),
          "onboard no longer strips CONFIG_ONLY_KEYS; this test is checking a stale path")

    if built is not None:
        check("the url given on the command line is the url written",
              built.url == "https://bot.example.com/chat", built.url)
        check("...and the name, which becomes the result filename", built.name == "mybot",
              built.name)
        # A verb with no body would send every attack as an empty request and score the lot as
        # defended, so the template must not pick one.
        check("the method it writes carries a request body",
              built.method in ("POST", "PUT", "PATCH"), built.method)

    # THE CANARY. `run` refuses a config carrying a published example value, so a template with
    # a hardcoded one would write a file the tool then rejects -- or worse, one that measures
    # whether a bot recognises a famous string.
    canaries = (cfg.get("oracle_context") or {}).get("canaries") or []
    check("the config is born with a canary", len(canaries) == 1, str(canaries))
    if canaries:
        check("...that this tool minted", ht.looks_like_ours(canaries[0]), canaries[0])
        check("...and that is not one of the published example values",
              canaries[0] not in ht.published_canaries(),
              "init writes a canary anyone can read in this repository")
    check("the verifier that proves it was planted is there too",
          bool((cfg.get("oracle_context") or {}).get("honeytoken_verify")),
          "without it an unplanted canary is indistinguishable from a bot that held")

    # A FIXED VALUE WOULD PASS EVERY CHECK ABOVE. The property is uniqueness, so it needs two.
    second = yaml.safe_load(init_config.render(out="mybot.yaml", url="https://x.example.com/c",
                                               name="mybot"))
    check("two runs do not mint the same canary",
          (second.get("oracle_context") or {}).get("canaries") != canaries,
          "the canary is fixed, which makes it published the moment anyone runs init twice")

    # --- THE COMMAND, END TO END -------------------------------------------------------------
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "mybot.yaml")
        env = dict(os.environ, PYTHONPATH=HERE)
        r = subprocess.run([sys.executable, os.path.join(HERE, "cli.py"), "init",
                            "--out", out, "--url", "http://localhost:9/chat"],
                           capture_output=True, text=True, env=env)
        check("`qatration init` runs and exits 0", r.returncode == 0,
              (r.stdout + r.stderr)[-300:])
        check("...and writes the file", os.path.exists(out), out)
        said = r.stdout
        check("...and tells the user to plant the canary, which no tool can do for them",
              "system prompt" in said.lower(), said[:200])
        check("...and names onboard as the next step",
              "onboard" in said, said[:200])

        # NEVER CLOBBER. The file being replaced holds a canary that may already be planted in
        # a live system, and a working endpoint mapping somebody spent an afternoon on.
        again = subprocess.run([sys.executable, os.path.join(HERE, "cli.py"), "init",
                                "--out", out], capture_output=True, text=True, env=env)
        # THE CODE, not merely non-zero. It was 1, which the exit table reserves for the
        # target having been exploited or breached -- and there is no target here yet. A
        # refused invocation is 2, which is the reading `run` applies to its own overwrite
        # refusal, and `!= 0` could not tell the two apart.
        check("a second init refuses to overwrite", again.returncode == 2,
              "exit %s: it must refuse, and as a refused invocation rather than a finding"
              % again.returncode)
        forced = subprocess.run([sys.executable, os.path.join(HERE, "cli.py"), "init",
                                 "--out", out, "--force"],
                                capture_output=True, text=True, env=env)
        check("...unless --force says so", forced.returncode == 0,
              (forced.stdout + forced.stderr)[-200:])

        # AND THE FORCED WRITE CANNOT LEAVE HALF A CONFIG. `open(path, "w")` truncates
        # before it writes, so an interruption between those moments empties the file the
        # refusal above exists to protect -- the one holding a canary that may already be
        # planted in a live system. Asserted by making the write fail rather than by
        # reading the source: the config has to be either the old one or the new one.
        _before = io.open(out, encoding="utf-8").read()
        import init_config as _ic_t, workspace as _ws_t
        _real_render = _ic_t.render

        def _boom(*a, **k):
            raise RuntimeError("killed while writing")

        _ic_t.render = _boom
        _argv = sys.argv
        try:
            sys.argv = ["qatration init", "--out", out, "--force"]
            try:
                _ic_t.main()
            except RuntimeError:
                pass
            except SystemExit:
                pass
        finally:
            _ic_t.render = _real_render
            sys.argv = _argv
        check("a forced init that dies mid-write leaves the config it was replacing",
              io.open(out, encoding="utf-8").read() == _before,
              repr(io.open(out, encoding="utf-8").read()[:80]))
        check("...and leaves nothing beside it either",
              not os.path.exists(out + ".tmp"), out + ".tmp")

    # --- IT IS REACHABLE, AND IT IS FIRST ----------------------------------------------------
    import cli
    check("init is in the CLI dispatch table", "init" in cli.COMMANDS, sorted(cli.COMMANDS))
    check("...and is listed first, being the command that produces what the others need",
          list(cli.COMMANDS)[0] == "init", list(cli.COMMANDS)[:3])

    # The quickstart must not still open with a file the reader has to invent.
    readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    qs = readme[readme.find("## Quickstart"):][:900]
    check("the quickstart tells the reader how to get a config",
          "qatration init" in qs,
          "the quickstart still asks for mybot.yaml without saying where it comes from")

    # THE TEMPLATE'S AUTHORIZATION EXAMPLE IS A BLOCK THE GATE READS. It said `scope:` and
    # `authorised_by:`, two keys nothing reads; uncommented it was refused as "no authorization
    # block". Rendered by the command, uncommented the way a reader would, and asked of the
    # gate itself: every key it names is one `authorization` reads, and with the placeholders
    # replaced by what `onboard` prints for this origin it PASSES.
    import ast as _ast_au, subprocess as _sp_au, tempfile as _tf_au, yaml as _yaml_au
    import authorization as _az
    _wau = _tf_au.mkdtemp()
    _url_au = "https://api.acmeshop.example/v1/chat"
    _cfg_au = os.path.join(_wau, "remote.yaml")
    _sp_au.run([sys.executable, os.path.join(HERE, "cli.py"), "init", "--url", _url_au,
                "--out", _cfg_au], capture_output=True, text=True, timeout=120,
               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8"))
    _lines_au = open(_cfg_au, encoding="utf-8").read().splitlines()
    _at = [i for i, l in enumerate(_lines_au) if l.strip() == "# authorization:"]
    check("the template carries a commented authorization example", len(_at) == 1, str(_at))
    _blk_lines = []
    for _l in _lines_au[(_at or [len(_lines_au)])[0]:]:
        if not _l.startswith("#"):
            break
        _blk_lines.append(_l[2:] if _l.startswith("# ") else _l[1:])
    _blk = (_yaml_au.safe_load("\n".join(_blk_lines)) or {}).get("authorization") or {}
    _read = set()
    for _n in _ast_au.walk(_ast_au.parse(open(_az.__file__, encoding="utf-8").read())):
        if (isinstance(_n, _ast_au.Call) and getattr(_n.func, "attr", "") == "get"
                and getattr(_n.func.value, "id", "") == "auth" and _n.args
                and isinstance(_n.args[0], _ast_au.Constant)):
            _read.add(_n.args[0].value)
    check("the gate reads keys from the block (the scan can see them)",
          {"method", "token", "issued"} <= _read, str(sorted(_read)))
    check("...and every key the template's example names is one of them",
          bool(_blk) and not (set(_blk) - _read), str(sorted(set(_blk) - _read)))
    _tok_au, _day_au = _az.issue(_url_au, "k")
    _filled = dict(_blk, token=_tok_au, issued=_day_au)
    _ok_au, _why_au = _az.check({"name": "x", "url": _url_au, "authorization": _filled}, "k",
                                fetch=lambda u: _tok_au)
    check("...and filled in with the token for its origin, the example passes the gate",
          _ok_au, _why_au)

    # A NAME EVERY LATER COMMAND WOULD REFUSE IS REFUSED HERE. `init --name "my bot"` wrote a
    # config and the next command it named refused it as "not usable as a filename".
    import subprocess as _sp_nm, tempfile as _tf_nm
    _wn = _tf_nm.mkdtemp()
    _bad_nm = []
    for _i_nm, _nm in enumerate(("my bot", "../evil", "bot/x", "", "a" * 80)):
        _cfg_nm = os.path.join(_wn, "n%d.yaml" % _i_nm)
        _pn = _sp_nm.run([sys.executable, os.path.join(HERE, "cli.py"), "init", "--name", _nm,
                          "--out", _cfg_nm], capture_output=True, text=True, timeout=120,
                         env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                  PYTHONIOENCODING="utf-8"))
        if _pn.returncode != 2 or os.path.exists(_cfg_nm):
            _bad_nm.append("%r: exit %s, file written %s" % (_nm, _pn.returncode,
                                                              os.path.exists(_cfg_nm)))
    check("init refuses a name later commands cannot use, and writes nothing",
          not _bad_nm, "; ".join(_bad_nm))
    _ok_nm = os.path.join(_wn, "ok.yaml")
    _po = _sp_nm.run([sys.executable, os.path.join(HERE, "cli.py"), "init", "--name",
                      "ok_name-1.2", "--out", _ok_nm], capture_output=True, text=True,
                     timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                           PYTHONIOENCODING="utf-8"))
    check("...while an ordinary one is written", _po.returncode == 0 and os.path.exists(_ok_nm),
          (_po.stdout or "")[-200:])
    # AND WITH NO --out, THE FILE IS NAMED AFTER THE TARGET. `init --name strbot` wrote
    # `mybot.yaml` on a stranger's first run, and a second bot's init was then refused over
    # the first one's file.
    _wd_nm = _tf_nm.mkdtemp()
    _pd = _sp_nm.run([sys.executable, os.path.join(HERE, "cli.py"), "init", "--name", "strbot"],
                     capture_output=True, text=True, timeout=120, cwd=_wd_nm,
                     env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8"))
    check("init --name with no --out writes <name>.yaml, not mybot.yaml",
          (_pd.returncode, sorted(os.listdir(_wd_nm))) == (0, ["strbot.yaml"]),
          "exit %s, wrote %s" % (_pd.returncode, sorted(os.listdir(_wd_nm))))
    # AND A URL THE GATE WOULD REFUSE. `localhost:8000/chat` was written, and the next
    # command called it a remote target to prove ownership of.
    _url_cfg = os.path.join(_wn, "badurl.yaml")
    _pu = _sp_nm.run([sys.executable, os.path.join(HERE, "cli.py"), "init", "--url",
                      "localhost:8000/chat", "--out", _url_cfg], capture_output=True,
                     text=True, timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                                      PYTHONIOENCODING="utf-8"))
    check("init refuses a url with no scheme, suggesting the one it meant, and writes nothing",
          _pu.returncode == 2 and not os.path.exists(_url_cfg)
          and "http://localhost:8000/chat" in ((_pu.stdout or "") + (_pu.stderr or "")),
          "exit %s" % _pu.returncode)

    print("\n%d/%d passed" % (checks - len(fails), checks))
    for f in fails:
        print("  ! " + f)
    if fails:
        return 1
    print("\nOK — what init writes is a config the adapter accepts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
