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

    print("\n%d/%d passed" % (checks - len(fails), checks))
    for f in fails:
        print("  ! " + f)
    if fails:
        return 1
    print("\nOK — what init writes is a config the adapter accepts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
