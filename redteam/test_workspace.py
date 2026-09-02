"""One place decides where artifacts go — no model, no network.

Thirteen modules used to answer that question and they answered it four different ways:
`Path(__file__).resolve().parents[1] / "out"`, `os.path.join(ROOT, "out")`,
`os.path.join(os.path.dirname(ROOT), "out")`, and a spelled-out double `dirname` — because
`ROOT` means the package directory in some files and the repository in others. Two more
built a RELATIVE default, `os.path.join("out", …)`, which is a working-directory dependency
by another name in a repo that had just finished removing its last one.

All of them landed on the same folder, which is the kind of agreement that holds until it
does not: one module moved a directory deeper, or one `ROOT` renamed to match its
neighbours, and a writer starts writing where no reader looks. A result nobody reads is a
gap reported as a measurement, arriving by the dullest possible route.

The checks below are in two halves. The first is arithmetic on `workspace.out_dir()`. The
second is the one that matters and the one that goes stale on its own: **every module that
names an artifact root must resolve to the same string**, asserted by importing them and
comparing, not by reading the source. A fourteenth module can be added tomorrow with its own
`parents[1] / "out"` and this is what says so.

    python test_workspace.py       # exits 1 on any failure (CI gate)
"""
import sys, os, ast, glob, importlib
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)

import workspace

# Every module that holds an artifact root, and the name it holds it under. Listed rather
# than discovered, because a module that STOPS exposing one has to be noticed too: a missing
# name fails here instead of quietly shrinking the check.
ROOTED = {
    "baseline": "OUT_DIR", "benign": "OUT_DIR", "build_index": "OUT",
    "compare_recon": "OUT_DIR", "compare_targets": "OUT_DIR", "defense_report": "OUT_DIR",
    "detector_coverage": "OUT", "discrimination": "OUT", "history": "OUT",
    "model_matrix": "OUT", "rejudge": "OUT_DIR", "run_adaptive": "OUT_DIR",
    "run_redteam": "OUT_DIR",
}


def builds_its_own_root(src):
    """-> [(line, expression)] for every path expression that joins the literal "out".

    Parsed rather than grepped: the last gate written here failed on the docstring that
    explained the defect it guarded, and a check that fires on its own explanation is one
    nobody keeps. `workspace.py` itself is the one file allowed to do this — it is the place
    the answer is supposed to live.
    """
    found = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            f = node.func
            name = getattr(f, "attr", "")
            if name == "join" and any(isinstance(a, ast.Constant) and a.value == "out"
                                      for a in node.args):
                found.append((node.lineno, "os.path.join(..., 'out')"))
        # Path(...) / "out"
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant) and node.right.value == "out"):
            found.append((node.lineno, "Path(...) / 'out'"))
    return found


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- what out_dir() answers ----------------------------------------------------------
    real = os.environ.pop(workspace.ENV_VAR, None)
    try:
        check("with nothing set, the root is <repo>/out",
              workspace.out_dir() == os.path.join(ROOT, "out"), workspace.out_dir())

        os.environ[workspace.ENV_VAR] = os.path.join(ROOT, "elsewhere")
        check("a named root is honoured",
              workspace.out_dir() == os.path.join(ROOT, "elsewhere"), workspace.out_dir())

        # A relative root is the working-directory dependency this repo just removed, so it
        # is resolved once, here, rather than re-resolved by whoever opens the file.
        os.environ[workspace.ENV_VAR] = "runs/7f3a"
        check("a relative root is made absolute",
              os.path.isabs(workspace.out_dir()), workspace.out_dir())

        os.environ[workspace.ENV_VAR] = "   "
        check("a blank root falls back to the default, rather than to the current directory",
              workspace.out_dir() == os.path.join(ROOT, "out"), workspace.out_dir())
    finally:
        os.environ.pop(workspace.ENV_VAR, None)
        if real is not None:
            os.environ[workspace.ENV_VAR] = real

    # --- and the assertion that keeps mattering ------------------------------------------
    disagree = []
    for mod, attr in sorted(ROOTED.items()):
        try:
            m = importlib.import_module(mod)
        except Exception as e:
            disagree.append(f"{mod}: will not import ({type(e).__name__}: {e})")
            continue
        if not hasattr(m, attr):
            disagree.append(f"{mod}: no longer exposes {attr}")
            continue
        got = os.path.abspath(str(getattr(m, attr)))
        if got != os.path.abspath(workspace.OUT):
            disagree.append(f"{mod}.{attr} = {got}")
    check(f"all {len(ROOTED)} modules resolve to the one root",
          not disagree, "; ".join(disagree))

    # --- nobody builds it again -----------------------------------------------------------
    offenders = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base == "workspace.py" or base.startswith("test_"):
            continue
        for lineno, what in builds_its_own_root(open(fp, encoding="utf-8").read()):
            offenders.append(f"{base}:{lineno}: {what}")
    check("no module computes the artifact root itself", not offenders, "; ".join(offenders))

    # Both directions, or a scan that matches nothing reads exactly like a clean repo.
    check("...and the scan can see an os.path.join form",
          builds_its_own_root('import os\nX = os.path.join(ROOT, "out")\n'))
    check("...and the Path form too",
          builds_its_own_root('from pathlib import Path\nX = Path(".") / "out"\n'))
    check("...and it does not fire on prose naming the pattern",
          not builds_its_own_root('def f():\n    """It used to be os.path.join(ROOT, "out").”"""\n'))

    # --- and the two naming conventions live here too -----------------------------------
    check("a per-model copy is recognised, and the canonical file is not",
          workspace.is_per_model_copy("results_opsbot_qwen.json")
          and not workspace.is_per_model_copy("results_opsbot.json"))
    check("...on a full path as well as a bare name",
          workspace.is_per_model_copy(os.path.join("a", "b", "results_x_y.json")))

    names = ["nemo", "nemo-inputonly", "portalagent", "with_underscore"]
    check("a target resolves to itself", workspace.target_of("portalagent", names) == "portalagent")
    check("a per-model tag is stripped",
          workspace.target_of("portalagent_mistral-nemo", names) == "portalagent")
    check("the longest matching name wins over its own prefix",
          workspace.target_of("nemo-inputonly_qwen", names) == "nemo-inputonly")
    check("a name containing an underscore resolves to itself",
          workspace.target_of("with_underscore", names) == "with_underscore")
    check("an unknown stem resolves to nothing, so the caller can say so",
          workspace.target_of("somebody-elses-bot", names) is None)

    # Both conventions were carried in six and two modules respectively, each spelled out by
    # hand. This is what says a ninth module has grown its own copy.
    RULES = {'count("_")': "the per-model copy rule",
             'split("_")[0]': "resolving a target from a filename",
             # A config's `name:` is optional and eleven shipped ones omit it, so the name
             # falls back to the filename stem. That was written out four times and the copy
             # in `sarif` did not have the fallback at all: it compared `cfg["name"]` alone,
             # so those eleven targets exported every finding with no location — 148 of 498
             # across the fleet, 95 of them on httpbot, while the module's own comment says
             # the anchor exists so a reviewer gets a file that is really there.
             'len("targets_")': "deriving a target name from a config filename"}
    strays = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base in ("workspace.py",) or base.startswith("test_"):
            continue
        src = open(fp, encoding="utf-8").read()
        for lineno, line in enumerate(src.splitlines(), 1):
            code = line.split("#")[0]
            for needle, what in RULES.items():
                if needle in code and not code.lstrip().startswith(('"', "'")):
                    strays.append(f"{base}:{lineno}: {what}")
    check("no module re-implements an artifact-naming rule", not strays, "; ".join(strays))

    # --- NOBODY WRITES INTO A DIRECTORY NOBODY MADE ------------------------------------------
    #
    # `OUT` is a path, not a directory: it is resolved at import and deliberately NOT created
    # there, or `qatration <anything> --help` would litter the filesystem. So whoever writes
    # has to create it, and that was remembered in four modules and forgotten in two.
    #
    # `benign` was the expensive one. Walked as a first-time user against a live model: fifty
    # probes sent, all fifty rows printed, a tally printed, and then FileNotFoundError on the
    # write. The traceback goes to stderr and the table to buffered stdout, so the failure
    # scrolls past ABOVE the results and the last thing on screen is `36/50 clean` -- a
    # summary that reads like a finished run. Exit 1, no baseline written, and every later
    # finding on that target unattributable because `baseline.rates` had nothing to read.
    #
    # It hid because the README's order covers it: `run` creates the directory and comes
    # first there. The order `init` prints INTO THE CONFIG IT WRITES puts `benign` before
    # `run`, so following the tool's own instructions is the way to meet it.
    #
    # By AST, so a paragraph mentioning OUT_DIR cannot answer for the code, and asking about
    # the WRITE rather than about the module: a file that reads from OUT all day is fine.
    import ast as _ast2
    _unmade = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base in ("workspace.py",) or base.startswith("test_"):
            continue
        try:
            tree = _ast2.parse(open(fp, encoding="utf-8").read())
        except SyntaxError:
            continue
        makes = any(getattr(n.func, "attr", None) == "makedirs"
                    for n in _ast2.walk(tree) if isinstance(n, _ast2.Call))
        goes_through = any(getattr(n.func, "attr", None) == "artifact"
                           for n in _ast2.walk(tree) if isinstance(n, _ast2.Call))
        for n in _ast2.walk(tree):
            if not (isinstance(n, _ast2.Call) and getattr(n.func, "id", None) == "open"):
                continue
            mode = ""
            if len(n.args) > 1 and isinstance(n.args[1], _ast2.Constant):
                mode = str(n.args[1].value)
            if "w" not in mode and "a" not in mode:
                continue
            # THE PATH IS USUALLY IN A VARIABLE, WHICH THE FIRST VERSION OF THIS MISSED. It
            # looked for OUT_DIR among the names INSIDE the open() call, so it caught
            # `open(os.path.join(OUT_DIR, x), "w")` and not the two-line form every module
            # here actually uses. Mutating benign back to the broken write left it green —
            # a check about a value, written about an expression. Assignments are followed.
            _tainted = set()
            for a in _ast2.walk(tree):
                if not isinstance(a, _ast2.Assign):
                    continue
                if {"OUT_DIR", "OUT", "WORKSPACE_OUT"} & {
                        x.id for x in _ast2.walk(a.value) if isinstance(x, _ast2.Name)}:
                    _tainted |= {t.id for t in a.targets if isinstance(t, _ast2.Name)}
            names = {x.id for x in _ast2.walk(n.args[0]) if isinstance(x, _ast2.Name)} \
                if n.args else set()
            if not (({"OUT_DIR", "OUT", "WORKSPACE_OUT"} | _tainted) & names):
                continue
            if makes or goes_through:
                continue
            _unmade.append(f"{base}:{n.lineno}")
    check("every module writing into the artifact directory creates it first",
          not _unmade,
          "opens a path under OUT for writing without makedirs or workspace.artifact: "
          + ", ".join(_unmade))

    # --- AND THE RULE ITSELF, not only that one copy of it exists ---------------------------
    #
    # The needle scan above is a spellcheck: it says nobody wrote the pattern out again, and
    # nothing about what the surviving copy does. Both halves are asserted here, because the
    # defect was in the behaviour of the half that had no fallback.
    check("a config that names itself is called what it says",
          workspace.config_name("/x/targets_thing.yaml", {"name": "acme-bot"}) == "acme-bot")
    check("...and one that does not is called after its file",
          workspace.config_name("/x/targets_httpbot.yaml", {}) == "httpbot")
    check("...which is what lets SARIF anchor a finding to a config that omits `name:`",
          workspace.config_name("/x/targets_httpbot.yaml", {}) != "")
    check("a path that is not a targets_ file keeps its own stem",
          workspace.config_name("/x/something.yaml", {}) == "something.yaml")
    # ...and every reader agrees, since disagreeing is what cost the locations.
    import yaml as _y
    from target import target_configs as _tc
    _by_helper = {workspace.config_name(fp) for fp in _tc()}
    import detector_coverage as _dc
    check("the coverage map and the helper name the same fleet",
          set(_dc.contexts()) <= _by_helper,
          f"only in coverage: {sorted(set(_dc.contexts()) - _by_helper)[:4]}")
    check("...and so does fleet_names", workspace.fleet_names() <= _by_helper,
          f"only in fleet_names: {sorted(workspace.fleet_names() - _by_helper)[:4]}")

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one place decides where artifacts go.")


def check_evidence_guard():
    """A run must not silently replace a results file somebody committed.

    WALKED INTO RATHER THAN IMAGINED. Eight attacks were run against a shipped practice bot from
    inside the checkout, and `out/results_httpbot.json` went from 1.6 MB of a full sweep to
    16 KB of an experiment. `detector_coverage` immediately reported 958 fewer probes, and the
    README, the site and the false-positive rates are all recounted from those files. Restored
    from git, which is the only reason it is a story rather than a wrong number in a release.

    The guard lives at the resource: both commands that write evidence call one function, so a
    third one cannot arrive without it by being written somewhere else.
    """
    import io
    import subprocess
    import tempfile
    from workspace import refuse_to_overwrite_evidence, tracked_by_git

    bad = []

    def want(label, ok, detail=""):
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            bad.append("%s: %s" % (label, detail))

    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                   GIT_CONFIG_SYSTEM=os.path.join(d, "none"))

        def git(*a):
            return subprocess.run(["git", "-C", d] + list(a), capture_output=True, text=True,
                                  env=env)

        git("init", "-q")
        git("config", "user.name", "QAtration")
        git("config", "user.email", "qatration@gmail.com")
        kept = os.path.join(d, "results_kept.json")
        io.open(kept, "w", encoding="utf-8").write('{"results": []}')
        git("add", "-A")
        r = git("commit", "-qm", "evidence")
        if r.returncode != 0 and "cannot spawn" in (r.stdout + r.stderr).lower():
            print("SKIP  the evidence guard: git cannot commit here, so it was NOT checked")
            return bad

        loose = os.path.join(d, "results_loose.json")
        io.open(loose, "w", encoding="utf-8").write('{"results": []}')

        want("a committed results file is recognised as evidence", tracked_by_git(kept))
        want("...and an uncommitted one is not", not tracked_by_git(loose))
        want("writing over the committed one is refused",
             bool(refuse_to_overwrite_evidence(kept)))
        want("...and the refusal says how to write elsewhere",
             "QATRATION_OUT" in refuse_to_overwrite_evidence(kept))
        want("...and names the file, so the reader knows what was nearly lost",
             "results_kept.json" in refuse_to_overwrite_evidence(kept))
        want("the flag is an escape hatch, not a suggestion",
             refuse_to_overwrite_evidence(kept, force=True) == "")
        want("an ordinary artifact is written without ceremony",
             refuse_to_overwrite_evidence(loose) == "")
        want("a file that does not exist yet is not evidence",
             refuse_to_overwrite_evidence(os.path.join(d, "results_new.json")) == "")

    # BOTH WRITERS, EXECUTED RATHER THAN GREPPED. The first version of this checked that the
    # string `refuse_to_overwrite_evidence(` appeared in each module, and a mutation proved what
    # that is worth: `_refusal = None and refuse_to_overwrite_evidence(...)` keeps the string,
    # disarms the guard, and passed. Both commands are run for real against a committed file
    # and have to refuse. Neither reaches a target, because both check before they send.
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                   GIT_CONFIG_SYSTEM=os.path.join(d, "none"), QATRATION_OUT=d)

        def git(*a):
            return subprocess.run(["git", "-C", d] + list(a), capture_output=True, text=True,
                                  env=env)

        git("init", "-q")
        git("config", "user.name", "QAtration")
        git("config", "user.email", "qatration@gmail.com")
        for name in ("results_httpbot.json", "benign_httpbot.json"):
            io.open(os.path.join(d, name), "w", encoding="utf-8").write('{"rows": [], "results": []}')
        git("add", "-A")
        r = git("commit", "-qm", "evidence")
        if r.returncode != 0 and "cannot spawn" in (r.stdout + r.stderr).lower():
            print("SKIP  the two commands: git cannot commit here, so they were NOT run")
            return bad

        cli = os.path.join(HERE, "cli.py")
        for label, argv in (
                ("qatration run", [cli, "run", "--target-config",
                                   os.path.join(HERE, "targets_httpbot.yaml"),
                                   "--attacks", os.path.join(HERE, "attacks_refusal.yaml"),
                                   "--trials", "1"]),
                ("qatration benign", [cli, "benign", "--target", "httpbot"])):
            # A GUARD THAT DOES NOT FIRE DOES NOT HANG THE SUITE, it fails by name. With the
            # check disarmed, `benign` starts its fifty-probe corpus against a live bot and the
            # call times out; without this the suite dies on a TimeoutExpired traceback and
            # says nothing about which guard was missing. Sixty seconds is generous: a guard
            # that works answers in under one.
            try:
                proc = subprocess.run([sys.executable] + argv, capture_output=True, text=True,
                                      env=env, timeout=60)
                said = proc.stdout + proc.stderr
                code = proc.returncode
            except subprocess.TimeoutExpired:
                said, code = "it started working instead of refusing", -1
            # 2, NOT 5, AND THE NUMBER IS THE POINT. This was pinned at 5 with nothing
            # saying why, next to the canary preconditions it shares no cause with. The
            # README's rule for these codes is that "the reason has to be recoverable from
            # the number alone", and 5 is documented there as "the canary is one this tool
            # publishes, or a declared honeytoken was not found in the target" -- so a CI
            # mapping the number would send somebody to check a canary that is fine. 2 is
            # "the config or the invocation was refused", nothing was sent either way, and
            # what clears this is a flag or QATRATION_OUT rather than anything about the bot.
            want("%s refuses to replace a committed artifact" % label,
                 code == 2, "exit %s: %s" % (code, said.strip()[:160]))
            want("...and says which file and how to write elsewhere",
                 "REFUSED" in said and "QATRATION_OUT" in said, said.strip()[:160])
            want("...and the file on disk is untouched",
                 io.open(os.path.join(d, "results_httpbot.json"), encoding="utf-8").read()
                 == '{"rows": [], "results": []}')
    return bad


if __name__ == "__main__":
    _bad = check_evidence_guard()
    if _bad:
        for _b in _bad:
            print('  !', _b)
        sys.exit(1)
    main()
