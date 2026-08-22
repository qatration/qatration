"""The install is a claim too, and it can be wrong in the same way everything else here can.

A dependency list is a statement about what the code needs. Written by hand it is a statement
about what was installed on the machine where it was written, which is a different thing and
drifts the moment an import is added. The failure is the familiar one: `pip install qatration`
succeeds, the first sweep dies on `ModuleNotFoundError`, and the install reported a success it
had not achieved.

So the dependency list is re-derived here from the code and compared with what is declared. It
is an AST walk rather than a grep because two different questions have to be asked of the same
files: which modules a command pulls in when it starts, and what those modules need in order to
work. A lazily imported dependency answers no to the first and yes to the second.

Offline. No model, no network, no fleet.
"""

import ast
import io
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import cli  # noqa: E402
import workspace  # noqa: E402

# Distribution name -> the module name it provides. Two entries because there are two
# dependencies; if this map ever needs a third, the dependency deserves a second look.
PROVIDES = {"pyyaml": "yaml", "pyfiglet": "pyfiglet"}

LOCAL = {f[:-3] for f in os.listdir(HERE) if f.endswith(".py")}


def _is_stdlib(name):
    """Is this module part of the standard library?

    `sys.stdlib_module_names` arrived in 3.10, and reading it through `getattr(..., ())` gave an
    EMPTY SET on 3.9 — so every stdlib import counted as an undeclared dependency and the
    dependency check failed with a list of forty names. The package claims `>=3.9` and CI runs
    that leg, so the check written to protect the oldest interpreter was the one thing
    guaranteed to fail on it. An empty default is not a safe default; it is a silent inversion.

    The fallback asks the import system where a module lives: built-in and frozen modules have
    no file, and everything else is stdlib exactly when its file sits under the stdlib prefix.
    """
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return name in names
    if name in sys.builtin_module_names:
        return True
    import importlib.util
    import sysconfig
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError, AttributeError):
        return False
    if spec is None:
        return False
    origin = spec.origin or ""
    if origin in ("built-in", "frozen"):
        return True
    stdlib = sysconfig.get_paths().get("stdlib") or ""
    if not stdlib or not origin:
        return False
    real = os.path.realpath(origin)
    return (real.startswith(os.path.realpath(stdlib))
            and "site-packages" not in real and "dist-packages" not in real)


def _imports(nodes):
    found = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def module_level_imports(path):
    """What a file pulls in the moment it is imported. Top level only.

    This decides which modules are on the core path, and top level is the right cut for that:
    `run_redteam.py` imports a target adapter from inside the branch that selects it, so
    `targets_dvla` and the model framework behind it are reached only by a run that actually
    points at one of the practice bots.
    """
    tree = ast.parse(io.open(path, encoding="utf-8").read(), filename=path)
    return _imports(tree.body)


def every_import(path):
    """Every import anywhere in a file, including inside functions.

    A different question from the one above, and the difference cost a real assertion: the
    dependency list came out missing `pyfiglet`, because `encoders.py` imports it lazily inside
    the function that needs it. Deferring an import changes WHEN it is paid, never WHETHER —
    the module still cannot do its job without it, and a wheel that omits it fails at the first
    ascii_art attack rather than at install.

    So where an import sits decides nothing here; which MODULE it sits in decides everything.
    Files off the core path are not scanned at all.
    """
    tree = ast.parse(io.open(path, encoding="utf-8").read(), filename=path)
    return _imports(ast.walk(tree))


def core_modules():
    """Every module reachable at import time from a shipped subcommand.

    This is the honest definition of "core": what a documented command drags in when it runs.
    Anything outside it is either a practice-fleet adapter or a development tool, and neither
    belongs in the default install.
    """
    seen, queue = set(), [m for m, _ in cli.COMMANDS.values()]
    while queue:
        name = queue.pop()
        if name in seen or name not in LOCAL:
            continue
        seen.add(name)
        path = os.path.join(HERE, name + ".py")
        tree = ast.parse(io.open(path, encoding="utf-8").read(), filename=path)
        for node in tree.body:
            if isinstance(node, ast.Import):
                queue.extend(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                queue.append(node.module.split(".")[0])
    return sorted(seen)


def declared_dependencies():
    """The runtime `dependencies` names from pyproject.toml, lowercased and stripped of specs.

    THROUGH `tools/licences.py`, which is the parser. This function used to keep its own, with
    its own tomllib fallback, and the fallback was the whole point: `requires-python` is 3.9 and
    tomllib arrived in 3.11, so a check that only runs on the newest interpreter is absent
    exactly where the support claim is widest. The copy that HAD the fallback was this one, and
    the copy everything else called -- `guard.py`, in all three of its modes -- did not, so the
    commit gate was a traceback on 3.9 and 3.10 and permanently red on the 3.9 leg of CI.

    One rule, one implementation. The reasoning now lives beside the code that does the work.
    """
    sys.path.insert(0, os.path.join(REPO, "tools"))
    import licences
    return {name for name, where in licences.declared(
        os.path.join(REPO, "pyproject.toml")).items() if where == "dependencies"}


def test_every_subcommand_resolves():
    """A command table is a promise that pressing Enter does something.

    IMPORTED, not parsed. This used to `ast.parse` each file and look for a top-level `def
    main`, while cli.py's comment claimed the test "imports every one of them" — so an
    import-time failure in `history` or `rejudge` or `coverage` would have sailed through and
    surfaced as a traceback on somebody's first Enter. The comment described the check that
    should have existed; now it describes the one that does.
    """
    import importlib
    for name, (module_name, blurb) in cli.COMMANDS.items():
        path = os.path.join(HERE, module_name + ".py")
        assert os.path.isfile(path), "%s -> %s.py does not exist" % (name, module_name)
        try:
            module = importlib.import_module(module_name)
        except Exception as e:
            raise AssertionError("qatration %s -> %s fails at import: %s: %s"
                                 % (name, module_name, type(e).__name__, e))
        assert callable(getattr(module, "main", None)), \
            "%s -> %s has no callable main()" % (name, module_name)
        assert blurb and blurb[0].islower(), "%s: help text should read as a phrase" % name
    print("  ok  %d subcommands import and expose main()" % len(cli.COMMANDS))


def test_requirements_txt_agrees_with_pyproject():
    """Two files stating the same dependency list, and only one of them was checked.

    `requirements.txt` says in its own header that this suite re-derives it and fails when the
    two disagree. It did not: `declared_dependencies()` reads pyproject.toml alone, and nothing
    anywhere read requirements.txt. A file whose header describes a guard that does not exist
    is worse than one with no header, because it is the reason nobody checks by hand.
    """
    path = os.path.join(REPO, "requirements.txt")
    assert os.path.isfile(path), "requirements.txt is gone; the header's claim went with it"
    listed = set()
    for line in io.open(path, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        name = line.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()
        if name:
            listed.add(name.lower())
    declared = declared_dependencies()
    assert listed == declared, \
        "requirements.txt lists %s, pyproject.toml lists %s" % (sorted(listed), sorted(declared))
    print("  ok  requirements.txt and pyproject.toml list the same dependencies: %s"
          % sorted(listed))


def _licences():
    """`tools/licences.py`, the one place that decides. Imported rather than copied: the commit
    hook reads the same module, and a second list here would be the one left un-updated."""
    import importlib.util
    path = os.path.join(REPO, "tools", "licences.py")
    spec = importlib.util.spec_from_file_location("qat_licences", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_dependency_carries_a_copyleft_licence():
    """Every name in pyproject.toml, runtime and extras alike, is a package we may hand on."""
    lic = _licences()
    found = lic.problems(os.path.join(REPO, "pyproject.toml"))
    assert not found, "; ".join(found)
    named = lic.declared(os.path.join(REPO, "pyproject.toml"))
    print("  ok  every declared dependency is a known permissive licence: %s"
          % sorted(f"{n} ({lic.ALLOWED[n]})" for n in named))


def test_the_licence_gate_would_catch_a_copyleft_package():
    """The gate above, shown failing on the package that actually got past it.

    A review said "pymupdf AGPL-3.0 undeclared", and the fix applied was to DECLARE it as an
    optional extra — putting an AGPL-3.0-or-commercial package into an Apache-2.0 project's own
    metadata. It was caught by a question, not by a check. A list nothing is measured against is
    a list, so the refusal is exercised here rather than trusted.
    """
    import tempfile
    lic = _licences()
    assert "pymupdf" not in lic.ALLOWED, \
        "pymupdf is AGPL-3.0-or-commercial and must never be on the allowed list"
    for spec in ("pymupdf>=1.24", "PyMuPDF", "pymupdf[extra]>=1.0", "PyMuPDF ; sys_platform"):
        assert lic.dist_name(spec) == "pymupdf", \
            "the name reader would not recognise %r, so the gate would pass it" % spec

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "pyproject.toml")
        io.open(p, "w", encoding="utf-8").write(
            '[project]\nname = "x"\nversion = "0"\ndependencies = ["PyYAML>=5.4"]\n'
            '[project.optional-dependencies]\nfixtures = ["pymupdf>=1.24"]\n')
        found = lic.problems(p)
        assert found and "pymupdf" in found[0] and "AGPL" in found[0], \
            "the gate did not refuse a planted AGPL extra: %s" % found
        assert "optional-dependencies.fixtures" in found[0], \
            "the refusal does not say WHERE the package was declared: %s" % found
    print("  ok  the licence gate refuses the package that got past it once, and says where")


def test_declared_dependencies_match_the_code():
    """The list in pyproject.toml is re-derived, not trusted."""
    needed = set()
    for name in core_modules():
        for mod in every_import(os.path.join(HERE, name + ".py")):
            if not _is_stdlib(mod) and mod not in LOCAL:
                needed.add(mod)

    declared = {PROVIDES.get(d, d) for d in declared_dependencies()}

    missing = needed - declared
    assert not missing, (
        "imported by a shipped command but NOT declared in pyproject.toml: %s. "
        "An install that omits these fails on the first sweep." % sorted(missing))

    unused = declared - needed
    assert not unused, (
        "declared in pyproject.toml but not imported by any shipped command: %s. "
        "Every install pays for these." % sorted(unused))
    print("  ok  dependencies re-derived from the code match what is declared: %s"
          % sorted(needed))


def test_no_model_framework_on_the_core_path():
    """The property the fleet extras exist to preserve, asserted rather than assumed.

    If a model framework ever reaches the core import graph, the split is a fiction and the
    default install quietly grows by hundreds of megabytes.
    """
    heavy = ("langchain", "langchain_core", "langchain_ollama", "openai", "smolagents",
             "nemoguardrails", "transformers", "torch")
    for name in core_modules():
        got = every_import(os.path.join(HERE, name + ".py"))
        bad = sorted(set(heavy) & got)
        assert not bad, "%s.py imports %s; that is a fleet dependency" % (name, bad)
    print("  ok  no model framework on the core import path (%d modules)" % len(core_modules()))


def test_package_rename_and_out_dir_agree():
    """pyproject renames the directory; workspace detects the rename to place evidence.

    Two files, one fact. If `package-dir` stops mapping `qatration` to `redteam`, or
    `in_checkout()` stops looking for `redteam`, an installed copy writes its evidence into
    site-packages and says nothing.
    """
    text = io.open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8").read()
    assert 'package-dir = { qatration = "redteam" }' in text, \
        "pyproject no longer maps qatration -> redteam"
    marker = io.open(os.path.join(HERE, "workspace.py"), encoding="utf-8").read()
    assert 'os.path.join(REPO, "redteam")' in marker, \
        "workspace.in_checkout() no longer looks for the directory pyproject renames"

    assert workspace.in_checkout(), "running from the repository, so this must be true"
    assert workspace.out_dir() == os.path.join(REPO, "out")
    assert workspace.out_origin() == "repository checkout"
    print("  ok  the rename and the evidence location are checked against each other")


def test_the_build_tree_holds_nothing_the_source_does_not():
    """A wheel is permanent, and `build/lib` is where a file goes to outlive its source.

    setuptools reuses `build/lib` between builds and does not prune it, so anything that was in
    the source when SOME earlier build ran is still there. The end-to-end suites write
    `attacks_e2e_*_tmp.yaml` and `targets_e2e_*_tmp.yaml` into `redteam/` while they run;
    `.gitignore` covers them, so git never sees them and no reviewer of a diff ever will --
    and `[tool.setuptools.package-data]` ships `*.yaml`, so a build during a suite run copies
    them in and they stay.

    Measured on this machine before the gate existed: ten `*_tmp.yaml` files in `build/lib`,
    which `python -m build` would have packaged. A stranger installing that wheel gets phantom
    targets that `target_configs()` enumerates.

    CI never sees this -- `actions/checkout` gives a clean tree with no `build/` -- which is
    exactly why it needs a check that runs where the risk is. An absent `build/` passes.

    Not a list of known-bad names: anything in the build tree with no counterpart in the source
    fails, whatever it is.
    """
    lib = os.path.join(REPO, "build", "lib")
    if not os.path.isdir(lib):
        print("  ok  no build/ tree on this machine, so nothing stale can be packaged")
        return

    stale = []
    for root, _dirs, files in os.walk(lib):
        for name in files:
            if name.endswith(".pyc") or "__pycache__" in root:
                continue
            built = os.path.join(root, name)
            rel = os.path.relpath(built, lib).replace("\\", "/")
            # build/lib/qatration/x -> redteam/x, the rename `pyproject.toml` declares
            src = rel.split("/", 1)[1] if rel.startswith("qatration/") else rel
            if not os.path.exists(os.path.join(REPO, "redteam", src)) and \
               not os.path.exists(os.path.join(REPO, src)):
                stale.append(rel)

    assert not stale, (
        "%d file(s) in build/lib have no counterpart in the source and would be packaged by "
        "`python -m build` on this machine: %s%s\n"
        "Delete the build/ directory before building. CI is unaffected -- it checks out clean -- "
        "so this only bites a local release, and a wheel on PyPI can be yanked but not "
        "unpublished." % (len(stale), ", ".join(sorted(stale)[:6]),
                          " ..." if len(stale) > 6 else ""))
    print("  ok  build/lib holds nothing the source does not")


def test_one_version_number():
    """pyproject.toml and __init__.py must agree, because pip believes one and the artifact
    header prints the other, and a bug report that quotes a version nobody shipped is worse
    than one that quotes none."""
    text = io.open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8").read()
    declared = text.split("\nversion = ", 1)[1].split("\n", 1)[0].strip().strip('"').strip("'")
    assert declared == cli.package_version(), \
        "pyproject says %r, __init__.py says %r" % (declared, cli.package_version())
    print("  ok  one version number, %s, in both places" % declared)


def test_out_dir_honours_the_env_var():
    old = os.environ.get(workspace.ENV_VAR)
    try:
        os.environ[workspace.ENV_VAR] = os.path.join("~", "somewhere")
        got = workspace.out_dir()
        assert os.path.isabs(got), "an artifact root must be absolute: %r" % got
        assert "~" not in got, "~ must be expanded, not passed through: %r" % got
        assert workspace.out_origin() == "$QATRATION_OUT"
    finally:
        if old is None:
            os.environ.pop(workspace.ENV_VAR, None)
        else:
            os.environ[workspace.ENV_VAR] = old
    print("  ok  $QATRATION_OUT wins and is made absolute")


def _cli(args):
    return subprocess.run([sys.executable, os.path.join(HERE, "cli.py")] + args,
                          capture_output=True, text=True, timeout=120)


def test_cli_help_version_and_unknown_command():
    p = _cli([])
    assert p.returncode == 0, "bare `qatration` should print usage and succeed"
    assert "usage: qatration <command>" in p.stdout
    for name in cli.COMMANDS:
        assert name in p.stdout, "%r missing from usage" % name

    p = _cli(["--version"])
    assert p.returncode == 0 and p.stdout.startswith("qatration "), p.stdout

    p = _cli(["definitely-not-a-command"])
    assert p.returncode == 2, "an unknown command must fail, not fall through"
    assert "unknown command" in p.stderr
    print("  ok  help, version and an unknown command all behave")


def test_a_subcommand_reaches_the_real_module():
    """--help through the dispatcher, because the dispatcher rewrites argv and could get it
    wrong in a way no import check would notice."""
    p = _cli(["run", "--help"])
    assert p.returncode == 0, p.stderr[-600:]
    assert "--target-config" in p.stdout, "run --help did not reach run_redteam's parser"
    assert "qatration run" in p.stdout, \
        "argv[0] was not rewritten, so the usage line names the wrong program"
    print("  ok  `qatration run --help` reaches run_redteam and names itself correctly")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print("packaging: %d checks" % len(fns))
    for fn in fns:
        fn()
    print("all packaging checks passed")
