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
             'split("_")[0]': "resolving a target from a filename"}
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

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one place decides where artifacts go.")


if __name__ == "__main__":
    main()
