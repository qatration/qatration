"""Which packages this project may ask pip to install, and under what licence.

ONE LIST, TWO CALLERS. `test_packaging.py` reads it so a CI run fails, and the commit hook reads
it so a working tree never gets that far. A second copy would be a second thing to update, and
the copy that is not updated is the one that lets a package through.

The list is short on purpose and adding to it is meant to be a decision rather than an edit.
QAtration is Apache 2.0, and `pip install qatration[...]` runs on somebody else's machine and in
somebody else's build: a copyleft package named in this metadata is a licence obligation handed
to every installer, arriving through a file nobody reads twice.

IT HAS ALREADY HAPPENED ONCE, in the direction that looks like diligence. A review said "pymupdf
AGPL-3.0 undeclared" — pymupdf is imported by `site/fixtures/gen_fixtures.py`, a one-off
generator for four PDFs that are committed and that the wheel does not contain — and the fix
applied was to DECLARE it, as an optional extra. That is backwards: the undeclared import was
harmless because nothing ships it, and declaring it put an AGPL-3.0-or-commercial package into
an Apache-2.0 project's own metadata. It was caught by a question, not by a check. This is the
check.

Licences are pinned by NAME here rather than read from the installed distribution, because the
suite runs offline on a machine where `[fleet]` is not installed — a check that can only run
where the packages are present is a check that does not run in CI.
"""
import os

ALLOWED = {
    "pyyaml": "MIT",
    "pyfiglet": "MIT",
    "langchain": "MIT",
    "langchain-core": "MIT",
    "langchain-ollama": "MIT",
}

# Named so the refusal can say what is wrong rather than only that something is. Not a gate on
# its own — anything absent from ALLOWED is refused whether or not it appears here.
KNOWN_COPYLEFT = {
    "pymupdf": "AGPL-3.0-or-commercial",
    "fitz": "AGPL-3.0-or-commercial (the import name of pymupdf)",
    "ghostscript": "AGPL-3.0",
    "mysql-connector-python": "GPL-2.0-with-FOSS-exception",
    "paramiko": "LGPL-2.1",
    "chardet": "LGPL-2.1",
    "unrar": "proprietary",
    "pyqt5": "GPL-3.0-or-commercial",
    "pyqt6": "GPL-3.0-or-commercial",
}


def dist_name(spec):
    """`PyMuPDF[x] >= 1.24` -> `pymupdf`. Extras and version specifiers are not the name."""
    for cut in (">", "<", "=", "!", "~", "[", ";", " ", "\t"):
        spec = spec.split(cut)[0]
    return spec.strip().lower()


def declared(pyproject_path):
    """-> {distribution name: where in pyproject.toml it was found}."""
    import tomllib
    with open(pyproject_path, "rb") as fh:
        proj = tomllib.load(fh)["project"]
    out = {}
    for spec in proj.get("dependencies", []):
        out.setdefault(dist_name(spec), "dependencies")
    for extra, specs in (proj.get("optional-dependencies") or {}).items():
        for spec in specs:
            out.setdefault(dist_name(spec), f"optional-dependencies.{extra}")
    return out


def problems(pyproject_path):
    """-> [] when every declared package is allowed, or one sentence per package that is not."""
    out = []
    for name, where in sorted(declared(pyproject_path).items()):
        if name in ALLOWED:
            continue
        why = KNOWN_COPYLEFT.get(name)
        out.append(
            f"{name} is named in pyproject.toml under `{where}` and is not on the allowed list"
            + (f" — it is {why}, which this project may not hand to an installer."
               if why else
               ". Add it to tools/licences.py WITH ITS LICENCE, having checked what that "
               "licence obliges an installer to do: this project is Apache 2.0 and every name "
               "here is installed on somebody else's machine."))
    return out


if __name__ == "__main__":
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(os.path.join(root, "pyproject.toml"))
    for line in found:
        print("  REFUSED:", line)
    if found:
        sys.exit(1)
    print("  ok  every declared dependency is a known permissive licence")
