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
import io
import os

ALLOWED = {
    # A BUILD DEPENDENCY IS STILL INSTALLED ON SOMEBODY ELSE'S MACHINE. `setuptools` sits in
    # `[build-system].requires`, so every `pip install` from an sdist pulls it before anything
    # else exists. It went unchecked until `declared()` learned to read that table, which is the
    # argument for reading every declaration site rather than the one everybody thinks of.
    "setuptools": "MIT",
    "pyyaml": "MIT",
    # pyfiglet WAS GPLv2+ AND THE FLOOR IS LOAD-BEARING. Verified against PyPI's JSON API on
    # 2026-08-22: 0.7.6 declares `GPLv2+`, 0.8.post1 declares `MIT`. The relicense is at 0.8, so
    # `pyfiglet>=0.8` in pyproject.toml is correct and must not be lowered. (0.8.0 is an empty
    # release carrying no files, so pip's effective floor is 0.8.post0, also MIT.)
    #
    # This is the one entry in this table where the NAME is not enough to answer the question,
    # which is the gap `dist_name()` cannot see: it strips the version specifier before
    # deciding, so `pyfiglet>=0.8` and `pyfiglet==0.7.6` are the same input to this check.
    # Anything added here whose licence changed at a version needs the same note.
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


def _split_items(body):
    """Split a TOML array body on its own commas, not on commas inside a quoted string."""
    out, cur, q = [], [], None
    for ch in body:
        if q:
            cur.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur.append(ch)
        elif ch == ",":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _decomment(block):
    """Drop `#` comments from a block of TOML, without cutting a quoted string.

    Quote-aware because PEP 508 allows a direct reference — `pkg @ https://host/x.zip#egg=pkg`
    — and a naive split on `#` would take half the URL with it.
    """
    out = []
    for raw in block.splitlines():
        q = None
        for i, ch in enumerate(raw):
            if q:
                if ch == q:
                    q = None
            elif ch in "\"'":
                q = ch
            elif ch == "#":
                raw = raw[:i]
                break
        out.append(raw)
    return "\n".join(out)


def parse(pyproject_path):
    """-> the parsed pyproject as a dict. The ONE parser, so 3.9 is not a second implementation.

    `tomllib` arrived in 3.11 and this package claims `requires-python = ">=3.9"`. A bare import
    here made the copyleft gate a traceback on 3.9 and 3.10 — on every commit, since `guard.py`
    calls `problems()` in all three of its modes, and permanently red on the 3.9 leg of CI. The
    reaction to a leg that has never passed is to delete the leg, and that leg is the only thing
    keeping the support claim honest.

    The hand parser is deliberately small: it reads the array literals this file asks about and
    nothing else. It existed already, in `test_packaging.declared_dependencies()`, which now
    calls this instead of keeping its own.
    """
    text = io.open(pyproject_path, encoding="utf-8").read()
    try:
        import tomllib
        return tomllib.loads(text)
    except ImportError:
        pass
    out, table = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line.startswith("[") and line.endswith("]"):
            table = line.strip("[]").strip()
            continue
        if "=" not in line:
            continue
        key, _, rest = line.partition("=")
        key, rest = key.strip(), rest.strip()
        if not rest.startswith("["):
            continue
        body = rest[1:]
        if "]" not in body:                       # a multi-line array: read to the closing ]
            # THE RAW TEXT, so the per-line `#` strip above never reached it. A comment inside
            # the array came back as packages — `#`, `and`, `or`, `which` — and this fallback
            # is what runs on Python 3.9, one of the four legs in CI. Feeding invented names to
            # the thing that decides whether a copyleft dependency was declared is worse than a
            # cosmetic bug.
            body = _decomment(text.split(line, 1)[1].split("]", 1)[0])
        else:
            body = body.split("]", 1)[0]
        # SPLIT OUTSIDE THE QUOTES. `"langchain>=0.2,<1"` is ONE dependency, and splitting on
        # every comma turned it into `langchain>=0.2` and `<1` — the second of which becomes a
        # package named "". `>=x,<y` is the ordinary way to pin a range, so this fallback could
        # never read the commonest constraint there is, on the interpreter it exists for.
        items = [p.strip().strip(",").strip().strip('"').strip("'")
                 for p in _split_items(body.replace("\n", " "))]
        node = out
        for part in (table.split(".") if table else []):
            node = node.setdefault(part, {})
        node[key] = [i for i in items if i]
    return out


def declared(pyproject_path):
    """-> {distribution name: where in pyproject.toml it was found}.

    EVERY DECLARATION SITE, because each one ends up installed on somebody else's machine and
    that is the whole question this file asks. Three were missing and reported nothing:

      * `[build-system].requires` — installed by every `pip install` from an sdist, before any
        of the rest exists. This project's own `setuptools>=61` lives here and was unchecked.
      * `[dependency-groups]` — PEP 735, the spelling a contributor reaching for dev extras
        will use next.
      * `[project].dynamic` naming `dependencies` — the list is then in a requirements file this
        cannot see, so the honest answer is to SAY so rather than report an empty set as clean.

    A pyproject with no `[project]` table used to raise KeyError out of a hook, where a refusal
    belongs.
    """
    doc = parse(pyproject_path)
    proj = doc.get("project") or {}
    out = {}
    if not proj:
        out["<no [project] table>"] = "the file could not be read as a project"
        return out
    for spec in proj.get("dependencies") or []:
        out.setdefault(dist_name(spec), "dependencies")
    for extra, specs in (proj.get("optional-dependencies") or {}).items():
        for spec in specs:
            out.setdefault(dist_name(spec), f"optional-dependencies.{extra}")
    for spec in (doc.get("build-system") or {}).get("requires") or []:
        out.setdefault(dist_name(spec), "build-system.requires")
    for group, specs in (doc.get("dependency-groups") or {}).items():
        for spec in specs if isinstance(specs, list) else []:
            out.setdefault(dist_name(spec), f"dependency-groups.{group}")
    if "dependencies" in (proj.get("dynamic") or []):
        out.setdefault("<dynamic dependencies>", "project.dynamic")
    return out


def problems(pyproject_path):
    """-> [] when every declared package is allowed, or one sentence per package that is not."""
    out = []
    for name, where in sorted(declared(pyproject_path).items()):
        if name == "<no [project] table>":
            out.append(f"{pyproject_path} has no [project] table, so nothing about its "
                       f"dependencies was checked")
            continue
        if name == "<dynamic dependencies>":
            out.append("pyproject.toml declares `dependencies` as dynamic, so the list is in a "
                       "file this cannot read and no licence was checked. Declare them here, or "
                       "state in tools/licences.py where they are and why that is acceptable")
            continue
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
