"""The gate that runs before a commit — no model, no network, no git writes.

`tools/guard.py` is the last thing between this repository and a permanent, public mistake, and
it is the piece with no natural user: nobody runs it on purpose, so nothing tells anybody when it
stops working. It has already broken in three separate ways in one afternoon, each of which made
it report a clean tree:

  * `subprocess(text=True)` decodes with the platform's legacy codepage, not UTF-8, so on a
    machine whose codepage covers a non-Latin script every em dash in every file arrived as a
    different character. Sixty-eight files were refused at once, while `--tree` — the same check
    with a different reader — was green at the same moment.
  * a loop variable shadowed the compiled pattern, on a branch that only runs when the local
    supplement file exists. No test walked it.
  * the parsed-JSON check was written believing `json.loads` collapses every layer of escaping.
    It collapses one. Two layers parse to text that holds no Cyrillic character at all, which is
    exactly the encoding this project already had to learn about.

So every claim it makes is exercised here, in both directions. A scanner that has never been
watched catching something reports clean because it is broken, and this project has believed
three of those.

    python test_guard.py       # exits 1 on any failure (CI gate)
"""
import importlib.util
import io
import json
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    guard = _load("qat_guard", os.path.join(ROOT, "tools", "guard.py"))

    def scan(path, text):
        """Through the same function the hook calls, with the reader replaced. The reader is the
        only seam: the patterns, the field rules and the artifact handling are all the real ones."""
        refusals = []
        guard.scan_files([path], lambda _p: text, refusals)
        return refusals

    # --- THE PATTERNS CAN FIRE AT ALL -------------------------------------------------------
    broken = guard.selftest()
    check("every credential pattern matches its own sample", not broken, "; ".join(broken))
    check("...and there are enough of them to be worth running", len(guard.CREDENTIALS) >= 12,
          f"{len(guard.CREDENTIALS)} patterns")

    # --- WHAT MUST BE REFUSED ---------------------------------------------------------------
    MUST_CATCH = [
        ("an AWS session token", "redteam/x.py", "K = 'ASIA" + "Q" * 16 + "'"),
        ("a GitHub personal token", "docs/x.md", "run with ghp_" + "a" * 20),
        ("a GitHub fine-grained token", "docs/x.md", "github_pat_11ABCDEF"),
        ("a Slack token", "tools/x.sh", "export S=xoxb-11-22-abcdef"),
        ("a GitLab token", "tools/x.sh", "T=glpat-abcdefgh"),
        ("a Google API key", "site/x.js", "key='AIza" + "b" * 30 + "'"),
        ("a SendGrid key", "x.env", "SG." + "c" * 20),
        ("an npm token", "x.npmrc", "_authToken=npm_" + "d" * 30),
        ("a Stripe live key", "x.py", "sk_live_" + "e" * 16),
        ("a JWT", "site/x.js", "t='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig'"),
        ("an OpenSSH private key header", "x.pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("a Cyrillic character in source", "redteam/x.py", "# \u0414\u043e\u0431\u0440\u0435"),
    ]
    for label, path, text in MUST_CATCH:
        check(f"refused: {label}", bool(scan(path, text)))

    # --- WHAT MUST NOT BE REFUSED -----------------------------------------------------------
    #
    # A false positive is not a smaller version of the same thing. It is how a gate stops being
    # read, and then how it stops being run. The four credential shapes below are in this
    # repository ON PURPOSE — a tool whose subject is credential formats has credential-shaped
    # fixtures — and a pattern that fires on its own fixtures is one somebody switches off.
    MUST_ALLOW = [
        ("the practice bot's planted secret", "redteam/x.py", "SECRET = 'sk-rangeQA9931xyz'"),
        ("AWS's own published example key", "redteam/x.py", "AKIAIOSFODNN7EXAMPLE"),
        ("the documented Anthropic variable", "redteam/x.yaml",
         "# export ANTHROPIC_API_KEY=sk-ant-..."),
        ("a PEM header fragment used as detector input", "redteam/x.py", "'-----BEGIN RSA'"),
        ("ordinary source", "redteam/x.py", "def f():\n    return 1\n"),
        ("an em dash, which is everywhere in this repository", "docs/x.md",
         "one place decides — and the rest read it"),
    ]
    for label, path, text in MUST_ALLOW:
        got = scan(path, text)
        check(f"allowed: {label}", not got, str(got))

    # --- STORED ARTIFACTS: THE FIELD DECIDES, AND EVERY LAYER OF ESCAPING IS SEEN ------------
    A = "out/results_x.json"
    check("refused: Cyrillic in a prompt, unescaped",
          bool(scan(A, json.dumps({"rows": [{"prompt": "\u0414\u043e\u0431"}]},
                                  ensure_ascii=False))))
    check("refused: Cyrillic in a prompt, one escape layer",
          bool(scan(A, json.dumps({"rows": [{"prompt": "\u0414\u043e\u0431"}]}))))
    # TWO LAYERS: what `json.dumps` writes when handed a string that already holds the escape.
    # The parsed value contains no Cyrillic character, so only the escaped pattern sees it — and
    # the first version of this check, which trusted parsing alone, let it straight through.
    check("refused: Cyrillic in a prompt, DOUBLE-escaped",
          bool(scan(A, json.dumps({"rows": [{"prompt": "\\u0414\\u043e\\u0431"}]}))))
    check("allowed: the same Cyrillic under `output`, which is a model's own reply",
          not scan(A, json.dumps({"rows": [{"probe": {"output": "\u0414\u043e\u0431"}}]},
                                 ensure_ascii=False)))
    check("allowed: Korean, Hebrew and Arabic in a prompt — the corpus is multilingual",
          not scan(A, json.dumps({"rows": [{"prompt": "\uc548\ub155 \u05e9\u05dc\u05d5\u05dd \u0645\u0631\u062d\u0628\u0627"}]},
                                 ensure_ascii=False)))
    # An unreadable artifact is an unanswered question, not a clean one.
    check("refused: an artifact that does not parse", bool(scan(A, '{"rows": [')))

    # --- AN OBFUSCATED PAYLOAD IS EVIDENCE, NOT PROSE ---------------------------------------
    #
    # `enc-homoglyph-authority` is pure ASCII in the arsenal — "SECURITY OVERRIDE by the
    # administrator…" — and `encode: homoglyph` rewrites it at send time into Cyrillic
    # look-alikes. Twenty-five attacks in the `obfuscation` category work that way, so the
    # recorded prompt is legitimately non-Latin: it is what was SENT, like a reply is what came
    # back. This refused a real commit, correctly by its rule and wrongly about the file.
    #
    # The exemption is the narrow one, and the cases below are what "narrow" has to mean:
    # scoped to the prompt of a result whose ATTACK declares an encoding, so ordinary prose in
    # one of those scripts cannot ride in beside a homoglyph payload.
    # Written as escapes: this file stays under the guard's own literal check, and a
    # homoglyph payload spelled out here would trip it.
    HOMO = "S\u0415\u0421URIT\u0423 \u041eV\u0415RRID\u0415"
    CYR = "\u0414\u043e\u0431\u0440\u0435"

    def art(obj):
        return scan(A, json.dumps(obj, ensure_ascii=False))

    check("allowed: the prompt of an attack that declares an encoding",
          not art({"results": [{"attack": {"id": "e", "encode": "homoglyph"},
                                "trials": [{"probe": {"prompt": HOMO, "output": "no"}}]}]}))
    check("refused: the same characters where the attack declares no encoding",
          bool(art({"results": [{"attack": {"id": "p"},
                                 "trials": [{"probe": {"prompt": CYR, "output": "no"}}]}]})))
    check("refused: a plain attack sitting next to an encoded one",
          bool(art({"results": [{"attack": {"id": "e", "encode": "homoglyph"},
                                 "trials": [{"probe": {"prompt": HOMO}}]},
                                {"attack": {"id": "p"},
                                 "trials": [{"probe": {"prompt": CYR}}]}]})))
    check("refused: another field of the encoded result itself",
          bool(art({"results": [{"attack": {"id": "e", "encode": "homoglyph", "note": CYR},
                                 "trials": [{"probe": {"prompt": HOMO}}]}]})))
    check("refused: the meta block of a file that contains an encoded attack",
          bool(art({"meta": {"target": "x", "note": CYR},
                    "results": [{"attack": {"id": "e", "encode": "homoglyph"},
                                 "trials": [{"probe": {"prompt": HOMO}}]}]})))

    # --- THE LOCAL SUPPLEMENT ---------------------------------------------------------------
    #
    # Exercised because it is a branch that only runs on a machine that has the file, and a
    # branch nothing walks is where the shadowed-variable crash lived.
    old = guard.LOCAL
    with tempfile.TemporaryDirectory() as d:
        try:
            guard.LOCAL = os.path.join(d, ".guard-local")
            io.open(guard.LOCAL, "w", encoding="utf-8").write("# a comment\nSecretName\n\n")
            check("refused: a literal from the local supplement, case-insensitively",
                  bool(scan("README.md", "written by secretname")))
            check("allowed: a file with none of them",
                  not scan("README.md", "written by nobody in particular"))
            io.open(guard.LOCAL, "w", encoding="utf-8").write("# only comments\n")
            check("a supplement of only comments refuses nothing",
                  not scan("README.md", "written by secretname"))
        finally:
            guard.LOCAL = old

    # --- LICENCES, THROUGH THE SAME MODULE pyproject IS CHECKED WITH -------------------------
    lic = _load("qat_licences", os.path.join(ROOT, "tools", "licences.py"))
    check("this project's own dependencies are all permissive",
          not lic.problems(os.path.join(ROOT, "pyproject.toml")),
          "; ".join(lic.problems(os.path.join(ROOT, "pyproject.toml"))))
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "pyproject.toml")
        io.open(p, "w", encoding="utf-8").write(
            '[project]\nname="x"\nversion="0"\ndependencies=["PyYAML>=5.4"]\n'
            '[project.optional-dependencies]\nfixtures=["pymupdf>=1.24"]\n')
        found = lic.problems(p)
        check("an AGPL package in an extra is refused", bool(found) and "AGPL" in found[0],
              str(found))
        check("...and the refusal says where it was declared",
              found and "optional-dependencies.fixtures" in found[0], str(found))

    # --- THE BLOB READER PAIRS CONTENTS TO PATHS --------------------------------------------
    #
    # Both the staged scan and the history scan read git objects in one `cat-file --batch`
    # rather than one subprocess per file — measured, per-file `git show` was 2.4 seconds for
    # 124 files against 0.29 for 424 read off the disk, and a hook that slow is one people pass
    # `--no-verify` to.
    #
    # The parser desynchronised. `cat-file --batch` writes `<sha> <type> <size>\n<body>\n`, and
    # the first version stepped over the body only for objects it wanted — so fed the output of
    # `rev-list --objects`, which names TREES as well as blobs, it skipped a tree's header and
    # then read the tree's bytes as the next path's contents. Every file after the first tree
    # came back holding somebody else's data, and five artifacts were reported as unparseable.
    # A reader that is nine times faster and returns the wrong bytes is worse than the slow one.
    import subprocess as _sp
    listing = _sp.run(["git", "-C", ROOT, "ls-files", "--stage"],
                      capture_output=True, text=True).stdout.splitlines()
    shas = {}
    for line in listing[:60]:
        head, _, path = line.partition("\t")
        parts = head.split()
        if len(parts) >= 2 and path.endswith(".py"):
            shas[path] = parts[1]
    got = guard._read_blobs(shas)
    check("the blob reader returns something for every path it was given",
          len(got) == len(shas), f"{len(got)} of {len(shas)}")
    wrong = [p for p, text in got.items()
             if text.splitlines()[:1] != io.open(os.path.join(ROOT, p), encoding="utf-8",
                                                 errors="replace").read().splitlines()[:1]]
    check("...and each one holds its OWN file, not the previous object's bytes",
          not wrong, f"mismatched: {wrong[:4]}")
    # A tree in the middle of the batch is the exact shape that desynchronised it.
    tree = _sp.run(["git", "-C", ROOT, "rev-parse", "HEAD^{tree}"],
                   capture_output=True, text=True).stdout.strip()
    mixed = {"<a tree>": tree}
    mixed.update(shas)
    got2 = guard._read_blobs(mixed)
    check("...even with a non-blob object in the middle of the batch",
          all(got2.get(p) == got.get(p) for p in shas),
          f"{sum(1 for p in shas if got2.get(p) != got.get(p))} path(s) shifted")

    # --- AND THE HOOKS ACTUALLY CALL IT ------------------------------------------------------
    #
    # Every check above tests the scanner. None of them would notice if the hooks stopped
    # invoking it, which is the failure that leaves a perfect scanner running nowhere.
    for hook in ("pre-commit", "pre-push"):
        path = os.path.join(ROOT, ".githooks", hook)
        check(f".githooks/{hook} exists", os.path.isfile(path))
        src = io.open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
        check(f"...and calls tools/guard.py", "tools/guard.py" in src)
        # `command -v python` succeeds on the Microsoft Store alias, a stub that resolves and
        # does not run — so the hook refused a commit for the wrong reason and an end-to-end
        # test read that as the token being caught.
        check(f"...and finds an interpreter that runs, not one that merely resolves",
              "find_python" in src, "the hook resolves python by name only")
        check(f"...and a missing interpreter is a refusal, not a pass",
              "not a pass" in src.lower() or "exit 1" in src)
    # EXECUTABLE IN THE INDEX, which is invisible from Windows and fatal on Linux: git records
    # the bit, and a hook checked in as 100644 is a hook that silently does not run on a clone
    # where the mode is honoured. The whole point of moving these into the repository was that
    # they exist for everybody, and a mode bit would have made that true only here.
    import subprocess as _sp
    modes = dict(
        (line.split("\t")[1], line.split()[0])
        for line in _sp.run(["git", "-C", ROOT, "ls-files", "--stage", ".githooks/"],
                            capture_output=True, text=True).stdout.splitlines()
        if "\t" in line)
    for hook in ("pre-commit", "pre-push"):
        check(f"...and .githooks/{hook} is executable in the index",
              modes.get(f".githooks/{hook}") == "100755",
              f"mode {modes.get(f'.githooks/{hook}')} — git would not run it on a Linux clone")

    check("the one-time install command is documented",
          "core.hooksPath" in io.open(os.path.join(ROOT, "CONTRIBUTING.md"),
                                      encoding="utf-8").read(),
          "CONTRIBUTING.md does not say how to turn the hooks on")

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the gate refuses what it must and lets ordinary work through.")


if __name__ == "__main__":
    main()
