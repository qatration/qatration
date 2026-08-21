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
    lic = _load("qat_licences", os.path.join(ROOT, "tools", "licences.py"))

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

    # --- A COMMIT'S TIMEZONE, WHICH IS A PLACE AND NOT A TIME -------------------------------
    #
    # Seven commits here were stamped with a local offset before anybody looked, and nothing
    # looked because nothing shows it: `git log` renders the local time by default, and the
    # author line — the field people do check — was already correct. The offset is as permanent
    # as the diff and no later commit can take it back.
    #
    # Built as a real repository rather than by parsing strings, because the claim is about what
    # `git` records, not about what a formatter prints.
    with tempfile.TemporaryDirectory() as d:
        def g(*a, **env):
            e = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                     GIT_CONFIG_SYSTEM=os.path.join(d, "none"), **env)
            return _sp.run(["git", "-C", d] + list(a), capture_output=True, text=True, env=e)

        g("init", "-q", "-b", "main")
        g("config", "user.name", "QAtration")
        g("config", "user.email", "qatration@gmail.com")
        io.open(os.path.join(d, "a.txt"), "w").write("one")
        g("add", "-A")
        g("commit", "-qm", "utc", GIT_AUTHOR_DATE="2026-01-01T12:00:00+00:00",
          GIT_COMMITTER_DATE="2026-01-01T12:00:00+00:00")
        io.open(os.path.join(d, "a.txt"), "w").write("two")
        g("add", "-A")
        g("commit", "-qm", "local", GIT_AUTHOR_DATE="2026-01-02T15:00:00+03:00",
          GIT_COMMITTER_DATE="2026-01-02T15:00:00+03:00")

        old_root = guard.ROOT
        try:
            guard.ROOT = d
            def offsets_refused(rng):
                found = []
                guard.scan_history(rng, found)
                return [f for f in found if "not UTC" in f]

            hits = offsets_refused("HEAD~1..HEAD")
            check("refused: a commit stamped with a local timezone offset", bool(hits),
                  f"scan_history saw nothing; all refusals: {hits}")
            check("...and the refusal names the offset it found",
                  any("+03:00" in f for f in hits), str(hits))
            check("allowed: a commit stamped UTC",
                  not offsets_refused("HEAD~1"), str(offsets_refused("HEAD~1")))
            # THE COMMITTER DATE ON ITS OWN. Rewriting only the author date is the easy half of
            # a history fix and leaves the other field carrying the same offset.
            g("commit", "-q", "--amend", "--no-edit", "--date=2026-01-03T09:00:00+00:00",
              GIT_COMMITTER_DATE="2026-01-03T12:00:00+02:00")
            check("...and a UTC author date does not excuse a local committer date",
                  bool(offsets_refused("HEAD~1..HEAD")),
                  "only the author date is being read")
        finally:
            guard.ROOT = old_root

    # --- THE THREE HOLES A REVIEW OPENED IN THIS GATE ----------------------------------------
    #
    # Every one of them reported the word `ok` and exit 0 with a live credential in front of it.
    # They are here as one repository because the point is not three separate bugs: it is that
    # the module written against "a check that did not run, read as a pass" had three of them.
    #
    # Read the REASON, never the exit code. Twice while proving these, an exit of 1 was taken
    # for a catch — once it was a crash from a missing import in the harness, once it was the
    # timezone check firing because `git commit --date` sets only the AUTHOR date. Hence the
    # explicit UTC stamps below, and hence `refused_for`.
    with tempfile.TemporaryDirectory() as d:
        genv = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                    GIT_CONFIG_SYSTEM=os.path.join(d, "none"),
                    GIT_AUTHOR_DATE="2026-01-01T12:00:00+00:00",
                    GIT_COMMITTER_DATE="2026-01-01T12:00:00+00:00")

        def g(*a):
            return _sp.run(["git", "-C", d] + list(a), capture_output=True, text=True, env=genv)

        def put(name, text):
            p = os.path.join(d, name)
            if os.path.dirname(name):
                os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, "w", encoding="utf-8", newline="\n").write(text)

        def snap(msg):
            g("add", "-A")
            g("commit", "-qm", msg)

        def refused_for(want, *args):
            """True only if the guard refused FOR `want` — not merely that it exited non-zero."""
            found = []
            old_root = guard.ROOT
            try:
                guard.ROOT = d
                if args[0] == "--range":
                    guard.scan_history(args[1], found)
                else:
                    guard.scan_files(sorted(_tracked()), _disk_reader, found)
            finally:
                guard.ROOT = old_root
            return [f for f in found if want in f]

        def _tracked():
            out = g("ls-files").stdout.split()
            return [p for p in out if p]

        def _disk_reader(path):
            try:
                return io.open(os.path.join(d, path), encoding="utf-8", errors="replace").read()
            except OSError:
                return ""

        TOKEN = "ghp_" + "a" * 20          # built, so this file stays under its own scan

        g("init", "-q", "-b", "main")
        g("config", "user.name", "QAtration")
        g("config", "user.email", "qatration@gmail.com")
        put("keep.txt", "nothing here")
        snap("scaffold")

        # 1. THE VERSION THAT IS NO LONGER AT THE TIP — the only case this function exists for.
        #    `blobs.setdefault(path, sha)` plus a newest-first walk read exactly one blob per
        #    path: the tip's, which `--tree` had already scanned.
        put("cfg.py", "TOKEN = os.environ['T']")
        snap("clean")
        put("cfg.py", "TOKEN = '%s'" % TOKEN)
        snap("credential goes in")
        put("cfg.py", "TOKEN = os.environ['T']")
        snap("credential taken out, FILE KEPT")
        root = g("rev-list", "--max-parents=0", "HEAD").stdout.strip()
        hits = refused_for("GitHub personal token", "--range", root + "..HEAD")
        check("refused: a credential in an older version of a file that still exists",
              bool(hits), "the push gate read only the tip's bytes")
        check("...and the refusal names the version, not just the path",
              any("cfg.py@" in h for h in hits), str(hits[:1]))

        # 2. A RANGE GIT COULD NOT READ. `_git` handed back `.stdout` and ignored the exit
        #    status, so `origin/main..HEAD` on a clone with no remote was an empty history.
        for bad in ("origin/main..HEAD", "v9.9.9..HEAD"):
            check(f"refused: {bad}, which git cannot resolve",
                  bool(refused_for("could not be read", "--range", bad)),
                  "an unreadable range reported clean")

        # 3. A TREE IS NOT AN UNREADABLE FILE. The shortfall report above fired on all 30
        #    directories in the repository the first time, because it inferred what was missing
        #    by subtracting keys instead of asking the reader.
        check("...and a directory is not reported as an unreadable file",
              not refused_for("could not be read back", "--range", root + "..HEAD"),
              "trees are being counted as unreadable blobs")

        # 4. AN ARTIFACT IS WHERE A PASTED KEY WOULD ACTUALLY LAND. `out/*.json` returned after
        #    its own Cyrillic check, skipping the credential scan and the local-supplement scan
        #    for all 113 tracked ones.
        put("out/results_x.json", '{"meta": {"note": "%s"}}' % TOKEN)
        snap("a token inside an artifact")
        check("refused: a credential inside a stored artifact",
              bool(refused_for("GitHub personal token", "--tree")),
              "out/*.json was scanned for one rule out of three")

        old_local = guard.LOCAL
        try:
            guard.LOCAL = os.path.join(d, ".guard-local")
            io.open(guard.LOCAL, "w", encoding="utf-8").write("SecretName\n")
            put("out/results_y.json", '{"meta": {"note": "written by secretname"}}')
            snap("a private literal inside an artifact")
            # NAMED, not merely counted. `git add -A` tracks `.guard-local` itself in a
            # throwaway repository with no ignore file, so the supplement matches its own
            # contents and this check passed against the BROKEN guard until it was made to
            # say which file it caught.
            _lit = refused_for(".guard-local", "--tree")
            check("refused: a .guard-local literal inside a stored artifact",
                  any("out/results_y.json" in f for f in _lit),
                  f"the supplement is the check an artifact never got; refusals were {_lit}")
        finally:
            guard.LOCAL = old_local

        # 5. `-0000` IS UTC. git writes it for "timezone unknown", which says less than +00:00.
        # `-0000` IS TESTED ON THE FUNCTION, NOT THROUGH A COMMIT, because git's own
        # formatter normalises it away and the fixture cannot be built. Measured three ways:
        # `--date=...-00:00`, `GIT_AUTHOR_DATE="<epoch> -0000"`, and a commit object written by
        # hand with `hash-object -t commit` — `git log --date=iso-strict` printed `Z` for all
        # three. So an end-to-end check here would assert nothing, which is how the first
        # version of it passed against a guard that did refuse `-00:00`.
        #
        # The tolerance stays, because `_offset` is a string function and its contract is about
        # what an offset MEANS: git writes `-0000` for "timezone unknown", which says less about
        # a machine's location than `+00:00` does. Refusing it would be the check inventing a
        # place out of an absence.
        check("_offset: -00:00 is UTC, not a location",
              guard._offset("2026-01-05T09:00:00-00:00|2026-01-05T09:00:00-00:00") == "",
              f"got {guard._offset('2026-01-05T09:00:00-00:00|x')!r}")
        check("_offset: +00:00 is UTC",
              guard._offset("2026-01-05T09:00:00+00:00|2026-01-05T09:00:00+00:00") == "")
        check("_offset: a real offset is reported",
              guard._offset("2026-01-05T09:00:00+03:00|2026-01-05T09:00:00+03:00") == "+03:00")
        check("_offset: a UTC author date does not hide a local committer date",
              guard._offset("2026-01-05T09:00:00+00:00|2026-01-05T12:00:00+02:00") == "+02:00")

    # --- THE TWO RULES THAT RAN IN ONE PLACE -------------------------------------------------
    #
    # Who wrote a commit, and what place its stamp names, were reachable only through
    # `scan_history`, i.e. only through `--range`, i.e. only through `pre-push` — opt-in,
    # skippable, and at the time verified by grepping its own text. CONTRIBUTING says CI is the
    # part that cannot be skipped, and CI runs `--tree`. A reviewer put a real name and a
    # `+03:00` stamp on a commit and walked it to a bare remote with everything else green.
    #
    # These two fields are also the ones a later commit cannot take back, which is what makes
    # "enforced in the one place a person can turn off" the wrong number of places.
    for mode in ("--tree", "--staged"):
        with tempfile.TemporaryDirectory() as d:
            genv = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                        GIT_CONFIG_SYSTEM=os.path.join(d, "none"))

            def gg(*a, **env):
                return _sp.run(["git", "-C", d] + list(a), capture_output=True, text=True,
                               env=dict(genv, **env))

            gg("init", "-q", "-b", "main")
            gg("config", "user.name", "QAtration")
            gg("config", "user.email", "qatration@gmail.com")
            io.open(os.path.join(d, "a.txt"), "w").write("x")
            gg("add", "-A")
            gg("commit", "-qm", "a stranger, from somewhere",
               GIT_AUTHOR_NAME="A Person", GIT_AUTHOR_EMAIL="person@example.com",
               GIT_AUTHOR_DATE="2026-08-22T10:00:00+03:00",
               GIT_COMMITTER_DATE="2026-08-22T10:00:00+03:00")
            # `getattr`, not a direct call: against a build where this rule does not exist yet
            # the point is a red check with a reason, not an AttributeError that ends the run
            # and takes every check after it down as collateral.
            _fn = getattr(guard, "_stamps", None)
            found = []
            old_root = guard.ROOT
            try:
                guard.ROOT = d
                if _fn:
                    _fn("HEAD", found)
                else:
                    found.append("guard has no _stamps: the author and timezone rules are "
                                 "reachable only from --range, i.e. only from pre-push")
                    _fn = None
            finally:
                guard.ROOT = old_root
            if not getattr(guard, "_stamps", None):
                check(f"{mode} mode reaches the author rule (via _stamps, one implementation)",
                      False, found[0])
                check(f"{mode} mode reaches the timezone rule", False, found[0])
                continue
            check(f"{mode} mode reaches the author rule (via _stamps, one implementation)",
                  any("not by the project identity" in f for f in found), str(found))
            check(f"{mode} mode reaches the timezone rule",
                  any("not UTC" in f for f in found), str(found))
    # And the wiring: `main` must call it whatever the mode, or the two checks above test a
    # function nothing runs. Read from the source, because that is the claim.
    _main_src = io.open(os.path.join(ROOT, "tools", "guard.py"), encoding="utf-8").read()
    _main_src = _main_src[_main_src.index("def main("):]
    # `.find`, not `.index`: a build without the call must give a red check with a reason, not
    # a ValueError out of the test harness that ends the run and hides everything after it.
    _at, _branch = _main_src.find("_stamps("), _main_src.find("if args.staged:")
    check("...and main() calls _stamps before it branches on the mode",
          0 <= _at < _branch,
          "main() never calls it" if _at < 0 else "the stamp rules are inside one branch")

    # --- AN EXEMPTION MUST NOT BE WIDER THAN ITS DATA ----------------------------------------
    #
    # MODEL_FIELDS exempted `text`, and `recon.hints()` writes tool-authored English into it —
    # 742 occurrences across the shipped artifacts, every one ours: an attack payload, a hint,
    # a seed. It also exempted `answer`, `response` and `completion`, which occur zero times.
    check("`text` is not exempt: it is our prose, not a reply",
          "text" not in guard.MODEL_FIELDS)
    for gone in ("answer", "response", "completion"):
        check(f"`{gone}` is not exempt: no artifact has that field",
              gone not in guard.MODEL_FIELDS)
    check("refused: Cyrillic in a generated hint, which lives under `text`",
          bool(scan("out/recon_x.json", json.dumps(
              {"hints": [{"level": "warn", "text": "\u0414\u043e\u0431\u0440\u0435"}]},
              ensure_ascii=False))))
    check("allowed: the same characters in a model's reply",
          not scan("out/results_x.json", json.dumps(
              {"results": [{"attack": {"id": "a"},
                            "trials": [{"probe": {"output": "\u0414\u043e\u0431\u0440\u0435"}}]}]},
              ensure_ascii=False)))

    # --- THE LICENCE PARSER, ON THE INTERPRETER THE PACKAGE CLAIMS ---------------------------
    #
    # `declared()` did a bare `import tomllib`, which arrived in 3.11, and `guard.py` calls
    # `problems()` in every mode. On 3.9 the commit gate was a traceback, and the 3.9 leg of CI
    # could only ever be red. The fallback existed in test_packaging.py and not in the copy
    # everything called.
    def _no_tomllib(fn, *a):
        import builtins
        real = builtins.__import__

        def fake(name, *rest, **kw):
            if name == "tomllib":
                raise ImportError("tomllib arrived in 3.11")
            return real(name, *rest, **kw)
        builtins.__import__ = fake
        try:
            return fn(*a)
        finally:
            builtins.__import__ = real

    # CAUGHT, not allowed to propagate. A parser that raises on 3.9 is the finding, and the
    # finding has to render as a red check with the traceback in its detail — not as a crash
    # that ends the suite and hides every check after it.
    _pyproject = os.path.join(ROOT, "pyproject.toml")
    _with = lic.declared(_pyproject)
    try:
        _without, _blew_up = _no_tomllib(lic.declared, _pyproject), None
    except Exception as e:
        _without, _blew_up = {}, f"{type(e).__name__}: {e}"
    check("the licence parser runs without tomllib, as it must on 3.9",
          bool(_without), _blew_up or "it returned nothing, so a 3.9 machine checks nothing")
    check("...and gives the SAME answer as tomllib does",
          _with == _without, f"tomllib={sorted(_with)} hand={sorted(_without)}")

    with tempfile.TemporaryDirectory() as d:
        def _proj(name, body):
            p = os.path.join(d, name)
            io.open(p, "w", encoding="utf-8", newline="\n").write(body)
            return p

        # `[build-system].requires` is installed by every sdist build, before anything else
        # exists. It was never read, and this project's own setuptools sat in it unchecked.
        p = _proj("build.toml", '[build-system]\nrequires = ["pymupdf>=1.24"]\n'
                                '[project]\nname="x"\nversion="0"\ndependencies=[]\n')
        found = lic.problems(p)
        check("an AGPL package in [build-system].requires is refused",
              any("AGPL" in f for f in found), str(found))
        check("...and the refusal says it came from the build system",
              any("build-system.requires" in f for f in found), str(found))

        # PEP 735, the spelling a contributor reaches for next.
        p = _proj("groups.toml", '[project]\nname="x"\nversion="0"\ndependencies=[]\n'
                                 '[dependency-groups]\ndev = ["pymupdf>=1.24"]\n')
        check("an AGPL package in [dependency-groups] is refused",
              any("AGPL" in f for f in lic.problems(p)), str(lic.problems(p)))

        # A list this file cannot see is not an empty list.
        p = _proj("dyn.toml", '[project]\nname="x"\nversion="0"\ndynamic=["dependencies"]\n')
        check("dynamic dependencies are refused, not reported as clean",
              any("dynamic" in f for f in lic.problems(p)), str(lic.problems(p)))

        # A traceback out of a hook is not a refusal.
        p = _proj("empty.toml", '[build-system]\nrequires=["setuptools>=61"]\n')
        try:
            found, crashed = lic.problems(p), None
        except Exception as e:
            found, crashed = [], f"{type(e).__name__}: {e}"
        check("a pyproject with no [project] table refuses rather than raising",
              crashed is None and bool(found), crashed or "it returned clean")

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
