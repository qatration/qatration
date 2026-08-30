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
import re
import shutil
import subprocess
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

    def git_env(tmp, **extra):
        """A git environment that says nothing about the machine running the tests.

        CI failed on all four platforms while every suite passed locally, and the whole of the
        difference was this: the checks around `_pending_stamp` inherited `os.environ`, so they
        inherited whoever the machine thinks you are. A fresh CI checkout has no configured
        identity, git guesses one from the host, and three checks went red for a property of
        the runner. A build must never fail for that, and this file is where it started.

        So the identity is pinned rather than borrowed, and taken from `guard.IDENTITY` because
        a literal copied here would be a second definition of the rule under test. The config
        files are pointed at a path that does not exist, so nothing on the developer's machine
        reaches the temporary repository either -- a global `commit.gpgsign` or a hooks path
        would otherwise walk straight in.
        """
        name, _, email = guard.IDENTITY.partition(" <")
        env = dict(os.environ,
                   GIT_CONFIG_GLOBAL=os.path.join(tmp, "none"),
                   GIT_CONFIG_SYSTEM=os.path.join(tmp, "none"),
                   GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email.rstrip(">"),
                   GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email.rstrip(">"),
                   GIT_AUTHOR_DATE="2026-01-01T12:00:00+00:00",
                   GIT_COMMITTER_DATE="2026-01-01T12:00:00+00:00")
        env.update(extra)
        return env
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
        # A WHOLE ONE. The signature used to be the three letters `sig`, and the pattern used
        # to stop at the second dot and never look -- so this fixture agreed with a pattern
        # that fired on the practice bot's hand-typed fake. A real HS256 signature is 43
        # base64url characters and this is built, not written out, like every other sample here.
        ("a JWT", "site/x.js",
         "t='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "s" * 43 + "'"),
        ("an OpenSSH private key header", "x.pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("a Cyrillic character in source", "redteam/x.py", "# \u0416\u0429\u04ae\u0424"),
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
          bool(scan(A, json.dumps({"rows": [{"prompt": "\u0416\u043e\u0431"}]},
                                  ensure_ascii=False))))
    check("refused: Cyrillic in a prompt, one escape layer",
          bool(scan(A, json.dumps({"rows": [{"prompt": "\u0416\u043e\u0431"}]}))))
    # TWO LAYERS: what `json.dumps` writes when handed a string that already holds the escape.
    # The parsed value contains no Cyrillic character, so only the escaped pattern sees it — and
    # the first version of this check, which trusted parsing alone, let it straight through.
    check("refused: Cyrillic in a prompt, DOUBLE-escaped",
          bool(scan(A, json.dumps({"rows": [{"prompt": "\\u0416\\u043e\\u0431"}]}))))
    check("allowed: the same Cyrillic under `output`, which is a model's own reply",
          not scan(A, json.dumps({"rows": [{"probe": {"output": "\u0416\u043e\u0431"}}]},
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
    CYR = "\u0416\u0429\u04ae\u0424"

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
    # `git commit` stamps the machine's local offset, and nothing surfaces it: `git log`
    # renders local time by default, and the field people do check — the author line — is
    # usually already correct. So the one part of a commit that says WHERE it was made is the
    # part nobody reads, and it is as permanent as the diff.
    #
    # Built as a real repository rather than by parsing strings, because the claim is about what
    # `git` records, not about what a formatter prints.
    with tempfile.TemporaryDirectory() as d:
        def g(*a, **env):
            return _sp.run(["git", "-C", d] + list(a), capture_output=True, text=True,
                           env=git_env(d, **env))

        g("init", "-q", "-b", "main")
        g("config", "user.name", "QAtration")
        g("config", "user.email", "qatration@gmail.com")
        io.open(os.path.join(d, "a.txt"), "w").write("one")
        g("add", "-A")
        g("commit", "-qm", "utc", GIT_AUTHOR_DATE="2026-01-01T12:00:00+00:00",
          GIT_COMMITTER_DATE="2026-01-01T12:00:00+00:00")
        io.open(os.path.join(d, "a.txt"), "w").write("two")
        g("add", "-A")
        g("commit", "-qm", "local", GIT_AUTHOR_DATE="2026-01-02T15:00:00+05:45",
          GIT_COMMITTER_DATE="2026-01-02T15:00:00+05:45")

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
                  any("+05:45" in f for f in hits), str(hits))
            check("allowed: a commit stamped UTC",
                  not offsets_refused("HEAD~1"), str(offsets_refused("HEAD~1")))
            # THE COMMITTER DATE ON ITS OWN. Rewriting only the author date is the easy half of
            # a history fix and leaves the other field carrying the same offset.
            g("commit", "-q", "--amend", "--no-edit", "--date=2026-01-03T09:00:00+00:00",
              GIT_COMMITTER_DATE="2026-01-03T12:00:00+05:45")
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
        genv = git_env(d)

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
              guard._offset("2026-01-05T09:00:00+05:45|2026-01-05T09:00:00+05:45") == "+05:45")
        check("_offset: a UTC author date does not hide a local committer date",
              guard._offset("2026-01-05T09:00:00+00:00|2026-01-05T12:00:00+05:45") == "+05:45")

    # --- THE TWO RULES THAT RAN IN ONE PLACE -------------------------------------------------
    #
    # Who wrote a commit, and what place its stamp names, were reachable only through
    # `scan_history`, i.e. only through `--range`, i.e. only through `pre-push` — opt-in,
    # skippable, and at the time verified by grepping its own text. CONTRIBUTING says CI is the
    # part that cannot be skipped, and CI runs `--tree`. A commit carrying an unrelated author
    # and a local offset walks past `--staged`, past `--tree`, and past a `pre-push` that has
    # been emptied — shown on a throwaway repository, which is the only place to show it.
    #
    # These two fields are also the ones a later commit cannot take back, which is what makes
    # "enforced in the one place a person can turn off" the wrong number of places.
    for mode in ("--tree", "--staged"):
        with tempfile.TemporaryDirectory() as d:
            genv = git_env(d)

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
               GIT_AUTHOR_DATE="2026-08-22T10:00:00+05:45",
               GIT_COMMITTER_DATE="2026-08-22T10:00:00+05:45")
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
            # THE LABEL USED TO SAY `{mode} mode reaches ...` and this calls `_stamps`
            # directly, so it never touched the dispatch: it passed under the old wiring, it
            # passes under the new one, and it would pass with no wiring at all. What it does
            # prove is that the history rule itself refuses a stranger and a local offset.
            # Which mode asks which question is checked against the source, below.
            if not getattr(guard, "_stamps", None):
                check(f"[{mode}] the history author rule exists at all", False, found[0])
                check(f"[{mode}] the history timezone rule exists at all", False, found[0])
                continue
            check(f"[{mode}] the history rule refuses an unrelated author",
                  any("not by the project identity" in f for f in found), str(found))
            check(f"[{mode}] the history rule refuses a local offset",
                  any("not UTC" in f for f in found), str(found))
    # AND THE WIRING, which is the claim the two checks above do not make. This used to read
    # `main() calls _stamps before it branches on the mode`, and that arrangement is what put
    # one retrospective check in front of every mode -- so a single commit with a local offset
    # refused every commit after it, the amend that fixes it included. The rule is not "one
    # call in front"; it is that NO ARM IS WITHOUT A STAMP RULE, each asking what it can act on.
    _main_src = io.open(os.path.join(ROOT, "tools", "guard.py"), encoding="utf-8").read()
    _guard_src = _main_src
    _main_src = _main_src[_main_src.index("def main("):]
    # `.find`, not `.index`: a build with an arm missing must give a red check with a reason,
    # not a ValueError out of the harness that ends the run and hides everything after it.
    _cuts = [_main_src.find(m) for m in ("if args.staged:", "elif args.tree:", "\n    else:")]
    check("main() still branches three ways on the mode", all(c > 0 for c in _cuts)
          and _cuts == sorted(_cuts), f"could not locate the arms: {_cuts}")
    if all(c > 0 for c in _cuts) and _cuts == sorted(_cuts):
        _end = _main_src.find("if refusals:", _cuts[2])
        _arms = {"--staged": _main_src[_cuts[0]:_cuts[1]],
                 "--tree": _main_src[_cuts[1]:_cuts[2]],
                 "--range": _main_src[_cuts[2]:_end if _end > 0 else len(_main_src)]}
        check("--staged reaches a stamp rule",
              "_pending_stamp(" in _arms["--staged"],
              "pre-commit would write a commit nothing had looked at")
        check("--tree reaches a stamp rule",
              "_stamps(" in _arms["--tree"],
              "CI, the part CONTRIBUTING says cannot be skipped, stopped checking")
        check("--range reaches a stamp rule",
              "_stamps(" in _arms["--range"] or "scan_history(" in _arms["--range"],
              "pre-push stopped checking who wrote the range")
        # ...and the indirect one is really indirect: `scan_history` must still call it.
        _sh = _guard_src[_guard_src.index("def scan_history("):]
        check("...and --range's route to it, scan_history, still calls _stamps",
              "_stamps(rng, refusals)" in _sh[:_sh.find("\ndef ", 1)],
              "scan_history no longer runs the stamp rules")

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
              {"hints": [{"level": "warn", "text": "\u0416\u0429\u04ae\u0424"}]},
              ensure_ascii=False))))
    check("allowed: the same characters in a model's reply",
          not scan("out/results_x.json", json.dumps(
              {"results": [{"attack": {"id": "a"},
                            "trials": [{"probe": {"output": "\u0416\u0429\u04ae\u0424"}}]}]},
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

    # --- THE HOOKS ARE EXECUTED, NOT GREPPED -------------------------------------------------
    #
    # Everything below this point used to be substring checks on the hooks' TEXT, and a reviewer
    # showed what that is worth: replace `.githooks/pre-commit` with
    #
    #     #!/usr/bin/env bash
    #     # Runs tools/guard.py via find_python. A missing interpreter is not a pass; we exit 1.
    #     exit 0
    #
    # and every check passed — the strings `tools/guard.py`, `find_python` and `not a pass` are
    # all still in the file, in a comment — while a staged `ghp_` committed cleanly. The mode
    # check passed too, because the mode was untouched.
    #
    # So: a real repository, `core.hooksPath` set the way CONTRIBUTING says to set it, a real
    # credential staged, and a real `git commit`. What is under test is whether the commit
    # HAPPENS, which no amount of grepping the hook can tell you.
    #
    # ATTEMPTED RATHER THAN PRE-CHECKED, and that distinction cost a red build. This began by
    # asking `bash -c "exit 0"` and failing when the answer was no, which turned a property of
    # the runner into a failure: the windows-latest leg has git on PATH and not bash, and it was
    # the only one of four to fail while the same claim passed on both ubuntu legs and on macOS.
    # CI does not use hooks — `guard.py --tree` is the step that cannot be skipped, and it runs
    # on its own.
    #
    # It must not become silence either. Measured on a PATH with every bash stripped out: git
    # does not skip a hook it cannot run, it dies with `cannot spawn .githooks/pre-commit` and
    # the commit fails outright. A machine without a shell does not get weaker hooks, it gets no
    # commits — which is why CONTRIBUTING says so beside the install line.
    #
    # Three outcomes, and only the last is a failure: it ran and passed, it could not start
    # here and said so, or it ran and gave the wrong answer.
    with tempfile.TemporaryDirectory() as d:
        henv = git_env(d)

        def hg(*a):
            return _sp.run(["git", "-C", d] + list(a), capture_output=True, text=True, env=henv)

        shutil.copytree(os.path.join(ROOT, ".githooks"), os.path.join(d, ".githooks"))
        os.makedirs(os.path.join(d, "tools"), exist_ok=True)
        for f in ("guard.py", "licences.py"):
            shutil.copy(os.path.join(ROOT, "tools", f), os.path.join(d, "tools", f))
        io.open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8").write(
            "\n".join(["[project]", 'name = "x"', 'version = "0"', "dependencies = []", ""]))
        hg("init", "-q", "-b", "main")
        hg("config", "user.name", "QAtration")
        hg("config", "user.email", "qatration@gmail.com")
        hg("config", "core.hooksPath", ".githooks")
        for f in ("pre-commit", "pre-push"):
            os.chmod(os.path.join(d, ".githooks", f), 0o755)

        io.open(os.path.join(d, "ok.txt"), "w", encoding="utf-8").write("nothing here")
        hg("add", "-A")
        first = hg("commit", "-qm", "ordinary work")
        said = (first.stdout + first.stderr).lower()

        if first.returncode != 0 and "cannot spawn" in said:
            print("SKIP  the hooks, end to end: no shell on this machine, so git cannot start "
                  "a hook at all.")
            print("      Verified on every platform in the matrix that has one. NOT verified "
                  "here, and this")
            print("      line exists so a green run on this platform is never read as having "
                  "checked it.")
        else:
            check("the pre-commit hook lets ordinary work through",
                  first.returncode == 0, (first.stdout + first.stderr)[:200])

            TOKEN = "ghp_" + "a" * 20
            io.open(os.path.join(d, "leak.py"), "w", encoding="utf-8").write(
                "KEY = '%s'" % TOKEN)
            hg("add", "-A")
            r = hg("commit", "-qm", "a credential")
            listed = hg("show", "--name-only", "--format=", "HEAD").stdout
            check("...and REFUSES a commit carrying a credential",
                  r.returncode != 0 and "leak.py" not in listed,
                  f"exit {r.returncode}; HEAD lists {listed.split()}")

            # AND THE SAME HOOK, GUTTED. If this passes, the check above proved nothing about
            # the hook — only that the guard works when something calls it.
            io.open(os.path.join(d, ".githooks", "pre-commit"), "w", encoding="utf-8",
                    newline="\n").write(
                "#!/usr/bin/env bash\n"
                "# Runs tools/guard.py via find_python. A missing interpreter is not a pass.\n"
                "exit 0\n")
            os.chmod(os.path.join(d, ".githooks", "pre-commit"), 0o755)
            hg("add", "-A")
            r = hg("commit", "-qm", "the same credential, hook gutted")
            check("...and this check would notice if the hook were gutted to `exit 0`",
                  r.returncode == 0,
                  "the gutted hook still refused, so the check above is not testing the hook")

    # --- THE PUSH PATH, WITH A REAL REMOTE, BECAUSE A TAG IS A NEW REF ----------------------
    #
    # `pre-push` read "a new branch: everything reachable from it" for any ref the remote does
    # not have, and a tag is exactly such a ref. So `git push origin v0.2.0` re-judged the whole
    # published history and refused on the one commit whose message quotes the offset it was
    # removing -- text that left this machine in August, that `scan_messages` records as
    # unrewritable, and that no action available to anyone could satisfy. A gate no release can
    # pass is the gate somebody passes `--no-verify` to, which is the one thing its own refusal
    # text says never to do.
    #
    # Executed, not read: a repository, a bare remote, real pushes. What is under test is
    # whether the push HAPPENS.
    with tempfile.TemporaryDirectory() as d:
        work, bare = os.path.join(d, "work"), os.path.join(d, "remote.git")
        os.makedirs(work)
        penv = git_env(d)

        def pg(*a):
            return _sp.run(["git", "-C", work] + list(a), capture_output=True, text=True,
                           env=penv)

        _sp.run(["git", "init", "-q", "--bare", bare], capture_output=True, text=True, env=penv)
        shutil.copytree(os.path.join(ROOT, ".githooks"), os.path.join(work, ".githooks"))
        os.makedirs(os.path.join(work, "tools"), exist_ok=True)
        for f in ("guard.py", "licences.py"):
            shutil.copy(os.path.join(ROOT, "tools", f), os.path.join(work, "tools", f))
        io.open(os.path.join(work, "pyproject.toml"), "w", encoding="utf-8").write(
            "\n".join(["[project]", 'name = "x"', 'version = "0"', "dependencies = []", ""]))
        # THE FIXTURE NEEDS THE ONE FILE EVERY REAL CHECKOUT HAS. This repository copies
        # `tools/*.py` in, python compiles them, and `git add -A` then stages
        # `tools/__pycache__/*.pyc`. A .pyc is a bag of bytes and some of those bytes decode as
        # Cyrillic, so the guard refused the push and this test failed for a reason that had
        # nothing to do with what it measures. It passed until yesterday only because the
        # compiled bytes happened not to contain one.
        io.open(os.path.join(work, ".gitignore"), "w", encoding="utf-8",
                newline="\n").write("__pycache__/\n*.pyc\n")
        pg("init", "-q", "-b", "main")
        pg("config", "user.name", "QAtration")
        pg("config", "user.email", "qatration@gmail.com")
        pg("config", "core.hooksPath", ".githooks")
        pg("remote", "add", "origin", bare)
        for f in ("pre-commit", "pre-push"):
            os.chmod(os.path.join(work, ".githooks", f), 0o755)

        def pcommit(msg, body, verify=True):
            io.open(os.path.join(work, "f.txt"), "w", encoding="utf-8").write(body)
            pg("add", "-A")
            return pg("commit", "-qm", msg) if verify else pg("commit", "-q", "--no-verify",
                                                              "-m", msg)

        first = pcommit("ordinary work", "one")
        said = (first.stdout + first.stderr).lower()
        if first.returncode != 0 and "cannot spawn" in said:
            print("SKIP  the push path, end to end: no shell on this machine, so git cannot "
                  "start a hook at all.")
            print("      Verified on every platform in the matrix that has one. NOT verified "
                  "here.")
        else:
            r = pg("push", "-q", "origin", "main")
            check("the pre-push hook lets ordinary work out", r.returncode == 0,
                  (r.stdout + r.stderr)[:200])

            # HISTORY THAT IS ALREADY PUBLISHED, and cannot be rewritten out of anyone's clone.
            # Assembled rather than spelled, so this file does not become a second copy of the
            # thing it is about.
            OFFSET = "+03" + ":00"
            pcommit("explain a fix\n\nthe machine stamped `%s`" % OFFSET, "two", verify=False)
            r = pg("push", "-q", "--no-verify", "origin", "main")
            check("...and a bad message can be got onto a remote, as one once was",
                  r.returncode == 0, (r.stdout + r.stderr)[:200])

            # THE RELEASE. The tag names a commit the remote already has, so the only honest
            # answer is that nothing is leaving.
            pg("tag", "-a", "v1", "-m", "a release")
            r = pg("push", "origin", "v1")
            check("a tag on an already-pushed commit is not refused for that history",
                  r.returncode == 0,
                  "the push path re-judged what the remote already holds: "
                  + (r.stdout + r.stderr)[:300])

            # AND IT IS STILL A GATE. Narrowing the range must not have narrowed the rule: a
            # new commit is exactly what the remote does NOT have.
            pcommit("a message quoting %s in prose" % OFFSET, "three", verify=False)
            r = pg("push", "origin", "main")
            check("...while a NEW commit with the same fault is still refused",
                  r.returncode != 0,
                  "the push path let a fresh bad message through")

            TOKEN2 = "ghp_" + "b" * 20
            pg("reset", "-q", "--hard", "HEAD~1")
            io.open(os.path.join(work, "leak.py"), "w", encoding="utf-8").write(
                "KEY = '%s'" % TOKEN2)
            pg("add", "-A")
            pg("commit", "-q", "--no-verify", "-m", "an ordinary looking change")
            r = pg("push", "origin", "main")
            check("...and so is a new commit carrying a credential",
                  r.returncode != 0,
                  "the push path let a credential out")

    # ONE GIT ENVIRONMENT, AND THE REASON IS A RED MATRIX. This file built the environment for
    # its throwaway repositories five separate times. Some copies pinned the dates, none pinned
    # the identity, and the checks that ask git who it would record therefore asked the machine
    # instead -- green here, red on every CI runner. The helper is the fix; a sixth copy would
    # undo it quietly, so the count is checked rather than trusted.
    # ASSEMBLED, NOT WRITTEN OUT: spelling the needle here would make this check count itself,
    # which it duly did on the first run and reported three constructions where there was one.
    _self_src = io.open(os.path.join(HERE, "test_guard.py"), encoding="utf-8").read()
    _needle = "GIT_CONFIG_" + "GLOBAL="
    check("the git environment is built in exactly one place",
          _self_src.count(_needle) == 1,
          f"{_self_src.count(_needle)} constructions — build it with git_env()")
    check("...and it pins the identity rather than inheriting it",
          "GIT_AUTHOR_NAME=name" in _self_src and "guard.IDENTITY.partition" in _self_src,
          "git_env borrows whoever the machine says you are")

    # --- THE STAMP THIS COMMIT WOULD CARRY ---------------------------------------------------
    #
    # `_stamps("HEAD")` ran in every mode, and at pre-commit the only commit in reach is the
    # previous one. So one commit with a local offset refused every commit after it, INCLUDING
    # the amend that fixes it, and the only way out was the `--no-verify` the refusal text tells
    # you never to pass. Found by making that commit.
    #
    # It now reads forward at `--staged`: `git var` resolves the identity and date exactly as
    # the commit will record them, which catches a local offset one commit EARLIER than the
    # rule it replaces -- before the object exists.
    #
    # `git var` reads config and environment only, so this needs no repository of its own.
    def _pending(**env):
        keep = {k: os.environ.get(k) for k in env}
        os.environ.update({k: v for k, v in env.items() if v is not None})
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
        try:
            found = []
            guard._pending_stamp(found)
            return found
        finally:
            for k, v in keep.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    # PINNED, NOT BORROWED. These left the name and email unset so git would fall back to
    # configuration -- which is the project identity on the machine this was written on and
    # something host-shaped on a CI runner. That is what turned the whole matrix red.
    _who, _, _mail = guard.IDENTITY.partition(" <")
    _utc = dict(GIT_AUTHOR_DATE="2026-01-01T12:00:00+00:00",
                GIT_COMMITTER_DATE="2026-01-01T12:00:00+00:00",
                GIT_AUTHOR_NAME=_who, GIT_AUTHOR_EMAIL=_mail.rstrip(">"),
                GIT_COMMITTER_NAME=_who, GIT_COMMITTER_EMAIL=_mail.rstrip(">"))

    _local = dict(_utc, GIT_AUTHOR_DATE="2026-01-01T12:00:00+05:45",
                  GIT_COMMITTER_DATE="2026-01-01T12:00:00+05:45")
    check("refused: the machine would stamp the commit with a local offset",
          any("+05:45" in f for f in _pending(**_local)),
          "a local offset is only caught after the commit exists")
    check("...and the refusal says how to fix it before the object is written",
          any("TZ=UTC" in f for f in _pending(**_local)),
          "the refusal does not say what to do")

    check("allowed: a UTC stamp", not _pending(**_utc), str(_pending(**_utc)))

    # `-0000` is git's "timezone unknown" and says less about a location than `+00:00` does.
    # The judgement lives in `_offset` and must not be re-decided here.
    check("allowed: -0000, which is an absence and not a place",
          not _pending(**dict(_utc, GIT_AUTHOR_DATE="2026-01-01T12:00:00-00:00",
                              GIT_COMMITTER_DATE="2026-01-01T12:00:00-00:00")),
          "a missing timezone was read as a location")

    check("refused: the commit would carry someone else's name",
          any("not by the project identity" in f
              for f in _pending(**dict(_utc, GIT_AUTHOR_NAME="Someone Else",
                                       GIT_AUTHOR_EMAIL="someone@example.com"))),
          "an unrelated author walks past pre-commit")

    # And the wiring, because the claim is about WHICH mode asks WHICH question.
    _g = io.open(os.path.join(ROOT, "tools", "guard.py"), encoding="utf-8").read()
    _m = _g[_g.index("def main("):]
    _staged_arm = _m[_m.index("if args.staged:"):_m.index("elif args.tree:")]
    _tree_arm = _m[_m.index("elif args.tree:"):_m.index("    else:")]
    check("--staged asks what the commit WOULD carry",
          "_pending_stamp(refusals)" in _staged_arm,
          "pre-commit does not check the stamp it is about to write")
    check("...and does not ask about history it cannot let you fix",
          "_stamps(" not in _staged_arm,
          "a bad commit would lock pre-commit against its own repair")
    check("--tree still reads history, as the force-push backstop",
          '_stamps("HEAD"' in _tree_arm,
          "CI stopped checking who wrote the history")

    # One identity, named once. Writing the literal a second time is the copy this project
    # keeps finding in its own code.
    check("the project identity is a constant, not a repeated literal",
          _g.count('"QAtration <qatration@gmail.com>"') == 1,
          f"the identity literal appears {_g.count(chr(34) + 'QAtration <qatration@gmail.com>' + chr(34))} times")

    # --- WHAT THE COMMITS SAY ----------------------------------------------------------------
    #
    # The gate read every blob, the author line and the timezone stamp, and never a word of the
    # messages. Sixty-seven thousand characters of prose, written faster than anything they
    # describe and reviewed by nobody, on the repository's front page and in every clone.
    #
    # It cost one: a `+03:00` survives in the message of the commit that removed that same
    # offset from the code comments, because the sentence explaining the removal quoted the
    # thing being removed. Already pushed by the time anyone looked.
    #
    # THE SCOPE IS THE DESIGN. A message does not exist at `--staged` time, and checking all of
    # HEAD on `--tree` would fail every CI run forever over a sentence nobody can rewrite. What
    # is still changeable is what has not left yet, so this runs on `--range`, which is exactly
    # the set `git push` is about to hand the remote.
    with tempfile.TemporaryDirectory() as d:
        menv = git_env(d)

        def mg(*a):
            return _sp.run(["git", "-C", d] + list(a), capture_output=True, text=True, env=menv)

        mg("init", "-q", "-b", "main")
        mg("config", "user.name", "QAtration")
        mg("config", "user.email", "qatration@gmail.com")

        def commit(msg, body="x"):
            io.open(os.path.join(d, "f.txt"), "w", encoding="utf-8").write(body)
            mg("add", "-A")
            return mg("commit", "-qm", msg)

        def refused_for(want, rng):
            found = []
            old_root = guard.ROOT
            try:
                guard.ROOT = d
                guard.scan_messages(rng, found)
            finally:
                guard.ROOT = old_root
            return [f for f in found if want in f]

        commit("a first commit that says nothing at all", "one")
        base = mg("rev-parse", "HEAD").stdout.strip()

        # THE ONE THAT GOT OUT. An offset in prose is as permanent as one in a header.
        commit("explain a fix\n\nthe machine stamped `+03:00` and nothing showed it", "two")
        check("refused: a timezone offset quoted in a commit message",
              bool(refused_for("+03:00", f"{base}..HEAD")),
              "an offset in prose went unread")
        check("...and the refusal says why an offset in a sentence still counts",
              any("location" in f for f in refused_for("+03:00", f"{base}..HEAD")),
              "the message does not explain itself")

        base2 = mg("rev-parse", "HEAD").stdout.strip()
        TOKEN = "ghp_" + "a" * 20
        commit("paste the key that leaked: %s" % TOKEN, "three")
        check("refused: a credential pasted into a commit message",
              bool(refused_for("GitHub personal token", f"{base2}..HEAD")),
              "a credential in a message went unread")

        base3 = mg("rev-parse", "HEAD").stdout.strip()
        commit("a message with \u0414\u043e\u0431\u0440\u0435 in it", "four")
        check("refused: a Cyrillic character in a commit message",
              bool(refused_for("Cyrillic", f"{base3}..HEAD")),
              "our own prose in another script went unread")

        base4 = mg("rev-parse", "HEAD").stdout.strip()
        commit("an ordinary message about an ordinary change", "five")
        check("allowed: a message that says nothing it should not",
              not refused_for("commit", f"{base4}..HEAD"),
              str(refused_for("commit", f"{base4}..HEAD")))

        # SCOPE. The offset above is still in this throwaway history, and a range that excludes
        # it must come back clean — otherwise every future push re-litigates a commit that
        # cannot be changed, which is how a gate gets switched off.
        check("a range that excludes an old bad message is clean",
              not refused_for("+03:00", f"{base4}..HEAD"),
              "the check re-reports history outside the range being pushed")

    # And the wiring: read from the source, because the claim is that it runs on the push path
    # and NOT on the other two.
    _src = io.open(os.path.join(ROOT, "tools", "guard.py"), encoding="utf-8").read()
    _main = _src[_src.index("def main("):]
    check("scan_messages is called on the --range path",
          "scan_messages(args.range" in _main,
          "the push path does not check what the commits say")
    check("...and not on --tree or --staged, which cannot fix what they would report",
          'scan_messages("HEAD"' not in _main,
          "checking all of HEAD would fail CI forever over an unrewritable commit")

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

    # THE COUNT IN ITS OWN COMMENT, RECOUNTED. That comment used to read "zero across all 429
    # tracked files", and by the time anyone looked there were 511 of them: a number typed once
    # into a file that describes the repository, which is the arrangement the comment beside it
    # now argues against. Saying so and leaving it ungated would have been the same mistake in
    # a more self-aware voice.
    _g = io.open(os.path.join(ROOT, "tools", "guard.py"), encoding="utf-8").read()
    _run = re.compile(guard.LITERAL_CYRILLIC[0] + "+")
    _tracked = [f for f in subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                          text=True).stdout.split()
                if not f.lower().endswith(guard.BINARY)]
    _carry = []
    for _f in _tracked:
        try:
            if _run.search(io.open(os.path.join(ROOT, _f), encoding="utf-8").read()):
                _carry.append(_f)
        except (IOError, OSError, UnicodeDecodeError):
            pass
    _said = re.search(r"Today it is (\w+) files:", _g)
    check("the guard's own comment states how much Cyrillic the repository holds", bool(_said),
          "the sentence recording the count is gone, so nothing recounts it")
    if _said:
        _words = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
                  "seven": 7, "eight": 8, "nine": 9, "ten": 10}
        check("...and the number of files it names is the number there are",
              _words.get(_said.group(1)) == len(_carry),
              "the comment says %s, the tree has %d: %s"
              % (_said.group(1), len(_carry), ", ".join(sorted(_carry))))

    # AND EVERY ONE IS A PLACE THE EXEMPTION ACTUALLY NAMES. The count alone would pass if a
    # leak replaced a translation file one for one, so the run itself is checked: outside a
    # declared dictionary, the only Cyrillic allowed is a language writing its own name.
    _stray = []
    for _f in _carry:
        if _f in guard.translation_files(ROOT):
            continue
        _txt = io.open(os.path.join(ROOT, _f), encoding="utf-8").read()
        _bad = [m.group(0) for m in _run.finditer(_txt) if m.group(0) not in guard.endonyms(ROOT)]
        if _bad:
            _stray.append("%s: %s" % (_f, _bad[0][:20]))
    check("...and every Cyrillic run outside a dictionary is a language naming itself",
          not _stray, "; ".join(_stray))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the gate refuses what it must and lets ordinary work through.")


if __name__ == "__main__":
    main()
