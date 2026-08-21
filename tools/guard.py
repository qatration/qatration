"""The gate that runs before something becomes permanent, and again before it leaves.

    python tools/guard.py --staged           # what is about to be committed
    python tools/guard.py --range A..B       # what is about to be pushed
    python tools/guard.py --tree             # the working tree, for CI and for a person
    python tools/guard.py --selftest         # every pattern, shown catching something

WHY IT IS IN THE REPOSITORY. The first version of this lived in `.git/hooks/pre-push` and was
deliberately untracked, on the argument that a list of forbidden strings must not itself be
published. That argument holds for a handful of literal strings and for nothing else, and the
cost of applying it to the whole file was steep: the checks did not exist on a fresh clone, did
not exist for anybody else, did not run in CI, and ran only on `git push` — so a working tree
could carry a credential through any number of commits and only hear about it at the end.

So the split is by what the pattern IS, not by which file it sits in. Everything here is a
format or a rule: an AWS session-token prefix, a Slack token shape, an AGPL dependency. Naming
those publicly gives away nothing — a scanner that refuses `ghp_` tells an attacker what every
GitHub tokeniser page already does. The literal private strings live in a local supplement,
`.guard-local`, which is gitignored and read if present; without it this still runs, and says
so rather than implying the check was complete.

WHAT IT CHECKS, AND WHY EACH IS HERE:

  * credential FORMATS — provider prefixes with fixed-length bodies. None has ever leaked from
    this repository, which is the wrong reason for a gate to be silent about it: the first one
    would be expensive and would go out at the speed of a `git push`.
  * dependency licences — through `tools/licences.py`, the same module `test_packaging.py`
    reads. An AGPL package reached `pyproject.toml` once and was caught by a question.
  * escaped codepoints in stored artifacts — `\\u0414` and its double-escaped form are a third
    encoding layer that a literal scan and a single-escape scan both miss.
  * a local supplement of exact strings, if one exists.

FOUR CREDENTIAL PATTERNS ARE DELIBERATELY ABSENT, and finding that out is why this list was run
against the real history before it was trusted. The first draft included them and refused this
repository's own fixtures:

    sk-                    `targets_rangebot.py` plants `sk-rangeQA9931…` as the practice bot's
                           secret, which its own attacks exist to extract
    AKIA[0-9A-Z]{16}       `test_oracle.py` feeds AWS's own published example key
                           (AKIAIOSFODNN7EXAMPLE) to a detector, three times
    sk-ant-                `targets_anthropic.yaml` documents the variable as
                           `export ANTHROPIC_API_KEY=sk-ant-…`
    BEGIN … PRIVATE KEY    `test_oracle.py` uses four characters of a PEM header as input

In a tool whose subject IS credential formats, the fixtures are credential-shaped by design, and
a pattern that fires on its own fixture is one somebody switches off. Everything below matches
nothing in this repository today, which is the only reason it will mean something tomorrow.
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL = os.path.join(ROOT, ".guard-local")

# (name, pattern, a string the pattern MUST match). The third element is not documentation: it
# is fed to the pattern by `--selftest`, in this process, every run. A scanner nobody has seen
# catch anything is a scanner that reports clean because it is broken.
CREDENTIALS = [
    ("AWS session token", r"ASIA[0-9A-Z]{16}", "ASIA" + "Q" * 16),
    ("OpenAI project key", r"sk-proj-", "sk-proj-abc123"),
    ("GitHub personal token", r"ghp_[0-9A-Za-z]{20}", "ghp_" + "a" * 20),
    ("GitHub OAuth token", r"gho_[0-9A-Za-z]{20}", "gho_" + "a" * 20),
    ("GitHub fine-grained token", r"github_pat_", "github_pat_11ABC"),
    ("GitLab token", r"glpat-", "glpat-xxxxxxxx"),
    ("Slack token", r"xox[baprs]-", "xoxb-1-2-abc"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{30}", "AIza" + "b" * 30),
    ("Google OAuth token", r"ya29\.", "ya29.a0Af"),
    ("SendGrid key", r"SG\.[0-9A-Za-z_-]{20}", "SG." + "c" * 20),
    ("Docker Hub token", r"dckr_pat_", "dckr_pat_xyz"),
    ("npm token", r"npm_[0-9A-Za-z]{30}", "npm_" + "d" * 30),
    ("Stripe live key", r"sk_live_[0-9A-Za-z]{16}", "sk_live_" + "e" * 16),
    ("Twilio account SID", r"AC[0-9a-f]{32}", "AC" + "f" * 32),
    ("private key header", r"-----BEGIN OPENSSH PRIVATE KEY-----",
     "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.",
     "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.sig"),
]

# TWO CHECKS, NOT ONE, and conflating them is how the first version of this self-test failed:
# a Cyrillic character and the six-character text of its escape are different bytes, and neither
# pattern sees the other.
#
#   LITERAL — the character itself. Zero across all 414 tracked files today, which is the only
#   reason it is worth asserting; a check that starts life with exemptions never gets any.
#
#   ESCAPED — the same character written `\\uXXXX`, and the same thing at more layers.
#   `json.dumps` handed a string that already contains the escape writes `\\\\uXXXX`, a third
#   encoding that a literal scan and a single-escape scan both miss.
#
# BOTH SIDES WRITTEN AS ESCAPES, so this file contains none of what it looks for and stays under
# its own literal check rather than needing an exemption from it. The credential patterns below
# cannot be written that way and do need one — see SELF.
LITERAL_CYRILLIC = ("[\u0400-\u052f]", "\u0414")
ESCAPED_CYRILLIC = (r"(?:\\){1,4}u04[0-9a-fA-F]{2}", r"\\u0414")

# Stored artifacts are JSON, and inside one the two kinds of string are structurally distinct:
# what we wrote (a prompt from the corpus, a note, a config path) and what a model said back.
ARTIFACT = re.compile(r"(^|/)out/.*\.json$")

# EXEMPT BY FIELD, NOT BY FILE. The earlier rule named `out/benign_guardedrag-naive.json` and
# its reason — "a model's own reply, recorded verbatim" — and that reason is not a property of
# the file. The moment a second model emitted a stray Cyrillic fragment inside a Korean answer,
# the list would have grown a second name, then a third, and a check that acquires an exemption
# every time it fires is a check on its way to being switched off.
#
# The reason IS a property of the field. Our text lives in prompts, notes and metadata; a
# model's reply is evidence and may legitimately contain anything at all. So the exemption is
# `output`, and the exemption list is empty. Measured across every artifact in `out/`: exactly
# one Cyrillic string exists, under `output`, in a NeMo reply that answered in Korean and
# slipped four Cyrillic letters into the middle of it.
MODEL_FIELDS = {"output", "full", "evidence", "reply", "observations", "answer", "text",
                "response", "completion"}

UNPARSEABLE = "<unparseable>"

# THE FILE THAT DEFINES THE PATTERNS CANNOT BE SCANNED FOR THEM. `sk-proj-` is a literal
# substring of the pattern `r"sk-proj-"`, so the first real run of this refused eight of its own
# rules. The docstring above already states the principle for the four credential patterns this
# repository leaves out: a pattern that fires on its own fixture is one somebody switches off.
# One file, named, with the reason — not a directory, and not a rule about "definitions".
#
# The samples in CREDENTIALS are built (`"ghp_" + "a" * 20`) rather than written out, so nothing
# here is a plausible-looking key that a reader has to check.
# `redteam/test_guard.py` is here for the same reason and no other: it feeds every pattern a
# sample, and a sample of a GitHub token is a GitHub token as far as a substring search is
# concerned. THE EXEMPTION IS NARROW ON PURPOSE — it covers the credential patterns only. Both
# files stay under the Cyrillic check (they write their samples as `\uXXXX` escapes, so neither
# holds the character) and under the local-supplement check, which is where a real leak of the
# kind this repository actually risks would show up.
SELF = {"tools/guard.py", "redteam/test_guard.py"}

BINARY = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".ico", ".woff", ".woff2")


def _git(*args):
    # UTF-8, EXPLICITLY. `text=True` alone decodes with `locale.getpreferredencoding()`, which on
    # Windows is the system's legacy ANSI codepage rather than UTF-8 — so on a machine whose
    # legacy codepage covers a non-Latin script, every em dash in every file came back as a
    # different character and a good number of them landed in that script's range. The first
    # real run of this hook refused sixty-eight files, one line each, at whichever line held
    # their first non-ASCII character. `--tree` was green at the same moment, because it reads
    # files directly and already said `encoding="utf-8"`: one check, two readers, two answers.
    return subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True,
                          encoding="utf-8", errors="replace")


def _local_literals():
    """Exact strings from `.guard-local`, one per line, `#` comments ignored. May not exist."""
    if not os.path.isfile(LOCAL):
        return None
    out = []
    for line in open(LOCAL, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if line:
            out.append(line)
    return out


def _staged_files():
    r = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [p for p in r.stdout.splitlines() if p.strip()]


def _tree_files():
    r = _git("ls-files")
    return [p for p in r.stdout.splitlines() if p.strip()]


def _read_blobs(sha_by_path):
    """{path: text} for a set of git objects, in ONE subprocess.

    `cat-file --batch` writes `<sha> <type> <size>\\n<size bytes>\\n` for an object it has, and
    `<sha> missing\\n` — no size, no body — for one it does not. BOTH have to advance the read
    position, and the first version of this only advanced past bodies it wanted: fed the output
    of `rev-list --objects`, which names trees as well as blobs, it skipped each tree's header
    and then read the tree's BYTES as the next path's contents. Every file after the first tree
    came back as somebody else's data, and five artifacts were reported as unparseable JSON.

    Bytes, not text: the size is a byte count, so decoding before slicing would make it useless.
    """
    return _read_blobs_report(sha_by_path)[0]


def _read_blobs_report(sha_by_path):
    """-> ({label: text}, [label]). The second list is what git could NOT hand back.

    NOT-A-BLOB AND NOT-READABLE ARE DIFFERENT THINGS, and this is the only code that can
    tell them apart, because it is the only code that sees git's `<sha> <type> <size>`
    line. `rev-list --objects` names trees as well as blobs, so a caller that infers the
    shortfall by subtracting keys reports every directory in the repository as an
    unreadable file — 30 of them here, on the first run. A gate that says that is a gate
    somebody stops reading.

    A tree is simply not returned and not complained about. `missing`, and a desynchronised
    stream, are named.
    """
    if not sha_by_path:
        return {}, []
    order = list(sha_by_path)
    proc = subprocess.run(["git", "-C", ROOT, "cat-file", "--batch"],
                          input=("\n".join(sha_by_path[p] for p in order) + "\n").encode(),
                          capture_output=True)
    raw, pos, out, lost = proc.stdout, 0, {}, []
    for i, path in enumerate(order):
        nl = raw.find(b"\n", pos)
        if nl < 0:
            lost.extend(order[i:])          # the stream ended early: everything after is unread
            break
        header = raw[pos:nl].split()
        pos = nl + 1
        if len(header) < 3:
            lost.append(path)                         # `<sha> missing`: no body to step over
            continue
        try:
            size = int(header[2])
        except ValueError:
            lost.extend(order[i:])
            # The stream is out of step: what should be a header is object bytes. Stop rather
            # than raise, so the caller reports "fewer paths came back than were asked for" —
            # a named failure a reader can act on instead of a traceback out of a git parser.
            break
        if header[1] == b"blob":
            out[path] = raw[pos:pos + size].decode("utf-8", "replace")
        pos += size + 1                               # ALWAYS, blob or not
    return out, lost


def _staged_contents(paths):
    """{path: text} for what is IN THE INDEX, in one subprocess rather than one per file.

    Reading the index and not the working tree is the point: `git add -p` stages a hunk, and a
    hook that scanned the file on disk would check something other than what is about to be
    committed.

    ONE `git cat-file --batch` INSTEAD OF `git show` PER PATH. Measured on this repository's own
    change set: 124 files took 2.4 seconds through per-file `git show`, against 0.29 seconds for
    424 files read straight off the disk — the staged scan, on a third of the files, was eight
    times slower, and all of it was process spawning. It matters because it scales with the
    commit: a thousand-file change would have been twenty seconds in front of every commit, and
    a hook that slow is a hook people pass `--no-verify` to.
    """
    if not paths:
        return {}
    ids = _git("ls-files", "--stage", "--", *paths).stdout.splitlines()
    blobs = {}
    for line in ids:
        # <mode> <sha> <stage>\t<path>
        head, _, path = line.partition("\t")
        parts = head.split()
        if len(parts) >= 2 and path:
            blobs[path] = parts[1]
    if not blobs:
        return {}
    return _read_blobs(blobs)


def _read_tree(path):
    full = os.path.join(ROOT, path)
    try:
        return open(full, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def _cyrillic_outside_model_output(text):
    """-> [(json path, sample)] for Cyrillic in a stored artifact that a model did not produce.

    Parsed rather than pattern-matched, so that a field can be told from a value — but parsing
    is not enough on its own, and believing it was is how the first version of this went wrong.
    MEASURED, per layer of escaping, on what the bytes in the file look like:

        the character   -> parses to the character.   Caught by LITERAL.
        "\\uXXXX"        -> parses to the character.   json.loads collapses one layer, so
                                                      LITERAL catches this one too.
        "\\\\uXXXX"       -> parses to the TEXT        TWO layers: what json.dumps writes when
                           "\\uXXXX", six characters   handed a string that already contains
                           and none of them Cyrillic.  the escape. LITERAL sees nothing here.
                                                      Caught only by ESCAPED.

    So both run, on every parsed string. Parsing collapses ONE layer, not every layer, and the
    layer it does not collapse is precisely the one this project already had to learn about.

    A file that does not parse is REPORTED, not skipped: an unreadable artifact is an unanswered
    question, not a clean one.
    """
    import json as _json
    lit = re.compile(LITERAL_CYRILLIC[0])
    esc = re.compile(ESCAPED_CYRILLIC[0])

    def _encoded_results(data):
        """Indices of stored results whose attack was OBFUSCATED before it was sent.

        A recorded `prompt` is our text, which is why it is checked — except where the whole
        technique is that it is not Latin. `enc-homoglyph-authority` is ASCII in the arsenal
        (`SECURITY OVERRIDE by the administrator…`) and `encode: homoglyph` rewrites it at send
        time into Cyrillic look-alikes; twenty-five attacks in the `obfuscation` category work
        that way. The artifact records what was SENT, so the Cyrillic there is evidence rather
        than prose, exactly like a reply.

        Scoped to the attack that declares an encoding rather than to the field, the file, or
        the category, so an unencoded prompt is still checked and prose in any of the scripts
        this looks for cannot ride in beside a payload that is allowed to contain it.
        """
        out = set()
        for i, r in enumerate(data.get("results") or []):
            if isinstance(r, dict) and (r.get("attack") or {}).get("encode"):
                out.add(f"results[{i}]")
        return out
    try:
        data = _json.loads(text)
    except Exception as e:
        return [(UNPARSEABLE, str(e)[:80])]
    encoded = _encoded_results(data) if isinstance(data, dict) else set()
    out, stack = [], [(data, "", None)]
    while stack:
        node, where, key = stack.pop()
        if isinstance(node, str):
            if key in MODEL_FIELDS:
                pass
            elif key == "prompt" and any(where.startswith(p + ".") for p in encoded):
                pass                          # an obfuscated payload; see _encoded_results
            elif lit.search(node) or esc.search(node):
                out.append((where, node[:60]))
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append((v, f"{where}.{k}" if where else str(k), str(k)))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                stack.append((v, f"{where}[{i}]", key))   # a list inherits its field's meaning
    return out[:3]


def scan_files(items, reader, refusals, path_of=None):
    """Every rule, over every item. `items` are LABELS, not necessarily paths.

    A label is usually just the path. From `scan_history` it is `path@sha`, because one
    path has many versions and every one of them is in the push — see there for what that
    cost. `path_of` maps a label back to the path, and only three things key on the path:
    which kind of file it is, whether it is one of the two that DEFINE the patterns, and
    the binary suffix. The refusal itself names the label, so a reader is told which
    version.

    ONLY THE CYRILLIC RULE VARIES BY KIND OF FILE, and that is the whole of the difference.
    An artifact used to `continue` here after its own Cyrillic check, which skipped the
    credential scan and the local-supplement scan for all 113 tracked `out/*.json` files.
    A stored artifact holds MODEL OUTPUT — it is the likeliest place in this repository for
    a pasted key to come to rest, not the least. The module docstring says the supplement
    is "where a real leak of the kind this repository actually risks would show up", and
    it was the one scan an artifact never got.

    A planted `ghp_…` inside `out/results_x.json` returned exit 0 and the word `ok`; the
    same string in `redteam/x.py` was refused.
    """
    to_path = path_of or (lambda label: label)
    literals = _local_literals()
    lit = re.compile(LITERAL_CYRILLIC[0])
    for item in items:
        path = to_path(item)
        if path.lower().endswith(BINARY):
            continue
        text = reader(item)
        if not text:
            continue
        if ARTIFACT.search(path):
            for where, sample in _cyrillic_outside_model_output(text):
                refusals.append(
                    f"{item}: does not parse as JSON ({sample}), so what it holds is unknown"
                    if where == UNPARSEABLE else
                    f"{item}: Cyrillic under `{where}`, which is not a model's reply: {sample!r}")
        else:
            m = lit.search(text)
            if m:
                line = text[:m.start()].count("\n") + 1
                refusals.append(f"{item}:{line}: a Cyrillic character in a tracked file "
                                f"({m.group(0)})")
        if path.replace("\\", "/") not in SELF:      # see SELF: these files ARE the patterns
            for label, pattern, _sample in CREDENTIALS:
                m = re.search(pattern, text)
                if m:
                    refusals.append(f"{item}: looks like a {label} ({m.group(0)[:12]}…)")
        if literals:
            low = text.lower()
            for literal in literals:
                if literal.lower() in low:
                    refusals.append(f"{item}: contains a string listed in .guard-local")
                    break


def _offset(iso_pair):
    """The timezone offset of an iso-strict stamp, or "" if it has none."""
    # `-00:00` IS UTC AND MUST PASS. git writes `-0000` for "timezone unknown" — what a
    # mail-imported patch carries — and that says even less about where a machine is than
    # `+00:00` does. Refusing it would be this check inventing a location out of an absence.
    for part in iso_pair.split("|"):
        tail = part.strip()[-6:]
        if len(tail) == 6 and tail[0] in "+-" and tail[3] == ":":
            if tail not in ("+00:00", "-00:00"):
                return tail
    return ""


def scan_history(rng, refusals):
    """Commits, not the working tree — the one place nobody looks.

    This distinction is why the check exists at all: a `filter-branch --env-filter` once rewrote
    every author line, `git log` read clean, and the real name sat untouched inside twelve
    versions of a file. An `--env-filter` never touches a blob.
    """
    who = _git("log", "--format=%an <%ae>%n%cn <%ce>", rng).stdout.splitlines()
    strangers = sorted({w for w in who if w.strip()
                        and w.strip() != "QAtration <qatration@gmail.com>"})
    for w in strangers:
        refusals.append(f"a commit in {rng} is authored by {w}, not by the project identity")

    # A TIMEZONE OFFSET IS NOT A TIME, IT IS A PLACE. `git commit` stamps the machine's local
    # offset, and that field is as permanent as the diff: it survives a squash, it is in every
    # fork and every mirror, and no later commit can take it back. Seven commits here carried
    # one before anybody looked, because nothing looks — `git log` renders the local time by
    # default and shows the author line, which was already correct.
    #
    # The fix is the same shape as the author check above and belongs beside it: every commit
    # in this project is stamped UTC, so its history says when something changed and nothing
    # else. Set `TZ=UTC` in the environment, or commit through `.githooks`.
    stamps = _git("log", "--format=%ad|%cd", "--date=iso-strict", rng).stdout.splitlines()
    offsets = sorted({o for line in stamps if (o := _offset(line))})
    for o in offsets:
        refusals.append(f"a commit in {rng} is stamped {o}, not UTC — an offset is a location, "
                        f"and it is as permanent as the diff")

    # THROUGH `scan_files`, THE SAME FUNCTION EVERYTHING ELSE USES. This ran `git grep -E -i`
    # over the range instead, and two implementations of one rule gave two answers:
    #
    #   * `-i` made every credential pattern case-insensitive, which `re.search` here is not.
    #     `AC[0-9a-f]{32}` — a Twilio account SID, uppercase by construction — matched
    #     `acd57cee…` inside an HMAC digest in `test_signing.py` and refused the push.
    #   * the SELF exemption did not exist on this path, so the two files that DEFINE the
    #     credential patterns were refused for containing them. Every commit adding them would
    #     have been unpushable.
    #
    # Both were the same mistake: a second copy of a rule. `git rev-list --objects` names every
    # blob the push would carry, they are read in one batch, and `scan_files` decides.
    # A RANGE THAT COULD NOT BE READ IS NOT A CLEAN RANGE. `_git` hands back `.stdout` and
    # nothing else, so a `rev-list` that exited 128 — `origin/main..HEAD` on a clone with no
    # remote, a `remote_sha` the local repository has never fetched — looked exactly like a
    # history with nothing in it. Measured: git exit 128, guard exit 0, the word `ok`. That
    # is this project's own defect class sitting in the gate against it: a check that did
    # not run, reported as a check that passed.
    proc = _git("rev-list", "--objects", rng)
    if proc.returncode != 0:
        why = " ".join(proc.stderr.split())[:120] or f"git exited {proc.returncode}"
        refusals.append(f"the range {rng} could not be read, so nothing about it was "
                        f"checked — {why}")
        return

    # EVERY VERSION OF EVERY FILE, not one per path. This was `blobs.setdefault(path, sha)`,
    # and `rev-list` walks newest-first, so exactly one blob per path was read: the tip's —
    # the same bytes `--tree` had already scanned. The whole reason this function exists is
    # the version that is NO LONGER at the tip. Proven with a three-commit history (clean,
    # credential, credential removed, file kept): both blobs present, `--range` exit 0.
    #
    # Keyed `path@sha` so a refusal names the version a reader has to go and rewrite, and
    # so two paths sharing one blob are still two findings. `path_of` strips it back for the
    # rules that key on the path.
    blobs = {}
    for line in proc.stdout.splitlines():
        sha, _, path = line.partition(" ")
        path = path.strip()
        if path and not path.lower().endswith(BINARY):
            blobs[f"{path}@{sha}"] = sha
    if not blobs:
        return
    contents, missing = _read_blobs_report(blobs)

    # WHAT DID NOT COME BACK IS NOT WHAT IS CLEAN. `_read_blobs` stops on a desynchronised
    # stream rather than raising, and its docstring says the caller reports the shortfall.
    # No caller did: `scan_files` read a missing label as an empty file and moved on.
    #
    # Asked for by the reader rather than inferred by subtracting keys. The subtracting
    # version named all 30 trees in the repository as unreadable files on its first run.
    for k in missing[:6]:
        refusals.append(f"{k} is in {rng} but could not be read back from git, so it was "
                        f"not checked")
    if len(missing) > 6:
        refusals.append(f"...and {len(missing) - 6} more objects in {rng} were unreadable")

    found = []
    scan_files(list(blobs), lambda k: contents.get(k, ""), found,
               path_of=lambda k: k.rsplit("@", 1)[0])
    for f in found[:12]:
        refusals.append(f"in the history being pushed — {f}")
    if len(found) > 12:
        refusals.append(f"...and {len(found) - 12} more in the history being pushed")


def selftest():
    """Every pattern, shown catching something, before any of them reports clean.

    A scanner is worth nothing until it has been seen failing. This project has had three
    scanners that reported CLEAN because their own pattern was mangled on the way in and matched
    nothing at all, and each one was believed.
    """
    bad = []
    for label, pattern, sample in CREDENTIALS:
        if not re.search(pattern, sample):
            bad.append(f"{label}: pattern does not match its own sample {sample!r}")
    # Every layer of escaping, and NOT the literal character — that is the other pattern's job,
    # and asserting it here is what broke the first version of this self-test.
    for layers in (1, 2, 3, 4):
        sample = "\\" * layers + "u0414"
        if not re.search(ESCAPED_CYRILLIC[0], sample):
            bad.append(f"the escaped-codepoint pattern misses {layers} layer(s): {sample!r}")
    if re.search(ESCAPED_CYRILLIC[0], "u0414 with no backslash"):
        bad.append("the escaped-codepoint pattern fires without an escape at all")
    if not re.search(LITERAL_CYRILLIC[0], LITERAL_CYRILLIC[1]):
        bad.append("the literal-Cyrillic pattern does not match its own sample")
    if re.search(LITERAL_CYRILLIC[0], "plain ascii only"):
        bad.append("the literal-Cyrillic pattern fires on ASCII")
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--staged", action="store_true", help="what is about to be committed")
    g.add_argument("--range", help="a commit range about to be pushed, e.g. origin/main..HEAD")
    g.add_argument("--tree", action="store_true", help="every tracked file")
    g.add_argument("--selftest", action="store_true", help="prove the patterns can fire")
    args = ap.parse_args(argv)

    broken = selftest()
    if broken:
        # A BROKEN SCANNER IS A REFUSAL, not a warning. Reporting clean from a pattern that
        # cannot match is the failure this whole project is named after.
        for b in broken:
            print("  BROKEN:", b, file=sys.stderr)
        return 2
    if args.selftest:
        print(f"  ok  {len(CREDENTIALS)} credential patterns and the codepoint pattern all fire "
              f"on a known sample")
        return 0

    refusals = []
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import licences
    refusals += licences.problems(os.path.join(ROOT, "pyproject.toml"))

    if args.staged:
        staged = _staged_files()
        blobs = _staged_contents(staged)
        scan_files(staged, lambda p: blobs.get(p, ""), refusals)
    elif args.tree:
        scan_files(_tree_files(), _read_tree, refusals)
    else:
        scan_history(args.range, refusals)
        scan_files(_tree_files(), _read_tree, refusals)

    if refusals:
        print("\n  REFUSED — nothing was committed or pushed:\n", file=sys.stderr)
        for r in refusals:
            print("    " + r, file=sys.stderr)
        print("\n  Fix it, or if this is a false positive say so in tools/guard.py with the "
              "reason — never by passing --no-verify.\n", file=sys.stderr)
        return 1

    where = "staged changes" if args.staged else ("the tree" if args.tree else args.range)
    note = "" if _local_literals() is not None else "  (no .guard-local on this machine)"
    print(f"  ok  guard: {where} — no credential, no copyleft dependency, "
          f"no Cyrillic outside a recorded reply{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
