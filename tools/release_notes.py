"""The text of a GitHub Release, taken from the changelog rather than typed into a box.

A release note written by hand at tag time is a second account of a change that is already
written down, produced in the least careful minute of the process, and it is the copy people
read first. `CHANGELOG.md` is the project's own record and it is where the reasoning already
lives, so this reads the entry that belongs to the version being released and prints it.

    python tools/release_notes.py v0.2.0        # -> the notes, on stdout

WHAT IT REFUSES. An empty note is worse than no release, because a release page that says
nothing still says "this is what changed". If the changelog has no entry at all, this exits
non-zero rather than printing a blank.

WHAT IT SAYS OUT LOUD instead of hiding: when no entry names the version, the newest entry is
printed with a line admitting that it does not describe this release specifically. That happens
for a tag cut before this file existed, and the honest answer there is the record as it stood at
that tag, labelled as such -- not silence, and not a heading that claims more than it knows.
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")


def entries(text):
    """-> [(heading, body)] newest first, for every `## ` section in the changelog.

    The separator is a `---` line between entries, which is the shape this file has always
    had. A body is everything up to the next entry or the next separator, whichever comes
    first, so a missing separator costs nothing.
    """
    out = []
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if l.startswith("## ")]
    for n, i in enumerate(starts):
        stop = starts[n + 1] if n + 1 < len(starts) else len(lines)
        body = []
        for l in lines[i + 1:stop]:
            if l.strip() == "---":
                break
            body.append(l)
        while body and not body[-1].strip():
            body.pop()
        while body and not body[0].strip():
            body.pop(0)
        out.append((lines[i][3:].strip(), "\n".join(body)))
    return out


def notes_for(tag, text):
    """-> the release body for `tag`, and never an empty string.

    Preferring an entry that names the version is what makes this correct for a tag cut long
    after the entry was written: the newest entry is not automatically the one that describes
    this release.
    """
    found = entries(text)
    if not found:
        raise ValueError("CHANGELOG.md has no `## ` entry, so there is nothing to publish as "
                         "release notes. A blank release page still claims to describe a "
                         "release.")
    version = tag[1:] if tag.startswith("v") else tag
    # A version is matched on its own, so 0.2.0 does not answer for 0.2.10.
    named = [e for e in found if re.search(r"(?<![\d.])%s(?![\d.])" % re.escape(version), e[0])]
    heading, body = (named[0] if named else found[0])
    lead = "## %s\n\n" % heading
    if not named:
        lead = ("*No changelog entry names %s. The newest entry at this tag is below, which is "
                "the record as it stood when the tag was cut.*\n\n" % version) + lead
    return lead + body + (
        "\n\nThe full record, with the reasoning behind each change, is in "
        "[CHANGELOG.md](https://github.com/qatration/qatration/blob/%s/CHANGELOG.md)." % tag)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: python tools/release_notes.py <tag>", file=sys.stderr)
        return 2
    text = io.open(CHANGELOG, encoding="utf-8").read()
    try:
        print(notes_for(argv[0], text))
    except ValueError as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
