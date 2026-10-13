"""May a check that needs a stored artifact skip when the artifact is not there?

A SKIP IS AN ANSWER ABOUT THE MACHINE, NOT ABOUT THE REPOSITORY. A suite that reads a committed
file out of `out/` printed `SKIP ... is not in this checkout` when the file was absent, and
`check.py` counts a SKIP as a pass. That is right on a copy with no `out/` at all, and wrong in
a checkout whose git index holds the file: there the file was deleted, and every check that
read it went quiet while the build stayed green. A gap reported as a measurement, one level up.
Found by an independent review of the suite.

    from tracked import need
    if need(check, path, "the localrag replay"):
        ...  # the artifact is here; run the check

`need` returns True when every path exists. When one is missing it returns False, and says why:
a FAIL through `check` when this checkout ships evidence in that directory, a printed SKIP when
it ships none (a copy without `out/`, or no git to ask).

THE DIRECTORY, NOT THE FILE. Asking whether git tracks the missing file catches a file deleted
by hand and passes one whose deletion was committed: pruned from `out/` in a commit, it is no
longer tracked, and the SKIP is silent again. A checkout that ships any evidence there is
expected to ship what its own suites read.
"""
import os
import subprocess


def ships_evidence(path):
    """-> True when git, in this checkout, tracks any file in `path`'s directory. False when it
    tracks none there, or when there is no checkout or no git to ask: an absence nobody can call
    a deletion."""
    d = os.path.dirname(os.path.abspath(path))
    top = d
    while top and not os.path.isdir(top):
        top = os.path.dirname(top)
    try:
        p = subprocess.run(["git", "-C", top, "ls-files", "--", d],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0 and bool(p.stdout.strip())


def need(check, paths, what):
    """-> True when every one of `paths` exists; otherwise FAIL (evidence shipped) or SKIP."""
    paths = [paths] if isinstance(paths, str) else list(paths)
    missing = [p for p in paths if not os.path.exists(p)]
    if not missing:
        return True
    gone = [p for p in missing if ships_evidence(p)]
    if gone:
        check("%s has the artifacts it reads" % what, False,
              "this checkout ships evidence there and not these: %s"
              % ", ".join(os.path.basename(p) for p in gone))
    else:
        print("SKIP  %s: %s is not in this checkout, so it was NOT checked"
              % (what, ", ".join(os.path.basename(p) for p in missing)))
    return False
