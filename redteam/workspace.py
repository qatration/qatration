"""Where a run's artifacts go, decided in exactly one place.

Thirteen modules used to answer this question, and they answered it four different ways —
`Path(__file__).resolve().parents[1] / "out"`, `os.path.join(ROOT, "out")`,
`os.path.join(os.path.dirname(ROOT), "out")` and a spelled-out double `dirname` — because
`ROOT` means the package directory in some files and the repository in others. All four
happened to land on the same folder, which is the kind of agreement that holds until it
does not: a module moved one directory deeper, or a `ROOT` renamed to match its neighbours,
and one writer starts writing somewhere no reader looks. A result nobody reads is a gap
reported as a measurement, arriving by the dullest possible route.

It is also the smallest change that keeps two targets' evidence apart, which is the point.
Everything under `out/` namespaces by TARGET NAME — `results_<target>.json`,
`history/<target>.jsonl`, `benign_<target>.json` — so two operators who both call their bot
"supportbot" overwrite each other's evidence, silently, and the second run's history diff
reads the first one's findings as their own regressions. Nothing about the security
logic breaks under concurrency: a detector is a pure `(probe, ctx) -> bool`. It is only ever
the FILENAMES, and one root fixes every one of them at once without renaming anything.

    QATRATION_OUT=./runs/mybot  qatration run --target-config …

A caller can set it per run. Today it is what keeps one target's evidence out of another's
files, and what lets two sweeps run side by side.

Read at import, deliberately: a run must not change where it is writing halfway through, and
a module-level constant is what the offline suites monkeypatch to point a scripted fleet at a
temp directory.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ENV_VAR = "QATRATION_OUT"

# DEFAULT_DIR is the folder an installed copy writes into, under the caller's working
# directory. Not `out/`: a bare `out/` appearing in somebody's project is anonymous, and the
# first thing they will do with an anonymous directory they did not create is delete it.
DEFAULT_DIR = "qatration-out"


def in_checkout():
    """Are we running from the repository, or from an installed package?

    `redteam/` beside us is the marker, and it is the right one because installation renames
    this directory to `qatration/`. A source tarball with no `.git` still has it, so this does
    not mistake a download for an install.

    It matters because `<repo>/out` becomes `<site-packages>/out` once installed: evidence
    written into a directory that is shared between projects, often not writable, and wiped by
    the next upgrade. A run whose results vanish on upgrade is the failure this codebase is
    named after — a gap that reads as a measurement.
    """
    return os.path.isdir(os.path.join(REPO, "redteam"))


def out_dir():
    """The artifact root: `$QATRATION_OUT`, else `<repo>/out` in a checkout, else
    `./qatration-out` beside whoever ran the command.

    Absolute in every case, because a relative artifact root is a working-directory dependency
    by another name, and this repo has just finished removing the last one of those. Resolving
    the caller's directory once at import is what keeps that true: the run cannot follow a
    later `chdir` into writing half its evidence somewhere else.
    """
    named = (os.environ.get(ENV_VAR) or "").strip()
    if named:
        return os.path.abspath(os.path.expanduser(named))
    if in_checkout():
        return os.path.join(REPO, "out")
    return os.path.abspath(os.path.join(os.getcwd(), DEFAULT_DIR))


def out_origin():
    """Which of the three rules chose OUT, in words, for a tool that wants to say so.

    An installed copy writes somewhere the reader did not pick, and a tool that writes files
    without saying where has told them nothing.
    """
    if (os.environ.get(ENV_VAR) or "").strip():
        return "$%s" % ENV_VAR
    return "repository checkout" if in_checkout() else "working directory"


OUT = out_dir()


def is_per_model_copy(path):
    """Is this a `--model` copy of a run rather than the canonical one?

    A `--model` override writes `results_<target>_<model>.json`, deliberately BESIDE the
    canonical `results_<target>.json`, so a model matrix is possible without a per-model run
    displacing the run everyone else reads. Every fleet aggregate therefore has to skip them,
    or one run is counted twice — once as itself and once as its own copy.

    Six modules carried the rule as `os.path.basename(fp).count("_") != 1`, and the only thing
    holding them together was a test asserting that the STRING `count("_")` appears in three of
    the six source files. That is a spellcheck, not a check: it says nothing about behaviour,
    it covered four of the places that have the rule, and any of them could have inverted the
    comparison and still passed.
    """
    return os.path.basename(str(path)).count("_") != 1


def results_files(root=None, include_model_copies=False):
    """Canonical `results_*.json` under `root`, sorted, per-model copies skipped by default.

    Takes the root rather than reading OUT, because the offline suites point a module at a
    scripted fleet in a temp directory by rebinding that module's own constant. A helper that
    ignored the caller's root would quietly test the real out/ instead of the fixture.
    """
    import glob
    base = str(root if root is not None else OUT)
    return [fp for fp in sorted(glob.glob(os.path.join(base, "results_*.json")))
            if include_model_copies or not is_per_model_copy(fp)]


def target_of(stem, names):
    """Which target wrote an artifact called `<target>` or `<target>_<tag>`, by longest name.

    Two modules reconstructed this as `stem.split("_")[0]`, which assumes a target name
    contains no underscore and that whatever follows the first one is a tag. It holds on this
    fleet and it is a property of nothing. Where the caller then does `ctxs.get(name, {})` the
    miss is silent and expensive: an empty oracle context means every canary detector is inert
    on real evidence, so nothing fires and the report reads clean.

    Longest known name wins, so `nemo-inputonly` is not read as `nemo`, and no match returns
    None so the caller can SAY it could not resolve rather than scanning against `{}`.
    """
    hits = [n for n in names if stem == n or stem.startswith(n + "_")]
    return max(hits, key=len) if hits else None


def verdict_for(meta):
    """-> "Vulnerable" | "Hardened" | "Not measured", from a results file's meta.

    ONE predicate because two pages were deciding this separately and reached opposite answers
    about the same run. `out/results_httpbot.json` records `attacks_n: 0` — a sweep that sent
    nothing — and both `build_index` and `compare_targets` tested `broke == 0`, so both called
    it hardened: one in the green of a bot that survived fifty attacks, the other in a verdict
    column, two blocks under a section reporting httpbot BROKEN by the adaptive attacker.

    Zero breaches out of zero attacks is not a defence. It is the absence of a measurement, and
    an absence rendered as the best possible result is the failure this project is named after.
    """
    if not (meta or {}).get("attacks_n"):
        return "Not measured"
    return "Vulnerable" if (meta or {}).get("broke", 0) > 0 else "Hardened"


def fleet_names(directory=None):
    """The target names the configs in `directory` define.

    Used to tell a fleet member from an artifact of something that no longer exists. `out/`
    keeps whatever ever ran — a one-off target, a deliberately-unreachable end-to-end fixture —
    and counted, those inflate every published fleet size. This page said 32 systems for 30.
    """
    import os as _os
    import yaml as _yaml
    from target import target_configs
    directory = directory or _os.path.dirname(_os.path.abspath(__file__))
    names = set()
    for fp in target_configs(directory):
        try:
            c = _yaml.safe_load(open(fp, encoding="utf-8")) or {}
        except Exception:
            continue
        names.add(c.get("name")
                  or _os.path.basename(fp)[len("targets_"):-len(".yaml")])
    return names


def fleet_filter(metas, known=None):
    """-> (keep, drop). Which of these results belong to the fleet `known` describes.

    THE DIRECTORY IS IDENTIFIED BY ITS CONTENTS, not by its path. The first version compared
    OUT_DIR against the workspace default, which is the same temp directory whenever a suite
    sets $QATRATION_OUT for a subprocess — so a scripted fleet was measured against the real
    configs and every row was dropped from its own report.

    If NOTHING here belongs to the fleet, this is not the fleet's directory and nothing is
    filtered. That is also the right way to degrade: rename every config and the pages
    over-report, which somebody notices, rather than silently emptying themselves.
    """
    known = set(known or ())
    if not known:
        return list(metas), []
    keep = [m for m in metas if (m or {}).get("target") in known]
    if not keep:
        return list(metas), []
    return keep, [m for m in metas if (m or {}).get("target") not in known]


def safe_target_name(name, where="target config"):
    """A target name that can be part of a filename, or a refusal saying why not.

    THE NAME BECOMES A FILENAME: `results_<name>.json`, `report_<name>.html`,
    `history/<name>.jsonl`, and the last is opened in append mode. `targets_http` wrote this
    rule and this reasoning for itself, and four callers then assigned the raw config value
    onto the target AFTER construction, which reinstated the problem for every adapter that
    does not happen to be the HTTP one.

    Restricted rather than escaped, because a name is a label somebody chose and there is no
    reason for a label to need escaping.
    """
    import re as _re
    name = str(name or "").strip()
    if not name:
        raise SystemExit(f"{where}: `name` is required — it labels the target in every result "
                         f"file and in the run record.")
    if not _re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) or name.strip(".") == "":
        raise SystemExit(
            f"{where}: name={name!r} is not usable as a filename. It is interpolated into "
            f"out/results_<name>.json and out/history/<name>.jsonl, so letters, digits, dot, "
            f"dash and underscore only, up to 64 characters.")
    return name


def read_artifact(path):
    """One stored artifact, or the reason it could not be read. -> (data, None) | (None, why).

    ONE READER, BECAUSE THERE WERE FIVE AND ALL FIVE DIED ON THE SAME FILE. `defense_report`,
    `build_index`, `compare_targets`, `detector_coverage` and `sarif` each opened this directory
    on their own, and a single truncated artifact took every one of them down with a raw
    `JSONDecodeError` — no page, no index, no coverage number, and nothing naming the file.

    A truncated artifact is not hypothetical: it is what an interrupted write leaves, and a
    sweep stopped by hand produces one. The tool that exists to say when a measurement did not
    happen should not be the one that cannot say which file it failed to read.

    The two wrong answers are equally wrong and this returns neither:

      * RAISING makes one bad file hide every good one, which is a coverage question answered
        by a stack trace.
      * SKIPPING silently removes a target from a report that then reads as complete — the
        defect this whole project is named after, delivered to a customer in a remediation
        page.

    So: parse it, or say what stopped you, and let the caller decide out loud.
    """
    import json
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as e:
        return None, f"{type(e).__name__}: {e}"


def read_artifacts(paths):
    """-> ({path: data}, [(path, why)]) — what parsed, and what did not, with the reason.

    The second half is not an error channel to be ignored: every caller is expected to print it.
    Returned rather than logged here, because where it belongs on a page is the page's business
    and a library that writes to stderr on its own is one nobody can put behind a UI.
    """
    good, bad = {}, []
    for p in paths:
        data, why = read_artifact(p)
        if why is None:
            good[p] = data
        else:
            bad.append((p, why))
    return good, bad


def say_unreadable(bad, where="", stream=None):
    """One sentence per unreadable artifact, in the one wording every caller should use.

    A count is not enough — "3 files skipped" tells nobody which run to re-do.
    """
    import os as _os
    import sys as _sys
    stream = stream or _sys.stderr
    for path, why in bad or ():
        print(f"  ! {_os.path.basename(path)} could not be read ({why}). "
              f"It is NOT counted{' in ' + where if where else ''}, and nothing below "
              f"describes whatever it held.", file=stream)
    return len(bad or ())
