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


def artifact(name, root=None):
    """The path to write an artifact to, with the directory it needs already created.

    EIGHT MODULES WRITE INTO THIS DIRECTORY AND FOUR OF THEM CREATED IT. The other four --
    `benign`, `rejudge`, `run_generate`, `sarif` -- opened a path under a folder nothing had
    made, and on a fresh `$QATRATION_OUT` that is a FileNotFoundError after the work is done.

    Walked as a first-time user: `qatration benign` sent fifty probes to a live model, printed
    all fifty rows and a tally, and then died writing the file. Worse than the loss, the
    traceback goes to stderr and the table to buffered stdout, so the failure scrolls past
    ABOVE the results and the last thing on screen is `36/50 clean` -- a summary that reads
    like a finished run. Exit 1, no baseline, and every later finding on that target
    unattributable because `baseline.rates` had nothing to read.

    It survived because the README's order happens to hide it: `run` creates the directory and
    comes first there. The order `init` prints into the config it writes puts `benign` before
    `run`, so following the tool's own instructions is what breaks.

    Not created at import, deliberately: `OUT` is resolved when this module loads, and making
    a directory there as a side effect of an import would have `qatration <anything> --help`
    litter the filesystem -- which `test_compare` explicitly checks for. It is created when
    somebody actually writes.
    """
    base = str(root if root is not None else OUT)
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, name)


def tracked_by_git(path):
    """Is this file committed to a repository, rather than an ordinary artifact?

    Answered by asking git, once, and treating every failure as "no": no git on PATH, not a
    checkout, a detached worktree. A guard that raises when it cannot answer would refuse runs
    on machines that have nothing to protect.
    """
    import subprocess
    try:
        r = subprocess.run(["git", "-C", os.path.dirname(path) or ".",
                            "ls-files", "--error-unmatch", os.path.basename(path)],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def refuse_to_overwrite_evidence(path, force=False):
    """-> a sentence explaining why this write must not happen, or ''.

    THE FILE THIS EXISTS FOR is a results file that somebody committed. In this repository the
    published counts are recounted from `out/`, so replacing one of those with a six-attack
    experiment does not corrupt a run, it corrupts the numbers on the front page. It happened
    here: a `--attacks` run against a shipped practice bot took `results_httpbot.json` from a
    full sweep to eight rows, and `detector_coverage` immediately reported 958 fewer probes.
    Nothing warned, because the write is an ordinary `open(path, "w")`.

    An untracked file is not evidence anybody publishes, so it is overwritten as before: a
    person re-running their own sweep must not be asked permission every time.
    """
    if force or not os.path.exists(path) or not tracked_by_git(path):
        return ""
    return (f"REFUSED: {os.path.basename(path)} is committed to a repository, and this run "
            f"would replace it.\n"
            f"  A tracked artifact is evidence something else recounts: in this project the "
            f"README, the site and `qatration coverage` all read these files.\n"
            f"  Write somewhere else instead:\n"
            f"      QATRATION_OUT=/tmp/scratch qatration run ...\n"
            f"  or pass --overwrite-evidence if replacing it is the point.")


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
    meta = meta or {}
    # THE DENOMINATOR IS WHAT WAS MEASURED. ERROR rows are excluded from `broke` and were
    # included in `attacks_n`, so a sweep against a target that fell over part-way — 19
    # errored, 1 defended — came back "Hardened" and rendered "0 / 20 breached" in green.
    # Same shape as the zero case above, reached through the error door.
    # ASYMMETRIC, AND THAT ASYMMETRY IS THE RULE: an errored row can HIDE a breach, it cannot
    # invent one. So a breach that was found stands however much of the run failed, and a clean
    # bill does not, because the attack that would have broken it may be among the rows that
    # never ran. `_resilient_send` already retries, so a row reaching ERROR failed after retry.
    if (meta.get("broke") or 0) > 0:
        return "Vulnerable"
    measured = (meta.get("attacks_n") or 0) - (meta.get("errors") or 0)
    if measured <= 0 or (meta.get("errors") or 0) > 0:
        return "Not measured"
    return "Hardened"


_CTX_KEYS = None
_CFG_KEYS = None


def no_results_note(out_dir=None):
    """What a page says when the workspace it was pointed at holds no run.

    ONE SENTENCE, ONE PLACE. It was written twice this morning -- in `build_index` and in
    `discrimination`, in the same hour, as part of a change about naming the real path and a
    typeable command. Two copies of one sentence is the defect this repository spends its time
    finding, introduced by the fix for another instance of it, and found by asking which prose
    literals appear in more than one module.

    Takes the directory rather than reading it, because the two callers already have it and a
    third might be pointed somewhere else.
    """
    return ("no results in %s — run a sweep first:\n"
            "    qatration run --target-config <your-config>.yaml" % (out_dir or OUT))


def config_keys_read(root=None):
    """Every TOP-LEVEL target-config key some part of this engine reads.

    THE http ADAPTER REFUSES WHAT IT CANNOT READ and the twelve built-in ones never look.
    `HttpConfiguredTarget.__init__` names its parameters and ends in `**unknown`, which it
    raises on, with the defect written beside it: a config saying `respones:` built a target
    with no response mapping, every reply read as empty, every attack scored DEFENDED, and the
    run looked like a hardened deployment. The practice bots are constructed from a table that
    reads named keys off the config -- `guard=cfg.get("guard", True)` -- so a config saying
    `gaurd: false` is not refused and not applied. The bot silently stays guarded, and the
    fleet's published numbers are about a different deployment from the one the file describes.

    TWO SOURCES, because neither alone is the answer: the literal reads (`cfg.get("guard")`)
    and every adapter constructor's parameter names, which is how the table's keys are spelled
    at the other end. Seventy-three keys, and the forty-three shipped configs use none outside
    them.

    A hand-typed list would be the copy that goes stale -- the same reason `context_keys_read`
    beside it scans instead of listing.
    """
    global _CFG_KEYS
    if _CFG_KEYS is not None and root is None:
        return _CFG_KEYS
    import glob as _glob
    import importlib as _il
    import inspect as _inspect
    import io as _io
    import re as _re
    here = root or os.path.dirname(os.path.abspath(__file__))
    keys = set()
    pats = (r'cfg\.get\(\s*["\']([a-z_]+)["\']',
            r'cfg\[["\']([a-z_]+)["\']\]',
            r'tcfg\.get\(\s*["\']([a-z_]+)["\']',
            r'c\.get\(\s*["\']([a-z_]+)["\']')
    for fn in _glob.glob(os.path.join(here, "*.py")):
        if os.path.basename(fn).startswith("test_"):
            continue
        try:
            src = _io.open(fn, encoding="utf-8").read()
        except OSError:
            continue
        for p in pats:
            keys |= set(_re.findall(p, src))
    for fn in sorted(_glob.glob(os.path.join(here, "targets_*.py"))):
        try:
            mod = _il.import_module(os.path.basename(fn)[:-3])
        except Exception:
            # An adapter that will not import is `test_packaging`'s business. Skipping it
            # here returns fewer keys, which makes the caller's complaint louder rather than
            # quieter -- the safe direction for a check that can be wrong.
            continue
        for nm in dir(mod):
            obj = getattr(mod, nm)
            if _inspect.isclass(obj):
                try:
                    keys |= set(_inspect.signature(obj.__init__).parameters) - {"self"}
                except (TypeError, ValueError):
                    pass
    if root is None:
        _CFG_KEYS = keys
    return keys


def unread_context_keys(cfg):
    """-> the `oracle_context` keys in this config that nothing in the engine reads.

    A KEY NOTHING READS IS A DETECTOR NOBODY ARMED. `canaries` misspelled `canarys` parses,
    sweeps, and disarms every canary detector in the oracle: a clean bill for checks that
    could not fire, out of the one file an operator edits by hand.

    HERE RATHER THAN IN `onboard`, WHERE IT WAS. Two commands need it -- `onboard` says so
    before a sweep and `run` says it beside the detectors that came back inert, because
    "canary_in_output needs canaries" over a config that plainly declares a canary is a riddle
    and the misspelling is the answer. Reaching into the onboarding COMMAND to ask a question
    about a config is the wrong direction, and it cost a silent one: the import sat behind a
    bare `except Exception` in the caller and something in it raised, so the line never
    printed and nothing said why. The rule belongs with the scan it consults.

    Empty when the scan finds nothing, rather than accusing the config of everything: a broken
    scan makes every key look wrong, and that is a worse answer than no answer.
    """
    known = context_keys_read()
    if not known:
        return []
    return sorted(k for k in ((cfg or {}).get("oracle_context") or {}) if k not in known)


def context_keys_read(root=None):
    """Every `oracle_context` key some part of this engine actually reads.

    A KEY NOTHING READS IS A DETECTOR NOBODY ARMED. `canaries` misspelled `canarys` disarms
    every canary detector in the oracle, and the run then reports a clean bill for checks that
    could not fire -- the failure this project is named after, arriving through the one file
    an operator edits by hand. Nothing said a word about it: the config parses, the sweep
    runs, and the key sits there being read by no one.

    DERIVED FROM THE SOURCE, in two passes, because one is not enough. The literal pass finds
    `ctx.get("canaries")` and its spellings; the second asks `inert_for` what it reports as
    missing on an empty context, which covers the keys that live in tables (`CONFIG_GATED`,
    `INAPPLICABLE`) and are never written next to a `ctx.get`. A hand-typed list here would be
    the copy that goes stale, which is the defect one directory along in every other form.

    HONEST ABOUT ITS LIMIT: a key read through a variable this scan cannot resolve would look
    unknown. So the caller WARNS and never refuses -- the cost of being wrong is a note a
    reader can dismiss, and the cost of silence is a clean report over a disarmed oracle.
    """
    global _CTX_KEYS
    if _CTX_KEYS is not None and root is None:
        return _CTX_KEYS
    import glob as _glob
    import io as _io
    import re as _re
    here = root or os.path.dirname(os.path.abspath(__file__))
    keys = set()
    pats = (r'ctx\.get\(\s*["\']([a-z_]+)["\']',
            r'ctx\[["\']([a-z_]+)["\']\]',
            r'oracle_context\.get\(\s*["\']([a-z_]+)["\']',
            r'_configured\(\s*["\']([a-z_]+)["\']')
    for fn in _glob.glob(os.path.join(here, "*.py")):
        if os.path.basename(fn).startswith("test_"):
            continue
        try:
            src = _io.open(fn, encoding="utf-8").read()
        except OSError:
            continue
        for p in pats:
            keys |= set(_re.findall(p, src))
    try:
        from oracle import inert_for, DETECTORS
        for _det, missing in inert_for({}, DETECTORS).items():
            for m in missing:
                for part in _re.split(r"\s+or\s+|,\s*", str(m)):
                    part = part.strip()
                    if part and _re.fullmatch(r"[a-z_]+", part):
                        keys.add(part)
    except Exception:
        # A scan that cannot ask the oracle still knows what the literals said; returning
        # fewer keys makes the caller's warning noisier, never quieter, which is the safe
        # direction for a note that can be dismissed.
        pass
    if root is None:
        _CTX_KEYS = keys
    return keys


def config_model(cfg):
    """Which model a target config runs against, whatever shape the config is.

    THE ARTIFACT WAS NAMED AFTER ONE AND RECORDED NONE. `meta["model"]` read `cfg["model"]`,
    a top-level key the practice bots have and an `adapter: http` config does not -- there the
    model lives at `request.model`, because every OpenAI-shaped body carries it there and
    `qatration init` has written it there since 0.4.0. Measured on a live run from a fresh
    install: `results_mybot_llama3.2-3b.json`, whose meta says `model: ""`. One artifact, two
    answers, and the meta is the half every page reads.

    `--model` does not save it either. On an http target the override is substituted into
    `request.model` and `cfg["model"]` is never touched, so the flag whose entire purpose is
    running one target across several models produced files that could not say which.

    WHAT IT COSTS IS `history`. That module treats the model as part of a run's IDENTITY --
    "the model, the trial count and the finding set" -- so two sweeps against different models
    with the same trials and the same findings collapse into one and the second is dropped.
    And its confound list warns "model 'a' -> 'b'" when a comparison spans a model change;
    with both sides empty the warning cannot fire. A confound detector blind to its confound,
    on the one adapter every outside user has.

    Reading the config the way the ADAPTER reads it is the whole rule, and it is one rule now
    rather than two that disagree.
    """
    cfg = cfg or {}
    top = str(cfg.get("model") or "").strip()
    if top:
        return top
    req = cfg.get("request")
    if isinstance(req, dict):
        return str(req.get("model") or "").strip()
    return ""


def config_name(path, cfg=None):
    """What target a config file defines, whether or not it says so.

    `name:` is optional and eleven of the shipped configs omit it, so the name falls back to
    the filename between `targets_` and `.yaml`. That rule was written out four times — here,
    in `benign._ctx_for`, in `detector_coverage.contexts`, and NOT in `sarif`, which compared
    against `cfg["name"]` alone. The one that did not have it emitted every finding for those
    eleven targets with `"locations": []`: 95 of 95 on httpbot, anchored nowhere, while the
    module's own comment says the fallback exists so a reviewer gets a file that is really
    there. The config was really there; two implementations of "what is this called"
    disagreed about which one it was.

    Takes the already-parsed mapping when the caller has it, because most of these loops are
    reading the YAML anyway and a second parse per file is the sort of thing that makes a
    shared helper worth avoiding.
    """
    import os as _os
    if cfg is None:
        import yaml as _yaml
        try:
            cfg = _yaml.safe_load(open(path, encoding="utf-8")) or {}
        except Exception:
            cfg = {}
    stem = _os.path.basename(str(path))
    if stem.startswith("targets_") and stem.endswith(".yaml"):
        stem = stem[len("targets_"):-len(".yaml")]
    return (cfg.get("name") or stem) if isinstance(cfg, dict) else stem


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
        names.add(config_name(fp, c))
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


def trial_count(value, where="--trials"):
    """A number of trials that can actually measure something, or a refusal saying why not.

    ZERO TRIALS IS NOT A SMALL RUN, IT IS NO RUN, and every command here took `--trials` as a
    bare `type=int` with no floor. What each did with a zero differed, and neither answer was
    the honest one:

      * `isolation` skipped the probe loop, scored every property `locked 0/0` — its guard
        reads `errors and errors >= trials`, which is falsy at zero — and printed the
        objective as **HARDENED**, "nothing gives, even in isolation". The strongest claim
        this tool can make about a target, on zero requests. That is the exact case
        `_status`'s own docstring records having fixed for a target that was DOWN, arriving
        through a second door.
      * the sweep crashed instead: `run_attack` returns [] and `headline` indexes `[0]`,
        which reaches Python's default handler and exits 1 — the code the README defines as
        "the target was exploited or breached", so a typed flag reads as a security finding.

    Refused at the edge rather than handled at each of the six commands that accept it, and
    at the config door too, because `trials:` in a target file reaches the same arithmetic
    without passing any argparse at all.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SystemExit(f"{where}: {value!r} is not a whole number of trials.")
    if n < 1:
        raise SystemExit(
            f"{where}={n} would send nothing. A run of zero trials cannot measure a target, "
            f"and the verdicts here are only worth reading because they can go down: with no "
            f"probe sent, every lock reads as held. Use 1 or more, or do not run the command.")
    return n


# A ROW THAT MEASURED NOTHING, in one place. Both verdicts mean the same thing to every
# reader downstream — no probe came back, so the row is neither a breach nor a defence — and
# they kept being handled one at a time. `history.state` named ERROR and not SKIP, so an
# attack that broke last run and was not delivered this run came back FIXED. `delivered`
# named SKIP and not ERROR, so a delivery family whose only attack errored was published as
# tried. `discrimination` named ERROR and not SKIP, so a control that could not be sent
# counted as a control that stayed quiet. Three modules, three different halves of one rule.
NOT_MEASURED = ("SKIP", "ERROR")

# AND ITS OPPOSITE, in one place for the same reason. This tuple was written out in three
# modules -- `history`, `discrimination` and `build_index` -- and a fourth was about to be
# added by a new command before the grep. Three copies of a rule agree until the day somebody
# decides a fourth verdict counts as a breach, and then two reports disagree about what a
# finding is.
BROKE = ("EXPLOITED", "PARTIAL")


# WHAT QUALIFIES A NUMBER, and the reason this list exists at all.
#
# Three qualifiers in one evening were carried by the console, the scorecard and the SARIF and
# missing from the pages that summarise: attribution (247 of 440 fleet findings are rows
# nothing can attribute, and neither summary page said so), the instrument spread (a header
# asserting "Same arsenal" over six of them, a column sorting counts from 1 and 10 trials),
# and the mute detectors (a median of 21 of 66 per target, `memorybot` published with zero
# breaches while 30 could not speak).
#
# The gap is STRUCTURAL, not carelessness. The console, the scorecard and the SARIF are built
# from ONE run and have the whole meta in hand; a page that summarises several reads only the
# fields it was told to, so every new qualifier has to be carried to each of them by hand and
# the fourth one will be missed the same way.
#
# So each surface answers for each of these: read it, or say in that module why not.
# `test_reports.py` quantifies over both. Exemptions live where the decision is, the way
# `NO_CLI_DOOR` does in `run_adaptive`, never as a second list inside the check.
# key -> (why it qualifies a number, the shared readers that carry it)
#
# THE READERS ARE PART OF THE RULE. Most of these are not meant to be read by name: a surface
# carries `errors` by asking `measured()`, `when` by asking `measured_when()`, the attribution
# by asking `baseline.qualified`. That is the fix each of them already got, and naming the
# reader here means the check accepts the right shape rather than any mention of the key.
QUALIFIERS = {
    "errors": ("rows that measured nothing, so a count over them is not coverage",
               ("measured", "measured_counts", "NOT_MEASURED")),
    "not_applicable": ("attacks this deployment cannot take", ()),
    "not_sent": ("attacks the invocation held back, which a flag brings back", ()),
    "inert": ("detectors that could not speak here, whose silence is not a defence", ()),
    "baseline": ("whether the target's own quiet traffic was measured at all",
                 ("qualified", "doubtful_count", "benign_seen", "rates")),
    "arsenal": ("which attacks produced this number, and whether two rows share them", ()),
    "trials": ("how many attempts each attack got, which decides what a count means", ()),
    "when": ("when the run happened, not when the file was last touched", ("measured_when",)),
    "run_id": ("which run produced this, and therefore how it ended",
               ("unfinished_note", "record_for")),
    # THE TWO CAVEATS THAT CAN INVERT A COUNT, added after the second of them was found by a
    # different method entirely -- a table of which module reads which meta field. This list
    # exists so the FOURTH qualifier would not be missed the way the first three were, and
    # `delivery` was missed anyway, because the list was built from the fields the pages
    # already argued about rather than from everything that qualifies a number.
    "attribution": ("whether the target does this anyway, without anybody attacking",
                    ("attribution", "doubtful_count", "rates")),
    "delivery": ("whether the ATTACK did anything once the payload was in front of the "
                 "model, as opposed to the target answering that way regardless",
                 ("two_factor", "two_factor_note")),
}


def measured(meta):
    """-> (attacks measured, attacks that errored), from a results file's meta.

    AGAINST WHAT WAS MEASURED, NOT AGAINST WHAT WAS ATTEMPTED. An errored row is neither a
    breach nor a defence: the request failed, or the budget refused it before it was sent,
    and nothing was learned either way. Counting it in the denominator only moves the number
    in the one direction a coverage figure must never drift.

    THE RULE WAS ALREADY HERE, spelled out with its reasoning — in exactly one of the places
    that need it. `build_index` subtracted the errors and said why; the scorecard and the
    defence page did not, and neither read `meta["errors"]` at all. So a sweep whose budget
    stopped it after one attack rendered as "20 attacks fired · 0 breached · 0 not
    applicable" on the page a customer reads, with the word "errored" nowhere on it and the
    nineteen error rows folded shut one by one in the table — while the index beside it
    scored the same run "not measured". The machine-readable SARIF said it correctly too,
    which left the two human surfaces as the only ones that did not.
    """
    meta = meta or {}
    errs = meta.get("errors") or 0
    return max(0, (meta.get("attacks_n") or 0) - errs), errs


def measured_when(meta, path=None):
    """-> (a date string for this run, True if the RUN said so).

    THE FILE'S MTIME IS NOT WHEN THE RUN HAPPENED, and two pages dated their evidence with it.
    Git does not preserve mtimes: a fresh clone stamps every file with the clone time, so in
    any checkout but the author's the fleet page prints one date for all forty-five artifacts
    -- including runs three weeks old -- and its staleness bar, whose whole job is to warn
    that rows were measured on different days, finds no difference and never renders. Measured
    by cloning: 45 files, one date. A `cp`, a `git checkout` or a `rejudge --write` does the
    same thing one file at a time.

    `meta["when"]` exists for exactly this and was added late, so 44 of the 45 shipped results
    files predate it. Where it is there, it is the answer; where it is not, the caller is told
    so rather than handed a date that looks like a measurement and is a filesystem event.
    """
    said = (meta or {}).get("when")
    if said:
        return str(said)[:16], True
    if path is None:
        return "", False
    import datetime as _dt
    return _dt.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M"), False


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
