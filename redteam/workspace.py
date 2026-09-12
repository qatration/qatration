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
import re

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


# The help for the flag that overrides the refusal below. Here because five commands offer
# it and a sentence written five times is five things to keep in step -- `test_reports`
# refuses a sentence of 55 characters or more that appears in two modules, and said so
# about this one the moment the third command grew it.
OVERWRITE_HELP = (
    "replace a results file that is committed to a repository. Refused by default, "
    "because published counts are recounted from those files")


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


def model_tag(model):
    """The suffix a `--model` run adds to its artifact names, separator included.

    THE RULE THAT WRITES THE NAME BELONGS BESIDE THE RULE THAT READS IT. `is_per_model_copy`
    below decides which files are per-model copies; this decides what makes one. They were
    in different modules and the writing half was spelled three times: twice inside
    `run_redteam.main`, once in `model_matrix`.

    The two in `run_redteam` are a guard and the thing it guards. One computes the path
    `refuse_to_overwrite_evidence` is asked about, before a single probe is sent; the other
    computes the path the results are written to, at the end of the run. A guard that
    derives its subject independently of the writer is a guard that can stop protecting it
    without anything failing — and the answer would be a sweep quietly overwriting evidence
    it had just promised not to touch.

    The third is a cross-module contract with no test behind it: `model_matrix` reconstructs
    the filename it expects `run_redteam` to have written, and if the two spellings drifted
    every model would be reported as having produced nothing to compare — a matrix that
    measured nothing, blaming the models.
    """
    return "_" + re.sub(r"[^A-Za-z0-9.]+", "-", model) if model else ""


def artifact_path(out_dir, kind, target_name, model=None, ext="json"):
    """Where one run's `<kind>_<target>[_<model>].<ext>` goes. One spelling, four callers."""
    return os.path.join(str(out_dir), "%s_%s%s.%s"
                        % (kind, target_name, model_tag(model), ext))


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
    # AND THROUGH `measured`, which is this same arithmetic written twice in this one file --
    # here, and twelve hundred lines down with the reasoning attached to the copy this one
    # never called. The two disagreed the moment a run could stop part way: attacks the sweep
    # never reached leave no ERROR behind, so a run stopped on its CONTROLS -- which are
    # excluded from `errors` -- came back "Hardened".
    if (meta.get("broke") or 0) > 0:
        return "Vulnerable"
    _n, _errs = measured(meta)
    if _n <= 0 or _errs > 0 or (meta.get("unreached") or 0) > 0:
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


# THE SPELLINGS A CONFIG READ TAKES IN THIS PACKAGE, and the reason there are two sets.
# `c.get("...")` is how `provenance` is read, and it also sweeps in `note`, `state`,
# `spent` and `verdict` from readers of RUN RECORDS that happen to use the same variable
# name. For membership that is harmless — an extra known key only ever makes the rule
# quieter. For a SUGGESTION it is poison: `notes:` on a config then reads as a misspelling
# of `note`, a key no config has ever had, and the run is refused.
#
# So the tight set is a PREFIX of the wide one rather than a second list. `test_workspace`
# asserts that suspects are a subset of known, because a suspect that is not known refuses
# a correct config for looking like a misspelling of itself; written this way the
# assertion is checking a property of the code instead of a coincidence between two
# hand-kept tuples.
SUSPECT_PATTERNS = (
    r'cfg\.get\(\s*["\']([a-z_]+)["\']',
    r'cfg\[["\']([a-z_]+)["\']\]',
    r'tcfg\.get\(\s*["\']([a-z_]+)["\']',
)
READ_PATTERNS = SUSPECT_PATTERNS + (r'c\.get\(\s*["\']([a-z_]+)["\']',)


def scan_source_keys(here, patterns):
    """Every string these patterns capture across this package's own modules.

    THREE VOCABULARIES, ONE SCAN. `config_keys_read` and `config_key_suspects` here, and
    `attack_keys_read` and `engine_keys` in `lint_arsenal`, each answer `what does this
    engine read off a mapping` for a different corpus — a target config, an attack, an
    objective — and each had its own copy of these eight lines. The patterns differ
    because the corpora do; the glob, the suite exclusion, the read and the union do not.

    Every one of those four decides whether a file is REFUSED for a key nothing reads, so
    a copy that learns something the others do not is a run refused, or a typo passed, in
    one corpus and not the next.

    The suites are excluded because a key a SUITE reads is not a key the engine follows,
    and a fixture naming one would make a real typo look known.
    """
    import glob as _glob
    import io as _io
    import re as _re
    keys = set()
    for fn in sorted(_glob.glob(os.path.join(here, "*.py"))):
        if os.path.basename(fn).startswith("test_"):
            continue
        try:
            src = _io.open(fn, encoding="utf-8").read()
        except OSError:
            continue
        for p in patterns:
            keys |= set(_re.findall(p, src))
    return keys


def _scan_config_keys(here, pats):
    """Every top-level config key this package reads, by two routes.

    THE SCAN, NOT THE ANSWER. `config_keys_read` and `config_key_suspects` ask different
    questions — is this key known, and what could a typo have been aiming at — and
    the difference between their answers is a pattern and a subtraction. The thirty lines
    that produce them were written out twice, identically: the glob, the `test_`
    exclusion, the read, the adapter import and the constructor walk. A fifth read spelling
    added to one of them is a key that is a SUSPECT and not KNOWN, and `near_miss_keys`
    then refuses a correct config for looking like a misspelling of itself.

    That invariant is asserted in `test_workspace`; this is the other half of keeping it
    true, which is not having two scans that can disagree.

    Two routes because neither alone is the answer: the literal reads (`cfg.get("guard")`)
    and every adapter constructor's parameter names, which is how the same key is spelled
    at the other end.
    """
    import glob as _glob
    import importlib as _il
    import inspect as _inspect
    keys = scan_source_keys(here, pats)
    for fn in sorted(_glob.glob(os.path.join(here, "targets_*.py"))):
        try:
            mod = _il.import_module(os.path.basename(fn)[:-3])
        except Exception:
            # An adapter that will not import is `test_packaging`'s business. Skipping it
            # here returns fewer keys, which makes the caller's complaint louder rather
            # than quieter -- the safe direction for a check that can be wrong.
            continue
        for nm in dir(mod):
            obj = getattr(mod, nm)
            if _inspect.isclass(obj):
                try:
                    keys |= set(_inspect.signature(obj.__init__).parameters) - {"self"}
                except (TypeError, ValueError):
                    pass
    return keys


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
    at the other end. This said `seventy-three keys` and the scan returns sixty-three; a count
    in prose is a number nothing recounts, so what is claimed here now is the property
    `test_workspace` actually checks: no key any shipped config uses falls outside the set.

    A hand-typed list would be the copy that goes stale -- the same reason `context_keys_read`
    beside it scans instead of listing.
    """
    global _CFG_KEYS
    if _CFG_KEYS is not None and root is None:
        return _CFG_KEYS
    here = root or os.path.dirname(os.path.abspath(__file__))
    keys = _scan_config_keys(here, READ_PATTERNS)
    if root is None:
        _CFG_KEYS = keys
    return keys


_LIST_KEYS = None


def list_context_keys(root=None):
    """Every `oracle_context` key whose value the engine ITERATES -- from two sources.

    A YAML scalar where a list belongs is the one config mistake that manufactures findings
    rather than hiding them, and it is the easiest to make:

        canaries: "ACME-9931"       ->  _canaries() yields 'a','c','e','m','1','3','9','-'

    Every one of those characters becomes a canary, so `canary_in_output` fires on any reply
    containing the letter 'a'. Every attack comes back EXPLOITED and a customer is told their
    bot hands over the secret on every probe. The list form differs by two characters.

    TWO SOURCES, because neither is complete. The shipped configs answer what these keys look
    like in practice -- twenty-four of them are a list in all forty-three, and not one key in
    any of them has two different types. The source answers what the code does with keys no
    shipped config happens to use: `ctx.get("analysis_tools") or []` is the same promise
    written the other way round. Scanned rather than listed for the reason every set here is:
    a key added on a Monday joins by existing.
    """
    global _LIST_KEYS
    if _LIST_KEYS is not None and root is None:
        return _LIST_KEYS
    import glob as _glob
    import io as _io
    import re as _re
    import yaml as _yaml
    here = root or os.path.dirname(os.path.abspath(__file__))
    keys = set()
    pat = _re.compile(r'ctx\.get\(\s*["\']([a-z_]+)["\']\s*(?:,\s*)?\)\s*or\s*\[\]'
                      r'|ctx\.get\(\s*["\']([a-z_]+)["\']\s*,\s*\[\]\s*\)')
    for fn in _glob.glob(os.path.join(here, "*.py")):
        if os.path.basename(fn).startswith("test_"):
            continue
        for m in pat.finditer(_io.open(fn, encoding="utf-8").read()):
            keys.add(m.group(1) or m.group(2))
    seen = {}
    # THROUGH `target_configs` for the same reason: this derives WHICH context keys are
    # lists, `bad_context_shapes` refuses a config on the answer, and the answer is cached
    # in `_LIST_KEYS` for the life of the process. A scratch config in this directory could
    # add a key, or change the kind inferred for one, for every later check in the run.
    from target import target_configs as _cfgs
    for fn in _cfgs(here):
        try:
            cfg = _yaml.safe_load(_io.open(fn, encoding="utf-8").read()) or {}
        except Exception:
            continue
        if not isinstance(cfg, dict):
            continue
        for k, v in (cfg.get("oracle_context") or {}).items():
            seen.setdefault(k, set()).add(type(v).__name__)
    keys |= {k for k, kinds in seen.items() if kinds == {"list"}}
    if root is None:
        _LIST_KEYS = keys
    return keys


def bad_context_shapes(cfg):
    """-> [(key, what is wrong)] for context values of a shape the engine cannot use.

    A STRING IS ITERABLE, which is the whole problem: nothing raises, nothing is empty, and
    the loop that expected eight-character tokens gets eight one-character ones. Refused where
    the config is read, because the failure downstream is a full sweep of EXPLOITED rows that
    look exactly like a real one.
    """
    out = []
    ctx = (cfg or {}).get("oracle_context") or {}
    if not isinstance(ctx, dict):
        return [("oracle_context", "is %s, not a mapping" % type(ctx).__name__)]
    # NO "IF THE SCAN IS EMPTY" GUARD HERE, and its absence is deliberate: the loop below
    # already skips every key that is not in `want`, so an empty set accuses nothing by
    # construction. The guard its neighbour `unread_context_keys` needs — that one asks the
    # opposite question and an empty set would accuse EVERY key — was written here too out of
    # symmetry, and a mutation proved it changed no input's answer.
    want = list_context_keys()
    for k, v in ctx.items():
        if k not in want or v is None or isinstance(v, (list, tuple)):
            continue
        if isinstance(v, str):
            out.append((k, "is a single string; this key is read as a LIST, so %r would be "
                           "used one character at a time (%s...). Write it as a list: [%r]"
                        % (v, ", ".join(repr(c) for c in v[:3]), v)))
        else:
            out.append((k, "is %s; this key is read as a list" % type(v).__name__))
    return out


# EVERY INVISIBLE CHARACTER A PAGE HERE MIGHT BE ASKED TO RENDER, in two families.
#
# The Unicode invisibles -- zero-width spaces and joiners, bidi overrides, the word joiner,
# soft hyphen, the byte-order mark -- hide text inside text.
#
# AND THE C0 CONTROLS, which were missing, and which are the half this project attacks with.
# `attacks_ansi.yaml` exists to plant ANSI and OSC-8 sequences, and every one of them is built
# from ESC (0x1B) and BEL (0x07). A report quoting such a reply printed the escape raw: a
# browser drops it, so the reader saw `click here` and not the terminal hyperlink that makes
# it a finding -- the evidence rendered as ordinary prose, on the page whose whole job is to
# show what came back.
#
# Tab, newline and carriage return are excluded: they are layout in a quoted reply, not
# concealment, and rendering them as codepoints would turn every multi-line payload into
# noise.
CONTROL_CHARS = re.compile(
    "[\u0000-\u0006\u0008\u000b\u000c\u000e-\u001f\u007f"
    "\u0007"
    "\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


# Layout in a quoted reply, and the attack itself in a table cell -- which is why `plain`
# takes an argument and `esc` does not. A page renders CR and LF as whitespace; a terminal
# obeys them.
LAYOUT = re.compile("[\t\n\r]")


def plain(s, oneline=False):
    """Make an invisible character visible as its codepoint. For a TERMINAL.

    `esc` below is the same rule for a page, and the page was the only surface that had
    it. The console is the one an operator actually watches -- `qatration profiles` and
    `qatration fixes` print a target's own words to stdout -- and a reply carrying
    ESC[2K and a carriage return erases the line the tool just printed and repaints it.
    Measured, not imagined: a profile whose `tool_channel` was that payload put

        ESC[2K CR ESC[32m "DEFENDED 0/10" ESC[0m  ESC]8;;http://evil BEL

    into the fleet table and into the `!` warning line under it, where it reads as a
    green verdict from the tool and hyperlinks the row somewhere the tool never mentioned.
    `attacks_ansi.yaml` exists because this is a finding when somebody else's product does
    it; the reports were hardened against it and the terminal was not.

    Shown rather than stripped, for the reason `esc` gives: the presence of the character
    IS the finding, and a tool that quietly deletes it disagrees with the evidence it is
    quoting.

    `oneline` for a value going into a SINGLE-LINE FIELD -- a table cell, a `!` line. The
    character list `esc` uses deliberately keeps tab, newline and carriage return, because
    on a page they are layout in a quoted reply. In a terminal table they are the attack,
    and not a subtle one: a profile whose `tool_channel` was

        "real" LF "safebot         real           stateless   held    0/0   -   -"

    printed a second row in the fleet table for a target that does not exist, reading
    clean on every column. A carriage return is the quieter version -- it returns the
    cursor to column 0 and whatever follows overwrites the row the tool just wrote.

    Off by default, so the multi-line reply a report quotes is still quoted as it came.
    """
    s = CONTROL_CHARS.sub(lambda m: "<U+%04X>" % ord(m.group(0)), str(s))
    if oneline:
        s = LAYOUT.sub(lambda m: "<U+%04X>" % ord(m.group(0)), s)
    return s


def esc(s):
    """HTML-escape, and make an invisible character visible as its codepoint.

    ONE IMPLEMENTATION. There were four -- `report_engine`, `build_index`, `compare_targets`,
    `compare_recon` and `defense_report` each defined their own -- and only one of them did
    anything about invisible characters. So the same payload rendered two ways: the per-target
    report showed `&lt;U+200B&gt;`, and the index, the fleet comparison and the fix list showed
    nothing at all, on pages built from the same artifact minutes apart.

    Shown rather than stripped. Stripping would make the report disagree with the payload it
    claims to be quoting, and the presence of the character IS the finding.

    Here rather than in `report_engine` because all five pages already import this module and
    it imports none of them; a shared rule living in one of the things that shares it is how
    the fourth copy gets written.
    """
    # THROUGH `plain`, not beside it. Escaping the codepoint marker `plain` writes gives
    # exactly the string this returned when it did its own substitution -- and there is
    # then no second copy of the rule to update when the character list grows.
    import html as _html
    return _html.escape(plain(s))


# WHAT EACH KIND OF DOCUMENT HAS TO BE, and the words for what it is instead.
#
# THE OTHER HALF OF `load_yaml_or_refuse`. That reader exists because a path that could not be
# READ came out as a traceback under the sentence "This is a bug in qatration, not a finding
# about your target and not a problem with your config" -- wrong on the last clause, and it
# asks the reader to file a bug for their own typo. It fixed the READ and never asked whether
# what came back is the document the command wanted.
#
# So a target config that parses to a YAML list, to a scalar, or to nothing at all reached the
# commands as itself, and every one of them called `.get` or `.items` on it. Walked: `run`,
# `recon`, `verify`, `matrix`, `isolation`, `generate` and `onboard` each answered with that
# same traceback and that same sentence. `attacks: []` written at the top of an arsenal does it
# from the other side, and an EMPTY arsenal crashed the one rule that did exist for this --
# 210 lines into `run`, where no sibling can call it, on `enumerate(None)` before it spoke.
#
# A TABLE RATHER THAN A PARAMETER at the call sites, so a caller cannot opt out by omission;
# `test_workspace` reads every call's `what` out of the AST and asks that this table knows it.
DOC_SHAPES = {
    "target config": (dict, "a mapping of keys -- `adapter`, `url`, `request`, `response`, "
                            "`oracle_context`"),
    "arsenal": (list, "a bare list of attack mappings, each with an `id`; a file whose top "
                      "level is `attacks:` loads as a mapping, not a list"),
    "objectives file": (list, "a list of objectives"),
}

# "a single string" in the same words `bad_context_shapes` uses one screen down, because
# it is the same mistake at the other level of the file.
_SHAPE_WORDS = {dict: "a mapping", list: "a list", str: "a single string"}


def wrong_shape(doc, what, path=""):
    """-> why this document is not a `what`, or "" when it is one.

    EMPTY IS ONE OF THE WRONG SHAPES and not a special case: a target config with nothing in
    it configures nothing, and the commands that read it as `{}` went on to ask an endpoint
    they were never given for an adapter nobody named.

    "" for a kind `DOC_SHAPES` does not know, because inventing a shape for an unnamed
    document would refuse a caller on a guess. `test_workspace` gates the table against the
    call sites, so silence cannot be how a caller skips this.
    """
    want = DOC_SHAPES.get(what)
    if want is None:
        return ""
    kind, says = want
    if isinstance(doc, kind):
        return ""
    where = ("the %s at %s" % (what, path)) if path else ("the %s" % what)
    if doc is None:
        return "%s is empty -- nothing parsed out of it. A %s is %s." % (where, what, says)
    return ("%s is %s, not %s. A %s is %s."
            % (where, _SHAPE_WORDS.get(type(doc), "a " + type(doc).__name__),
               _SHAPE_WORDS.get(kind, kind.__name__), what, says))


def load_yaml_or_refuse(path, what="target config", where=""):
    """Read a YAML path somebody typed, or refuse it. -> the parsed document.

    THE OTHER HALF OF THE RULE BELOW, which says of the parse step that there is no
    shared loader and so the checks lived in two commands and were missing from eight.
    That was fixed for what a config CONTAINS and not for whether it could be read at
    all: `run` grew a `_load` closure no sibling can call, `generate` wrote a second
    version of the same refusal, and five commands still opened the path bare.

    Walked, not supposed. `qatration benign --target-config nope.yaml`, and the same
    for `verify`, `recon`, `isolation` and `matrix`, each answered a mistyped filename
    with a Python traceback and the sentence `This is a bug in qatration, not a
    finding about your target and not a problem with your config`, which is wrong on
    the last clause and asks the reader to file a bug for their own typo.

    THE COMMONEST CAUSE IS A FLAG THAT LOOKS RIGHT. `--target` is an unambiguous
    prefix of `--target-config`, so argparse accepts it and hands a target NAME to
    something that opens a FILE. Said only when the path looks like a name, because a
    hint printed on every mistyped path is one nobody reads by the third time.
    """
    import yaml
    lead = (where + ": ") if where else ""
    # ASKED OF THE PATH, NOT OF THE ERRNO. `run`'s closure caught `IsADirectoryError`, which
    # POSIX raises and Windows does not: there a directory arrives as `PermissionError` and
    # fell through to the generic branch, so the message read `Permission denied` and sent the
    # reader after file ownership for a path that was simply a folder. What the path IS does
    # not depend on the platform.
    if os.path.isdir(path):
        raise SystemExit(lead + "ABORT — %s is a directory, not a %s file. Nothing was sent."
                         % (path, what))
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except FileNotFoundError:
        why = "no %s at %s." % (what, path)
    except Exception as e:
        why = "could not read the %s at %s: %s: %s" % (what, path, type(e).__name__, e)
    else:
        # AND WHAT CAME BACK IS THE DOCUMENT THAT WAS ASKED FOR, which is the half this
        # reader did not have. See `wrong_shape` above: the refusal for a path that could
        # not be read was written, and the one for a file that read fine and is not a
        # config was not, so the traceback it exists to stop was still the answer.
        bad = wrong_shape(doc, what, path)
        if not bad:
            return doc
        why = bad
    lines = [lead + "ABORT — " + why + " Nothing was sent."]
    if not os.path.splitext(str(path))[1] and not os.path.dirname(str(path)):
        lines += [
            "  That looks like a NAME rather than a path. `--target` is an unambiguous",
            "  prefix of `--target-config`, argparse accepts the abbreviation, and this",
            "  command is handed a name where it wanted a file. Give it the config itself:",
            "  it reads the url and the oracle context from there.",
        ]
    raise SystemExit("\n".join(lines))


MISSPELT_CUTOFF = 0.7


_CFG_SUSPECTS = None


def config_key_suspects(root=None):
    """The keys a mistyped config key could have been AIMING at.

    Not the same question as `config_keys_read`, and the difference is what makes a
    near-miss rule usable. That one asks IS THIS KEY KNOWN and is deliberately wide: it
    scans `c.get("...")` too, which is how `provenance` is read, and which also sweeps in
    `note`, `state`, `spent` and `verdict` from readers of run records that happen to use
    the same variable name. Membership only ever gets quieter from extra entries.

    A near-miss test is the opposite: a spurious entry there INVENTS a refusal. `notes:` on
    a config is a plausible annotation, and against the wide set it reads as a misspelling
    of `note` -- a key no config has ever had, in a message that would send the reader
    looking for it. So the suggestion side is the tight derivation: what a config reader
    names (`cfg`, `tcfg`) and what an adapter constructor takes.

    A key missing from HERE costs nothing: it is still known, so it is never a candidate.
    """
    global _CFG_SUSPECTS
    if _CFG_SUSPECTS is not None and root is None:
        return _CFG_SUSPECTS
    here = root or os.path.dirname(os.path.abspath(__file__))
    keys = _scan_config_keys(here, SUSPECT_PATTERNS)
    # PYTHON PLUMBING IS NOT A CONFIG KEY. `*args` and `**kwargs` are in every constructor
    # signature and in no config, and leaving them here made `tags:` read as a misspelling of
    # `args` -- a suggestion pointing at something that cannot be written in a YAML file.
    if root is None:
        _CFG_SUSPECTS = keys - {"args", "kwargs", "unknown", "_"}
        return _CFG_SUSPECTS
    return keys - {"args", "kwargs", "unknown", "_"}


def near_miss_keys(mapping, known, cutoff=None, suspects=None):
    """-> [(key, the key it looks like)] for keys that read as a typo of a known one.

    ONE RULE FOR THREE CORPORA. An arsenal, an objectives file and a target config all
    arrive from a path somebody typed, and each had a check for keys nothing reads that
    lived where only the SHIPPED copy of that corpus reaches it. This is the shared
    half; the three doors supply their own vocabulary.

    A NEAR MISS, NOT AN UNKNOWN KEY. Refusing every key the engine does not read is
    right for a curated corpus and hostile to somebody annotating their own file with
    `owner:` or `ticket:`. Measured over this engine's vocabularies: typos score 0.71
    to 0.97 against the key they meant and plausible annotations score 0.44 to 0.62,
    so the line sits between `encoding` -> `encode` and `severity` -> `delivery`.

    AND THE INTENDED KEY MUST BE ABSENT: a config carrying both `guard:` and its own
    `guards:` note is annotating, not misspelling, and nothing here should have an
    opinion about it.
    """
    import difflib
    if not isinstance(mapping, dict):
        return []
    # TWO SETS, because they answer different questions. `known` decides whether a key is
    # a candidate at all, and being wide there only ever means fewer complaints. `suspects`
    # is what the suggestion is drawn from, and a spurious entry THERE invents a refusal --
    # so a caller with a looser membership set passes a tighter one for the naming.
    aim = sorted(set(known) if suspects is None else set(suspects))
    out = []
    for k in sorted(set(mapping) - set(known)):
        near = difflib.get_close_matches(str(k), aim, n=1,
                                         cutoff=cutoff or MISSPELT_CUTOFF)
        if near and near[0] not in mapping:
            out.append((k, near[0]))
    return out


def refuse_unusable_config(cfg, where):
    """Refuse a target config the engine cannot use, wherever it was loaded.

    THE RULE HAD NOWHERE TO LIVE. Ten commands read a target config and every one of them
    calls `yaml.safe_load` itself; there is no shared loader, so the checks that stop a
    manufactured finding were written into `run` and `onboard` and were missing from the other
    eight. `benign` is the worst of those by some distance: it is the command this tool TELLS
    an operator to run to measure their false-positive rate, and with `canaries: "ACME"` it
    would report a wall of noise that the operator would read as the detector being broken.
    `verify` re-sends the findings a report claims. `isolation` publishes HARDENED.

    Two failures, both of which produce a run that looks exactly like a real one:

      * A SCALAR WHERE A LIST BELONGS. A string is iterable, so `canaries: "ACME-9931"` is
        used one character at a time and `canary_in_output` fires on any reply containing the
        letter 'a'.
      * A REFUSAL VOCABULARY THAT CANNOT BE USED. A misspelled class name is silently inert;
        a pattern that does not compile raises out of `classify` mid-sweep.

    `where` names the command, so the message says which invocation stopped.
    """
    # A KEY THIS ENGINE DOES NOT READ DOES NOTHING, and a key that LOOKS like one it
    # reads does nothing while looking like it did. `gaurd: false` is not refused and
    # not applied: the bot stays guarded and the published numbers describe a different
    # deployment from the file. `test_http_adapter` has asked this of the SHIPPED
    # configs since it was written, and every command takes `--target-config <a path
    # somebody typed>`, which is the copy that never reaches it.
    problems = [(k, "is not a key this engine reads, and it looks like %r. Nothing "
                    "follows it: the field is never looked at, and the run describes a "
                    "deployment configured the way you meant rather than the way it is."
                 % near)
                for k, near in near_miss_keys(cfg, config_keys_read(),
                                              suspects=config_key_suspects())]
    problems += [("oracle_context.%s" % k, why) for k, why in bad_context_shapes(cfg)]
    from refusal import bad_patterns
    problems += bad_patterns((cfg or {}).get("oracle_context") or {})
    if not problems:
        return
    raise SystemExit(
        "%s: this target config cannot be used as written. Nothing was sent.\n" % where
        + "\n".join("    %-34s %s" % (w, why) for w, why in problems[:8]))


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
    # KEYED ON THE DIRECTORY IT READ, for the reason `lint_arsenal.list_attack_fields`
    # carries: a cache that stores an answer without the question it was about hands a
    # fixture's answer to the next honest caller, and `ROOT` is a module global that the
    # suites reassign. Nothing has gone wrong here yet; the neighbour with the identical
    # shape did, the moment a second caller started asking from inside a fixture.
    global _CTX_KEYS
    _ctx_here = root or os.path.dirname(os.path.abspath(__file__))
    if _CTX_KEYS is not None and _CTX_KEYS[0] == _ctx_here:
        return _CTX_KEYS[1]
    import glob as _glob
    import io as _io
    import re as _re
    here = _ctx_here
    keys = set()
    pats = CTX_READ_FORMS
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
    _CTX_KEYS = (_ctx_here, keys)
    return keys


# EVERY WAY THIS ENGINE READS A CONTEXT KEY, in one place because two scans ask it.
#
# `context_keys_read` above derives the whole set an operator may configure, and
# `oracle.quieted_by` derives the suppressor keys ONE detector reads. They are the same
# question at two scopes, and the second had a single pattern -- `ctx.get(...)` -- while
# this one had five. A detector reading its suppressor as `ctx["allowed_domains"]`, or
# through `_configured` or `_num`, was therefore reported as having no suppressor at
# all, and `noisy_for` never told the operator the detector was unarmed.
#
# No detector does that today: measured over all 66, the narrow scan and this one
# return the same keys. The divergence is the defect -- four of these five forms were
# added HERE one at a time, each because a read this scan could not see became a key
# `onboard` told an operator nothing reads, and none of those four lessons reached the
# copy one file over.
CTX_READ_FORMS = (
    r'ctx\.get\(\s*["\']([a-z_]+)["\']',
    r'ctx\[["\']([a-z_]+)["\']\]',
    r'oracle_context\.get\(\s*["\']([a-z_]+)["\']',
    r'_configured\(\s*["\']([a-z_]+)["\']',
    # `_num(ctx, "key", default)` is the numeric read, and it exists because
    # `int(ctx.get(k) or D)` threw away a configured 0.
    r'_num\(\s*ctx\s*,\s*["\']([a-z_]+)["\']',
)


def ctx_keys_in(src):
    """Every context key this source reads, in any of the forms the engine uses."""
    import re as _re
    keys = set()
    for p in CTX_READ_FORMS:
        keys |= set(_re.findall(p, src or ""))
    return keys


def side_artifact(explicit, default_name, key, root=None, warn=None):
    """A recon profile or an isolation map, folded into the report if one exists.

    Dated by ITSELF rather than by the run: a fingerprint from last week silently presented
    as today's is worse than no fingerprint, so the age travels with the data. An mtime is a
    filesystem event git does not preserve, so in a clone that printed the clone time beside
    the HARDENED verdicts the panel qualifies.

    A LOCK MAP KEEPS ITS DATE IN `meta` AND A RECON PROFILE AT THE TOP LEVEL, and a lock map
    written before `write_maps` existed is a bare LIST with nowhere to keep one. All three
    shapes reach here, so the shape is asked rather than assumed.

    HERE BECAUSE TWO COMMANDS WRITE THE SAME PAGE. `run` built it with both panels and
    `rejudge --write` rebuilt it with `build_html(meta, results)` -- no recon, no isolation
    -- so re-scoring a stored run silently deleted the fingerprint panel and the lock map
    from the page. Ten targets in this repository ship a side artifact, and every one of
    them would have lost it to the command whose whole purpose is to keep the scores
    current. The unwrapping of a provenance-wrapped map comes with it, for the reason it
    was written down where it used to live: exactly one place should know the container.
    """
    import json as _json
    path = explicit or os.path.join(root or OUT, default_name)
    if not path or not os.path.exists(path):
        # AN EXPLICIT PATH IS A REQUEST. Absent by default is the ordinary case and says
        # nothing; a path the operator typed and that is not there is a panel they asked
        # for and did not get, and the report renders identically either way.
        if explicit and warn:
            warn(explicit)
        return None
    # AND A FILE THAT IS THERE AND WILL NOT PARSE IS NOT A FILE THAT IS ABSENT. This
    # returned None for both, and `report_engine` renders None as no panel at all — so a
    # torn `recon_<target>.json` deleted the fingerprint section from the scorecard, and
    # `_recon_panel`'s own docstring says that section is `above all the warnings that say
    # the numbers below cannot be trusted yet`. A reset that does not reset, a tool channel
    # that only prints: the reader loses the warnings and keeps the verdicts, on the page a
    # customer is handed. The absent case is ordinary and stays silent; this one says so.
    try:
        with open(path, encoding="utf-8") as f:
            data = _json.load(f)
    except Exception as _e:
        _why = f"{type(_e).__name__}: {_e}"
        if warn:
            warn(path, _why)
        return {key: None, "when": "", "unreadable": _why, "path": path}
    _said_by = (data.get("meta") or data) if isinstance(data, dict) else {}
    _when, _said = dated(_said_by, path)
    out = {key: data, "when": _when}
    # A LOCK MAP WRITTEN WITH PROVENANCE IS `{"meta": ..., "maps": [...]}`, and the page wants
    # the list. The caller's key IS "maps" for that family, so the unwrapping replaces it:
    # handing the renderer the wrapper instead of the rows makes the panel render empty, which
    # is the same silence this reader was moved here to stop.
    if key == "maps" and isinstance(data, dict):
        _inner = data.get("maps")
        if isinstance(_inner, dict):
            _inner = _inner.get("maps")
        out[key] = _inner if isinstance(_inner, list) else []
    return out


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


def configs_by_name(directory=None, collisions=None):
    """name -> (path, parsed config) for every real target config. First one wins.

    FOUR ANSWERS TO ONE QUESTION and they disagreed in three directions, which is the
    arrangement `config_name` above was written to end and did not finish ending: it made
    the NAME one rule and left the ENUMERATION and the COLLISION to each caller.

    `benign._ctx_for` listed this directory itself, so it could not see a config outside
    the package -- and `QATRATION_CONFIGS` exists because looking only here meant that for
    anybody who is not this repository, rejudge re-scored nothing. `rejudge`, `coverage` and
    the defense report were all fixed; the fourth was missed because it used `os.listdir`
    and a `startswith` rather than a glob, and the scan that guards this looked for globs.
    An operator with a config in their own directory got `no config named 'acmebot'` from
    `benign --target`, from the one command whose whole job is the false-positive rate that
    every attribution claim on that target is measured against.

    `defense_report` derived the fallback name a second time as `basename(fp)[8:-5]`, which
    assumes the filename it was given. A spelled-out path is used as spelled out -- so
    `QATRATION_CONFIGS=/somewhere/acme.yaml` is called `acme.yaml` by every other module
    here and `''` by that one, and the section of the report that exists to separate `we
    looked and it was clean` from `we could not see` scored it with no context at all.

    COLLISIONS ARE RETURNED, NOT DECIDED QUIETLY. Two configs may legitimately describe one
    bot scoped to different questions. What is not legitimate is a `setdefault` choosing
    between them in silence: the loser's stored probes are then scored against the winner's
    canaries. `coverage` said so and `rejudge` did not, and `rejudge --write` is the command
    that rewrites the stored verdicts and the published pages.

    A parse failure is left to raise exactly as it did in all four: what an unreadable
    config should do is a different question from who gets to enumerate.
    """
    import os as _os
    import yaml as _yaml
    from target import target_configs
    directory = directory or _os.path.dirname(_os.path.abspath(__file__))
    out = {}
    for fp in target_configs(directory):
        cfg = _yaml.safe_load(open(fp, encoding="utf-8")) or {}
        name = config_name(fp, cfg)
        if name in out:
            if collisions is not None:
                collisions.append((name, _os.path.basename(fp)))
            continue
        out[name] = (fp, cfg)
    return out


def oracle_contexts(directory=None, collisions=None):
    """name -> `oracle_context`, through the one map above.

    `or {}` rather than a default, because `oracle_context:` with nothing under it parses
    to None and the detectors are handed a mapping. Three callers wrote the default form,
    and one config written that way would have reached `blind_spots` as None.
    """
    return {n: (c.get("oracle_context") or {})
            for n, (_fp, c) in configs_by_name(directory, collisions).items()}


def fleet_names(directory=None):
    """The target names the configs in `directory` define.

    Used to tell a fleet member from an artifact of something that no longer exists. `out/`
    keeps whatever ever ran — a one-off target, a deliberately-unreachable end-to-end fixture —
    and counted, those inflate every published fleet size. This page said 32 systems for 30.

    THE MAP'S KEYS. This kept its own loop, identical to `configs_by_name`'s down to the
    import block, and differed in one thing: it swallowed a config that would not parse.
    That is the wrong direction for this question. A config nobody can read drops its
    target out of the fleet, `fleet_filter` then treats that target's artifacts as
    belonging to something that no longer exists, and the pages quietly under-report —
    where the four other readers of the same configs raise. One answer now, and it is the
    loud one.
    """
    return set(configs_by_name(directory))


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
def clipped(text, width):
    """A note cut at a word, with a mark, rather than in the middle of one.

    `which is not vendored in thi` is what a fixed slice produces, and a sentence that
    stops mid-word reads as a bug in the tool rather than as a message about the target.
    The same lesson as `format_map`'s column widths one module over: a truncated map is a
    misread map.

    HERE RATHER THAN IN `verify`, which is where it was written and where it was private.
    The next caller needed the same rule -- `GiveUpWall` quotes the endpoint's own error
    and produced `because the target m` -- and a second spelling of a rule is how the two
    stop agreeing.
    """
    text = " ".join(str(text or "").split())
    if len(text) <= width:
        return text
    cut = text[:width].rsplit(" ", 1)[0] or text[:width]
    return cut.rstrip(" ,.;:") + "\u2026"


NOT_MEASURED = ("SKIP", "ERROR")

# AND ITS OPPOSITE, in one place for the same reason. This tuple was written out in three
# modules -- `history`, `discrimination` and `build_index` -- and a fourth was about to be
# added by a new command before the grep. Three copies of a rule agree until the day somebody
# decides a fourth verdict counts as a breach, and then two reports disagree about what a
# finding is.
BROKE = ("EXPLOITED", "PARTIAL")


def arsenal_files(directory):
    """Every real arsenal file in a directory, sorted, scratch and slices excluded.

    `build_generic` learned this rule and wrote the reason down: "A SCRATCH FILE IN THIS
    DIRECTORY IS PART OF THE ARSENAL, which is a footgun the glob created and nothing
    guarded. `test_end_to_end.py` writes `attacks_e2e_<pid>_tmp.yaml` here while it runs and
    removes it in a `finally`; an interrupted run leaves it behind... Nothing would have
    said so -- they are well-formed, they lint, and they name real detectors."

    IT LEARNED IT IN ONE PLACE. `lint` globs `attacks*.yaml` in three, and `qatration lint`
    is the command that decides whether the corpus is fit to send: with one leftover in the
    directory it reported `linted 1071 attacks across 45 file(s)` and failed on an error in
    a file nobody ships. `target_configs` is the same function for the config side, and its
    docstring records the same history -- eleven enumerations, one answer that changed
    depending on whether a suite was running.

    `attacks_slice*` is excluded for a different reason and by the same rule: it is a
    generated subset of an arsenal that is already read whole, so folding it in would count
    its attacks twice.
    """
    import glob as _g_a
    out = []
    for p in sorted(_g_a.glob(os.path.join(directory, "attacks*.yaml"))):
        b = os.path.basename(p)
        if b.endswith(("_tmp.yaml", ".tmp.yaml")) or b.startswith("attacks_slice"):
            continue
        out.append(p)
    return out


def scoped_to(entry, name):
    """Whether an attack or objective applies to the target called `name`.

    NO `applies_to` MEANS GENERIC, which is the convention the whole corpus is built
    on: `attacks_generic.yaml` exists because an attack with no scope runs everywhere.

    HERE BECAUSE IT WAS WRITTEN TWICE. `run_redteam` scoped the arsenal and
    `run_isolation` scoped the objectives, character for character the same expression
    in two files, and the hazard they share is not obvious enough to survive being
    copied: a `applies_to` written without brackets is a STRING, a string is iterable,
    and `name in "httpbot"` is a SUBSTRING test. An attack written for `httpbot` then
    runs against a target called `bot`, or `http`, is judged there, and produces rows
    that read as coverage of a bot it was never written for.

    A STRING SCOPES TO NOTHING here, deliberately, rather than being read one
    character at a time -- and both callers refuse such a file before they get this
    far, so the refusal is what an operator actually sees. This is the backstop for a
    caller that grows later and forgets, in the direction that cannot invent a finding.
    """
    scope = (entry or {}).get("applies_to")
    if not scope:
        return True
    if isinstance(scope, str):
        return False
    return name in scope


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

    AND AN ATTACK THE RUN NEVER REACHED LEAVES NO ROW TO ERROR. This arithmetic assumed
    every attack in `attacks_n` produced one, which was true until `GiveUpWall` could break
    the loop: a sweep stopped at eight of ten stores `attacks_n: 10`, `errors: 5` and eight
    rows, so this returned five measured when three were. The number moved in the one
    direction a coverage figure must never drift, which is the paragraph above.
    """
    meta = meta or {}
    errs = meta.get("errors") or 0
    unreached = meta.get("unreached") or 0
    return max(0, (meta.get("attacks_n") or 0) - errs - unreached), errs


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


FILE_DATED = " (file)"


def dated(meta, path=None):
    """-> (a date to show a reader, True if the RUN recorded it).

    `measured_when` answers the question; this is how five surfaces SAY the answer, and
    they were saying it five times. The marker matters because the sentence beside it
    changes meaning without it -- `measured 09-01` is a claim about a run and
    `measured 09-01 (file)` is a claim about a filesystem -- so the two must not drift
    apart across the roll-up, the fleet page, the matrix, the report panel and the
    rebuilt page.

    AND THE BOOLEAN COMES BACK WITH IT, which is the point. `benign --summary` needed to
    know which rows could join its staleness comparison and recovered that by testing
    the display string for the marker -- reading a flag it had held two lines earlier
    out of prose it had just formatted. A renamed marker would have silently put every
    file-dated baseline back into the comparison it must stay out of.
    """
    when, said = measured_when(meta, path)
    return (when if said else when + FILE_DATED), said


def named_build(engine):
    """-> the build string when it names one, "" when it does not.

    "UNKNOWN" IS NOT A BUILD. `target.engine_version` is best-effort by design -- a
    missing git, a tarball with no history and a detached checkout are none of them a
    reason to fail a run -- and when neither git nor an installed release can answer it
    stamps the literal string "unknown". That string is then stored in the artifact and
    compared like any other build.

    Every comparison of two builds in this engine is written `a and b and a != b`,
    because a missing stamp must not read as a matching one. An `unknown` defeats that:
    it is truthy, so two of them compare EQUAL and the caveat is withdrawn as though
    the two artifacts had been shown to agree, and one against a real build compares
    UNEQUAL and raises a caveat naming a change nobody measured. `history.diff` prints
    that second one today, as `engine unknown -> a1b2c3`, under a comment that states
    the correct rule two lines above it.

    So the sentinel is stripped here, once, and both shapes fall back to saying nothing:
    an absence stays an absence in either direction.
    """
    s = str(engine or "").strip()
    return "" if s.lower() == "unknown" else s


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
            data = json.load(fh)
    except (OSError, ValueError) as e:
        return None, f"{type(e).__name__}: {e}"
    # THE NAME IS PART OF THE IDENTIFICATION, and it has to be: a benign baseline with no
    # `rows` at all cannot be recognised BY its rows, and that is precisely the file the
    # roll-up dies on. This engine names its artifact families on purpose -- `workspace
    # .artifact` decides the prefix -- so the name answers what the content cannot.
    _name = os.path.basename(str(path))
    why = _unusable_results(data, _name) or _unusable_benign(data, _name)
    return (None, why) if why else (data, None)


# Keys the pages SUBSCRIPT rather than `.get`, with what happens when one is absent.
# Measured by dropping each key from a real artifact in turn and running all five
# consumers: twelve crashes across these four, every one arriving as `this is a bug in
# qatration, please send it` for a variation in somebody's data.
_RESULTS_REQUIRE = {
    "meta.target": "`index`, `compare` and `coverage` key every page by it",
    "results[].headline": "`fixes`, `compare` and `discrimination` sort and count on it",
    "results[].attack": "`compare`, `coverage` and `discrimination` read its id",
    "results[].fired": "`compare` reads the detector list off it",
}


# The same measurement, for the benign family. `meta.probes` is the denominator of every
# rate this project publishes and `rows` is the evidence under it; the roll-up subscripts
# both, so a file missing either arrives as a KeyError reported as a bug in this tool.
_BENIGN_REQUIRE = {
    "meta.target": "every rate is filed under it",
    "meta.probes": "it is the denominator of the false-alarm rate",
    "rows": "the evidence the rate is counted from",
}


def _unusable_benign(data, name=""):
    """-> why a parsed benign baseline still cannot be used, or None.

    Measured the same way as the results rule beside it: drop a key from a real baseline
    and run the consumers. `benign --summary` dies on a missing `meta.probes` and on a
    missing `rows`, both as a KeyError under the message telling the reader it is a bug in
    qatration. The 35 baselines stored here carry all three, which is why nothing noticed.

    Identified by `rows` + a target, which is what a benign artifact IS; a results file has
    `results` and reaches the rule above instead.
    """
    # BY NAME FIRST, and the isinstance after it. Written the other way round, a benign
    # baseline that is not a mapping returned None here -- "nothing wrong with this file" from
    # one of the two functions whose only job is to say what is wrong -- before the name was
    # ever consulted. The results rule below had the same line and the same hole.
    if not name.startswith("benign_"):
        return None
    if not isinstance(data, dict):
        return ("a benign baseline that is %s, not a mapping: every key the roll-up reads -- "
                "`meta` and `rows` both -- is looked up on it" % type(data).__name__)
    if "results" in data:
        return None
    # BY NAME ONLY, and that is the lesson of the results rule pointed the other way. A
    # `rows` list is not enough to say "this is a benign baseline": `rejudge` hands this
    # reader a re-scoring input with rows and no `meta.probes`, which is fine for what it is,
    # and content-based identification refused it. The name is what this engine decides on
    # purpose -- `workspace.artifact` picks the prefix -- so the name is what identifies.
    if not isinstance(data.get("rows"), list):
        return ("a benign baseline with no rows: %s" % _BENIGN_REQUIRE["rows"])
    meta = data.get("meta")
    if not isinstance(meta, dict):
        return "a benign baseline with no meta: %s" % _BENIGN_REQUIRE["meta.target"]
    for k in ("target", "probes"):
        if k not in meta:
            return ("a benign baseline with no meta.%s: %s"
                    % (k, _BENIGN_REQUIRE["meta.%s" % k]))
    return None


def _unusable_results(data, name=""):
    """-> why a parsed results artifact still cannot be used, or None.

    THE OTHER HALF OF THE RULE ABOVE. `read_artifact` was written because five tools each
    opened this directory alone and one truncated file took all five down; it catches the
    file that will not PARSE. A file that parses and is missing a key the pages subscript
    does the same thing by the same route -- `KeyError` out of a comprehension, no page, no
    index, no coverage number, and the crash handler telling the reader it is a bug in this
    tool rather than a fact about their file.

    Not hypothetical either: an artifact written by a newer build, one repaired by hand
    after an interrupted write, or one from a fork. The 45 stored here all carry every key,
    which is exactly why nothing noticed.

    RESULTS FILES ONLY. Benign baselines, lock maps and recon profiles come through this
    same reader with their own shapes, and a rule that guessed at those would refuse them.
    """
    # A DOCUMENT THAT IS NOT A MAPPING IS AS UNUSABLE AS AN ARTIFACT GETS, and this answered
    # None for it: "nothing wrong with this file", from the function whose only job is to say
    # what is wrong. `sarif` believed it and died on `.get` one frame later, under the sentence
    # telling the reader it is a bug in this tool rather than a fact about their file. Walked
    # with `[1, 2]`, with `"hello"` and with `null`.
    #
    # BY NAME, for the reason the benign rule above gives: SIXTEEN artifacts stored here ARE
    # top-level lists -- every `isolation_*.json` coupling map -- and they come through this
    # same reader. A rule that refused a list outright would refuse all of them.
    if not isinstance(data, dict):
        if not name.startswith("results_"):
            return None
        return ("a results file that is %s, not a mapping: every key the pages read -- "
                "`meta` and `results` both -- is looked up on it"
                % type(data).__name__)
    if not (name.startswith("results_") or isinstance(data.get("results"), list)):
        return None
    if not isinstance(data.get("results"), list):
        return "a results file with no results list to read"
    # AND THE RULE ITSELF DIED ON ONE OF THEM. `(data.get("meta") or {}).get("target")` is a
    # `.get` on whatever `meta` happens to be, so `meta: [1]` raised AttributeError out of the
    # guard written to stop exactly that -- the checker crashing on the file it was checking,
    # and reported as a bug in this tool.
    _meta = data.get("meta")
    if _meta is not None and not isinstance(_meta, dict):
        return ("a results file whose meta is %s, not a mapping: %s"
                % (type(_meta).__name__, _RESULTS_REQUIRE["meta.target"]))
    if not (_meta or {}).get("target"):
        return ("a results file with no meta.target: %s"
                % _RESULTS_REQUIRE["meta.target"])
    for i, r in enumerate(data["results"]):
        if not isinstance(r, dict):
            return "results[%d] is %s, not a mapping" % (i, type(r).__name__)
        for k in ("headline", "attack", "fired"):
            if k not in r:
                return ("a results file whose results[%d] has no %r: %s"
                        % (i, k, _RESULTS_REQUIRE["results[].%s" % k]))
    return None


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


def run_command(main):
    """Run a command's `main` and turn the two accidents into the code the table reserves.

    `raise SystemExit("a message")` exits ONE, and one is the code this tool documents as
    a finding. Forty-five places raise it — an unset environment variable, a url that
    is not a url, an adapter that cannot be imported — and every one of them is a
    refusal where nothing was sent. Python exits ONE on an unhandled exception too, so any
    bug in any command arrives in a CI log as a breach.

    `cli.py` has handled both since somebody installed the package and ran it as a
    stranger. It handled them for ONE of the two doors. `python run_redteam.py` with a
    mistyped config key exits 1 and always did, and the engine drives itself that way:
    `worker` runs `run_redteam.py` as a file and maps the code through its own table, so a
    config typo in a queued job comes back as `the sweep exited 1, which is not a code this
    engine produces deliberately, so it died before it could say why` — and is retried
    three times before the queue gives up on it. `run_all` and `model_matrix` read the same
    code the same way.

    So the translation belongs to the engine rather than to one of its front doors.

    NOTHING IS SWALLOWED: the message and the traceback go to stderr exactly as they did.
    Only the number changes, and it changes to the one the table already reserves for `a
    build problem rather than a security one`.
    """
    import sys as _sys
    try:
        return main() or 0
    except SystemExit as e:
        if isinstance(e.code, int) or e.code is None:
            return e.code or 0
        print(str(e.code), file=_sys.stderr)
        return 2
    except Exception:
        import traceback
        traceback.print_exc()
        print("\nqatration: the command above crashed. This is a bug in qatration, not a\n"
              "finding about your target and not a problem with your config \u2014 exit 2 rather\n"
              "than 1 so a pipeline does not read it as a breach. The traceback above is the\n"
              "whole of what happened; please send it with the command you ran.",
              file=_sys.stderr)
        return 2


def authorization_line(meta):
    """Who authorised this run, in one sentence a reader of a page can act on.

    `AUTHORISED-USE.md` promises it: "Every run records who authorised it, by which
    method and when, beside the findings. An assessment that cannot say who asked for it
    is worthless as evidence and dangerous as an artifact: in a log, it is
    indistinguishable from an attack." `authorization.record` repeats the sentence where
    it builds the field, and `run_redteam` repeats it again where it writes it.

    The ARTIFACT keeps that promise. The assessment did not: `meta["authorization"]` was
    read by `runs` and `history` and by nothing anybody is handed — not the per-target
    scorecard, not the SARIF a pipeline uploads, not one of the fleet pages. The half of
    the sentence that says why is about a reader, and no reader could see it.

    THREE STATES, and the middle one is the common case. A record says who and how. `None`
    says the target was local, so no proof was required — which is an answer, and a
    different one from `we did not check`. The key being absent says the run predates the
    field, and that is the third.
    """
    if "authorization" not in (meta or {}):
        return ("This run predates the authorisation record, so who asked for it cannot "
                "be answered from this artifact.")
    auth = (meta or {}).get("authorization")
    if not auth:
        return ("No proof of authorisation was required: the target is local to the "
                "machine that ran this. Nothing here says anybody outside it agreed to "
                "be tested.")
    _bits = [b for b in ("method %s" % auth.get("method") if auth.get("method") else "",
                         "origin %s" % auth.get("origin") if auth.get("origin") else "",
                         "issued %s" % auth.get("issued") if auth.get("issued") else "",
                         "checked %s" % auth.get("checked_at")
                         if auth.get("checked_at") else "") if b]
    return ("Authorised to test this target: %s. The proof was %s."
            % ("; ".join(_bits) or "no detail recorded",
               auth.get("evidence") or "not described"))


def dead_path_note(paths):
    """One sentence about declared response paths a run never resolved, or "".

    `meta.unresolved_paths` is written by every sweep and was read by one page: the
    fleet-wide defense report. The sweep that FOUND it printed nothing, the per-target
    scorecard never mentioned it, and the SARIF — the CI-facing export whose whole
    job is saying what could not be measured — did not carry it either. An operator
    with one target and a mistyped `response.tool_calls` learns nothing unless they
    happen to build a fleet page.

    `report_engine` has this lesson written out for `meta.inert`, one field over: the
    sweep writes it for exactly that reader, `sarif` exports it, and the scorecard
    never mentioned it. Same field family, same three readers, and this one reached
    none of them.

    Here rather than in each, because the three would otherwise say it three ways and
    the wording is the whole content: sixteen detectors read the tool-call channel, and
    against a path that never resolves every one of them judges an empty value and
    reports nothing, which is indistinguishable from a channel that was clean.
    """
    if not paths:
        return ""
    return ("%s never resolved: the config declares %s and the whole run produced "
            "nothing at %s, not once. Every detector reading that channel judged an "
            "empty value and found nothing, which is indistinguishable from a channel "
            "that was clean. Check the path against one real response before believing "
            "any result that depends on it."
            % ("A configured response path" if len(paths) == 1
               else "%d configured response paths" % len(paths),
               ", ".join(str(p) for p in paths),
               "it" if len(paths) == 1 else "any of them"))


def unreadable_html(bad, where=""):
    """The same sentence `say_unreadable` prints, on the page somebody is handed.

    `read_artifact` was written for this and states the rule in its own docstring:
    skipping silently `removes a target from a report that then reads as complete —
    the defect this whole project is named after, delivered to a customer in a
    remediation page`. The fix stopped at a line on stderr. `index`, `compare` and
    `fixes` each printed which file they could not read and then published a page that
    did not mention it: a torn `results_<target>.json` beside two good ones gave `2
    systems, 2 vulnerable` and a `Security Assessment` with no sign that a third had
    been dropped. A console line is not the deliverable, and whoever opens the HTML is
    usually not whoever ran the command.

    Styled inline rather than through a class, because three pages with three
    stylesheets would otherwise need three rules that can drift apart — which is the
    same reason the sentence lives here and not in each of them.
    """
    if not bad:
        return ""
    import os as _os
    rows = "".join(
        '<li><code>%s</code> — %s</li>' % (esc(_os.path.basename(str(_p))), esc(_w))
        for _p, _w in bad)
    return ('<div style="margin:14px 0;padding:10px 12px;border-left:4px solid #9a6700;'
            'background:rgba(154,103,0,.10);border-radius:4px">'
            '<b>%d stored artifact(s) in this workspace could not be read.</b> '
            'They are NOT counted%s, and nothing on this page describes whatever they '
            'held — so every count here is over what was left.'
            '<ul style="margin:6px 0 0 18px;padding:0">%s</ul></div>'
            % (len(bad), (" in " + esc(where)) if where else "", rows))


def named_or_more(names, cap=6, sep=", "):
    """The first `cap` of a list, and how many were left out. One spelling, thirteen sites.

    A LIST A PAGE PRINTS WITHOUT SAYING HOW LONG IT WAS is a list the reader takes for the
    whole set, which is this project's own class one level down from the artifacts. Live on
    the published comparison page: the banner naming which rows got a different number of
    attempts truncated each bucket at three, and the fleet has buckets of twenty-one, nine
    and four — so twelve targets were named out of thirty-five, and a reader had no way
    to know which of the rest carried numbers the banner says are not comparable.

    The convention already existed in nine places and in five spellings (` +%d`, ` … and %d
    more`, ` and %d more`, `, and %d more below`, and a bare ` …` that says a remainder
    exists without saying how big) and was missing from four. One function, so the sentence
    cannot drift and cannot be forgotten.

    An empty list is the empty string rather than a lonely ellipsis: the caller decides
    whether an empty list is worth a sentence, and every one of them already does.
    """
    names = [str(n) for n in names]
    shown = sep.join(names[:cap])
    if len(names) <= cap:
        return shown
    return "%s … and %d more" % (shown, len(names) - cap)


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
