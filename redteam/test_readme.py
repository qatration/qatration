"""
The README's numbers, checked against the code that has to keep them true — no model, no network.

Every defect this project has produced was a wrong NUMBER rather than an error, and the
sharpest form of it is **a count that is declared rather than counted**. That has now been
found three times inside the engine: `test_oracle`'s gates adding their pass-count to
numerator and denominator so a failing gate deleted itself, seven suites hardcoding
`total = N` with five drifted below their real count, and `rejudge` calling a row unchanged
when the verdict held but the detector set had moved. Each time the fix was to count the
thing instead of asserting it.

The README was the one place still asserting. It is the design record and the document
anyone evaluating this is handed first, and it said **fifty-five detectors** in three
sentences and **55** in the layout while the oracle held fifty-six, and **4 declared-only**
while the tool printed five. Nothing was wrong with the code; the claim about the code had
simply been left behind by it, which is exactly the failure mode this repo names and then
walked into in prose.

So the counts the README states are recounted here from the source of truth, and the gate
is built the way the other gates are: **plant a specific drift, prove it is seen; hand it
the real document, prove it stays quiet.** A gate that fires on everything passes the first
half perfectly.

One rule is worth stating because it is what makes this gate more than a spellchecker: a
claim that has DISAPPEARED from the README is a failure too. A pattern that matches nothing
would otherwise silently retire the check it was written for, which is the same "a guard
only covers where it looks" that made `detector_coverage`'s unconfigured bucket unreachable.

Measurements are treated differently from counts. "1,180 stored probes" was true of a
moment and every new run makes it stale in the harmless direction, so it is gated in the
dishonest direction only: the README may understate the evidence it has, never overstate it.

    python test_readme.py        # exits 1 on any failure (CI gate)
"""
import sys, os, re, ast, glob, json, io
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)

import yaml
from oracle import DETECTORS
import detector_coverage as dc
from target import target_configs

README = os.path.join(ROOT, "README.md")

# THE WHOLE DESIGN RECORD, not just the front page. The README used to be 2,400 lines and was
# split into docs/ plus a CHANGELOG, which moved most of the claims this gate exists to check.
# Reading only README.md afterwards would have retired those checks silently — a gate quietly
# covering less than it says it does, which is the same failure the gate is written against.
#
# One corpus, so a claim may move freely between pages and still cannot disappear. Order is
# fixed rather than glob order, because a failure message that names a line number should mean
# the same thing on two machines.
def _corpus_paths():
    # NOT the CHANGELOG, and that omission is deliberate rather than an oversight. A dated entry
    # records what was true on its date: "thirty-four offline suites" was correct on 18 August
    # and adding a suite does not make it wrong, it makes it history. Gating it would demand the
    # record be edited every time a number moves — teaching exactly the habit this project
    # exists to refuse, and quietly rewriting evidence to satisfy a test.
    paths = [README]
    paths += sorted(glob.glob(os.path.join(ROOT, "docs", "*.md")))
    # THE SITE TOO, because it is the page a stranger reads first and the one where a stale
    # number costs most. It carried "576 ordinary support requests" while the corpus had grown
    # to 1,440 — understating, but unchecked either way, and nothing here had ever looked at
    # it. A claim is a claim wherever it is published.
    paths.append(os.path.join(ROOT, "site", "index.html"))
    # CONTRIBUTING and SECURITY too. They tell a stranger which commands to run and what the
    # build enforces, which makes every sentence in them the same kind of claim as a number:
    # a contributor who follows an instruction that no longer works concludes the project is
    # dead, and is not wrong to.
    paths += [os.path.join(ROOT, "CONTRIBUTING.md"), os.path.join(ROOT, "SECURITY.md")]
    return [p for p in paths if os.path.isfile(p)]


def _corpus():
    return "\n".join(open(p, encoding="utf-8").read() for p in _corpus_paths())

# The teens are irregular, so they are listed rather than composed. Their absence was found the
# way everything here is found: a real claim — "Seventeen frames across thirteen families" —
# that the table could not spell, refused loudly rather than skipped.
_WORDS = {10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
          15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen",
          20: "twenty", 30: "thirty", 40: "forty", 50: "fifty", 60: "sixty",
          70: "seventy", 80: "eighty", 90: "ninety"}
_UNITS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
          6: "six", 7: "seven", 8: "eight", 9: "nine"}


def spell(n):
    """Small deliberate range: an unspellable number is a failure, not a silent skip."""
    if n in _WORDS:
        return _WORDS[n]
    # `_UNITS` was only ever reached through the tens branch below, so `spell(4)` raised
    # "extend the number-word table" with "four" already sitting in the table. Found by
    # gating the first single-digit claim in the README.
    if n in _UNITS:
        return _UNITS[n]
    tens, unit = (n // 10) * 10, n % 10
    if tens in _WORDS and unit in _UNITS:
        return f"{_WORDS[tens]}-{_UNITS[unit]}"
    raise AssertionError(f"extend the number-word table before claiming {n} in the README")


def facts():
    """Recount everything the README asserts, from the code rather than from the README."""
    hits, where, probes, broke, _src = dc.replay()
    demo = sorted(k for k in DETECTORS if hits[k])
    declared = sorted(k for k in DETECTORS if not hits[k])
    unconfigured, untried = dc.buckets(declared, broke)

    def count_ids(name):
        path = os.path.join(HERE, name)
        if not os.path.exists(path):
            return 0
        return len(yaml.safe_load(open(path, encoding="utf-8")) or [])

    frames = yaml.safe_load(open(os.path.join(HERE, "frames.yaml"), encoding="utf-8")) or []
    n_frames = len(frames)

    # The benign gate's own dimensions, taken from the gate rather than from the prose. Stated
    # as 26 contexts x 50 detectors on two pages while the gate printed 35 x 62 — and a claim
    # about a CHECK is the worst one to leave stale, because it is the sentence a sceptic reads
    # to decide whether the check is worth anything.
    import test_benign
    n_contexts = len(test_benign.contexts())
    n_prompts = len(test_benign.ALL_PROMPTS)

    # THE PORTABLE ARSENAL, which is the number a stranger cares about — the one describing what
    # runs against somebody else's endpoint rather than against this repo's practice bots. It
    # was stated in the docs as 241 across 52 while the generator produced 285 across 58, and
    # nothing checked it, so the figure a reader would use to compare this tool against another
    # was the stalest number in the document.
    # The benign corpus, counted from the artifacts rather than from any page describing it.
    benign_probes = 0
    for fp in glob.glob(os.path.join(ROOT, "out", "benign_*.json")):
        try:
            rows = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue
        rows = rows.get("rows", rows) if isinstance(rows, dict) else rows
        benign_probes += len(rows) if isinstance(rows, list) else 0

    # THE PUBLISHED ROLL-UP, from the tool that prints it rather than from the page quoting it.
    # docs/oracle.md carried a pasted transcript — 489 fires, 103/489, "all 489 are settled" —
    # true on the day it was pasted. The corpus then grew from 48 prompts to 50, the tool began
    # printing sixteen fires nobody had adjudicated, and the page went on asserting the opposite
    # because no pattern here had ever looked at those digits.
    #
    # `benign.adjudicated` rather than a recount: the count runs over candidate false positives,
    # so over_refusal and its kin are excluded as usability findings, and recounting by hand
    # comes out 73 fires high while looking entirely reasonable.
    import benign as _benign
    _s = _benign.roll_up()
    _find, _fp, _unk, _ = _benign.adjudicated(_s)

    # THE EXAMPLE CONFIGS THE README OFFERS A STRANGER, counted from the list itself. The
    # sentence said "Two configs are ready to copy" above four bullets: somebody added two and
    # did not reread the line. Small, and exactly the shape this suite exists for — a count
    # stated in words, in prose, where no pattern was looking.
    _readme = open(README, encoding="utf-8").read()
    _copyable = 0
    if "configs are ready to copy" in _readme:
        _tail = _readme[_readme.index("configs are ready to copy"):]
        _tail = _tail[:_tail.index("\n\n#")] if "\n\n#" in _tail else _tail
        _copyable = len(re.findall(r"^\* \[`targets_[a-z0-9_]+\.yaml`\]", _tail, re.M))

    gen_path = os.path.join(HERE, "attacks_generic.yaml")
    gen = yaml.safe_load(open(gen_path, encoding="utf-8")) if os.path.exists(gen_path) else []
    gen_rows = gen.get("attacks", gen) if isinstance(gen, dict) else (gen or [])

    return {
        "copyable_configs": _copyable,
        "rollup_fires": _find + _fp + _unk,
        "rollup_findings": _find,
        "rollup_false_alarms": _fp,
        "rollup_unadjudicated": _unk,
        "rollup_rate": f"{100 * _fp / (_find + _fp):.1f}" if (_find + _fp) else "0.0",
        "benign_probes": benign_probes,
        "benign_contexts": n_contexts,
        "benign_prompts": n_prompts,
        "generic_attacks": len(gen_rows),
        "generic_categories": len({r.get("category") for r in gen_rows if r.get("category")}),
        "detectors": len(DETECTORS),
        "demonstrated": len(demo),
        "declared_only": len(declared),
        "untried": len(untried),
        "unconfigured": len(unconfigured),
        "probes": probes,
        "attacks": count_ids("attacks.yaml"),
        "frames": n_frames,
        "test_files": len(glob.glob(os.path.join(HERE, "test_*.py"))),
    }


def claims(f):
    """(label, pattern, expected-string) — the pattern must match, and match this value.

    Each one is anchored on enough surrounding words that it cannot drift onto a different
    sentence, because a check that quietly starts measuring the wrong claim is worse than
    one that fails.
    """
    return [
        ("the oracle section heading counts detectors",
         r"## The oracle: ([a-z-]+) detectors, and how many have ever fired",
         spell(f["detectors"])),
        ("'there are N, across the channels'",
         r"There are ([a-z-]+), across the channels a breach actually uses",
         spell(f["detectors"])),
        ("'the number that matters is not N'",
         r"The number that matters is not ([a-z-]+)\.",
         spell(f["detectors"])),
        ("the count of example configs offered to a stranger",
         r"([A-Za-z]+) configs are ready to copy",
         spell(f["copyable_configs"]).capitalize()),

        # --- the roll-up quoted in docs/oracle.md ------------------------------------------
        # Anchored on the transcript's own wording, which is what the page presents as the
        # tool's current output. A pasted transcript is the most convincing thing on a page
        # and the least likely to be re-run.
        ("the quoted roll-up's fire count",
         r"of (\d+) fire\(s\) on clean traffic:", str(f["rollup_fires"])),
        ("the quoted roll-up's findings line",
         r"(\d+) adjudicated as FINDINGS about the target", str(f["rollup_findings"])),
        ("the quoted roll-up's false-alarm line",
         r"(\d+) adjudicated as false alarms", str(f["rollup_false_alarms"])),
        ("the quoted roll-up's rate, numerator",
         r"false-alarm rate over what HAS been settled: (\d+)/\d+",
         str(f["rollup_false_alarms"])),
        ("the quoted roll-up's rate, denominator",
         r"false-alarm rate over what HAS been settled: \d+/(\d+)",
         str(f["rollup_findings"] + f["rollup_false_alarms"])),
        ("the quoted roll-up's percentage",
         r"rate over what HAS been settled: \d+/\d+ \(([\d.]+)%\)", f["rollup_rate"]),
        ("the prose's fire count beside the probe count",
         r"anything\*\*,\s*and (\d+) detector fires across them", str(f["rollup_fires"])),
        ("the claim that nothing is left unadjudicated names the right total",
         # `\s+` and not a space: the sentence wraps between "30" and "targets", and a
         # pattern that assumes one line is a pattern that silently matches nothing.
         r"in it\.\*\* All (\d+) fires across \d+\s+targets are settled",
         str(f["rollup_fires"])),
        ("the benign probe count on the page",
         r"\*\*([\d,]+) probes on which nobody attacked", f"{f['benign_probes']:,}"),

        ("the layout comment on oracle.py",
         r"oracle\.py\s+# (\d+) detectors \+ judge",
         str(f["detectors"])),
        ("the headline: demonstrated",
         r"It reports \*\*(\d+) demonstrated, \d+ declared-only\*\*",
         str(f["demonstrated"])),
        ("the headline: declared-only",
         r"It reports \*\*\d+ demonstrated, (\d+) declared-only\*\*",
         str(f["declared_only"])),
        ("the declared-only split, untried half",
         r"split \*\*(\d+) untried / \d+ unconfigured\*\*", str(f["untried"])),
        ("the declared-only split, unconfigured half",
         r"split \*\*\d+ untried / (\d+) unconfigured\*\*", str(f["unconfigured"])),
        ("the false-positive section's premise counts demonstrated detectors",
         r"([A-Z][a-z]+-?[a-z]*) demonstrated detectors says none of those is dead",
         spell(f["demonstrated"]).capitalize()),
        # The front page states the number too, and a number on the front page is the one most
        # people will ever read. Gated like every other, because "the README was the one place
        # still asserting" is how this suite came to exist.
        ("the front page's detector count",
         r"\*\*(\d+) detectors\*\*, no grader model", str(f["detectors"])),
        ("the arsenal size",
         r"of the (\d+) attacks", str(f["attacks"])),
        ("the hand-written payload count",
         r"The arsenal is (\d+) hand-written payloads", str(f["attacks"])),
        ("the portable arsenal size",
         r"The arsenal is \*\*(\d+) attacks across \d+ categories\*\* now",
         str(f["generic_attacks"])),
        ("...and its category count",
         r"The arsenal is \*\*\d+ attacks across (\d+) categories\*\* now",
         str(f["generic_categories"])),
        ("the offline suite count",
         r"([A-Z][a-z]+(?:-[a-z]+)?) offline suites", spell(f["test_files"]).capitalize()),
        # The false-positive gate's own dimensions, stated on two pages and wrong on both:
        # 26 contexts and 50 detectors while the gate printed 35 and 62. A claim about a
        # CHECK is the worst one to leave stale, because it is the sentence a sceptic reads
        # to decide whether the check is worth anything.
        ("the benign gate's prompt count",
         r"(\d+) (?:prompts|exchanges) x \d+ oracle contexts", str(f["benign_prompts"])),
        ("the benign gate's oracle-context count",
         r"\d+ (?:prompts|exchanges) x (\d+) oracle contexts", str(f["benign_contexts"])),
        ("the benign gate's detector count",
         r"\d+ (?:prompts|exchanges) x \d+ oracle contexts x (\d+) detectors",
         str(f["detectors"])),
        # Re-anchored onto the live sentence in docs/findings.md. It used to match a numeral in
        # a dated CHANGELOG entry, and when the changelog left the corpus the check went with
        # it — a gate quietly retiring itself, which is the thing this file exists to catch.
        ("the frame library size",
         r"([A-Z][a-z]+(?:-[a-z]+)?) frames across", spell(f["frames"]).capitalize()),
    ]


def audit(text, f):
    """-> list of complaints. Empty means the document and the code agree."""
    bad = []
    for label, pat, want in claims(f):
        found = re.findall(pat, text)
        if not found:
            # A claim that vanished retires its own check. Say so instead of passing.
            bad.append(f"{label}: the sentence this gate checks is no longer in the README "
                       f"(pattern {pat!r} matched nothing)")
            continue
        wrong = sorted({g for g in found if g != want})
        if wrong:
            bad.append(f"{label}: README says {wrong}, code says {want!r}")

    # Measurements, gated in the dishonest direction only: a page may understate the evidence
    # it ran against, never overstate it. The site's corpus line joins the rule rather than
    # getting an exact check, because every new benign run makes it stale downward.
    for m in re.finditer(r"([\d,]+) ordinary support requests", text):
        claimed = int(m.group(1).replace(",", ""))
        if claimed > f["benign_probes"]:
            bad.append(f"benign corpus: a page claims {claimed} ordinary requests, "
                       f"only {f['benign_probes']} exist in out/benign_*.json")

    # The CI guide tells people to COMMIT their timeline, and the whole argument rests on it
    # being small. A claim about a file size is a promise about somebody's repository, so it is
    # gated in the direction that would embarrass us: the doc may overstate what a run costs to
    # store, never understate it.
    for m in re.finditer(r"about \*\*([\d.]+) ?KB a run\*\*", text):
        claimed_kb = float(m.group(1))
        total = runs = 0
        for fp in glob.glob(os.path.join(ROOT, "out", "history", "*.jsonl")):
            total += os.path.getsize(fp)
            runs += sum(1 for _ in open(fp, encoding="utf-8"))
        if runs:
            real_kb = (total / runs) / 1024.0
            if real_kb > claimed_kb * 1.35:
                bad.append("history size: the guide says about %.1f KB a run, the stored "
                           "timelines average %.1f KB" % (claimed_kb, real_kb))

    # The cost table rests on having measured real replies rather than guessed at them, and
    # "1,273 stored replies" is the sentence that makes it credible. Same rule as everywhere
    # else: a page may understate the evidence behind a claim, never overstate it.
    for m in re.finditer(r"\*\*([\d,]+) stored replies\*\*", text):
        claimed = int(m.group(1).replace(",", ""))
        have = 0
        for fp in glob.glob(os.path.join(ROOT, "out", "results_*.json")):
            try:
                r = json.load(open(fp, encoding="utf-8"))
            except Exception:
                continue
            for row in r.get("results", []):
                for t in row.get("trials") or []:
                    if ((t or {}).get("probe") or {}).get("output"):
                        have += 1
        if claimed > have:
            bad.append("cost table: claims %d stored replies, only %d exist" % (claimed, have))

    for m in re.finditer(r"([\d,]+) stored probes", text):
        claimed = int(m.group(1).replace(",", ""))
        if claimed > f["probes"]:
            bad.append(f"stored probes: README claims {claimed}, only {f['probes']} exist")
    return bad


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    f = facts()
    text = _corpus()

    print(f"recounted: {json.dumps(f)}\n")

    # --- the real document agrees with the real code -------------------------------------
    complaints = audit(text, f)
    check("every count the README states matches a recount from the code",
          not complaints, "; ".join(complaints))

    # --- and the gate can actually see a drift -------------------------------------------
    # Both halves, because a gate that passes on the merits and one that cannot fail look
    # identical from the outside.
    drifted = text.replace(f"There are {spell(f['detectors'])}, across the channels",
                           "There are ninety-nine, across the channels")
    check("a drifted word-count is caught",
          any("across the channels" in c for c in audit(drifted, f)))

    drifted2 = re.sub(r"It reports \*\*\d+ demonstrated",
                      "It reports **999 demonstrated", text)
    check("a drifted headline number is caught",
          any("demonstrated" in c for c in audit(drifted2, f)))

    deleted = text.replace("The number that matters is not", "The number that counts is not")
    check("a claim that disappeared is caught, not silently retired",
          any("not N" in c for c in audit(deleted, f)))

    # Derived, not hard-coded. This mutation named "1,180 stored probes" literally and went
    # stale the moment the count moved, so the check that proves the auditor works started
    # failing for a reason that had nothing to do with the auditor — a test whose fixture is a
    # snapshot of the thing it tests.
    _probes = re.search(r"([\d,]+) stored probes", text)
    _claim = f"{_probes.group(1)} stored probes" if _probes else "1,180 stored probes"
    check("the README states a probe count for the mutation to work on", bool(_probes))

    overclaim = text.replace(_claim, "999,999 stored probes")
    check("claiming more evidence than exists is caught",
          any("stored probes" in c and "only" in c for c in audit(overclaim, f)))

    understate = text.replace(_claim, "1 stored probes")
    check("...while understating the evidence is not an error",
          not any("stored probes" in c for c in audit(understate, f)))

    check("the number-word table refuses a number it cannot spell",
          _spells_or_raises(1000))

    # --- and the same rule applied to these suites' own totals ---------------------------
    # "A count that is declared rather than counted" has now been found three times in the
    # engine and once in this document. The fourth instance was a SNAPSHOT: test_recon read
    # `total = checks` thirty-seven lines above its print, so five checks added below it ran,
    # could fail, and were invisible to the number beside them — 45/45 while running 50.
    # A snapshot is a hardcoded total with a shorter fuse.
    # --- and the Layout has to list what is actually there -------------------------------
    # The Layout is the map a reader uses to find their way into the engine, and it had
    # drifted 23 modules behind the repo — including baseline, history, discrimination and
    # adaptive, four of the things the README spends the most words on. A map missing a
    # quarter of its territory is the documentation form of a count nobody keeps true.
    # The Layout moved to docs/internals.md in the split. Located by content rather than
    # by filename so that moving it again is a rename, not a silently retired check.
    lay_src = next((t for t in (open(p, encoding="utf-8").read() for p in _corpus_paths())
                    if "## Layout" in t), "")
    assert lay_src, "the Layout section is in none of the design-record pages"
    lay = lay_src[lay_src.index("## Layout"):
                  lay_src.index("## Run", lay_src.index("## Layout"))]
    lay = lay[lay.index("redteam/"):lay.index("external/")]      # the engine block only
    listed = set(re.findall(r"^\s{4}([\w*][\w.*]*\.py)", lay, re.M))
    globs = [l[:-len(".py")].replace("*", "") for l in listed if "*" in l]
    on_disk = {os.path.basename(f) for f in glob.glob(os.path.join(HERE, "*.py"))}
    missing = sorted(m for m in on_disk
                     if m not in listed and not any(m.startswith(g) for g in globs))
    check("every engine module appears in the Layout", not missing, str(missing))
    phantom = sorted(l for l in listed if "*" not in l and l not in on_disk)
    check("...and the Layout names nothing that is gone", not phantom, str(phantom))

    # --- every documented command and flag has to exist ----------------------------------
    #
    # The README's quickstart said `qatration onboard --target-config mybot.yaml` and the parser
    # declared `--config`, required. The very first command a new reader runs, rejected on a
    # flag name — and the same wrong spelling sat in two shipped example configs and in cli.py's
    # own docstring, because four copies of an instruction were written and none was executed.
    #
    # So the design record's commands are executed against the real parsers. This is slow
    # (one --help per command) and it is the only check here that catches a documented
    # invocation rather than a documented number.
    import subprocess
    import cli
    bad = []
    helps = {}
    # A shell continuation splits one command across lines, and the first version of this
    # pattern stopped at the newline — so every flag in `docs/ci.md`'s workflow, which is
    # written the way anyone would actually write it, went unchecked. The guard covered the
    # single-line spelling only, which is not the spelling a real workflow uses.
    #
    # And it stopped at the first POSITIONAL argument. `(?:\s+--[\w-]+)*` matches flags only
    # while they are adjacent, so in `qatration run --target-config mybot.yaml --fail-on
    # regression` it captured `--target-config` and then gave up at `mybot.yaml` — every flag
    # after the first value went unchecked, in every command anyone actually types. Take the
    # whole invocation to the end of its line and pull the flags out of it.
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    found = set()
    for m in re.finditer(r"qatration (\w+)([^\n`]*)", joined):
        found.add((m.group(1), " ".join(re.findall(r"--[\w-]+", m.group(2)))))
    for cmd, flags in sorted(found):
        if cmd not in cli.COMMANDS:
            bad.append("qatration %s is documented but is not a command" % cmd)
            continue
        if cmd not in helps:
            p = subprocess.run([sys.executable, os.path.join(HERE, "cli.py"), cmd, "--help"],
                               capture_output=True, text=True, timeout=120)
            helps[cmd] = p.stdout
        for flag in re.findall(r"--[\w-]+", flags):
            if flag not in helps[cmd]:
                bad.append("qatration %s %s is documented but the parser has no such flag"
                           % (cmd, flag))
    # THE OTHER SPELLING, and it is the one a contributor actually types. Everything above
    # scans `qatration <cmd> --flags`, which is the installed form. From a checkout the docs
    # say `python tools/check.py`, `python redteam/benign.py --target x`, and the label on
    # this check claimed all of it. Found by planting `--only-fast` on a documented
    # `tools/check.py` invocation and watching the suite stay green.
    ROOT_DIR = os.path.dirname(HERE)
    scripts = {}
    for m in re.finditer(r"python (?:-m\s+)?([\w./-]+\.py)([^\n`]*)", joined):
        rel, rest = m.group(1), m.group(2)
        scripts.setdefault(rel, set()).update(re.findall(r"--[\w-]+", rest))
    for rel, flags in sorted(scripts.items()):
        path = os.path.join(ROOT_DIR, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            bad.append("`python %s` is documented but that file does not exist" % rel)
            continue
        if not flags:
            continue
        key = "py:" + rel
        if key not in helps:
            p = subprocess.run([sys.executable, path, "--help"],
                               capture_output=True, text=True, timeout=120,
                               cwd=ROOT_DIR)
            helps[key] = (p.stdout or "") + (p.stderr or "")
        for flag in sorted(flags):
            if flag not in helps[key]:
                bad.append("python %s %s is documented but the script has no such flag"
                           % (rel, flag))

    check("every command and flag in the design record exists", not bad, "; ".join(bad))

    # --- and every exit code a run can produce is in the contract -------------------------
    #
    # The table calls itself "a contract, not an accident" and left out 4, which is the one a
    # stranger is most likely to meet: pointing at anything that is not localhost without
    # proving they control it. A CI that sees an undocumented number has to guess, and the
    # guess it will make is the one the table teaches — that non-zero means the bot broke.
    codes = set()
    for name in ("run_redteam.py", "authorization.py", "honeytoken.py", "onboard.py"):
        src = open(os.path.join(HERE, name), encoding="utf-8").read()
        codes |= {int(n) for n in re.findall(r"sys\.exit\((\d)\)", src)}
        codes |= {int(n) for n in re.findall(r"SystemExit\((\d)\)", src)}
    documented = {int(n) for n in re.findall(r"^\| `(\d)` \|", text, re.M)}
    missing_codes = sorted(codes - documented)
    check("every exit code a run can produce is in the documented contract",
          not missing_codes,
          "%s produced by the code, absent from the table" % missing_codes)
    phantom_codes = sorted(documented - codes - {0})
    check("...and the table documents no code the code cannot produce",
          not phantom_codes, str(phantom_codes))

    # A `raise SystemExit("message")` exits ONE, which this table reserves for "the target was
    # exploited". Ten of them exist and all are refusals, so the dispatcher converts them —
    # but the conversion is the kind of thing that gets refactored away by someone who does not
    # know why it is there, and the symptom would be a CI treating a typo as a breach.
    cli_src = open(os.path.join(HERE, "cli.py"), encoding="utf-8").read()
    check("a refusal carrying a message is not reported with the code for a breach",
          "isinstance(e.code, int)" in cli_src and "return 2" in cli_src)
    p = subprocess.run([sys.executable, os.path.join(HERE, "cli.py"), "run",
                        "--target-config", os.path.join(HERE, "no_such_config_at_all.yaml")],
                       capture_output=True, text=True, timeout=120)
    check("...and an unreadable config really does exit 2, not 1",
          p.returncode == 2, "exited %d" % p.returncode)

    # --- the third-party share is counted, not written down --------------------------------
    #
    # `provenance` exists so a fleet count does not read as a claim about software in the world
    # when most of it is about bots written here. It was declared in three places and counted in
    # none: a docstring said nine, docs/onboarding.md said six, the dashboard computed eight.
    #
    # The count went wrong in one specific way, so that way is checked directly: two CLONED
    # third-party applications declared `provenance: practice` with the note "written here to
    # exercise the engine". NOTICE and .gitignore both said otherwise. The field built to stop
    # the fleet counting its own homework was doing it.
    import importlib
    _bi = importlib.import_module("build_index")
    _prov = _bi.provenance()

    lying = sorted(n for n, (kind, note) in _prov.items()
                   if not kind.startswith("third-party")
                   and ("cloned" in note.lower() or "third-party" in note.lower()))
    check("no config calls itself practice while its note says otherwise", not lying, str(lying))

    measured = set()
    for _fp in glob.glob(os.path.join(HERE, "..", "out", "results_*.json")):
        try:
            measured.add(json.load(open(_fp, encoding="utf-8"))["meta"]["target"])
        except (ValueError, KeyError, OSError):
            pass
    third = sorted(t for t in measured
                   if _prov.get(t, ("", ""))[0].startswith("third-party"))
    n_third = len(third)

    prose = text
    m = re.search(r"\*\*(\d+) of the (\d+)\*\*", prose)
    stated = re.search(r"(?i)\b(six|seven|eight|nine|ten|eleven|twelve|\d+)\s+are third-party", prose)
    WORDS = {"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
    if stated:
        w = stated.group(1).lower()
        said = WORDS.get(w, int(w) if w.isdigit() else -1)
        check("the documented third-party TARGET count matches the configs",
              said == n_third, f"docs say {said}, configs and results give {n_third}")

    # --- one project URL, in every place that states one ----------------------------------
    #
    # The package metadata, the SARIF `informationUri` a code-scanning tab links to, and four
    # places on the site all name a repository. They were written at different times against a
    # guessed account name, and the only thing that had ever kept them equal was that one
    # person changed them together. A dead link in package metadata is discovered by whoever
    # tries to report a bug, which is the worst possible moment.
    own = set()
    for rel in ("pyproject.toml", os.path.join("site", "index.html"),
                os.path.join("redteam", "sarif.py"), "README.md", "CHANGELOG.md"):
        fp = os.path.join(ROOT, rel)
        if not os.path.isfile(fp):
            continue
        for m in re.finditer(r"github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)",
                             open(fp, encoding="utf-8").read()):
            owner, repo = m.group(1), m.group(2)
            if owner.lower() in ("nvidia-nemo", "github"):     # third-party references
                continue
            own.add("%s/%s" % (owner, repo))
    check("every place that names this project's repository names the same one",
          len(own) <= 1, "found %s" % sorted(own))

    early = []
    for fp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        src = open(fp, encoding="utf-8").read()
        lines = src.splitlines()
        snap = [i for i, l in enumerate(lines) if l.strip() == "total = checks"]
        shown = [i for i, l in enumerate(lines) if "passed\")" in l and "print(" in l]
        if not snap or not shown:
            continue
        for i in snap:
            after = [j for j in range(i + 1, shown[-1])
                     if lines[j].lstrip().startswith("check(")]
            if after:
                early.append(f"{os.path.basename(fp)}: total taken at line {i + 1}, "
                             f"{len(after)} check(s) run after it")

    # THE SAME DEFECT WITHOUT THE SNAPSHOT, which this gate could not see. It looked only for
    # `total = checks` — a count assigned to a variable early — and missed the blunter version:
    # checks that run AFTER the summary has already been printed. Nine of them were appended to
    # test_history.py, it printed "36/36 passed" and then ran nine more, and this check passed.
    # A guard only covers where it looks, and it was looking for one spelling of the mistake.
    # AND THIRD, PARSED RATHER THAN GREPPED, because the pattern above knew exactly one
    # spelling. It looked for the literal `passed")`, so a suite ending
    # `print("%d/%d passed" % (...))` matched nothing and was skipped WHOLE -- six of the
    # forty-six here, silently uncovered by a gate reporting green. In the other direction it
    # read any line containing those characters, so a suite whose FIXTURE prints "1/1 passed"
    # was judged against a string constant and every real check after it called trailing.
    # Both arrived on the same day, from the same suite. A summary is a call to print, and a
    # check is a call to check; asking the parser costs the same and cannot be spelled around.
    def _literals(node):
        """Every string that a print() argument is built from, whatever the formatting."""
        out = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                out.append(sub.value)
        return out

    for fp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        try:
            tree = ast.parse(open(fp, encoding="utf-8").read())
        except SyntaxError:            # a broken suite is another gate's finding, not this one
            continue
        summaries, ran = [], []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called = getattr(node.func, "id", None)
            if called == "print":
                if any("passed" in lit for arg in node.args for lit in _literals(arg)):
                    summaries.append(node.lineno)
            elif called == "check":
                ran.append(node.lineno)
        if not summaries:
            # A suite with no summary line at all is a separate finding, made elsewhere.
            continue
        last = max(summaries)
        trailing = [ln for ln in ran if ln > last]
        if trailing:
            early.append(f"{os.path.basename(fp)}: {len(trailing)} check(s) run after the "
                         f"summary was printed at line {last}")
    check("no suite counts itself before its last check has run",
          not early, "; ".join(early))

    # --- EVERY SHIPPED PAGE DECLARES ITS ENCODING --------------------------------------------
    #
    # `site/index.html` went live without `<meta charset>`. Cloudflare serves `text/html` with
    # no charset parameter, so the browser fell back to windows-1252 and every em dash, middle
    # dot and curly quote on the landing page rendered as mojibake. Measured on the deployed
    # page: `document.characterSet` was `windows-1252`.
    #
    # All 46 generated reports had it, because `report_engine.py` prints it into every one. The
    # hand-written page did not, and nothing opened it in a browser — the same shape as the
    # rest of this project's findings, where what a machine produces is consistent and what a
    # person typed once is the gap.
    #
    # Within the first 1024 bytes, which is the window a browser scans before it commits to a
    # guess. A declaration further down is a declaration that arrives too late.
    import subprocess as _sp2
    _pages = [p for p in _sp2.run(["git", "-C", ROOT, "ls-files", "*.html"],
                                  capture_output=True, text=True).stdout.split() if p]
    check("there are shipped HTML pages to check", bool(_pages), "git ls-files found none")
    _late, _missing = [], []
    for _rel in _pages:
        _head = io.open(os.path.join(ROOT, _rel), encoding="utf-8",
                        errors="replace").read(4096)
        _at = _head.lower().find("charset")
        if _at < 0:
            _missing.append(_rel)
        elif len(_head[:_at].encode("utf-8")) > 1024:
            _late.append(_rel)
    check("every shipped HTML page declares a charset",
          not _missing, f"no <meta charset> in: {_missing[:5]}")
    check("...and declares it inside the first 1024 bytes, where a browser still looks",
          not _late, f"declared too late in: {_late[:5]}")

    # --- THE ICON STILL MATCHES ITS GENERATOR ------------------------------------------------
    #
    # `tools/favicon.py` exists so the mark is coordinates rather than three binary blobs
    # nobody can diff. That only holds while the checked-in files agree with it, and the two
    # ways they stop agreeing are both silent.
    #
    # ONE: the writer lies. Pillow's ICO save took `sizes=[16,32,48,64]` and `append_images`,
    # raised nothing, and wrote the 16px frame by itself. The script reported a byte count.
    # Every size a browser actually asks for would have been upscaled from sixteen pixels.
    #
    # TWO: the palette moves. Change `--accent` and re-run nothing, and the tab icon keeps the
    # old brand colour indefinitely, because nobody looks at their own favicon.
    #
    # Read with `struct`, not Pillow: this suite must not go red on a runner that lacks a
    # library the site does not need at runtime.
    import struct as _struct
    _site = io.open(os.path.join(ROOT, "site", "index.html"), encoding="utf-8").read()
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import i18n as _i18n
    _langs = _i18n.languages()
    _page_url = lambda c: (_i18n.SITE_URL if c == _i18n.DEFAULT
                           else "%s%s/" % (_i18n.SITE_URL, c))
    _ico = os.path.join(ROOT, "site", "favicon.ico")
    check("the favicon.ico referenced by the page exists", os.path.exists(_ico), _ico)
    if os.path.exists(_ico):
        _raw = open(_ico, "rb").read()
        _res, _kind, _n = _struct.unpack("<HHH", _raw[:6])
        check("favicon.ico is a well-formed icon directory", _res == 0 and _kind == 1 and _n > 0,
              f"reserved={_res} type={_kind} count={_n}")
        _sizes = sorted((_raw[6 + i * 16] or 256) for i in range(_n))
        check("...and carries every size the generator writes, not just the first",
              _sizes == [16, 32, 48, 64],
              f"the ico holds {_sizes} — re-run: python tools/favicon.py")

    # THE LETTERS carry the brand colour, not the tile: the mark is the dark theme's --accent on
    # a ground dark enough to hold it. So the tie to the stylesheet is on INK. The tile is only
    # required to be readable from the source, because it is what the counters are punched with
    # and a change to it that nothing re-rendered would leave the holes the wrong colour.
    _fav_src = io.open(os.path.join(ROOT, "tools", "favicon.py"), encoding="utf-8").read()
    _tile = re.search(r'^TILE\s*=\s*"(#[0-9a-fA-F]{6})"', _fav_src, re.M)
    _ink = re.search(r'^INK\s*=\s*"(#[0-9a-fA-F]{6})"', _fav_src, re.M)
    check("the generator names its two colours where they can be read", bool(_tile and _ink),
          "TILE and INK must stay module-level literals")
    _accents = re.findall(r"--accent:\s*(#[0-9a-fA-F]{6})", _site)
    check("the stylesheet still defines an accent", bool(_accents), "no --accent found")
    if _ink and _accents:
        check("the icon's blue is one the stylesheet actually uses",
              _ink.group(1).lower() in {a.lower() for a in _accents},
              f"icon ink {_ink.group(1)} is not among {sorted(set(_accents))} — "
              f"re-run: python tools/favicon.py")
    if _tile and _ink:
        # A mark the tile cannot carry is a mark nobody sees. WCAG's own formula, because
        # "looks fine on my monitor" is the reasoning that picks a pairing nobody measured.
        def _lum(h):
            def c(v):
                v /= 255.0
                return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
            r, g, b = (int(h[i:i + 2], 16) for i in (1, 3, 5))
            return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b)
        _a, _b = sorted((_lum(_tile.group(1)), _lum(_ink.group(1))))
        _ratio = (_b + 0.05) / (_a + 0.05)
        check("the letters are readable on the tile they sit on",
              _ratio >= 4.5, f"contrast is {_ratio:.1f}:1, below 4.5:1")

    # ONE SOURCE, TWO OUTPUTS -- checked, not asserted. The first icon drew the vector and the
    # raster through separate code and they disagreed: SVG centres a stroke on its path, Pillow
    # draws an ellipse outline inward from the bounding box, so the .svg and the .ico shipped
    # different-sized letters. Nothing caught it because nothing compared them; it surfaced as
    # somebody asking why one letter looked bigger than the other.
    #
    # So the shipped .svg is parsed back and its numbers matched against the generator's data,
    # in order. Every coordinate or the check is worthless -- a subset would pass a file that
    # had lost a contour.
    import xml.etree.ElementTree as _ET
    import importlib.util as _ilu
    # Imported rather than re-parsed, and safe to import: the module defines constants at top
    # level and pulls Pillow only inside the functions that raster, so this costs no dependency.
    _spec = _ilu.spec_from_file_location("qat_favicon",
                                         os.path.join(ROOT, "tools", "favicon.py"))
    _favmod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_favmod)
    _glyphs = _favmod.GLYPHS
    check("the generator still carries the glyph outlines as data",
          bool(_glyphs) and all(c for c in _glyphs), "GLYPHS is empty")

    _svg_path = os.path.join(ROOT, "site", "favicon.svg")
    if os.path.exists(_svg_path):
        _svg = io.open(_svg_path, encoding="utf-8").read()
        try:
            _root = _ET.fromstring(_svg)
        except _ET.ParseError as e:
            _root = None
            check("the shipped favicon.svg is well-formed", False, str(e))
        if _root is not None:
            check("the shipped favicon.svg is well-formed", True)
            _ns = "{http://www.w3.org/2000/svg}"
            _p = _root.find(_ns + "path")
            _r = _root.find(_ns + "rect")
            check("...and it has the tile and the letters", _p is not None and _r is not None,
                  "expected one <rect> and one <path>")
            if _p is not None and _r is not None:
                check("the svg paints the same two colours the generator names",
                      _r.get("fill") == (_tile.group(1) if _tile else None)
                      and _p.get("fill") == (_ink.group(1) if _ink else None),
                      f"svg has tile={_r.get('fill')} ink={_p.get('fill')}")
                # evenodd is what makes the counters holes; nonzero would fill the Q solid.
                check("...with the fill rule that punches the counters",
                      _p.get("fill-rule") == "evenodd", f"fill-rule={_p.get('fill-rule')}")
                _want = [round(v, 2) for c in _glyphs for seg in c
                         for pt in seg[1:] for v in pt]
                _got = [float(x) for x in re.findall(r"-?\d+\.\d+", _p.get("d") or "")]
                check("the vector and the raster are drawn from the same coordinates",
                      _got == _want,
                      f"svg carries {len(_got)} numbers, the glyph data {len(_want)}"
                      if len(_got) != len(_want) else "same count, different values")
                check("...and every contour is closed",
                      (_p.get("d") or "").count("Z") == len(_glyphs),
                      f"{(_p.get('d') or '').count('Z')} subpaths for {len(_glyphs)} contours")

    # And the page has to point at what was generated, or none of the above is reachable.
    for _rel, _attr in (("favicon.svg", 'href="/favicon.svg"'),
                        ("favicon.ico", 'href="/favicon.ico"'),
                        ("apple-touch-icon.png", 'href="/apple-touch-icon.png"')):
        check(f"the page links {_rel}", _attr in _site, f"{_attr} is not in index.html")
        check(f"...and {_rel} is actually shipped",
              os.path.exists(os.path.join(ROOT, "site", _rel)), "referenced but missing")

    # --- WHAT A LINK TO THIS PAGE PROMISES ---------------------------------------------------
    #
    # The preview card is a PNG. Nothing about it changes when the page is edited, so a headline
    # rewritten here leaves an image promising the old one to every reader on every platform
    # that ever cached it. The words are read out of the generator and required to still be on
    # the page -- which is the same rule this whole suite exists for, applied to a picture.
    _og = os.path.join(ROOT, "tools", "og_card.py")
    check("the preview card is generated, not a loose binary", os.path.exists(_og),
          "tools/og_card.py is missing but site/og-card.png would still be shipped")
    if os.path.exists(_og):
        _og_src = io.open(_og, encoding="utf-8").read()
        _page_text = re.sub(r"<[^>]+>", " ", _site)
        _page_text = (_page_text.replace("&amp;", "&").replace("&mdash;", "—")
                      .replace("&rsquo;", "\u2019").replace("&nbsp;", " "))
        _page_text = re.sub(r"\s+", " ", _page_text)
        _claims = []
        for _name in ("HEADLINE", "SUB"):
            _m = re.search(_name + r'\s*=\s*\(?\s*"([^"]+)"(?:\s*"([^"]+)")?', _og_src)
            if _m:
                _claims.append((_name, "".join(p for p in _m.groups() if p)))
        check("the card's sentences can be read out of the generator",
              len(_claims) == 2, f"found {[c[0] for c in _claims]}")
        for _name, _text in _claims:
            check(f"the card's {_name} is a sentence the page actually says",
                  re.sub(r"\s+", " ", _text) in _page_text,
                  f"the card claims {_text!r}, which is not on the page any more")

    # THE TAGS, and that the file each absolute URL names is really shipped. `og:image` can 404
    # while the page renders perfectly; the failure only shows up in somebody else's chat window.
    for _prop in ("og:title", "og:description", "og:image", "og:url", "og:type",
                  "twitter:card", "twitter:image"):
        check(f"the page declares {_prop}", f'"{_prop}"' in _site, "missing")
    check("the page has a meta description",
          'name="description"' in _site, "search results would show scraped text")

    _abs = set(re.findall(r'content="https://qatration\.com/([A-Za-z0-9._/-]+)"', _site))
    _gone = sorted(f for f in _abs if not os.path.exists(os.path.join(ROOT, "site", f)))
    check("every absolute site url in a meta tag points at a shipped file",
          not _gone, f"declared but not in site/: {_gone}")

    # robots.txt and the sitemap must not contradict each other.
    _rob_p = os.path.join(ROOT, "site", "robots.txt")
    _map_p = os.path.join(ROOT, "site", "sitemap.xml")
    check("robots.txt is shipped", os.path.exists(_rob_p), "crawlers get no guidance")
    check("a sitemap is shipped", os.path.exists(_map_p), "missing")
    if os.path.exists(_rob_p) and os.path.exists(_map_p):
        _rob = io.open(_rob_p, encoding="utf-8").read()
        _map = io.open(_map_p, encoding="utf-8").read()
        _sitemap_line = re.search(r"(?im)^\s*Sitemap:\s*(\S+)", _rob)
        check("robots.txt points at the sitemap", bool(_sitemap_line), "no Sitemap: line")
        _disallowed = [d.strip() for d in re.findall(r"(?im)^\s*Disallow:\s*(\S+)", _rob)]
        # PARSED, NOT MATCHED. This was a regex over the text, and a regex is happy to find
        # `<loc>` in a document no parser will accept -- which is what happened: the file
        # shipped for a day with a double hyphen inside an XML comment, illegal in XML, and
        # this check reported it fine. Google would have rejected the sitemap outright.
        import xml.etree.ElementTree as _EX
        try:
            _root = _EX.fromstring(_map)
            _locs = [e.text.strip() for e in _root.iter() if e.tag.endswith("loc") and e.text]
            check("the sitemap is well-formed XML", True)
        except _EX.ParseError as _e:
            _locs = []
            check("the sitemap is well-formed XML", False,
                  f"{_e} — a crawler will refuse the whole file")
        _want_locs = {_page_url(c) for c in _langs}
        check("the sitemap lists every language and nothing else",
              set(_locs) == _want_locs,
              f"sitemap has {sorted(_locs)}, the site has {sorted(_want_locs)}")
        _contra = [l for l in _locs for d in _disallowed
                   if d != "/" and l.startswith("https://qatration.com" + d)]
        check("...and lists nothing robots.txt tells crawlers to skip",
              not _contra, f"the sitemap offers {_contra}, robots.txt disallows {_disallowed}")

    # --- ONE PROJECT, ONE SENTENCE -----------------------------------------------------------
    #
    # See the note at the top of this block's history: four surfaces, four different
    # introductions, none of them wrong and no two the same. The packaging description is the
    # source here because it is the one a release publishes and the one that cannot be edited
    # in a dashboard afterwards.
    def _norm(t):
        t = t.replace("&amp;", "and").replace("&", "and").replace("\u2019", "'")
        return re.sub(r"\s+", " ", t).strip().lower()

    _pyproj = io.open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    _m = re.search(r'(?m)^description\s*=\s*"([^"]+)"', _pyproj)
    check("the packaging description is readable", bool(_m),
          "no description in [project] of pyproject.toml")
    if _m:
        # First clause only. The rest of the line qualifies the claim and is allowed to differ
        # between a package index and a landing page; what must not differ is what the thing is.
        _clause = _norm(re.split(r"[.:;]", _m.group(1))[0])
        check("...and its first clause is a real sentence, not a fragment",
              len(_clause.split()) >= 4, f"{_clause!r} is too short to be a description")

        _init = io.open(os.path.join(ROOT, "redteam", "__init__.py"), encoding="utf-8").read()
        # VISIBLE TEXT, NOT THE MARKUP. Searching the raw HTML made this pass for the wrong
        # reason: the phrase also sits in the `og:title` attribute, so rewriting the headline a
        # reader actually sees left the check green. Caught by mutating the tagline and getting
        # nothing. Tags are stripped first, which takes every attribute with them.
        _visible = _norm(re.sub(r"<[^>]+>", " ", _site))
        for _label, _hay in (("the package docstring", _norm(_init[:400])),
                             ("the landing page", _visible)):
            check(f"{_label} introduces the project the same way",
                  _clause in _hay,
                  f"pyproject says {_clause!r}; this surface does not. Also check the GitHub "
                  f"About field by hand -- it is dashboard state and no test can see it.")

    # --- THE PANEL SITS ON THE WARNING BLOCK'S ROW -------------------------------------------
    #
    # `.term{grid-row:4}` reads as "beside the red warning block", and it is, for as long as the
    # warning block is the fourth child of the hero's left column. That is a position and not a
    # name: add a badge above the headline and the panel moves to whatever lands in row 4, on a
    # published page that nobody rebuilds locally to notice.
    #
    # The row is read from the CSS and the position is counted from the markup, so a change to
    # either one alone fails here. A constant `4` written in this test would just be a third
    # place to keep in step.
    from html.parser import HTMLParser as _HP

    class _Kids(_HP):
        """Direct element children of the hero's first div, in order, by class."""

        def __init__(self):
            _HP.__init__(self)
            # 0 before the hero, 1 inside it looking for the column, 2 inside the column,
            # 3 done. The first version had no state 3: it stopped decrementing at the column's
            # closing tag and went on collecting the panel, the sections after it and the
            # footer -- fifteen "children" of a div with eight. The check it feeds only ever
            # reads the fourth, so it passed; a helper whose name does not describe what it
            # returns is the next person's wrong answer.
            self.state = 0
            self.d = 0
            self.kids = []

        VOID = ("br", "img", "input", "hr", "meta", "link", "source", "wbr")

        def handle_starttag(self, tag, attrs):
            cls = dict(attrs).get("class", "")
            if self.state == 0:
                if "hero" in cls.split():
                    self.state = 1
                return
            if self.state == 1:
                if tag == "div":
                    self.state = 2
                return
            if self.state == 2:
                if self.d == 0:
                    self.kids.append(cls.split()[0] if cls else tag)
                if tag not in self.VOID:
                    self.d += 1

        def handle_startendtag(self, tag, attrs):
            if self.state == 2 and self.d == 0:
                cls = dict(attrs).get("class", "")
                self.kids.append(cls.split()[0] if cls else tag)

        def handle_endtag(self, tag):
            if self.state != 2:
                return
            if self.d == 0:
                self.state = 3          # the column itself closed
            else:
                self.d -= 1

    _k = _Kids()
    _k.feed(_site)
    check("the hero's left column can be read", len(_k.kids) >= 4,
          f"parsed {_k.kids} — the markup moved and this check is blind")

    _m = re.search(r"\.term\{[^}]*grid-row:\s*(\d+)", _site)
    check("the panel declares which row it sits on", bool(_m),
          ".term has no grid-row; the alignment is not expressed in the CSS any more")

    if _m and len(_k.kids) >= 4:
        _row = int(_m.group(1))
        _at = _k.kids[_row - 1] if 0 < _row <= len(_k.kids) else "(out of range)"
        check("...and that row is the warning block, counted in the markup",
              _at == "warnbox",
              f"grid-row:{_row} is child #{_row}, which is {_at!r}, not the warnbox. "
              f"Order is {_k.kids}. The panel would line up with the wrong thing.")

    # And the single-column layout must undo the placement, or below 820px the panel is put in
    # a column that does not exist.
    # THE BLOCK, BY ITS BRACES, not by a byte count. This read the first 700 characters after
    # the `@media` line, so the day a rule was added above `.hero` with a comment explaining
    # why, the rules this checks fell out of the window and the gate reported the CSS broken
    # while the CSS was fine. A check whose coverage is a magic number fails when the file
    # grows, which is the one thing a file reliably does.
    def _block(css, opener):
        i = css.find(opener)
        if i < 0:
            return ""
        j = css.find("{", i)
        depth, k = 1, j + 1
        while k < len(css) and depth:
            if css[k] == "{":
                depth += 1
            elif css[k] == "}":
                depth -= 1
            k += 1
        return css[j + 1:k - 1]

    _mobile = _block(_site, "@media (max-width:820px)")
    # AND THE TOP BAR WRAPS, or the theme toggle leaves the screen. Measured in a browser at
    # 375px before this was written: the row is 737px wide, the `Light` button sat at x=419,
    # and the page scrolled 110px sideways to reach it. A phone user had to swipe right to
    # find the only control on the page.
    #
    # A TEXT CHECK STANDING IN FOR A BROWSER, and said so rather than dressed up: nothing in
    # this suite renders anything, so this asserts the rule is present and the measurement
    # that justified it lives in the CSS comment beside it. It catches the deletion, which is
    # the failure that actually happened, and not a subtler regression.
    # AND EXACTLY ONE THING IN THAT ROW PUSHES. Two auto margins on one flex line SPLIT the
    # free space instead of pooling it, and the first version of the wrap rule added a second
    # one to `.theme` while `.ghlink` already carried one unconditionally. Measured on the
    # deployed page: 219px of gap either side of the controls at 820px and 193 at 768, the
    # header torn in half at every width between 375 and 820, to fix an alignment that only
    # misbehaves below 400. It shipped green, because nothing in this file renders anything.
    #
    # This cannot see a layout, so it checks the arrangement that produces one: if the narrow
    # block introduces an auto margin, it has to say what happens to the one already there.
    _autos = re.findall(r"margin-(?:left|right):\s*auto", _mobile)
    check("only one control in the narrow top bar carries an auto margin",
          not _autos or "margin-left:0" in _mobile,
          "the narrow block adds %d auto margin(s) and never zeroes `.ghlink`'s, so the free "
          "space is split between them rather than pooled" % len(_autos))

    check("the narrow layout lets the top bar wrap, so the theme toggle stays on screen",
          "flex-wrap:wrap" in _mobile and ".top" in _mobile,
          "no wrapping rule for .top below 820px; the toggle goes off the right edge")

    check("the narrow layout puts the panel back in the one column it has",
          "grid-column:1" in _mobile and "grid-row:auto" in _mobile,
          "below 820px `.term` keeps grid-column:2 and lands outside the grid")
    check("...and restores the row gap the wide rule zeroes",
          "row-gap:34px" in _mobile,
          "row-gap:0 leaks into the narrow layout and the panel touches the column above it")

    # --- WHAT THE TOOL CHANNEL IS WORTH, RECOUNTED -------------------------------------------
    #
    # The page says a number about agents: how many findings vanish when the engine can only
    # read the reply. It is the sharpest claim this project makes about agent targets, so it is
    # derived here from the artifacts rather than trusted.
    #
    # Judge every stored trial twice with the CURRENT oracle: once as recorded, once with the
    # tool channel blanked. Blanking is exactly what a config with no `response.tool_calls`
    # produces, so the difference is what mapping it buys. Same method the NEEDS_CONFIG entries
    # were measured with -- replay, remove one thing, count.
    from oracle import judge as _judge
    from target import Probe as _Probe

    _ctxs = {}
    for _fp in target_configs(HERE):
        _c = yaml.safe_load(open(_fp, encoding="utf-8")) or {}
        if _c.get("name"):
            _ctxs[_c["name"]] = _c.get("oracle_context") or {}

    _BREACH = ("EXPLOITED", "PARTIAL")
    _with = _blind = 0
    for _path in sorted(glob.glob(os.path.join(ROOT, "out", "results_*.json"))):
        try:
            _data = json.load(open(_path, encoding="utf-8"))
        except Exception:
            continue
        _name = os.path.basename(_path)[len("results_"):-len(".json")]
        _ctx = _ctxs.get(_name) or next((v for k, v in _ctxs.items()
                                         if _name.startswith(k)), None)
        if _ctx is None:
            continue
        _has_calls = False
        _rows = []
        for _r in _data.get("results", []):
            if (_r.get("attack") or {}).get("category") == "control":
                continue
            _a = _b = False
            for _t in _r.get("trials", []):
                _p = _t.get("probe")
                if not _p:
                    continue
                _calls = [tuple(c) for c in (_p.get("tool_calls") or [])]
                _res = [tuple(c) for c in (_p.get("resolved") or [])]
                if _calls or _res:
                    _has_calls = True
                _kw = dict(prompt=_p.get("prompt") or "", output=_p.get("output") or "",
                           observations=_p.get("observations") or [],
                           seconds=float(_p.get("seconds") or 0))
                if _judge(_r["attack"], _Probe(tool_calls=_calls, resolved=_res, **_kw),
                          _ctx)[0] in _BREACH:
                    _a = True
                if _judge(_r["attack"], _Probe(tool_calls=[], resolved=[], **_kw),
                          _ctx)[0] in _BREACH:
                    _b = True
            _rows.append((_a, _b))
        if _has_calls:
            _with += sum(1 for a, _ in _rows if a)
            _blind += sum(1 for _, b in _rows if b)

    _only = _with - _blind
    check("there is agent evidence to count", _with > 0,
          "no stored run reports tool calls, so this claim has nothing behind it")
    if _with:
        # The page may say the number is smaller than it is; it may never say it is larger.
        # Same asymmetry the probe-count claim uses: understating the evidence is harmless,
        # overstating it is the thing this file exists to stop.
        _m = re.search(r"(\d+)\s+of\s+(\d+)\s+findings[^.]*only the reply", _site)
        check("the page states the tool-channel number", bool(_m),
              f"recounted {_only} of {_with}; the page says nothing, so the check is blind")
        if _m:
            _claim_only, _claim_all = int(_m.group(1)), int(_m.group(2))
            check("...and it matches the artifacts",
                  (_claim_only, _claim_all) == (_only, _with),
                  f"the page says {_claim_only} of {_claim_all}; the evidence says "
                  f"{_only} of {_with}")

    # --- WHETHER A BIGGER MODEL IS THE FIX, RECOUNTED ----------------------------------------
    #
    # MODEL CHOICE IS THE FIRST THING ANYBODY REACHES FOR, and the page says it does not close
    # the hole. That is the claim on this page most likely to be read as an opinion, so it is
    # derived from the artifacts here rather than trusted -- same as the tool-channel number
    # above and the benign rate below.
    #
    # Derived rather than listed: a target with two per-model results files IS a pair, so a
    # third model or a second target changes what this measures with nobody editing the check.
    # Counted over attacks present in BOTH files, because one the other run never sent says
    # nothing about the difference between them, and over rows that measured something, because
    # a SKIP on one side is not a model holding.
    _pairs = {}
    for _p in sorted(glob.glob(os.path.join(ROOT, "out", "results_*.json"))):
        _b = os.path.basename(_p)[len("results_"):-len(".json")]
        if _b.count("_") != 1:
            continue
        _t, _mdl = _b.rsplit("_", 1)
        _pairs.setdefault(_t, {})[_mdl] = _p

    _best = None                     # the pair with the most attacks behind it
    for _t, _ms in sorted(_pairs.items()):
        if len(_ms) != 2:
            continue
        _names = sorted(_ms)
        _rows = {}
        for _mdl in _names:
            try:
                _d = json.load(open(_ms[_mdl], encoding="utf-8"))
            except Exception:
                _rows = None
                break
            _rows[_mdl] = {r["attack"]["id"]: r for r in _d.get("results", [])
                           if (r.get("attack") or {}).get("category") != "control"
                           and r.get("headline") not in ("SKIP", "ERROR")}
        if not _rows:
            continue
        _a, _b2 = _names
        _ids = set(_rows[_a]) & set(_rows[_b2])
        _ka = {i for i in _ids if _rows[_a][i]["headline"] in _BREACH}
        _kb = {i for i in _ids if _rows[_b2][i]["headline"] in _BREACH}
        _shared = _ka & _kb
        _always = {i for i in _shared
                   if _rows[_a][i].get("rate") == _rows[_b2][i].get("rate")
                   and (_rows[_a][i].get("rate") or "0/0").split("/")[0]
                   == (_rows[_a][i].get("rate") or "0/1").split("/")[1]}
        if _best is None or len(_ids) > _best[0]:
            _best = (len(_ids), len(_ka), len(_kb), len(_shared), len(_always), _t, _names)

    check("there is a two-model pair to compare", _best is not None,
          "no target in out/ has results for two models, so this claim has nothing behind it")
    if _best:
        _n, _ka_n, _kb_n, _sh, _al, _tname, _mnames = _best
        # Ordered so the page can name them either way round without the check caring which
        # model is which -- what it must not do is print a pair of numbers the runs do not
        # support.
        # `[\s\S]*?` and not `[^.]*?`: the sentence has a full stop in the middle of it, so
        # the first version of this pattern matched nothing and reported the page as silent.
        _mm = re.search(r"(\d+)\s+attacks each[\s\S]*?broke on\s+(\d+),"
                        r"[\s\S]*?the larger on\s+(\d+)"
                        r"[\s\S]*?(\d+)\s+of those are the same attacks,\s*(\d+)\s+of them",
                        _site, re.S)
        check("the page states the model-comparison numbers", bool(_mm),
              f"recounted {_n} attacks, {_ka_n} vs {_kb_n} breaches, {_sh} shared, {_al} on "
              f"every try; the page says nothing, so the check is blind")
        if _mm:
            _c = tuple(int(g) for g in _mm.groups())
            check("...and they match the artifacts",
                  _c == (_n, _ka_n, _kb_n, _sh, _al)
                  or _c == (_n, _kb_n, _ka_n, _sh, _al),
                  f"the page says {_c}; the evidence for {_tname} "
                  f"({', '.join(_mnames)}) says {(_n, _ka_n, _kb_n, _sh, _al)}")
            check("...and the shared count is not larger than either side",
                  _sh <= min(_ka_n, _kb_n),
                  f"{_sh} shared cannot exceed {_ka_n} and {_kb_n}")

    # --- HOW MANY ASSERTIONS THE SUITE CARRIES, RECOUNTED -------------------------------
    #
    # The README says one QA engineer wrote this with Claude, and in the next breath that no
    # number here needs taking on trust because a test recounts it. That paragraph states a
    # number itself, so without this it would be the one claim on the page that is false about
    # itself.
    #
    # It moved inside a single evening -- written as 1,358, typed into the README as 1,372,
    # because the same evening added assertions. A number that drifts that fast is a number
    # that has to be derived rather than remembered.
    #
    # Counted the way `test_names.py` counts it: `check()` calls and bare asserts across every
    # suite in this directory. Understating is allowed and overstating is not, like the other
    # claims here.
    _readme_txt = io.open(README, encoding="utf-8").read()
    _n_assert = 0
    for _sp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        try:
            _tree = ast.parse(io.open(_sp, encoding="utf-8").read())
        except SyntaxError:
            continue
        for _n in ast.walk(_tree):
            if isinstance(_n, ast.Assert):
                _n_assert += 1
            elif (isinstance(_n, ast.Call) and isinstance(_n.func, ast.Name)
                  and _n.func.id == "check" and len(_n.args) >= 2):
                _n_assert += 1

    _am = re.search(r"([\d,]+)\s+of them, `check\(\)` calls and bare\s+asserts", _readme_txt, re.S)
    check("the README states how many assertions the suite carries", bool(_am),
          f"recounted {_n_assert}; the README says nothing, so the check is blind")
    if _am:
        _claim = int(_am.group(1).replace(",", ""))
        check("...and it is not more than the suite actually has",
              _claim <= _n_assert,
              f"the README says {_claim}; the suites carry {_n_assert}")
        check("...and it has not fallen far behind either",
              _n_assert - _claim <= 25,
              f"the README says {_claim}; the suites carry {_n_assert}")

    # --- WHAT A DETECTOR DOES WHEN NOBODY IS ATTACKING ---------------------------------------
    #
    # The page names a rate: how often the noisiest detector on any target here fires on
    # ordinary traffic. It is the number behind the whole attribution argument -- a breach is
    # only a breach if the attack caused it -- so it is recounted from `out/` rather than
    # trusted, like every other number on that page.
    import baseline as _baseline
    _worst = 0.0
    for _f in sorted(glob.glob(os.path.join(ROOT, "out", "benign_*.json"))):
        _t = os.path.basename(_f)[len("benign_"):-len(".json")]
        for _rate in (_baseline.rates(_t, out_dir=os.path.join(ROOT, "out")) or {}).values():
            if _rate and _rate > _worst:
                _worst = _rate
    _worst_pct = int(_worst * 100)

    check("there is benign evidence to count", _worst > 0,
          "no stored benign run shows a detector firing, so this claim has nothing behind it")
    if _worst > 0:
        _m = re.search(r"fires on (\d+)% of that ordinary traffic", _site)
        check("the page states the benign-noise rate", bool(_m),
              f"recounted {_worst_pct}%; the page says nothing, so the check is blind")
        if _m:
            # UNDERSTATING IS FINE, OVERSTATING IS NOT. Same asymmetry the probe count uses:
            # the page may be behind the evidence, never ahead of it.
            _claim = int(_m.group(1))
            check("...and does not claim more noise than the artifacts show",
                  _claim <= _worst_pct,
                  f"the page says {_claim}%; the worst rate in out/ is {_worst_pct}%")
            check("...and is not stale by more than a little",
                  _worst_pct - _claim <= 10,
                  f"the page says {_claim}% and the evidence now shows {_worst_pct}%")

    # ============================================================== TRANSLATIONS
    #
    # A SECOND LANGUAGE IS A SECOND COPY OF EVERY NUMBER ON THIS PAGE, and every check above
    # this line recounts exactly one of them. Left as hand-written files, the translated pages
    # would go on publishing last month's figures in languages nobody here reads closely
    # enough to catch it, which is the failure this whole file exists to prevent.
    #
    # So they are generated from the English page, and these are the rules that make generating
    # them safe. Each one is a way the arrangement could quietly stop working.
    _keys = set(_i18n.extract(_site))

    # 1. NOTHING ON DISK IS HAND-WRITTEN. Without this the generator is a suggestion: an edit
    #    to a translated page survives until the next build, and in the meantime it is a
    #    sentence no check on this page has ever read.
    _drifted = [os.path.relpath(p, ROOT) for p, _changed in _i18n.build(write=False) if _changed]
    check("every published page is exactly what the source generates",
          not _drifted,
          "stale or hand-edited: %s (run `python tools/i18n.py`)" % ", ".join(_drifted))

    for _lang in [c for c in _langs if c != _i18n.DEFAULT]:
        _table = _i18n.load(_lang)

        # 2. NO ENGLISH LEFT IN. A missing translation renders as the English sentence, which
        #    reads as a deliberate choice rather than as a gap, and nothing else would notice.
        _missing = sorted(k for k in _keys if not _table.get(k))
        check("%s translates every string the page shows" % _lang, not _missing,
              "%d untranslated, first: %s" % (len(_missing), (_missing or [""])[0][:60]))

        # 3. NO TRANSLATION OF A SENTENCE THAT NO LONGER EXISTS. The dictionary is keyed by the
        #    English text, so editing a sentence orphans its translation. An orphan is harmless
        #    on the page and dangerous in the file: it makes a dictionary look complete.
        _orphans = sorted(k for k in _table if k not in _keys)
        check("...and %s carries no translation of a sentence that is gone" % _lang,
              not _orphans,
              "%d orphaned key(s), first: %s" % (len(_orphans), (_orphans or [""])[0][:60]))

        # 4. EVERY FIGURE SURVIVES. This is the one that matters. Thousands separators may move
        #    (`1,500` and `1 500` are the same measurement); digits may not. A number written
        #    out as a word, or quietly rounded, stops being the thing the artifacts recount.
        _moved = sorted(k for k, v in _table.items()
                        if v and _i18n.numbers(k) != _i18n.numbers(v))
        check("...and every number in %s is still the number in the artifacts" % _lang,
              not _moved,
              "%d string(s) changed a figure, first: %s"
              % (len(_moved), (_moved or [""])[0][:60]))

    # 5. NO VISIBLE TEXT BUILT IN JAVASCRIPT. The theme button used to set its own label from
    #    two string literals in the script, so a translated page said everything in its own
    #    language until the first repaint and then said "Light". The generator cannot see
    #    inside a script, so nothing user-facing may be assembled there.
    _script = "\n".join(re.findall(r"(?s)<script\b[^>]*>(.*?)</script>", _site))
    # COMMENTS ARE NOT CODE, and this check called its own explanation a defect: the line
    # recording why the labels were moved out of the script quotes the word it moved, and a
    # scan of raw text cannot tell the two apart. Reading the file rather than the thing it
    # describes is precisely the mistake being checked for, so the comments come out first.
    _script = re.sub(r"(?s)/\*.*?\*/", " ", re.sub(r"(?m)//.*$", " ", _script))
    _lits = set(re.findall(r"'([^'\n]{2,})'", _script)) | set(re.findall(r'"([^"\n]{2,})"', _script))
    _leaked = sorted(_lits & _keys)
    check("no string the page displays is written inside its script", not _leaked,
          "the script hardcodes %s, which no translation can reach" % ", ".join(_leaked[:3]))

    _assigns = re.findall(r"(?:textContent|innerText|innerHTML)\s*=\s*['\"]", _script)
    _assigns += re.findall(r"setAttribute\(\s*['\"]aria-label['\"]\s*,\s*['\"]", _script)
    check("...and none is assigned to an element as a literal", not _assigns,
          "%d assignment(s) of a literal string to visible text or a label" % len(_assigns))

    # 6. THE ALTERNATES AGREE WITH WHAT IS ACTUALLY PUBLISHED, on every page and in both
    #    directions. A page that advertises a language it does not link to, or omits one that
    #    exists, sends a search engine to a URL that is not there.
    _want_alt = set(_langs) | {"x-default"}
    for _lang in _langs:
        _path = _i18n.page_path(_lang)
        _page = io.open(_path, encoding="utf-8").read()
        _got = set(re.findall(r'<link rel="alternate" hreflang="([^"]+)"', _page))
        check("the %s page lists every language and no other" % _lang, _got == _want_alt,
              "hreflang is %s, the site has %s" % (sorted(_got), sorted(_want_alt)))
        _self = _i18n.SITE_URL if _lang == _i18n.DEFAULT else "%s%s/" % (_i18n.SITE_URL, _lang)
        check("...and the %s page names itself as its own canonical" % _lang,
              '<link rel="canonical" href="%s">' % _self in _page,
              "canonical does not point at %s, so the page declares itself a copy" % _self)
        # 7. AND A READER CAN GET FROM ONE TO THE OTHER. hreflang is for crawlers; a person
        #    who lands on the wrong one needs a link they can see.
        #    Read the hrefs off the switch links rather than matching a run of attributes:
        #    the first version of this looked for `class="lang" href="/uk/"` and went red the
        #    moment a `translate="no"` was added between the two, reporting a missing link
        #    that was right there. A check that depends on attribute order is checking the
        #    spelling of the markup, not the thing the markup does.
        _switch = {m.group(1) for m in
                   re.finditer(r'<a\b[^>]*\bclass="lang"[^>]*\bhref="([^"]+)"', _page)}
        _switch |= {m.group(1) for m in
                    re.finditer(r'<a\b[^>]*\bhref="([^"]+)"[^>]*\bclass="lang"', _page)}
        for _other in [c for c in _langs if c != _lang]:
            _href = "/" if _other == _i18n.DEFAULT else "/%s/" % _other
            check("...and the %s page offers the reader %s" % (_lang, _other),
                  _href in _switch,
                  "no visible switch from %s to %s; the page offers %s"
                  % (_lang, _other, sorted(_switch) or "nothing"))

    # 6. NODE BY NODE AGAINST THE ENGLISH PAGE, and this is the only check here that does not
    #    ask the extractor what it found. Everything above is quantified over `extract()`, so a
    #    walker that stops finding strings satisfies all of it at once: measured, one void
    #    element carrying `translate="no"` in the top bar took the key set from 141 to 134, and
    #    the documented repair then rewrote the dictionary to match and left the suite green
    #    with seven English strings in the header of a page served as `uk`.
    #
    #    The first version of this looked for the twelve longest English sentences and missed
    #    exactly that case, because the strings it lost were short. The pages are generated
    #    from one source, so their visible nodes align one for one; anything identical in both
    #    is a string that was not translated, and there are only ever a handful of those.
    #
    #    Identical BY DESIGN: commands you type, an identifier, and half of a brand. The list
    #    is short on purpose, and its growth is the signal - a translation lost anywhere adds
    #    to it, and adding to it has to be a decision somebody writes down.
    _SAME_BY_DESIGN = {
        "tration",                 # the second half of the brand, split for the accent colour
        "pip install qatration", "qatration onboard", "qatration mint", "qatration sarif",
        "--fail-on exploited",     # commands: a localised one is a broken instruction
        "ACME-SK-7731-QA",         # the leaked key in the illustrated transcript
        "canary_in_tool_call",     # a detector's name, which is what you grep for
    }

    def _nodes(path):
        _t = io.open(path, encoding="utf-8").read()
        _t = re.sub(r"(?s)<(script|style)\b.*?</\1>", " ", _t)
        _t = re.sub(r"(?s)<!--.*?-->", " ", _t)
        return [x for x in (re.sub(r"\s+", " ", n).strip()
                            for n in re.split(r"(?s)<[^>]*>", _t)) if x]

    _en_nodes = _nodes(_i18n.page_path(_i18n.DEFAULT))
    for _lang in [c for c in _langs if c != _i18n.DEFAULT]:
        _tbl = _i18n.load(_lang)
        _uk_nodes = _nodes(_i18n.page_path(_lang))
        check("the %s page has the same shape as the English one" % _lang,
              len(_en_nodes) == len(_uk_nodes),
              "%d visible nodes against %d, so they cannot be compared in step"
              % (len(_uk_nodes), len(_en_nodes)))
        if len(_en_nodes) == len(_uk_nodes):
            _untouched = [a for a, b in zip(_en_nodes, _uk_nodes)
                          if a == b and re.search(r"[A-Za-z]{4}", a)
                          and a not in _SAME_BY_DESIGN and _tbl.get(a) != a]
            check("...and every string on it that should differ does",
                  not _untouched,
                  "%d English string(s) survived into %s, first: %s"
                  % (len(_untouched), _lang, (_untouched or [""])[0][:60]))

    # 7. A TRANSLATION IS TEXT, NEVER MARKUP. The generator escapes what it substitutes, so a
    #    stray quote can no longer close an attribute; this catches the other half, a
    #    translator pasting a tag, before it becomes an escaped tag printed on the page.
    _markupy = []
    for _lang in [c for c in _langs if c != _i18n.DEFAULT]:
        for _k, _v in _i18n.load(_lang).items():
            if re.search(r"<[a-zA-Z/!]", _v or ""):
                _markupy.append("%s: %s" % (_lang, (_v or "")[:40]))
    check("no translation contains markup", not _markupy, "; ".join(_markupy[:3]))

    # 8. EVERY PAGE SAYS WHAT LANGUAGE IT IS IN. The English page had no `lang` at all, which
    #    is a WCAG 3.1.1 failure at level A and leaves a screen reader reading it in whatever
    #    voice the visitor happens to have set.
    for _lang in _langs:
        _page = io.open(_i18n.page_path(_lang), encoding="utf-8").read()
        _decl = re.findall(r"(?is)\A<html[^>]*\blang=\"([^\"]+)\"", _page)
        check("the %s page declares its own language" % _lang, _decl == [_lang],
              "the root element declares %s" % (_decl or "nothing"))

        # 9. AND THE ALTERNATES POINT AT REAL URLS. The codes were compared and the addresses
        #    were not, so dropping a trailing slash would have sent every alternate at a 308
        #    and stayed green. The pattern reads whole tags rather than a fixed attribute
        #    order, which is the mistake the switch check above already made once.
        _alts = {}
        for _tag in re.findall(r"<link\b[^>]*\brel=\"alternate\"[^>]*>", _page):
            _c = re.search(r'hreflang="([^"]+)"', _tag)
            _h = re.search(r'href="([^"]+)"', _tag)
            if _c and _h:
                _alts[_c.group(1)] = _h.group(1)
        _want_alts = dict({c: _page_url(c) for c in _langs},
                          **{"x-default": _i18n.SITE_URL})
        check("...and the %s page's alternates address every language exactly" % _lang,
              _alts == _want_alts,
              "alternates are %s, they should be %s" % (sorted(_alts.items()),
                                                        sorted(_want_alts.items())))

        # 10. AND SO DOES og:url, which nothing checked. It is rewritten by exact string match,
        #     so reformatting the source tag makes the rewrite a silent no-op and every share
        #     of a translated page previews as the English one.
        _og = re.findall(r'<meta property="og:url" content="([^"]+)"', _page)
        check("...and the %s page's og:url is its own address" % _lang,
              _og == [_page_url(_lang)],
              "og:url is %s, this page is %s" % (_og or "absent", _page_url(_lang)))

    # 11. THE THEME BUTTON'S SPOKEN NAME CONTAINS ITS WRITTEN ONE, in every language. English
    #     passed on a case-insensitive reading and Ukrainian did not: the label is nominative
    #     and the phrase around it inflected the word, so the string written on the button was
    #     not inside the name it answers to, and a voice-control user reading the button aloud
    #     could not press it. WCAG 2.5.3, and a failure a dictionary can reintroduce at any
    #     time without touching a line of markup.
    _pairs = [("data-to-light", "data-aria-light"), ("data-to-dark", "data-aria-dark")]
    for _lang in _langs:
        _tbl = {} if _lang == _i18n.DEFAULT else _i18n.load(_lang)
        for _vis_attr, _name_attr in _pairs:
            _vis = re.search(r'%s="([^"]*)"' % _vis_attr, _site)
            _name = re.search(r'%s="([^"]*)"' % _name_attr, _site)
            if not (_vis and _name):
                continue
            _v = _tbl.get(_vis.group(1)) or _vis.group(1)
            _n = _tbl.get(_name.group(1)) or _name.group(1)
            check("the %s theme button can be pressed by saying what it says (%s)"
                  % (_lang, _vis_attr[-5:]),
                  _v.lower() in _n.lower(),
                  "the button reads %r and answers to %r" % (_v, _n))

    # THE SITEMAP AND ROBOTS.TXT ARE NOT CHECKED AGAIN HERE. Both were, and both were already
    # covered upstream: the URL list is compared against the languages where the file is
    # parsed, and `...and lists nothing robots.txt tells crawlers to skip` is strictly stronger
    # than the rule written here, which matched `Disallow: /uk` exactly and would have missed
    # `Disallow: /u` and `Disallow: /uk/index.html` alike. The copy written second had the more
    # confident name, which is how a weaker rule ends up looking like the authority.

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for x in fails:
            print("  !", x)
        sys.exit(1)
    print("\nOK — the README's numbers are counted, not declared.")


def _spells_or_raises(n):
    try:
        spell(n)
        return False
    except AssertionError:
        return True


if __name__ == "__main__":
    main()
