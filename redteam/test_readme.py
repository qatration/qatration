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
import sys, os, re, glob, json
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
    for fp in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        lines = open(fp, encoding="utf-8").read().splitlines()
        shown = [i for i, l in enumerate(lines) if "passed\")" in l and "print(" in l]
        if not shown:
            continue
        trailing = [j for j in range(shown[-1] + 1, len(lines))
                    if lines[j].lstrip().startswith("check(")]
        if trailing:
            early.append(f"{os.path.basename(fp)}: {len(trailing)} check(s) run after the "
                         f"summary was printed at line {shown[-1] + 1}")
    check("no suite counts itself before its last check has run",
          not early, "; ".join(early))

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
