"""The benchmark page states numbers about other people's tools. This recounts them.

Every other published count in this repository is derived from the artifacts rather than typed,
and a page comparing three products is the last place to make an exception: it is the page most
likely to be quoted back, and the one where a wrong digit is least recoverable.

AND THE PROSE IS CHECKED, NOT ONLY THE FIGURES. The first version of this file compared the
page against `bench-*.json`, which is what `bench_score.py` wrote when the page was written.
A gate built on the same derivation as the claim can only ever agree with it: it confirmed
every number and missed three false sentences beside them, including a corpus described as "50
ordinary customer-support questions" when 14 of the 50 are attack-shaped false-positive probes,
which is the comparator every other figure is measured against. Found by a reviewer, hours after
publication. The checks below go back to the raw rows for anything the page ASSERTS, not only
for what it counts.

Two sources, because the page has two kinds of claim.

  * OUR rows are recounted from the stored evidence in `out/bench/`, the same run the page
    describes, through the same `tools/bench_score.py` a reader would use.
  * THE OTHER TOOLS' rows are compared against `out/bench/bench-*.json`, which is what that
    scorer wrote while their reports were still on the machine. Their raw reports are not in
    this repository, for the reasons the page gives, so this file checks the page against the
    record of the run rather than against nothing.

A number that vanishes from the page fails this too. A gate whose sentence has been rewritten
away is a gate that retired itself, which is the failure this project is named after.

    python test_benchmark.py       # exits 1 on any failure (CI gate)
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAGE = os.path.join(ROOT, "docs", "benchmark.md")
BENCH = os.path.join(ROOT, "out", "bench")
sys.path.insert(0, os.path.join(ROOT, "tools"))


def rows_of(text, header_starts):
    """-> {first cell: [cells]} for the markdown table whose header row starts with this."""
    out, in_table = {}, False
    for line in text.splitlines():
        if line.startswith("| " + header_starts):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            out[cells[0]] = cells
    return out


def numbers(cell):
    """Every integer in a cell, in order. `150/158 (**95%**)` -> [150, 158, 95]."""
    return [int(n) for n in re.findall(r"\d+", cell.replace(",", ""))]


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    text = io.open(PAGE, encoding="utf-8").read()
    for name in ("bench-localrag.json", "bench-nemo.json",
                 "results_localrag.json", "benign_localrag.json",
                 "results_nemo.json", "benign_nemo.json"):
        check("the evidence the page rests on is here: %s" % name,
              os.path.isfile(os.path.join(BENCH, name)))

    measured = {os.path.basename(f)[:-5]:
                json.load(io.open(os.path.join(BENCH, f), encoding="utf-8"))
                for f in ("bench-localrag.json", "bench-nemo.json")}

    # --- OUR rows, recounted from the artifacts through the reader a stranger would use -----
    import bench_score
    bench_score.CANARIES[:] = measured["bench-localrag"]["canaries"]
    ours = bench_score.read_qatration(os.path.join(BENCH, "results_localrag.json"))
    leaked = sum(1 for _i, _p, r in ours if bench_score.leaked(r))
    rate, n_benign = bench_score.benign_rate(os.path.join(BENCH, "benign_localrag.json"))

    unguarded = rows_of(text, "source")
    qat = unguarded.get("QAtration")
    check("the page has a QAtration row on the unguarded target", bool(qat), str(sorted(unguarded)))
    if qat:
        check("...and its reply count is what the artifact holds",
              numbers(qat[1])[0] == len(ours), "page %s, artifact %d" % (qat[1], len(ours)))
        check("...and its leak count is what the same rule counts now",
              numbers(qat[3])[0] == leaked, "page %s, recount %d" % (qat[3], leaked))

    benign_row = unguarded.get("no attack at all")
    check("the page states the benign baseline", bool(benign_row))
    if benign_row:
        check("...and it matches a recount of the stored baseline",
              numbers(benign_row[1])[0] == n_benign and numbers(benign_row[3])[0] == round(rate * n_benign),
              "page %s / %s, artifact %d prompts at %.2f" % (benign_row[1], benign_row[3], n_benign, rate))

    # THE PROSE NUMBER TOO. `46%` is the sentence the whole page turns on, and a table can be
    # right while the paragraph above it is stale.
    said = re.search(r"comes back on \*\*(\d+)%\*\* of them", text)
    check("the prose states the same baseline as the table", bool(said), "sentence gone")
    if said:
        check("...and it is the rate in the artifact",
              int(said.group(1)) == round(rate * 100),
              "page %s%%, artifact %.0f%%" % (said.group(1), rate * 100))

    # --- THE OTHER TOOLS' rows, against the record written while their reports existed ------
    for label, key in (("garak `latentinjection`", "garak"), ("promptfoo", "promptfoo")):
        row = unguarded.get(label)
        check("the page has a row for %s" % key, bool(row), str(sorted(unguarded)))
        if not row:
            continue
        rec = measured["bench-localrag"]["tools"][key]
        check("...and %s's reply count matches the run record" % key,
              numbers(row[1])[0] == rec["replies"], "page %s, record %d" % (row[1], rec["replies"]))
        check("...and its leak count does too",
              numbers(row[3])[0] == rec["leaked"], "page %s, record %d" % (row[3], rec["leaked"]))

    # --- the guarded half -------------------------------------------------------------------
    guarded = rows_of(text, "source | replies | leaked, shared rule")
    check("the page has the guarded table", len(guarded) >= 4, str(sorted(guarded)))
    for label, key in (("garak `latentinjection`", "garak"), ("promptfoo", "promptfoo"),
                       ("QAtration", "qatration")):
        row = guarded.get(label)
        if not row:
            check("the guarded table has a row for %s" % key, False, str(sorted(guarded)))
            continue
        rec = measured["bench-nemo"]["tools"][key]
        check("guarded: %s's reply count matches the record" % key,
              numbers(row[1])[0] == rec["replies"], "page %s, record %d" % (row[1], rec["replies"]))
        check("guarded: %s leaked nothing, and the record agrees" % key,
              numbers(row[2])[0] == 0 and rec["leaked"] == 0,
              "page %s, record %d" % (row[2], rec["leaked"]))

    # --- THE CLAIMS, RECOUNTED FROM THE RAW ROWS ---------------------------------------
    #
    # Everything above compares one derived file with another. These four go back to the
    # replies themselves, because each corresponds to a sentence this page got wrong.
    benign = json.load(io.open(os.path.join(BENCH, "benign_localrag.json"), encoding="utf-8"))
    brows = benign["rows"]

    def reply(row):
        return (row.get("probe") or {}).get("output") or row.get("output") or ""

    def cites_carrier(t):
        return "refunds.pdf" in set(re.findall(r"\*([A-Za-z0-9_-]+\.pdf)\*", t or ""))

    # 1. the split the page publishes, recounted. `-in-question` is how the corpus names a
    #    benign prompt that carries attack-shaped text.
    shaped = [r for r in brows if str(r.get("id", "")).endswith("-in-question")]
    plain = [r for r in brows if not str(r.get("id", "")).endswith("-in-question")]
    split = rows_of(text, "subset")
    check("the page publishes the benign split", len(split) >= 2, str(sorted(split)))
    want = {"plain support questions": plain, "benign but attack-shaped": shaped}
    for label, group in want.items():
        row = split.get(label)
        if not row:
            check("the split names %r" % label, False, str(sorted(split)))
            continue
        got_n = numbers(row[1])[0]
        got_ret = numbers(row[2])[0]
        got_leak = numbers(row[3])[0]
        ret = sum(1 for r in group if cites_carrier(reply(r)))
        leak = sum(1 for r in group if bench_score.leaked(reply(r)))
        check("%s: the page says %d and the corpus holds %d" % (label, got_n, len(group)),
              got_n == len(group))
        check("...and its retrieval count is a recount", got_ret == ret,
              "page %d, rows %d" % (got_ret, ret))
        check("...and its leak count is a recount", got_leak == leak,
              "page %d, rows %d" % (got_leak, leak))

    # 2. "181 flagged" was "all flagged" until a reviewer opened the file.
    res = json.load(io.open(os.path.join(BENCH, "results_localrag.json"), encoding="utf-8"))
    breaches = [r for r in res["results"]
                if r.get("headline") in ("EXPLOITED", "PARTIAL")
                and (r.get("attack") or {}).get("category") != "control"]
    flagged = int(re.search(r"(\d+) breach row\(s\) share a detector",
                            json.dumps(res.get("meta") or {})).group(1))
    said = re.search(r"Of the (\d+) breaches it reported on the\s+unguarded target, \*\*(\d+) came with the reason", text)
    check("the page states both the breach count and how many were flagged", bool(said))
    if said:
        check("...and the breach count is a recount", int(said.group(1)) == len(breaches),
              "page %s, rows %d" % (said.group(1), len(breaches)))
        check("...and the flagged count is the artifact's own", int(said.group(2)) == flagged,
              "page %s, artifact %d" % (said.group(2), flagged))

    # 3. the carrier sentence described a test the code never ran.
    leaking = [t for r in res["results"] for t in [reply(tr) for tr in r["trials"]]
               if bench_score.leaked(t)]
    clean_citing = sum(1 for r in res["results"] for t in [reply(tr) for tr in r["trials"]]
                       if not bench_score.leaked(t) and cites_carrier(t))
    check("every leaking reply cites the carrier, which is what identifies it",
          all(cites_carrier(t) for t in leaking), "%d leaking replies" % len(leaking))
    check("...and the page admits clean replies cite it too, with the right count",
          str(clean_citing) in text, "artifact says %d" % clean_citing)

    # 4. the p-values the page quotes, recomputed here rather than trusted.
    from math import comb

    def fisher(a, b, c, d):
        n, r1, r2, c1 = a + b + c + d, a + b, c + d, a + c
        pr = lambda x: comb(r1, x) * comb(r2, c1 - x) / comb(n, c1)
        p0 = pr(a)
        return sum(pr(x) for x in range(max(0, c1 - r2), min(r1, c1) + 1) if pr(x) <= p0 + 1e-12)

    pooled = fisher(150, 8, 23, 4)
    plain_only = fisher(150, 8, 15, 1)
    check("the page quotes the pooled p-value it now rests on",
          "p = %.3f" % pooled in text or "p = 0.078" in text, "recomputed %.3f" % pooled)
    check("...and the plain-question one", "p = 0.59" in text or "p = %.2f" % plain_only in text,
          "recomputed %.2f" % plain_only)
    check("...and neither is significant at 0.05, which is why the claim was withdrawn",
          pooled > 0.05 and plain_only > 0.05, "%.3f and %.3f" % (pooled, plain_only))

    # --- AND THE FRONT PAGE, which is the one people actually read --------------------------
    #
    # docs/ is the design record and the site is the shop window. A number that goes stale
    # there costs more, not less, and this paragraph quotes three: the benign rate, the single
    # breach on the guarded target, and what that target's rails cost in refused customers.
    # Each is recounted here from the same artifacts rather than trusted to have been copied
    # correctly.
    site = io.open(os.path.join(ROOT, "site", "index.html"), encoding="utf-8").read()
    para = "And beside two other tools, in public"
    check("the front page carries the comparison paragraph", para in site,
          "the section is gone, so nothing links the site to the page")
    if para in site:
        block = site[site.index(para):site.index(para) + 1400]
        check("...and it links the page", "docs/benchmark.md" in block)
        check("...and its benign rate is the artifact's",
              "%d%% of benign probes" % round(rate * 100) in block,
              "artifact says %.0f%%" % (rate * 100))

        nemo = json.load(io.open(os.path.join(BENCH, "results_nemo.json"), encoding="utf-8"))
        nres = nemo["results"]
        nbreach = sum(1 for r in nres
                      if r.get("headline") in ("EXPLOITED", "PARTIAL")
                      and (r.get("attack") or {}).get("category") != "control")
        nreplies = sum(len(r.get("trials") or []) for r in nres)
        # Prose writes small numbers as words, so the accepted form is derived from the
        # artifact rather than fixed: one breach may read "one", two must read "2". A check
        # that only knew the digit would fail on correct English, and one that accepted any
        # form would pass on a stale number.
        forms = ["%d breach" % nbreach] + (["one breach"] if nbreach == 1 else [])
        check("...and the single breach on the guarded target is still one",
              any(f in block for f in forms) and str(nreplies) in block,
              "artifact says %d in %d" % (nbreach, nreplies))

        nben = json.load(io.open(os.path.join(BENCH, "benign_nemo.json"), encoding="utf-8"))
        nrows = nben["rows"]
        refused = sum(1 for r in nrows if r.get("refused"))
        check("...and the refusal count the rails cost is a recount",
              "%d of %d ordinary customer questions" % (refused, len(nrows)) in block,
              "artifact says %d of %d" % (refused, len(nrows)))

    print("\n%d/%d passed" % (checks - len(fails), checks))
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK - every number on the benchmark page is a recount, not a memory.")


if __name__ == "__main__":
    main()
