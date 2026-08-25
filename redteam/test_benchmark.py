"""The benchmark page states numbers about other people's tools. This recounts them.

Every other published count in this repository is derived from the artifacts rather than typed,
and a page comparing three products is the last place to make an exception: it is the page most
likely to be quoted back, and the one where a wrong digit is least recoverable.

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

    print("\n%d/%d passed" % (checks - len(fails), checks))
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK - every number on the benchmark page is a recount, not a memory.")


if __name__ == "__main__":
    main()
