# -*- coding: utf-8 -*-
"""Move a backend failure that was stored as a REPLY into the field that says it was one.

An adapter that reads an HTTP body and finds a 200 has no exception to catch, so a deployment
that reports its own failure inside a successful response used to arrive here as the target's
answer. `redteam/targets_localrag.py` and `redteam/targets_httpbot.py` were both fixed to put
that in `probe.error`, which is the field every scorer in this repository consults -- but the
fix only changes what future runs record. The runs already on disk keep the failure where it
was put, and there it is indistinguishable from something the model said.

WHAT THAT COSTS, MEASURED: `out/results_localrag-refusal.json` carries seven attack rows at
EXPLOITED where every trial of every row is "There was an error processing the query: Failed
to connect to Ollama." `refusal.classify` labels prose with no refusal language `compliance`,
`declined` agrees, and `refusal_expected_but_absent` reports that a bot which should have
declined did not. Those rows are read by `build_index` like any other, so seventy probes
against a model that was never up are inside a published finding count.

THIS IS NOT A REWRITE OF A MEASUREMENT. The bytes are not discarded: they move from `output`
to `error`, prefixed so their origin is legible, and the text a person can read is the same
text. What changes is that the engine can now tell an absence from an answer, which is the one
distinction this project exists to keep. Re-running would be better and is not available
here -- the cloned RAG application is not in `external/` -- and leaving seven fabricated
exploits in a published count is the worse of the two remaining options.

    python tools/repair_probes.py            # preview, writes nothing
    python tools/repair_probes.py --write    # apply

Read-only by default for the same reason `rejudge` is: these files are the record of expensive
runs, and a tool that edits them has no business doing it before somebody has read the list.
Idempotent -- a probe whose error is already set is left alone -- so a second run reports
nothing and changes nothing. Run `qatration rejudge --write` afterwards to re-score.
"""
import argparse
import glob
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "redteam"))

# THE ADAPTERS' OWN CONTRACTS, imported rather than restated, so this tool and the adapters
# cannot drift into disagreeing about what a failure looks like. A second spelling of the same
# rule is the copy that goes stale.
try:
    from targets_localrag import APP_ERROR as LOCALRAG_APP_ERROR
except Exception:                                    # pragma: no cover - a broken checkout
    LOCALRAG_APP_ERROR = None

# Anchored at the START of the reply, never searched inside it. Every corpus in this fleet is
# deliberately poisoned and a retrieved document can contain any sentence at all, so a
# substring match here would let a planted document rewrite the record.
SHAPES = [
    ("localrag", LOCALRAG_APP_ERROR),
    # A transport failure some adapters used to stringify into the reply rather than raise.
    ("connection", re.compile(r"\s*(?:failed to connect to|connection (?:refused|reset))\b",
                              re.I)),
]


def failure_in(text):
    """-> the name of the shape that matched the OPENING of this reply, or None."""
    for name, pat in SHAPES:
        if pat is not None and pat.match(text or ""):
            return name
    return None


def walk(out_dir):
    """-> [(path, artifact, [(row_index, trial_index, shape, text), ...]), ...]"""
    found = []
    for fp in sorted(glob.glob(os.path.join(out_dir, "results_*.json"))):
        try:
            doc = json.loads(io.open(fp, encoding="utf-8").read())
        except Exception:
            continue
        rows = doc if isinstance(doc, list) else (doc.get("results") or [])
        hits = []
        for i, r in enumerate(rows):
            for j, t in enumerate(r.get("trials") or []):
                pr = t.get("probe")
                if not isinstance(pr, dict) or pr.get("error"):
                    continue                          # already recorded as a failure
                shape = failure_in(pr.get("output") or "")
                if shape:
                    hits.append((i, j, shape, pr.get("output") or ""))
        if hits:
            found.append((fp, doc, hits))
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(prog="repair_probes",
                                 description="a backend failure stored as a reply")
    ap.add_argument("--write", action="store_true", help="apply (default: preview only)")
    ap.add_argument("--out", default=None, help="workspace to read (default: the configured one)")
    args = ap.parse_args(argv)

    out_dir = args.out
    if out_dir is None:
        from workspace import OUT
        out_dir = OUT

    found = walk(out_dir)
    if not found:
        print("nothing to repair in %s — no stored reply opens with a backend failure."
              % out_dir)
        return 0

    total = 0
    for fp, doc, hits in found:
        rows = doc if isinstance(doc, list) else (doc.get("results") or [])
        print("\n%s" % os.path.basename(fp))
        seen_rows = sorted({i for i, _, _, _ in hits})
        for i in seen_rows:
            r = rows[i]
            a = r.get("attack")
            aid = a.get("id") if isinstance(a, dict) else a
            n = sum(1 for x, _, _, _ in hits if x == i)
            trials = len(r.get("trials") or [])
            print("  %-28s %-14s %d/%d trial(s) are a backend failure"
                  % (aid, r.get("headline"), n, trials))
        for i, j, shape, text in hits:
            total += 1
            if args.write:
                pr = rows[i]["trials"][j]["probe"]
                pr["error"] = "AppError: %s" % " ".join(text.split())[:200]
                pr["output"] = ""
        if args.write:
            io.open(fp, "w", encoding="utf-8", newline="").write(
                json.dumps(doc, indent=2, ensure_ascii=False))

    print("\n%d probe(s) across %d file(s)." % (total, len(found)))
    if args.write:
        print("written. Re-score with: qatration rejudge --write")
    else:
        print("nothing was written — re-run with --write to apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
