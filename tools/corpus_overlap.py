"""How much of this arsenal already exists in a published jailbreak corpus?

Every prompt here was written in this repository. That is a claim, and this is the check that
makes it one somebody else can run.

WHY IT MATTERS RATHER THAN BEING A BOAST. Red-team corpora are scraped from the same public
sources that jailbreak classifiers are trained on, and the 2026 surveys put the overlap between
the two at well over half. A prompt a guard has already seen in training measures the guard's
memory, not its behaviour, and a tool built out of such prompts reports a number about its own
provenance. Writing prompts by hand is only worth the effort if it can be shown to have worked.

    python tools/corpus_overlap.py <corpus.json> [corpus.json ...]

Each corpus is a JSON list of objects; every string field of every object is treated as a
candidate prompt, because these datasets disagree about what the column is called.

WHAT IS MEASURED, and none of it is exact-match alone. Two people writing an English sentence
about refunds share words without either copying the other, and two people copying the same
Reddit post share thirty. So:

  * an exact match after normalisation, which is the only unambiguous answer and is expected to
    be zero;
  * the longest run of consecutive words any of our prompts shares with any published one,
    which is what catches a paraphrase;
  * the best five-word shingle overlap, which is what catches a rewrite.

A long shared run is the finding. A high shingle score with a short run is usually two people
using the same ordinary phrases, and the report prints the matching text so a person decides.
"""
import io
import json
import os
import re
import sys
from collections import defaultdict

WORD = re.compile(r"[a-z0-9']+")
SHINGLE = 5


def words(text):
    return WORD.findall((text or "").lower())


def shingles(ws, n=SHINGLE):
    return {" ".join(ws[i:i + n]) for i in range(len(ws) - n + 1)}


def ours():
    """Every attack text this repository ships, by id, from every arsenal file."""
    import yaml
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "redteam")
    out = {}
    import glob
    for fp in sorted(glob.glob(os.path.join(here, "attacks*.yaml"))):
        try:
            with io.open(fp, encoding="utf-8") as f:
                arr = yaml.safe_load(f)
        except Exception:
            continue
        for a in arr or []:
            if not isinstance(a, dict) or not a.get("id"):
                continue
            text = a.get("text") or " ".join(str(s) for s in (a.get("steps") or []))
            if text and a["id"] not in out:
                out[a["id"]] = (os.path.basename(fp), text)
    return out


def published(paths):
    """-> [(source, text)]. Every string field, because the column names disagree."""
    rows = []
    for p in paths:
        with io.open(p, encoding="utf-8") as f:
            data = json.load(f)
        tag = os.path.basename(p)
        for r in data:
            if isinstance(r, str):
                rows.append((tag, r))
                continue
            for v in (r or {}).values():
                if isinstance(v, str) and len(v.split()) >= SHINGLE:
                    rows.append((tag, v))
    return rows


def longest_run(a_words, b_words):
    """Longest run of consecutive words shared, by the usual dynamic-programming table."""
    if not a_words or not b_words:
        return 0
    prev = [0] * (len(b_words) + 1)
    best = 0
    for i in range(1, len(a_words) + 1):
        cur = [0] * (len(b_words) + 1)
        ai = a_words[i - 1]
        for j in range(1, len(b_words) + 1):
            if ai == b_words[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best


def main(argv):
    if not argv:
        print(__doc__.strip().splitlines()[0])
        print("usage: python tools/corpus_overlap.py <corpus.json> [...]", file=sys.stderr)
        return 2
    mine, theirs = ours(), published(argv)
    print("%d prompts here, %d published strings from %d corpus file(s)\n"
          % (len(mine), len(theirs), len(argv)))

    # An inverted index, so each of ours is compared against the documents it could match
    # rather than against all of them.
    index = defaultdict(set)
    their_words = []
    for k, (tag, t) in enumerate(theirs):
        ws = words(t)
        their_words.append(ws)
        for sh in shingles(ws):
            index[sh].add(k)

    exact = {" ".join(w) for w in their_words}
    hits = []
    exact_n = 0
    for aid, (src, text) in sorted(mine.items()):
        ws = words(text)
        if " ".join(ws) in exact:
            exact_n += 1
        mine_sh = shingles(ws)
        if not mine_sh:
            continue
        counts = defaultdict(int)
        for sh in mine_sh:
            for k in index.get(sh, ()):
                counts[k] += 1
        best_k, shared = (None, 0)
        for k, c in counts.items():
            if c > shared:
                best_k, shared = k, c
        run = longest_run(ws, their_words[best_k]) if best_k is not None else 0
        hits.append((run, shared / len(mine_sh), aid, src,
                     theirs[best_k][0] if best_k is not None else "-",
                     " ".join(their_words[best_k][:14]) if best_k is not None else ""))

    hits.sort(reverse=True)
    print("EXACT matches after normalisation: %d of %d" % (exact_n, len(mine)))
    print("\nthe ten closest, by longest run of consecutive shared words:")
    print("%-5s %-7s %-30s %s" % ("run", "shingle", "our attack", "closest published text"))
    for run, frac, aid, src, tag, sample in hits[:10]:
        print("%-5d %-7s %-30s %s…" % (run, "%.0f%%" % (100 * frac), aid[:30], sample[:60]))
    over = [h for h in hits if h[0] >= 8]
    print("\nprompts sharing a run of 8+ consecutive words with a published one: %d" % len(over))
    for run, frac, aid, src, tag, sample in over:
        print("   %-28s run=%d  vs %s" % (aid, run, tag))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
