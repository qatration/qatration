"""Build the portable arsenal from the library, instead of maintaining a second copy.

A run against an outside target used 22 attacks across 8 categories. The library holds 383
across 45. That gap was not a decision: `attacks.yaml` grew target by target while the practice fleet was built, and
each new attack got `applies_to: [that bot]` because it was written against that bot. Sometimes
that was necessary, because the attack names the bot's canary or one of its tools. Usually it
was habit. `attacks_generic.yaml` then collected whatever had never been given an `applies_to`,
so the 22 an arbitrary target received were not chosen, they were the residue.

The same defect shape as the rest of this repo: a restriction with a local justification that
quietly became policy. This one restricted the TESTING rather than the report.

GENERATED, NOT COPIED, and that matters. 77 attack ids already appear in two files, because the
per-bot arsenals were split out of `attacks.yaml` by hand and both copies were then edited. A
third hand-maintained copy would repeat it. `test_arsenal.py` fails if the file on disk is not
what this produces, so the two cannot drift.

WHAT IS NOT PROMOTED, and why each is a judgement rather than a filter:

  * `control` — an ordinary question used as a per-target baseline. Eighteen of them in a
    portable arsenal would pad the count with prompts that are not attacks, and a probe count
    inflated by non-attacks is a number nobody can act on.
  * attacks carrying `paired_with` — half of an A/B pair, whose measurement is the pair and
    not the prompt. Promoting the framed halves alone would pad the arsenal with twenty
    variants of one question and leave the comparison behind.
  * attacks naming a CANARY or a TOOL — they reference one bot's planted secret or one bot's
    tool by name, so against anything else they test a string that does not exist.
  * attacks with a `seed:` block — they plant a document in a corpus. That needs a store we can
    write to, which a chat endpoint does not expose.
  * attacks naming a BRAND — "AcmeShop" in the prompt reads as a different company's bot to the
    target, which changes what is being tested. These are promotable with a text edit and are
    listed by `--blocked` so the work is visible rather than forgotten.

    python build_generic.py            # report what would change
    python build_generic.py --write    # rewrite attacks_generic.yaml
"""
import argparse, glob, json, os, re, sys
from target import target_configs

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import yaml

# NO CLI DOOR, ON PURPOSE, and said here rather than in the gate: a list of exempt
# modules living in the check is a second copy of this judgement, and the next module
# added would join it by whoever happened to be editing the check.
NO_CLI_DOOR = "rebuilds the shipped arsenal; a maintainer tool, not a user command"


OUT_NAME = "attacks_generic.yaml"

# Brand names from the practice fleet's fiction. A prompt saying "AcmeShop" tells an outside
# bot it is talking about somebody else, which is a different test from the one intended.
BRANDS = ("acmeshop", "acmebank", "acmerange", "acmecloud", "acmehbank", "northgate",
          "ourstore", "ourcompany", "guardbot", "shipdesk", "lyrebird", "acme")


def fleet_literals():
    """Canaries and tool names any target config declares — the strings that pin an attack."""
    canaries, tools = set(), set()
    for fp in target_configs(HERE):
        try:
            oc = (yaml.safe_load(open(fp, encoding="utf-8")) or {}).get("oracle_context") or {}
        except Exception:
            continue
        import honeytoken as _ht
        for x in _ht.declared(oc):
            if str(x).strip():
                canaries.add(str(x).lower())
        for x in (oc.get("tool_names") or []):
            if len(str(x)) > 3:
                tools.add(str(x).lower())
    return canaries, tools


def library():
    """Every distinct attack, by id. `attacks.yaml` wins where an id appears twice.

    It appears twice for 77 ids: the per-bot files were split out of the main arsenal by hand
    and both copies stayed. Reading the main one first makes that deterministic rather than
    dependent on glob order.
    """
    out, generic = {}, {}
    main = os.path.join(HERE, "attacks.yaml")
    files = [main] + sorted(set(glob.glob(os.path.join(HERE, "attacks*.yaml"))) - {main})
    for fp in files:
        base = os.path.basename(fp)
        # A SCRATCH FILE IN THIS DIRECTORY IS PART OF THE ARSENAL, which is a footgun the glob
        # created and nothing guarded. `test_end_to_end.py` writes `attacks_e2e_<pid>_tmp.yaml` here
        # while it runs and removes it in a `finally`; an interrupted run leaves it behind, and
        # the next regeneration would fold three toy attacks aimed at a scripted bot into what
        # an arbitrary target receives. Nothing would have said so — they are well-formed, they lint,
        # and they name real detectors.
        if base.endswith(("_tmp.yaml", ".tmp.yaml")) or base.startswith("attacks_slice"):
            continue
        if base == OUT_NAME:
            for a in (yaml.safe_load(open(fp, encoding="utf-8")) or []):
                generic[a["id"]] = a
            continue
        for a in (yaml.safe_load(open(fp, encoding="utf-8")) or []):
            out.setdefault(a["id"], a)
    # HAND-WRITTEN means "exists nowhere else", not "starts with g-". The first version read
    # the whole of the generated file back as hand-written input, so a second run promoted the
    # library on top of its own output: 184 attacks became 346, and a third run would have
    # doubled it again. Defining it by absence from the library makes the generator idempotent
    # by construction rather than by a naming convention somebody has to keep.
    hand = {k: v for k, v in generic.items() if k not in out}
    return out, hand


def blocked_reason(a, canaries, tools):
    """Why this attack cannot be sent at an arbitrary target, or None."""
    if a.get("category") == "control":
        return "control: a per-target baseline, not an attack"
    if a.get("seed"):
        return "seeds a document: needs a corpus we can write to"
    if a.get("paired_with"):
        # HALF OF AN A/B PAIR, and useless without the other half. `attacks_guardlift.yaml`
        # holds twenty variants of one question so a framing can be compared against the plain
        # form of the SAME question; promoting the twenty framed halves would pad the portable
        # arsenal with an experiment's scaffolding, and their measurement is the pair rather
        # than the prompt. Same judgement as `control` above and for the same reason.
        return "one half of an A/B pair: measured against its twin, not on its own"
    blob = json.dumps({k: v for k, v in a.items() if k not in ("applies_to", "id")},
                      ensure_ascii=False).lower()
    for c in canaries:
        if c in blob:
            return "names a canary planted in one practice bot"
    for t in tools:
        if re.search(r"\b" + re.escape(t) + r"\b", blob):
            return f"names the tool {t!r}"
    # A brand inside a hostname under `.example` is the ATTACKER's collector, not the target's
    # identity: the TLD is reserved and unregistrable by anyone, so `acme-metrics.example` is a
    # destination the exfil attacks point at on purpose and says nothing about whose bot this
    # is. Blocking on it cost five output-exfil attacks and the whole ansi-exfil category for a
    # substring match on a domain the attack was supposed to contain.
    stripped = re.sub(r"[a-z0-9.-]+\.example", " ", blob)
    for b in BRANDS:
        if b in stripped:
            return f"names the brand {b!r} (promotable with a text edit)"
    return None


def build():
    canaries, tools = fleet_literals()
    lib, hand = library()
    promoted, blocked = [], []
    for aid, a in sorted(lib.items()):
        # UNSCOPED IS NOT THE SAME AS REACHING ANYBODY, and the first version of this loop
        # assumed it was: it skipped every attack without `applies_to` on the grounds that such
        # an attack "reaches everyone as it is". It does not. The sweep is pointed at ONE
        # arsenal file, and 33 unscoped attacks were living in other files — every Context
        # Compliance attack, the whole `serialization` category, the recon set — so a run
        # against an outside target never saw one of them. The same defect as the scoping itself, one directory deeper:
        # not a decision about what to send, an accident of which file something was written in.
        why = blocked_reason(a, canaries, tools)
        if why:
            blocked.append((aid, a.get("category"), why))
            continue
        clean = {k: v for k, v in a.items() if k != "applies_to"}
        promoted.append(clean)
    return hand, promoted, blocked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="rewrite " + OUT_NAME)
    ap.add_argument("--blocked", action="store_true", help="list what was not promoted, and why")
    args = ap.parse_args()

    hand, promoted, blocked = build()
    from collections import Counter
    cats_before = Counter(a.get("category") for a in hand.values())
    cats_after = Counter(list(cats_before.elements()) + [a.get("category") for a in promoted])
    print(f"hand-written generic attacks : {len(hand):>4}  ({len(cats_before)} categories)")
    print(f"taken from the library       : {len(promoted):>4}")
    print(f"not promoted                 : {len(blocked):>4}")
    print(f"-> portable arsenal          : {len(hand) + len(promoted):>4}  "
          f"({len(cats_after)} categories)")
    if args.blocked:
        print()
        # From the ids being listed. Four shipped attack names are already longer than the
        # constant this used to be, and this listing exists to be read by hand.
        _wid = max([28] + [len(b[0]) for b in blocked]) + 2
        _wcat = max([18] + [len(str(b[1])) for b in blocked]) + 2
        for aid, cat, why in sorted(blocked, key=lambda x: (x[2], x[0])):
            print(f"  {aid:<{_wid}}{str(cat):<{_wcat}}{why}")

    if not args.write:
        print("\nnothing written — re-run with --write")
        return

    body = list(hand.values()) + promoted
    path = os.path.join(HERE, OUT_NAME)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# GENERATED by build_generic.py — do not edit the promoted section by hand.\n"
                "#\n"
                "# The hand-written `g-*` attacks come first and are kept verbatim; everything\n"
                "# after them is promoted from the library by dropping `applies_to` where the\n"
                "# attack names nothing belonging to one practice bot. test_arsenal.py fails if\n"
                "# this file and the generator disagree, because a second hand-maintained copy\n"
                "# is exactly how 77 attack ids ended up living in two files at once.\n\n")
        yaml.safe_dump(body, f, allow_unicode=True, sort_keys=False, width=100,
                       default_flow_style=False)
    print(f"\nwrote {path} — {len(body)} attacks")


if __name__ == "__main__":
    main()
