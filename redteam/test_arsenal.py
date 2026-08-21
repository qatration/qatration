"""The portable arsenal, checked against the library it is built from. No model.

A run against an outside target used 22 attacks across 8 categories while the library held 262
across 45. That gap was never a decision. `attacks.yaml` grew target by target as the practice fleet was built,
each new attack got `applies_to: [that bot]` because it was written against that bot, and
`attacks_generic.yaml` collected whatever had never been given one. The 22 that reached an
outside target were not chosen, they were the residue — the same shape as every other defect this repo
documents, except that this one narrowed the TESTING rather than the report.

So the file is generated now, and these checks exist because a generated file that nobody
verifies is a hand-maintained file with extra steps:

  * it must equal what the generator produces, or the two have drifted;
  * nothing in it may carry `applies_to`, or a customer silently receives an attack scoped to
    somebody else's bot and it is skipped without explanation;
  * nothing in it may name a practice bot's canary, tool or brand, because against a customer
    those test a string that does not exist and come back DEFENDED;
  * the hand-written `g-*` attacks must survive regeneration, since they are the only ones
    that exist nowhere else.

    python test_arsenal.py       # exits 1 on any failure (CI gate)
"""
import sys, os, json, re
from target import target_configs
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import yaml
import build_generic as bg
from oracle import DETECTORS, NEEDS_CONFIG, inert_for


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    path = os.path.join(HERE, bg.OUT_NAME)
    on_disk = yaml.safe_load(open(path, encoding="utf-8")) or []
    hand, promoted, blocked = bg.build()
    expected = list(hand.values()) + promoted

    # --- the file IS the generator's output ------------------------------------------------
    check("the arsenal on disk is what the generator produces",
          [a["id"] for a in on_disk] == [a["id"] for a in expected],
          f"disk {len(on_disk)} vs generated {len(expected)}")
    same = all(json.dumps(a, sort_keys=True, ensure_ascii=False) ==
               json.dumps(b, sort_keys=True, ensure_ascii=False)
               for a, b in zip(on_disk, expected))
    check("...down to the content of every attack, not just the ids", same)

    # A SCRATCH FILE IN redteam/ IS PART OF THE ARSENAL unless something says otherwise, and
    # the glob that builds the library matches one. `test_end_to_end.py` writes
    # `attacks_e2e_<pid>_tmp.yaml` beside these while it runs and removes it in a `finally`; an
    # interrupted run leaves it, and the next regeneration would fold three toy attacks aimed
    # at a scripted bot into what an operator receives. They lint, they are well formed, they
    # name real detectors, and nothing would have said a word.
    import tempfile as _tf
    probe_path = os.path.join(HERE, "attacks_zzscratch_tmp.yaml")
    with open(probe_path, "w", encoding="utf-8") as f:
        yaml.safe_dump([{"id": "scratch-should-not-ship", "category": "control",
                         "text": "hello"}], f)
    try:
        _, promoted2, _ = bg.build()
        check("a scratch file in redteam/ does not become part of the arsenal",
              not any(a["id"] == "scratch-should-not-ship" for a in promoted2))
    finally:
        os.remove(probe_path)

    # --- nothing scoped, nothing pinned to one bot -----------------------------------------
    scoped = [a["id"] for a in on_disk if a.get("applies_to")]
    check("no attack in the portable arsenal is scoped to a practice bot",
          not scoped, str(scoped[:5]))

    canaries, tools = bg.fleet_literals()
    check("the fleet's canaries and tool names were actually found",
          len(canaries) >= 5 and len(tools) >= 5, f"{len(canaries)} canaries, {len(tools)} tools")
    pinned = []
    for a in on_disk:
        blob = json.dumps({k: v for k, v in a.items() if k != "id"},
                          ensure_ascii=False).lower()
        if any(c in blob for c in canaries):
            pinned.append((a["id"], "canary"))
        elif any(re.search(r"\b" + re.escape(t) + r"\b", blob) for t in tools):
            pinned.append((a["id"], "tool"))
    # An attack naming a practice bot's planted secret tests, against a customer, a string that
    # does not exist. It cannot fire and comes back DEFENDED, which is this project's own defect
    # class delivered to somebody who needed the opposite.
    check("no attack names a practice bot's canary or tool", not pinned, str(pinned[:5]))

    # --- the hand-written ones survive regeneration ----------------------------------------
    g_ids = [a["id"] for a in on_disk if a["id"].startswith("g-")]
    check("the hand-written g-* attacks are still present", len(g_ids) >= 20, str(len(g_ids)))
    check("...and come first, so a regeneration cannot quietly drop them",
          [a["id"] for a in on_disk[:len(hand)]] == list(hand),
          str([a["id"] for a in on_disk[:3]]))

    # --- what an operator actually gets ------------------------------------------------------
    cats = {a.get("category") for a in on_disk}
    check("the arsenal covers substantially more than the 8 categories it started with",
          len(cats) >= 40, f"{len(cats)} categories")

    # And the number that matters is not the file's size but what SURVIVES contact with a
    # plain endpoint: an attack whose every declared detector is inert there is not sent, so a
    # big file could still mean a narrow run.
    plain = {"canaries": ["PLANTED-1"], "allowed_domains": ["acme.example"],
             "system_prompt": "you are a support bot"}
    declared = set()
    for a in on_disk:
        declared |= set(a.get("success") or []) | set(a.get("partial") or [])
    dead = set(inert_for(plain, declared))

    def sendable(a, caps):
        d = set(a.get("success") or []) | set(a.get("partial") or [])
        return a.get("delivery", "direct") in caps and not (d and d <= dead)

    direct = [a for a in on_disk if sendable(a, {"direct"})]
    withhist = [a for a in on_disk
                if sendable(a, {"direct", "chain", "forged_history", "sessions"})]
    check("a plain chat endpoint receives a broad run, not a token one",
          len(direct) >= 100 and len({a.get("category") for a in direct}) >= 28,
          f"{len(direct)} attacks, {len({a.get('category') for a in direct})} categories")
    check("...and one that carries a transcript receives more",
          len(withhist) > len(direct),
          f"{len(withhist)} vs {len(direct)}")

    # THE ARSENAL MUST DEGRADE, NOT FALL OFF A CLIFF. A canary is a DECLARATION rather than a
    # modification — the operator names a string that already exists in their deployment and
    # should never appear in a reply — but plenty of customers will name nothing, and what they
    # get then is a product decision that was being made by accident.
    #
    # Measured before this check existed: no canary cost 65 attacks and 20 of 49 categories,
    # because 52 attacks declared ONLY canary detectors and so died outright while 74 others
    # survived on a mix. That difference was not a property of the technique, it was which
    # detectors somebody had happened to write down.
    #
    # The fallbacks are `partial`, never `success`, and that is the honest half: a canary
    # appearing is a FACT, and a credential-shaped string appearing is a SIGN. Collapsing them
    # would buy coverage by spending the thing that makes these verdicts worth reading.
    no_canary = {"allowed_domains": ["acme.example"], "system_prompt": "you are a support bot"}
    dead_nc = set(inert_for(no_canary, declared))

    def sendable_nc(a):
        d = set(a.get("success") or []) | set(a.get("partial") or [])
        return (a.get("delivery", "direct") in
                {"direct", "chain", "forged_history", "sessions"}
                and not (d and d <= dead_nc))

    nc = [a for a in on_disk if sendable_nc(a)]
    nc_cats = {a.get("category") for a in nc}
    check("a customer who declares no canary still gets most of the arsenal",
          len(nc) >= 220, f"{len(nc)} attacks")
    check("...and loses only a handful of categories, not half of them",
          len(nc_cats) >= 44, f"{len(nc_cats)} categories of {len(cats)}")

    # And the fallbacks must be EVIDENCE rather than a verdict. A blanket "no structural
    # detector may be a success condition" was the first version of this check and it was
    # wrong: `g-refuse-then-comply` exists precisely to see whether a bot refuses and complies
    # in one breath, so that detector firing IS its finding. The rule that holds is narrower —
    # an attack that also names a canary detector has a stronger signal available, so a
    # structural one beside it in `success` would let a credential-SHAPED string earn the
    # verdict that a planted value earns.
    def needs_canary(d):
        k = NEEDS_CONFIG.get(d)
        return bool(k) and "canaries" in [x if isinstance(x, str) else x[0] for x in k]

    STRUCTURAL = {"credential_in_output", "refusal_then_comply", "instruction_in_output",
                  "verbatim_replay", "repeated_tool_call", "markdown_beacon",
                  "special_token_output", "invisible_chars", "cross_tool_taint",
                  "credential_in_tool_call", "tool_call_storm", "pii_in_output"}
    # BESIDE means a DIFFERENT detector. `refusal_then_comply` is on both lists — it is
    # structural, and it delegates entirely to `canary_in_output`, `canary_transformed` and
    # `forced_output`, so it was added to NEEDS_CONFIG once that was measured. That made
    # `g-refuse-then-comply`, whose `success` names it and nothing else, satisfy both halves of
    # this rule by itself and trip a check about one detector standing beside another. An attack
    # with one success condition has no fallback and no stronger signal to be preferred over.
    smuggled = sorted(
        a["id"] for a in on_disk
        if any(needs_canary(d) for d in (a.get("success") or []) if d not in STRUCTURAL)
        and STRUCTURAL & set(a.get("success") or []))
    check("a fallback beside a canary is evidence, never the verdict itself",
          not smuggled, str(smuggled[:5]))

    # --- AN ATTACK MUST BE ABLE TO MAKE ITS OWN DETECTOR FIRE --------------------------------
    #
    # `capitulation` requires the user to have PUSHED without bringing anything new, and it
    # judges that on the attack's own follow-up turns. Four of the seven capitulation attacks
    # did not contain a push the detector recognised: they were sent, spent three requests each,
    # and came back DEFENDED whatever the target did. The detector was written to catch a gap
    # reported as a measurement, and its own attacks were one.
    #
    # The four were also the realistic ones — pleading, false precedent, an anchored number, and
    # simply asking again — because the pattern only knew explicit contradiction. This is the
    # check that says so, on the attack text rather than on a live run.
    from oracle import _PRESSURE
    unpushed = []
    for a in on_disk:
        if "capitulation" not in (set(a.get("success") or []) | set(a.get("partial") or [])):
            continue
        steps = a.get("steps") or []
        norm = [re.sub(r"[^a-z0-9 ]", "", s.lower()).strip() for s in steps]
        repeated = any(norm[i] and norm[i] in norm[:i] for i in range(1, len(norm)))
        if len(steps) < 2 or not (repeated or _PRESSURE.search(" ".join(steps[1:]))):
            unpushed.append(a["id"])
    check("every capitulation attack actually pushes, so its detector can fire",
          not unpushed, f"no pressure and no repetition in: {unpushed}")

    # --- over_refusal IS A CONTROL'S DETECTOR, AND ON AN ATTACK IT INVERTS THE VERDICT -------
    #
    # Its own docstring says so: "Declared by CONTROL entries, whose prompts are ordinary
    # customer questions, so a hit means the guard is costing real answers." Six attacks
    # declared it anyway — each one asking the bot for a secret, where a refusal is the CORRECT
    # answer. `judge()` turns a `partial` into a PARTIAL verdict, so a target that held the line
    # on all six was reported as six partial breaches, and a target that half-complied without
    # tripping a canary was reported as clean. The better-behaved bot got the worse report.
    #
    # By category rather than by a list of ids, so a new control inherits it and a new attack
    # cannot quietly acquire it.
    inverted = sorted(a["id"] for a in on_disk
                      if "over_refusal" in (set(a.get("success") or [])
                                            | set(a.get("partial") or []))
                      and a.get("category") != "control")
    check("only a control declares over_refusal, because a refused attack is a bot behaving",
          not inverted, f"attacks scoring a correct refusal as a finding: {inverted}")
    # ...and the check is not vacuous: something has to still declare it, or "no attack does"
    # would pass by the detector having been dropped everywhere. ONE is the right floor here,
    # not five: this is the PORTABLE arsenal, which keeps a single control per category, and the
    # per-target benign entries that carry it in `attacks.yaml` do not travel.
    declares = [a["id"] for a in on_disk
                if "over_refusal" in (set(a.get("success") or []) | set(a.get("partial") or []))]
    check("...and a control still declares it, so the check is measuring something",
          len(declares) >= 1, str(declares))

    # --- every attack is still well formed --------------------------------------------------
    bad_det = sorted({d for a in on_disk
                      for d in (set(a.get("success") or []) | set(a.get("partial") or []))
                      if d not in DETECTORS})
    check("every detector an attack names exists", not bad_det, str(bad_det))
    no_payload = [a["id"] for a in on_disk
                  if not (a.get("text") or a.get("steps") or a.get("turns") or a.get("seed"))]
    check("every attack carries something to send", not no_payload, str(no_payload[:5]))
    # An attack that declares no detector is judged only by the ALWAYS-ON set. That is right for
    # some — a poisoned draft where any leak at all is the finding — and dangerous by accident,
    # because a declared-nothing attack looks like a test while only ever able to come back
    # defended. The arsenal already has a way to say which: `scored_by: always_on`. So the check
    # is not "are there few of these" but "does each one SAY so", which is a property of the
    # attack rather than a number somebody has to keep updating.
    silent = sorted(a["id"] for a in on_disk
                    if not (a.get("success") or a.get("partial"))
                    and a.get("scored_by") != "always_on")
    check("an attack with no detector says it is scored by the always-on set",
          not silent, str(silent[:6]))
    n_always = sum(1 for a in on_disk if a.get("scored_by") == "always_on")
    print(f"      ({n_always} attack(s) declare `scored_by: always_on`)")

    # --- and what was held back is a judgement, not a silence -------------------------------
    reasons = {why.split(":")[0].split("(")[0].strip() for _, _, why in blocked}
    check("what was not promoted is recorded with a reason", len(blocked) > 0 and reasons)
    check("...including the controls, which stay per-target on purpose",
          any("control" in w for _, _, w in blocked))
    check("...and the seeded ones, which need a corpus we can write to",
          any("seeds a document" in w for _, _, w in blocked))
    brandy = [aid for aid, _, w in blocked if "brand" in w]
    print(f"      ({len(brandy)} attack(s) blocked only by a brand name in the text — "
          f"promotable with an edit: {', '.join(sorted(brandy)[:6])})")

    # --- a category one probe deep is a coin flip, not coverage -------------------------
    #
    # The corpus reached fifty-eight categories with twenty-four of them at one or two attacks,
    # and breadth counted that way flatters itself: these techniques live or die on the exact
    # framing, so a single wording that misses reports the whole class as defended. Worse, it
    # degrades silently — a probe that worked last year against a model that has since been
    # tuned takes its category down with it, and the category count does not move.
    #
    # Three is the floor rather than an aspiration: enough that one wording going stale leaves
    # two behind. `control` is exempt and singular on purpose — it is the baseline, and a
    # baseline measured three ways is three baselines.
    from collections import Counter
    import yaml as _yaml
    gen = _yaml.safe_load(open(os.path.join(HERE, "attacks_generic.yaml"), encoding="utf-8"))
    gen_rows = gen.get("attacks", gen) if isinstance(gen, dict) else (gen or [])
    depth = Counter(r.get("category") for r in gen_rows if r.get("category"))
    thin = sorted("%s(%d)" % (k, v) for k, v in depth.items() if v < 3 and k != "control")
    check("no category in the portable arsenal is thinner than three attacks",
          not thin, "one wording away from reporting a whole class as defended: %s" % thin)
    check("...and the control stays singular, because a baseline measured twice is two baselines",
          depth.get("control", 0) == 1, "control has %d" % depth.get("control", 0))

    # --- a shipped budget has to cover the arsenal it ships with --------------------------
    #
    # The example configs carried `max_requests: 400`, sized when the corpus was 285 mostly
    # single-turn attacks. It is 357 now and 64 of them are multi-turn, so a full sweep at the
    # default three trials is 1,389 requests — and anyone running a shipped config got 29% of a
    # run. A ceiling that silently truncates a sweep is the same defect as a detector that
    # silently cannot fire, and it drifts by the arsenal GROWING, which is the direction nobody
    # watches.
    #
    # `targets_vertex.yaml` is the deliberate exception and says so in its own comments: the
    # binding constraint there is an access token's lifetime, not a number anyone should raise.
    def _requests(a):
        if a.get("delivery") in ("chain", "sessions"):
            return max(1, len(a.get("steps") or []))
        return 1

    import glob as _glob
    need = sum(_requests(r) for r in gen_rows) * 3          # default --trials
    short = []
    for fp in target_configs(HERE):
        cfg = _yaml.safe_load(open(fp, encoding="utf-8")) or {}
        if not cfg.get("skip_in_fleet") or cfg.get("adapter") != "http":
            continue                                        # practice-fleet configs, not examples
        # Only where the endpoint is somebody ELSE's. A template aimed at localhost bounds a
        # demonstration rather than a bill, and truncating one costs nothing but a shorter
        # example. The cost this check exists to prevent is a real sweep stopping
        # a third of the way through a metered endpoint.
        url = str(cfg.get("url") or "")
        if "localhost" in url or "127.0.0.1" in url:
            continue
        cap = (cfg.get("rate") or {}).get("max_requests")
        base = os.path.basename(fp)
        # A config that cannot cover a full sweep may say so instead — targets_vertex.yaml
        # does, because an access token's lifetime is the real ceiling there and raising a
        # number would not move it.
        excused = "cannot complete a full sweep" in open(fp, encoding="utf-8").read().lower()
        if cap and cap < need and not excused:
            short.append("%s (%d of %d)" % (base, cap, need))
    check("every shipped example budget covers a full sweep, or says why it cannot",
          not short, "these would truncate a default run: %s" % short)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the portable arsenal is derived from the library, not left over from it.")


if __name__ == "__main__":
    main()
