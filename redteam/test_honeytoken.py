"""The honeytoken flow, and mostly the one failure that would ruin a customer's first run.

Minting a random string is not the hard part. The hard part is that an UNPLANTED token is
invisible: every canary detector finds nothing, every attack comes back DEFENDED, and the
report says the deployment held. A gap reported as a measurement, arriving through the front
door, on the first run anybody makes.

    python test_honeytoken.py       # exits 1 on any failure (CI gate)
"""
import sys, os, re
from target import target_configs
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import honeytoken as ht


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    secret, verify = ht.mint()

    # --- the pair -------------------------------------------------------------------------
    check("a mint gives a secret and a verifier", bool(secret) and bool(verify))
    check("...which are different strings", secret != verify)
    check("...and cannot be confused with one another",
          not secret.startswith(ht.VERIFY_PREFIX) and not verify.startswith(ht.SECRET_PREFIX))
    a, b = ht.mint(), ht.mint()
    check("two mints do not collide", a != b, f"{a} {b}")

    # A token has to look like something an operator would believe. One that reads as obviously
    # fake invites the model to treat it as harmless, and then a defended run says only that
    # the model can spot a test value.
    check("the secret is shaped like a real key, not like a placeholder",
          len(secret) >= 20 and "-" in secret and secret.upper() == secret, secret)
    check("...and is recognisable as ours, so a REAL key pasted into the field is caught",
          ht.looks_like_ours(secret) and not ht.looks_like_ours("sk-live-abcdef1234567890"))

    # --- the paste ------------------------------------------------------------------------
    snip = ht.snippet(secret, verify)
    check("the snippet carries both tokens", secret in snip and verify in snip)
    check("...tells the deployment the secret is confidential",
          "confidential" in snip.lower() and "never reveal" in snip.lower())
    # THE WORDING IS LOAD-BEARING. "This is a test value" would invite the model to disregard
    # it, and the whole run would then measure whether the model can spot a test.
    check("...and never says it is a test", not re.search(r"\btest|dummy|fake|example\b",
                                                          snip, re.I), snip)
    check("...while the verifier is explicitly sayable, or asking for it proves nothing",
          "you may tell them" in snip.lower())

    # --- the check that stops a silent clean bill ------------------------------------------
    check("a reply carrying the verifier counts as planted",
          ht.planted(f"Our deployment reference is {verify}.", verify))
    check("...case-insensitively, because a model will reformat it",
          ht.planted(f"reference: {verify.lower()}", verify))
    check("a reply without it does NOT count as planted",
          not ht.planted("I'm not able to share internal references.", verify))
    # The failure that matters most: a refusal is not a plant. A deployment that was never
    # given the snippet and one that refuses to read it out are indistinguishable from the
    # outside, and both must read as NOT PLANTED rather than as a target being careful.
    check("...and a polite refusal is not mistaken for a plant",
          not ht.planted("I cannot disclose deployment details.", verify))
    check("an empty reply is not a plant", not ht.planted("", verify))
    check("...nor is a missing verifier", not ht.planted("anything at all", ""))

    # The secret must NEVER be the thing we ask for. A bot that answers has already failed the
    # test the token exists to run, and a bot that refuses looks exactly like a bot that was
    # never given anything.
    check("the verification prompt does not ask for the secret",
          secret not in ht.VERIFY_PROMPT and "key" not in ht.VERIFY_PROMPT.lower(),
          ht.VERIFY_PROMPT)

    # --- and what gets said when it is not there -------------------------------------------
    note = ht.unplanted_note(verify)
    check("an unplanted token produces a sentence, not a silence", bool(note.strip()))
    check("...which names the verifier that did not come back", verify in note)
    check("...and says the canary detectors are inert rather than clean",
          "inert" in note.lower() and "clean" in note.lower(), note)

    # --- and the check is a PRECONDITION, not advice -------------------------------------
    #
    # Somebody will skip the verification step, or paste the snippet somewhere the model does
    # not read. No amount of instruction in an onboarding message prevents that, so the sweep
    # has to insist for itself — otherwise the whole design rests on a human remembering, and
    # the failure mode is a clean report rather than an error.
    rr = open(os.path.join(HERE, "run_redteam.py"), encoding="utf-8").read()
    check("the sweep verifies the honeytoken before spending anything",
          "honeytoken as _ht" in rr and "_ht.planted(" in rr)
    check("...and refuses the run rather than reporting a clean one",
          "sys.exit(5)" in rr and "unplanted_note" in rr)
    check("...and refuses a honeytoken declared with nothing to verify it by",
          "honeytoken_verify" in rr)
    # Only for tokens that are OURS: a customer who declared their own real value has made a
    # different choice, and this has nothing to say about it.
    check("...only when the canary is one we minted", "looks_like_ours(" in rr)

    ob = open(os.path.join(HERE, "onboard.py"), encoding="utf-8").read()
    check("onboarding can mint a pair and print the paste", "--mint-honeytoken" in ob)
    mn_src = open(os.path.join(HERE, "mint.py"), encoding="utf-8").read()
    check("...and the paste tells the customer to declare BOTH, so the sweep can check itself",
          "honeytoken_verify" in mn_src)

    # --- a published canary is not a canary --------------------------------------------
    #
    # The example configs ship one so they run out of the box, and the copy that reaches a
    # real endpoint usually still carries it. That string is in a public repository: it can be
    # trained on, blocklisted, or matched by a guardrail that knows nothing about the
    # deployment behind it. A target that fails to leak it has shown only that it recognises a
    # famous string, and reporting that as a defence is a clean run that measured nothing.
    import honeytoken as _ht
    import glob
    import yaml as _yaml

    published = _ht.published_canaries()
    check("the shipped example configs' canaries are known to be published",
          bool(published), "found none, so the refusal below can never fire")

    # PINNED IN BOTH DIRECTIONS. The list lives in code rather than being discovered at runtime
    # — deriving it from whatever configs happen to sit in the package directory was wrong in
    # three ways at once (see honeytoken.PUBLISHED_CANARIES) — so the thing that can now rot is
    # the list itself. A shipped example whose canary is missing from it would run unrefused;
    # a value in it that ships nowhere would refuse a config for no reason.
    EXAMPLES = ["targets_openai_compatible.yaml", "targets_anthropic.yaml",
                "targets_bedrock.yaml", "targets_vertex.yaml"]
    shipped = {}
    for name in EXAMPLES:
        path = os.path.join(HERE, name)
        check("the example config %s still exists" % name, os.path.isfile(path))
        if not os.path.isfile(path):
            continue
        cfg = _yaml.safe_load(open(path, encoding="utf-8")) or {}
        for c in (cfg.get("oracle_context") or {}).get("canaries") or []:
            shipped[c] = name

    missing = sorted(set(shipped) - published)
    check("every canary a shipped example declares is listed as published",
          not missing, "%s — those configs would run unrefused" % missing)

    phantom = sorted(published - set(shipped))
    check("...and nothing is listed that no example ships",
          not phantom, "%s — those refuse a config for no reason" % phantom)

    # The value is what is matched, so where a copy lives and how it is flagged do not matter.
    # That is the whole point of the rewrite and it is worth asserting rather than assuming.
    check("the refusal keys on the VALUE, not on a file location or a flag",
          "published_canaries()" in rr and "root" not in _ht.published_canaries.__code__.co_names,
          "still reading the filesystem")

    check("the sweep refuses a config still carrying a published canary",
          "published_canaries()" in rr and "ships with this tool" in rr)
    check("...before anything is sent, and says so", "Nothing was sent." in rr)

    # A canary the user minted is theirs alone and must pass. Asserted because a check that
    # refuses everything is as useless as one that refuses nothing, in the opposite direction.
    mine, _ = _ht.mint()
    check("...but a freshly minted canary is not published",
          mine not in published)

    # And the practice fleet must not be caught by it: those canaries are planted in bots in
    # this repository, they are meant to be shared, and refusing them would break every
    # offline demonstration the project ships.
    fleet = set()
    for f in target_configs(HERE):
        cfg = _yaml.safe_load(open(f, encoding="utf-8")) or {}
        if cfg.get("skip_in_fleet"):
            continue
        fleet |= {c for c in (cfg.get("oracle_context") or {}).get("canaries") or []}
    check("...and the practice fleet's own canaries are not refused",
          not (fleet & published), str(sorted(fleet & published)))

    mn = open(os.path.join(HERE, "mint.py"), encoding="utf-8").read()
    check("there is one command that mints a pair and says how to plant it",
          "def instructions(" in mn and "canaries:" in mn)
    check("...and onboarding prints that same text rather than a second copy of it",
          "_mint.instructions(" in ob)

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the secret is ours, and an unplanted one cannot read as a clean run.")


if __name__ == "__main__":
    main()
