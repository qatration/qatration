"""Mint a canary pair that belongs to you and to nobody else.

    qatration mint

A canary is only worth the fact that nothing else in the world knows it. The example configs
ship one so they run out of the box, and that value is published — it sits in a public
repository, where it can be trained on, blocklisted, or matched by a guardrail that knows
nothing about the deployment behind it. A target that fails to leak a published string has
shown that it recognises a famous string, which is not what anyone was testing. `qatration run`
refuses a config that still carries one, before sending anything.

So every run gets its own. This prints the pair, the block to paste into your system prompt,
and the two config lines that make the detectors able to speak.

TWO TOKENS, NOT ONE, and the second is what keeps the first honest. An unplanted canary is
invisible: every canary detector finds nothing, every attack comes back DEFENDED, and the
report says the deployment held. It cannot be checked by asking the bot for the secret, because
a bot that answers has already failed the test the token exists to run. So the pair carries a
public verifier the deployment is told it MAY say, and asking for that is an ordinary question
with an unambiguous answer.

Nothing real is involved. The value the attacks hunt for is one this command generated,
and it stops meaning anything the moment you remove it.
"""

import honeytoken as _ht


def instructions(secret, verify, config_path="<your.yaml>"):
    """The whole minting message, in one place.

    One copy, because `onboard --mint-honeytoken` prints it too and two copies of an
    instruction are two instructions: the day one of them starts naming a command that no
    longer exists, it will be the one nobody ran while editing.
    """
    return "\n".join([
        "Paste this into your system prompt for the duration of the test, then remove it:",
        "",
        "    " + _ht.snippet(secret, verify).replace("\n", "\n    "),
        "",
        "Then put both values in your target config:",
        "",
        "    oracle_context:",
        '      canaries: ["%s"]' % secret,
        '      honeytoken_verify: "%s"' % verify,
        "",
        "Before the run, confirm the paste actually landed:",
        "",
        "    qatration onboard --config %s --verify-honeytoken %s" % (config_path, verify),
        "",
        "Nothing real leaves your side. The value the attacks hunt for is one this command "
        "generated, and it stops meaning anything the moment you remove it.",
    ])


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Mint a canary pair unique to this deployment, and print how to plant it.")
    ap.add_argument("--config", default="<your.yaml>",
                    help="your target config, used only to spell the verify command correctly")
    args = ap.parse_args()

    secret, verify = _ht.mint()
    print(instructions(secret, verify, args.config))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
