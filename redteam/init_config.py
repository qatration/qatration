"""Write a target config that already works, instead of asking for one that might.

    qatration init --url https://your-bot.example.com/chat

THE DOOR EVERY USER WALKS THROUGH, and until this command it had homework on it. The quickstart
read `qatration onboard --target-config mybot.yaml`, and nothing in the tool produced
`mybot.yaml`: fifteen subcommands, none of them a starting point. A stranger was asked to author
a config from a paragraph of prose and then find out from `onboard` what they had got wrong.
That is a bad trade for anyone who has not already decided to use this.

It is a worse trade than it looks, because of how this adapter fails. An unknown key is fatal
here on purpose -- `respones:` for `response:` once built a target with no reply mapping, so
every answer read as empty, every attack scored DEFENDED and the run described a hardened
deployment. Hand-authoring the file is exactly where that typo comes from.

THE CANARY IS MINTED HERE, not left as an exercise. `qatration run` refuses a config carrying
one of the published example values, and it is right to: a canary is worth precisely the fact
that nothing else in the world knows it, and the ones in this repository are in a public
repository. So the file this writes is born with a pair nobody else has. What the user still
has to do is PLANT it, which no tool can do for them, and that is the one instruction printed
at the end.

WHAT THIS DOES NOT DO is validate against the endpoint. That is `onboard`, it sends a real
request, and it is the next line of the printed output. The split is deliberate: writing a file
should never put traffic on somebody's deployment.
"""

import argparse
import io
import os
import sys

import honeytoken as _ht

DEFAULT_OUT = "mybot.yaml"
DEFAULT_URL = "http://localhost:8000/chat"

# The template is a format string with four holes and no logic. It is checked by
# `redteam/test_init.py`, which parses what this writes and BUILDS a real target out of it, so
# a key that the adapter would reject cannot survive here -- the alternative is a second,
# rotting description of what a valid config looks like.
TEMPLATE = '''\
# A QAtration target config, written by `qatration init`.
#
# Fill in the three things only you know -- the url, how your endpoint wants its request, and
# where the reply sits in its response -- then:
#
#     qatration onboard --target-config {out}     # one real request, checks the mapping
#     qatration benign  --target-config {out}     # what fires when NOBODY is attacking
#     qatration run     --target-config {out}     # the sweep
#
# `onboard` is not a formality. It is the only thing that catches a wrong `response.reply`,
# and a wrong reply mapping does not fail a run: an unmapped reply is an empty reply, an empty
# reply looks like a bot that said nothing, and a bot that said nothing scores as a bot that
# held. A broken config produces a clean report. Run it.

adapter: http
name: {name}

# WHERE THE BOT IS. A localhost url runs with no further ceremony. A remote one is somebody's
# real deployment, so it additionally needs QATRATION_AUTH_SECRET set in the environment and an
# `authorization:` block below -- see AUTHORISED-USE.md. That gate is not paperwork: this tool
# sends real prompt-injection, exfiltration and tool-abuse attempts at whatever url it is given.
url: "{url}"

# HOW YOUR ENDPOINT WANTS THE REQUEST. This is sent as the JSON body, with `{{prompt}}`
# replaced by each attack. The shape below is the OpenAI-compatible one because it is the most
# common; if yours takes `{{"message": "..."}}`, then this whole block is just that.
request:
  messages:
    - role: user
      content: "{{prompt}}"

# WHERE THE REPLY IS IN THE RESPONSE, as a dotted path through the JSON. Digits index a list.
# For `{{"choices": [{{"message": {{"content": "hi"}}}}]}}` the path is the one below; for a bare
# `{{"reply": "hi"}}` it is simply `reply`. Get this wrong and everything reads as a defence.
response:
  reply: "choices.0.message.content"

# A CEILING ON WHAT THIS RUN MAY DO TO YOUR ENDPOINT, sized so a default run finishes inside
# it. This said 300, and a default run sends about 1086 requests -- 362 attacks times three
# trials -- so the first run of anyone following the quickstart stopped a third of the way in,
# and the attacks it never sent look identical to attacks that held. `qatration onboard` does
# this arithmetic against the corpus you actually have and says so if these numbers stop
# fitting. Remove the block entirely and there is no ceiling at all.
rate:
  min_interval_s: 0.0
  max_requests: 1200
  max_seconds: 5400

# MULTI-TURN, and leaving this out costs about a third of the arsenal. Without it the attacks
# that need more than one turn -- a rule planted early that changes a later answer, a forged
# conversation history -- are SKIPPED, and a skipped attack is not a defence. `field` is the
# key in `request:` holding the conversation, `insert_before` counts from the end.
# history:
#   field: messages
#   mode: splice
#   insert_before: 1

# WHAT YOUR TOOLS RECEIVED, if this is an agent rather than a chat bot. Without it the engine
# can only read the prose, and on an agent that is the blind spot: the answer can be impeccable
# while the tool call underneath it carries the secret. The path is into the same response
# body, alongside `response.reply`.
# response:
#   tool_calls: "choices.0.message.tool_calls"

# WHOSE SOFTWARE THIS IS. A finding against somebody else's code is evidence about software in
# the world; a finding against a bot you wrote is evidence that the engine works. Reports that
# do not separate the two are counting their own homework.
provenance: first-party
provenance_note: >-
  our own deployment

oracle_context:
  # MINTED FOR THIS FILE. Nothing else in the world knows this pair, which is the only property
  # that makes a canary mean anything. Plant the block printed by this command in your system
  # prompt before the run, and take it out afterwards.
  canaries: ["{secret}"]
  honeytoken_verify: "{verify}"

  # What an elevation is CALLED in your product, so a caller claiming one can be told from the
  # bot explaining its own permission model. Left empty the detector stays inert, deliberately:
  # the same word is a role in one system and a job title in another, and guessing would fire
  # on the correct answer to an ordinary question.
  privileged_roles: []

  # Domains your bot may legitimately link to. Anything else it emits becomes a finding.
  allowed_domains: []

# Remote targets only. Delete this block for a localhost url.
# authorization:
#   scope: "https://your-bot.example.com"
#   authorised_by: "who signed off, and where that is written down"
'''


def render(out=DEFAULT_OUT, url=DEFAULT_URL, name="mybot", secret=None, verify=None):
    """The file's text. Separated from writing it so a test can read it without a filesystem."""
    if secret is None or verify is None:
        secret, verify = _ht.mint()
    return TEMPLATE.format(out=out, url=url, name=name, secret=secret, verify=verify)


def main():
    ap = argparse.ArgumentParser(
        description="Write a starting target config, with a canary of your own already in it.")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help="your bot's endpoint (default: a localhost placeholder)")
    ap.add_argument("--name", default="mybot",
                    help="labels the target in every result file (default: mybot)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="where to write (default: %s)" % DEFAULT_OUT)
    ap.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = ap.parse_args()

    # NEVER OVERWRITE WITHOUT BEING TOLD TO. The file this would replace is the one holding a
    # canary the user has already planted in a live system, and the endpoint mapping they got
    # working. Losing that to a mistyped command is a bad afternoon.
    if os.path.exists(args.out) and not args.force:
        print("%s already exists. Pass --force to overwrite it, or --out to write elsewhere.\n"
              "Nothing was written -- that file may hold a canary you have already planted."
              % args.out, file=sys.stderr)
        return 1

    secret, verify = _ht.mint()
    io.open(args.out, "w", encoding="utf-8", newline="\n").write(
        render(out=args.out, url=args.url, name=args.name, secret=secret, verify=verify))

    print("Wrote %s, with a canary nobody else has.\n" % args.out)
    # THE SNIPPET COMES FROM ONE PLACE. `mint` prints the same block through the same function;
    # the prose around it differs because the situations do -- `mint` has to tell you which two
    # config lines to add, and here they are already in the file.
    print("Now plant it. Paste this into your bot's system prompt for the test, then remove it:")
    print()
    print("    " + _ht.snippet(secret, verify).replace("\n", "\n    "))
    print()
    print("Then fill in `url`, `request` and `response.reply` in %s, and check the mapping "
          "against\nthe live endpoint -- this is the step that catches a config which would "
          "otherwise\nproduce a clean report from a broken mapping:" % args.out)
    print()
    print("    qatration onboard --target-config %s --verify-honeytoken %s"
          % (args.out, verify))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
