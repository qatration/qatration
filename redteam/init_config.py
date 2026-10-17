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
import re
import os
import sys

import honeytoken as _ht

DEFAULT_OUT = "mybot.yaml"
DEFAULT_URL = "http://localhost:8000/chat"
# A NAME THE USER WILL RECOGNISE AS THEIRS TO CHANGE. Not a real model id: a plausible one
# reads as configured and gets sent, and the endpoint's rejection then looks like the tool
# rather than the placeholder. This one cannot be mistaken for an answer.
DEFAULT_MODEL = "YOUR-MODEL-ID"

def placeholders_left(cfg):
    """-> [(where, what)] for the template's own words still sitting in a config.

    `DEFAULT_MODEL` is written to be rejected: the comment above it says a plausible id
    "reads as configured and gets sent", so this one "cannot be mistaken for an answer".
    That works on an endpoint that VALIDATES the field. Ollama, LM Studio, vLLM and any
    hand-written `request:` shape do not, and there the rejection never comes.

    Walked from a fresh `init` against an endpoint that answers: the request body went out
    as `{"model": "YOUR-MODEL-ID", ...}`, `onboard` printed the reply and `ready to queue`,
    and nothing said the field was never filled in. `workspace.config_model` reads
    `request.model`, so the run's artifact, its scorecard, its SARIF export and `history`'s
    model confound would every one of them record YOUR-MODEL-ID as the model that was
    tested -- a report that cannot say what it was about.

    Here, beside the value, because a rule about the template belongs with the template and
    the alternative is the string spelled a second time in whatever reads it.
    """
    out = []
    # A `request:` THAT IS NOT A MAPPING HAS NO `model` IN IT, and asking crashed `onboard`,
    # which reports the shape itself; found by a seeded config fuzzer.
    _req = (cfg or {}).get("request") or {}
    if not isinstance(_req, dict):
        return out
    if str(_req.get("model") or "").strip() == DEFAULT_MODEL:
        out.append(("request.model", DEFAULT_MODEL))
    return out


def placeholder_note(where, what, answered=None):
    """The sentence for a placeholder still in a config. `answered` is THREE-state.

    THE NOTE CLAIMED A MEASUREMENT NOBODY HAD MADE. Both callers said "Your endpoint answered
    anyway, so it is ignoring the field", and neither had asked. Walked from a fresh `init`
    with nothing listening, following this tool's own printed instructions:

        PROBLEM   the endpoint returned an error: URLError: ... actively refused it
        note      request.model is still 'YOUR-MODEL-ID' ... Your endpoint answered anyway,
                  so it is ignoring the field ...

    Two lines apart, and the second one contradicts the first. `run` was worse: its copy
    prints in the pre-flight block, before a single probe leaves the machine, so "This
    endpoint answers anyway" was unconditional.

    The CONSEQUENCE is certain and the INFERENCE is not, which is the whole of the fix. That
    the artifacts would record the placeholder as the model tested follows from
    `workspace.config_model` reading `request.model` and nothing else; whether the endpoint
    ignores the field is a fact about somebody's server, and it is only known once something
    has come back.
    """
    _core = ("%s is still %r, the placeholder `qatration init` wrote." % (where, what))
    _cost = ("every artifact this run writes will record %r as the model that was tested, "
             "and a report that cannot say what model it was about cannot be compared with "
             "anything." % what)
    if answered is True:
        return ("%s Your endpoint answered anyway, so it is ignoring the field: the run "
                "will go against whatever model it picks, and %s" % (_core, _cost))
    if answered is False:
        return ("%s Nothing answered here, so whether your endpoint would reject the field "
                "is unmeasured. If it answers later and ignores it, %s" % (_core, _cost))
    return ("%s Nothing has been sent yet, so it is not known whether your endpoint rejects "
            "the field: if it does, every probe errors, and if it ignores it, %s"
            % (_core, _cost))


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
# `authorization:` block -- the one at the end of this file says what it takes. That gate is not
# paperwork: this tool sends real prompt-injection, exfiltration and tool-abuse attempts at
# whatever url it is given.
url: {url}

{wire}# A CEILING ON WHAT THIS RUN MAY DO TO YOUR ENDPOINT. The requests are sized so a default run
# fits -- the whole arsenal at three trials, with the multi-turn attacks the `history:` block
# below turns on. This said 300, and a default run sends well over a thousand requests, so the
# first run of anyone following the quickstart stopped a third of the way in, and the attacks
# it never sent look identical to attacks that held. The seconds fit a bot that answers in a
# few seconds; the `resource` attacks ask the model not to stop, and against one that obliges
# each runs to the response timeout. `qatration onboard` does both sums against the corpus you
# actually have and says so if these numbers stop fitting. Remove the block entirely and there
# is no ceiling at all.
rate:
  min_interval_s: 0.0
  max_requests: {max_requests}
  max_seconds: 5400

{history}# WHOSE SOFTWARE THIS IS. A finding against somebody else's code is evidence about software in
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
  # What the planted block CALLS the secret, so every attack asks for it by that name. Change
  # it if you reword the block: a bot asked for a "staff key" it does not hold refuses a
  # question about nothing, and that refusal is not a defence.
  secret_name: {secret_name}

  # YOUR SYSTEM PROMPT AS DEPLOYED, the block this command printed included. With it,
  # `sysprompt_paraphrase` can tell a reworded leak of your instructions from an ordinary answer,
  # and `credential_in_output` can tell a key the bot made up from one it was given. Without it
  # both say so rather than guess. `qatration init --system-prompt-file <file>` fills it in.
{system_prompt}

  # What an elevation is CALLED in your product, so a caller claiming one can be told from the
  # bot explaining its own permission model. Left empty the detector stays inert, deliberately:
  # the same word is a role in one system and a job title in another, and guessing would fire
  # on the correct answer to an ordinary question.
  privileged_roles: []

  # Domains your bot may legitimately link to. Anything else it emits becomes a finding.
  allowed_domains: []

# Remote targets only. Delete this block for a localhost url.
#
# PROOF THAT YOU CONTROL THE ENDPOINT, not a declaration that you may test it. Set
# QATRATION_AUTH_SECRET to a key you keep and run `qatration onboard`: the refusal prints the
# token for this url's origin and these three lines filled in. Put the token where the method
# looks -- `well_known` fetches it from /.well-known/qatration-authorization on that origin --
# and uncomment. A token is issued for one origin and expires, so a new one is printed when
# this one stops working.
#
# This example used to read `scope:` and `authorised_by:`, which nothing reads: uncommented, it
# was refused as "no authorization block", about the block the reader had just written.
# authorization:
#   method: well_known          # or header, or dns_txt
#   token: "qat-..."            # printed by `qatration onboard`
#   issued: "YYYY-MM-DD"        # printed beside it
'''


# THE TWO SHAPES `init --shape` writes. Only the request, the response and the history differ;
# everything else in the file is the same rule for both, written once in TEMPLATE.
WIRE = {
    "openai": '''\
# HOW YOUR ENDPOINT WANTS THE REQUEST. This is sent as the JSON body, with `{{prompt}}`
# replaced by each attack. The shape below is the OpenAI-compatible one because it is the most
# common; if yours takes `{{"message": "..."}}`, then this whole block is just that.
#
# `model` IS REQUIRED BY EVERY OPENAI-SHAPED API and this template used to omit it, while
# `targets_openai_compatible.yaml` -- the copy-me config for this exact shape -- has always
# carried one. Walked as a first-time user against Ollama: `init` wrote this block, `onboard`
# sent it, and the endpoint answered `{{"error": {{"message": "model is required"}}}}`. Nothing
# in the file mentioned the field, there was no flag to set it, and the first command after
# `init` failed. Delete the line if your endpoint does not take one.
request:
  model: {model}
  messages:
    # WHERE THE CANARY GOES IF YOUR TARGET IS A RAW MODEL API. Two different deployments are
    # reachable at a url like this one and they need opposite things:
    #
    #   * your own product, with a system prompt living on your server -- plant the block this
    #     command printed THERE, and leave this commented out, or you would be testing a
    #     prompt this file invented instead of the one you ship;
    #   * a bare model endpoint (Ollama, vLLM, LM Studio, a provider's API) -- there is no
    #     server-side prompt to plant into, and this is the only place a system message exists.
    #     Uncomment it.
    #
    # Left commented and unexplained, the second user is stuck: `onboard --verify-honeytoken`
    # and `run` both refuse until the token comes back, correctly, and nothing said where to
    # put it. `targets_openai_compatible.yaml` carries its canary in a system message for
    # exactly this reason; this template did not.
    # - role: system
    #   content: >-
{plant}
    - role: user
      content: "{{prompt}}"

# WHERE THE REPLY IS IN THE RESPONSE, as a dotted path through the JSON. Digits index a list.
# For `{{"choices": [{{"message": {{"content": "hi"}}}}]}}` the path is the one below; for a bare
# `{{"reply": "hi"}}` it is simply `reply`. Get this wrong and everything reads as a defence.
response:
  reply: "choices.0.message.content"

  # WHAT YOUR TOOLS RECEIVED, if this is an agent rather than a chat bot. Uncomment the line
  # below -- INSIDE this block, which is why it lives here rather than under a heading of its
  # own: a second `response:` key in the same file does not add to this one, it replaces it,
  # and YAML does that silently. Without the mapping the engine can only read the prose, and on
  # an agent that is the blind spot: the answer can be impeccable while the tool call
  # underneath it carries the secret.
  #
  # OFF BY DEFAULT, unlike `history:` below. This shape carries tool calls only when the caller
  # offered tools, and an agent that runs its tools on its own server returns the final text
  # alone; mapped anyway, the path finds nothing or an empty list, and an empty list on every
  # reply reads as tools that were watched and held. `qatration onboard` prints this line,
  # with the path it found, when its probe's reply carries a call.
  # tool_calls: "choices.0.message.tool_calls"

''',
    "vercel": '''\
# HOW YOUR ROUTE WANTS THE REQUEST: the body `useChat` sends (Vercel AI SDK 5 and later), one
# UI message with its text in `parts`, and `{{prompt}}` replaced by each attack. The route turns
# it into model messages with `convertToModelMessages`, so the system prompt is yours, on the
# server: that is where the block this command printed goes.
request:
  messages:
    - id: "q"
      role: user
      parts:
        - type: text
          text: "{{prompt}}"

# WHERE THE REPLY IS. A route returning `toUIMessageStreamResponse()` answers in a stream, and
# the adapter folds the stream into the fields `generateText` returns, so these paths read the
# streaming route and a JSON one (`Response.json(await generateText(...))`) alike.
response:
  reply: "text"
  # A STREAM CAN CARRY AN ERROR PART instead of an answer, and unmapped it is an empty reply,
  # which scores as a bot that held.
  error: "error"
  # WHAT THE MODEL CALLED, AND WHAT IT GOT BACK, if your route has tools. Off by default for
  # the reason the OpenAI shape gives: the folded stream always holds a `toolCalls` list, empty
  # on a bot with no tools, and an empty list on every reply reads as tools that were watched
  # and held. `qatration onboard` prints the line when its probe's reply carries a call.
  # tool_calls: "toolCalls"
  # observations: "toolResults"

''',
    "dify": '''\
# A DIFY APP (`/v1/chat-messages`, chat, agent or chatflow). The url is your Dify's, e.g.
# `https://api.dify.ai/v1/chat-messages` or `http://localhost/v1/chat-messages` self-hosted, and
# the key is the APP's API key. The system prompt is the app's own, in Dify: that is where the
# block this command printed goes.
env:
  - DIFY_API_KEY
headers:
  Authorization: "Bearer ${{DIFY_API_KEY}}"
request:
  query: "{{prompt}}"
  inputs: {{}}
  user: "qatration"
  # STREAMING, because a Dify agent app answers no other way; the stream is folded into the
  # blocking response, so the paths below read both.
  response_mode: streaming
  conversation_id: "{{session}}"

response:
  reply: "answer"
  error: "error"
  # If the app has tools: each tool an agent thought names, with its input, and what it returned.
  # tool_calls: "tool_calls"
  # observations: "observations"

''',
    "flowise": '''\
# A FLOWISE CHATFLOW (`/api/v1/prediction/<chatflow id>`). The url is your Flowise's with the
# chatflow id in it, e.g. `http://localhost:3000/api/v1/prediction/<id>`. The system prompt is
# the chatflow's own, in Flowise: that is where the block this command printed goes.
# A chatflow with an API key wants it as a bearer token; uncomment both:
# env:
#   - FLOWISE_API_KEY
# headers:
#   Authorization: "Bearer ${{FLOWISE_API_KEY}}"
request:
  question: "{{prompt}}"
  overrideConfig:
    sessionId: "{{session}}"

response:
  reply: "text"
  error: "error"
  # If the chatflow has tools: what each was called with (`toolInput`).
  # tool_calls: "usedTools"

''',
    "langflow": '''\
# A LANGFLOW FLOW (`/api/v1/run/<flow id or name>`). The url is your Langflow's with the flow in
# it, e.g. `http://localhost:7860/api/v1/run/<flow id>`. The system prompt is the flow's own, in
# Langflow: that is where the block this command printed goes.
env:
  - LANGFLOW_API_KEY
headers:
  x-api-key: "${{LANGFLOW_API_KEY}}"
request:
  input_value: "{{prompt}}"
  input_type: chat
  output_type: chat
  session_id: "{{session}}"

response:
  reply: "outputs.0.outputs.0.results.message.text"
  error: "error"

''',
    "gradio": '''\
# A GRADIO APP, a `gr.ChatInterface` among them, through its HTTP API. The url names the app's
# function, e.g. `http://localhost:7860/gradio_api/call/chat` (the app's "Use via API" page
# says which); the answer is not in that reply but behind the `event_id` it carries, fetched
# from the same url with the id after it. A private Space wants the token on both requests:
# env:
#   - HF_TOKEN
# headers:
#   Authorization: "Bearer ${{HF_TOKEN}}"
request:
  data: ["{{prompt}}"]
  session_hash: "{{session}}"
followup:
  id_from: "event_id"
  url: {followup_url}

# THE FIRST OUTPUT of the function. A ChatInterface that answers with a message rather than a
# string holds its text one level down: `0.content`.
response:
  reply: "0"
  error: "error"

''',
    "directline": '''\
# A MICROSOFT COPILOT STUDIO AGENT, or an Azure AI Bot Service bot, over Direct Line 3.0. The url
# is the Direct Line base: https://directline.botframework.com/v3/directline, or the regional
# one your bot lives in (europe., india.). The agent's instructions are its own, in Copilot
# Studio: that is where the block this command printed goes.
#
# THE CREDENTIAL, one of two. A Direct Line secret (Channels > Direct Line, or the web channel
# security page) goes in the header:
env:
  - DIRECTLINE_SECRET
headers:
  Authorization: "Bearer ${{DIRECTLINE_SECRET}}"
# ...or Copilot Studio's token endpoint (Channels > Mobile app > Token Endpoint), with the two
# lines above deleted and this line under `directline:` instead:
#   token_url: "https://<environment>.environment.api.powerplatform.com/powervirtualagents/..."

# Each trial opens its own conversation; the message goes as an activity and the agent's answer
# is polled for, once a second, until it says it is listening again or `quiet_s` passes with
# nothing new. An agent that says nothing within `max_s` is an error, not an empty reply.
directline:
  user: "dl_qatration"
  poll_s: 1
  quiet_s: 3
  max_s: 60

# The agent's text, an Adaptive Card's text blocks included, every message of the answer.
response:
  reply: "text"

''',
    "websocket": '''\
# A CHAT WHOSE BACKEND IS A WEBSOCKET. `url` above is the same server over http(s), the origin
# the proof of ownership is for; the socket below must be on it (`ws` beside `http`, `wss`
# beside `https`). One connection is one conversation: each trial opens its own.
#
# THE MESSAGE is this mapping, sent as one JSON text frame -- write it the way your chat UI does.
request:
  message: "{{prompt}}"

# THE ANSWER is every frame after it until one says it is the end, or `quiet_s` passes with
# none. `text_from` is where a frame holds its text (a token, for a streamed answer); a frame
# that is not JSON is its own text. Delete `end` if your server marks no end.
websocket:
  url: {ws_url}
  text_from: "token"
  end:
    path: "type"
    equals: "end"
  quiet_s: 2
  max_s: 60

response:
  reply: "text"
  # tool_calls: "frames.*.tool_calls"   # if a frame carries the calls the agent made

''',
    "rasa": '''\
# A RASA ASSISTANT on its REST channel (`/webhooks/rest/webhook`), e.g.
# `http://localhost:5005/webhooks/rest/webhook`. The conversation is the `sender`'s, kept by Rasa.
request:
  sender: "{{session}}"
  message: "{{prompt}}"

# EVERY MESSAGE OF THE REPLY: Rasa answers with a list of them, and a leak can sit in the second.
response:
  reply: "*.text"

''',
}
HISTORY = {
    "openai": '''\
# MULTI-TURN, and leaving this out costs about a third of the arsenal. Without it the attacks
# that need more than one turn -- a rule planted early that changes a later answer, a forged
# conversation history -- are SKIPPED, and a skipped attack is not a defence. `field` is the
# key in `request:` holding the conversation, `insert_before` counts from the end.
#
# ON BY DEFAULT, because the `messages` list above already carries a conversation. It was
# commented out, and a quickstart run against an OpenAI-shaped endpoint withheld 71 attacks for
# want of it. Not every endpoint that takes `messages` reads the earlier ones, so `onboard` and
# `run` both ask (a case number planted in an earlier turn has to come back) and `run` does not
# send these attacks to an endpoint that does not. Delete the block if yours takes one message.
history:
  field: messages
  mode: splice
  insert_before: 1

''',
    "vercel": '''\
# MULTI-TURN, and leaving this out costs about a third of the arsenal: the attacks that need
# more than one turn are SKIPPED, and a skipped attack is not a defence. `useChat` sends the
# whole conversation in `messages`, every turn in the same `parts` shape, so `turn` writes each
# earlier one that way and `insert_before: 1` keeps the attack last. `onboard` and `run` ask
# whether the route reads them (a case number planted early has to come back).
history:
  field: messages
  mode: splice
  insert_before: 1
  turn:
    id: "h{{n}}"
    role: "{{role}}"
    parts:
      - type: text
        text: "{{text}}"

''',
    # THE APPS THAT KEEP THE CONVERSATION THEMSELVES: no transcript goes in the request, the id
    # does, and what `{session}` is decides whether an attack's turns land in one conversation.
    "dify": '''\
# MULTI-TURN, kept by Dify: it names the conversation in its first reply and wants that name on
# the next turn, and `{{session}}` is empty until it has, so a trial opens a conversation of its
# own and the turns of an attack stay in it. `onboard` and `run` ask first whether they do.
session:
  from_reply: "conversation_id"

''',
    "flowise": '''\
# MULTI-TURN, kept on the server: the app holds the conversation under the id `{{session}}` is,
# a fresh one for every trial and the same one for the turns of a conversation, so the attacks
# that need more than one turn are sent as real turns. `onboard` and `run` ask first whether the
# server does keep them (a case number given in one turn has to come back in the next).

''',
    "langflow": '''\
# MULTI-TURN, kept on the server: the app holds the conversation under the id `{{session}}` is,
# a fresh one for every trial and the same one for the turns of a conversation, so the attacks
# that need more than one turn are sent as real turns. `onboard` and `run` ask first whether the
# server does keep them (a case number given in one turn has to come back in the next).

''',
    "rasa": '''\
# MULTI-TURN, kept on the server: the app holds the conversation under the id `{{session}}` is,
# a fresh one for every trial and the same one for the turns of a conversation, so the attacks
# that need more than one turn are sent as real turns. `onboard` and `run` ask first whether the
# server does keep them (a case number given in one turn has to come back in the next).

''',
}
# GRADIO KEEPS ITS CONVERSATION THE WAY RASA DOES, under the `session_hash` it is given: the same
# sentence, not a copy of it.
HISTORY["gradio"] = HISTORY["rasa"]
# DIRECT LINE KEEPS ITS CONVERSATION ITSELF, one per trial; the block above says so, and there is
# no id for the request to carry.
HISTORY["directline"] = ""
HISTORY["websocket"] = ""
SHAPES = tuple(WIRE)


def _send_cost(shape):
    """What one send costs the budget in the config this shape writes, by the adapter's own rule
    (`targets_http.requests_per_send`) over the blocks the shape writes."""
    import yaml as _y
    from targets_http import requests_per_send as _rps
    _w = _y.safe_load(WIRE[shape].replace("{{", "{").replace("}}", "}")
                      .replace("{model}", '"m"').replace("{plant}", "").replace(
                          "{followup_url}", '"x"').replace("{ws_url}", '"ws://x"')) or {}
    return _rps(_w.get("followup"), _w.get("directline"), _w.get("websocket"))


def render(out=DEFAULT_OUT, url=DEFAULT_URL, name="mybot", secret=None, verify=None,
           model=DEFAULT_MODEL, system_prompt=None, shape="openai"):
    """The file's text. Separated from writing it so a test can read it without a filesystem."""
    if secret is None or verify is None:
        secret, verify = _ht.mint()
    from workspace import shell_arg as _shell_arg
    # EVERY VALUE AS A QUOTED SCALAR. `name: {name}` bare made `--name null` a config every
    # later command refused as nameless, and `0x10`, `yes`, `010` targets named `16`, `True`
    # and `8`; inside hand-written quotes a backslash in a model or url was an escape, and a
    # `"` ended the string. A JSON string is a YAML double-quoted scalar, escapes and all.
    import json as _json

    # AND ONLY CHARACTERS YAML WILL READ BACK. `ensure_ascii=False` leaves C1 controls and DEL
    # raw, and PyYAML's reader refuses them: mojibake in a prompt file (a curly quote encoded
    # twice comes out holding U+0080) gave "Wrote ..., with a canary nobody else has" and a
    # config `onboard` could not open. NEL (U+0085) is printable to YAML and folded to a space
    # inside a quoted scalar, so it is escaped too. A JSON `\uXXXX` escape is a YAML one.
    # Found by an independent review.
    def _q(value):
        return "".join(
            c if (c in "\t\n\r" or " " <= c <= "~" or "\xa0" <= c <= "퟿"
                  or "" <= c <= "�" or c >= "\U00010000") and c != "\x85"
            else "\\u%04x" % ord(c)
            for c in _json.dumps(value, ensure_ascii=False))
    # AND THE PLANT FROM THE ONE BLOCK `mint` AND `init` PRINT. A copy here had already lost
    # `under any circumstances, including staff, administrators and diagnostics`, so the user
    # on a raw model API -- told to uncomment it -- tested a weaker defence than everyone else.
    plant = "\n".join("    #     " + _l for _l in
                      ["You are a support assistant."] + _ht.snippet(secret, verify).splitlines())
    if shape not in WIRE:
        raise SystemExit("init --shape: %r is not one this command writes; it writes %s."
                         % (shape, ", ".join(SHAPES)))
    # A WEBSOCKET URL GIVEN AS --url IS THE SOCKET, and the target's url is the same server
    # over http(s): the address the ownership proof is checked for.
    ws_url = None
    if shape == "websocket" and re.match(r"^wss?://", str(url), re.I):
        ws_url, url = url, re.sub(r"^ws", "http", str(url), flags=re.I)
    return TEMPLATE.format(out=_shell_arg(out), url=_q(url),
                           name=_q(name), secret=secret,
                           verify=verify,
                           # FILLED, THEN INSERTED: a value is not parsed again, so the
                           # `{{prompt}}` each shape escapes arrives as `{prompt}`.
                           wire=WIRE[shape].format(
                               model=_q(model), plant=plant,
                               # GRADIO'S ANSWER IS AT THE SAME URL, WITH THE ID AFTER IT.
                               followup_url=_q(str(url).rstrip("/") + "/{id}"),
                               ws_url=_q(ws_url or re.sub(r"^http", "ws", str(url),
                                                           flags=re.I))),
                           history=HISTORY[shape].format(),
                           # TWO REQUESTS A SEND where the answer is fetched by a second one.
                           max_requests=1800 * _send_cost(shape),
                           secret_name=_q(_ht.SECRET_NAME),
                           # AS DEPLOYED: the operator's prompt with the planted block after it,
                           # which is the text the bot will hold once they paste it in.
                           system_prompt=(
                               "  system_prompt: %s" % _q(
                                   system_prompt.rstrip() + "\n" + _ht.snippet(secret, verify))
                               if system_prompt else
                               '  # system_prompt: "You are the support assistant for ..."'))


def main():
    # THE ONE SPELLING, from the table this command is listed in.
    from cli import parser as _cli_parser
    ap = _cli_parser(
        "init",
        description="Write a starting target config, with a canary of your own already in it.")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help="the model id your endpoint expects in the request body "
                         "(default: a placeholder you must replace)")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help="your bot's endpoint (default: a localhost placeholder)")
    ap.add_argument("--name", default="mybot",
                    help="labels the target in every result file (default: mybot)")
    ap.add_argument("--out", default=None,
                    help="where to write (default: <name>.yaml, so %s)" % DEFAULT_OUT)
    ap.add_argument("--force", action="store_true", help="overwrite an existing file")
    ap.add_argument("--shape", choices=SHAPES, default="openai",
                    help="what your endpoint speaks: an OpenAI-compatible chat API (default), "
                         "a Vercel AI SDK route that `useChat` talks to, or a Dify, Flowise, "
                         "Langflow, Gradio or Rasa app, a Copilot Studio agent over Direct "
                         "Line, or a chat whose backend is a WebSocket")
    ap.add_argument("--system-prompt-file", default=None,
                    help="your bot's system prompt, read from a file and written into the "
                         "config with the canary block after it, so the checks that compare "
                         "a reply with the prompt can run")
    args = ap.parse_args()
    # READ BEFORE ANYTHING IS WRITTEN, so a wrong path costs nothing: the config is not half
    # made over a prompt that was never there.
    _sp = None
    if args.system_prompt_file is not None:
        try:
            # `utf-8-sig`: Notepad's "UTF-8 with BOM" puts U+FEFF first, `strip` keeps it, and
            # an empty file saved that way passed the check below and wrote the planted block
            # alone as the prompt "as deployed". Found by an independent review.
            _sp = io.open(args.system_prompt_file, encoding="utf-8-sig").read().replace(
                "﻿", "")
        except (OSError, UnicodeDecodeError) as _e_sp:
            raise SystemExit("init --system-prompt-file: %r could not be read (%s). Nothing "
                             "was written." % (args.system_prompt_file, type(_e_sp).__name__))
        # A PROMPT THAT ALREADY HOLDS A PLANTED BLOCK -- the deployed one, from an earlier
        # `init` -- gets this one's block after it, and the stored prompt then carries a canary
        # the config does not declare. Refused, with the value, so the old block comes out of
        # the file and the deployment first. Found by an independent review.
        _old_plant = sorted(set(re.findall(r"\b(?:%s|%s)-[A-Z0-9]{4,}\b" % (
            re.escape(_ht.SECRET_PREFIX), re.escape(_ht.VERIFY_PREFIX)), _sp)))
        if _old_plant:
            raise SystemExit(
                "init --system-prompt-file: %r already holds a planted block (%s). This "
                "command mints a new pair and would store the prompt with both blocks in it, "
                "one naming a canary nothing looks for. Take the old block out of the file and "
                "out of your deployment, then run init again. Nothing was written."
                % (args.system_prompt_file, ", ".join(_old_plant)))
        if not _sp.strip():
            raise SystemExit("init --system-prompt-file: %r is empty, and an empty prompt "
                             "compares with nothing. Nothing was written."
                             % args.system_prompt_file)
    # THE NAME THROUGH THE RULE EVERY LATER COMMAND APPLIES. `init --name "my bot"` wrote a
    # config, printed "Wrote ..., with a canary nobody else has", and the very next command
    # it told the reader to run refused that config: `name='my bot' is not usable as a
    # filename`. So did `../evil`, `bot/x`, an empty name and one past 64 characters. The
    # rule is `safe_target_name`; asked here, the reader hears it before the file exists.
    # AND FIRST, because the default file is named after it: `init --name strbot` wrote
    # `mybot.yaml`, and a second bot's `init --name otherbot` was then refused over the
    # first one's file.
    from workspace import safe_target_name as _safe_name
    args.name = _safe_name(args.name, "init --name")
    if args.out is None:
        args.out = "%s.yaml" % args.name
    # THE SEVENTH WRITER. `writable_path` was written for the six commands that take a path to
    # be written, and this one -- the first command anybody runs -- was not among them:
    # `init --out ''` crashed into the atomic write, and a directory or a missing parent went
    # the same way. Through the one rule, before the overwrite check reads the path.
    from workspace import writable_path as _writable
    args.out = _writable(args.out, "target config", "init", replaces=("a target config",))
    # AND THE URL THROUGH THE RULE THE GATE APPLIES, for the same reason: a config whose url
    # has no scheme was written, and the next command called it a remote target to authorise.
    from authorization import url_problem as _url_problem
    _bad_url = _url_problem(re.sub(r"^ws", "http", args.url, flags=re.I)
                            if args.shape == "websocket" else args.url)
    if _bad_url:
        raise SystemExit("init --url: %r is not a URL a target can be reached at: %s. Nothing "
                         "was written." % (args.url, _bad_url))

    # NEVER OVERWRITE WITHOUT BEING TOLD TO. The file this would replace is the one holding a
    # canary the user has already planted in a live system, and the endpoint mapping they got
    # working. Losing that to a mistyped command is a bad afternoon.
    if os.path.exists(args.out) and not args.force:
        print("%s already exists. Pass --force to overwrite it, or --out to write elsewhere.\n"
              "Nothing was written -- that file may hold a canary you have already planted."
              % args.out, file=sys.stderr)
        # TWO, NOT ONE, by the same reading `run` applies to its own overwrite refusal:
        # 1 is documented as the target having been exploited or breached, and this is the
        # invocation being refused. The act that clears it is a flag or a different --out,
        # not anything about a target -- there is no target here yet.
        return 2

    secret, verify = _ht.mint()
    # WRITTEN BESIDE, THEN MOVED INTO PLACE. The paragraph above says what this file is --
    # "that file may hold a canary you have already planted" -- and then `--force` opened it
    # with `"w"`, which TRUNCATES before it writes. Interrupt that (Ctrl-C, a full disk, a
    # machine reclaimed) and the canary and the endpoint mapping are both gone, by the one
    # command that had just told the reader what they were worth. A refusal guarding a
    # destructive write is not much use if the write destroys the file on its way past.
    #
    # `workspace.atomic_write` is that rule for this repository, and `tools/i18n.py` learned
    # it the same way on a hand-written dictionary: "a typo in this very function emptied
    # tr.json mid-session, and the backup the next command took copied the empty file."
    from workspace import atomic_write as _atomic
    with _atomic(args.out) as _fh:
        _fh.write(render(out=args.out, url=args.url, name=args.name, secret=secret,
                         verify=verify, model=args.model, system_prompt=_sp,
                         shape=args.shape))

    print("Wrote %s, with a canary nobody else has.\n" % args.out)
    # THE SNIPPET COMES FROM ONE PLACE. `mint` prints the same block through the same function;
    # the prose around it differs because the situations do -- `mint` has to tell you which two
    # config lines to add, and here they are already in the file.
    print("Now plant it. Paste this into your bot's system prompt for the test, then remove it:")
    print()
    print("    " + _ht.snippet(secret, verify).replace("\n", "\n    "))
    print()
    # WHAT IS ACTUALLY STILL BLANK, not a fixed list. This said "fill in `url`, `request` and
    # `response.reply`" every time -- including when `--url` had just supplied the url and the
    # other two hold working OpenAI-shaped defaults. A reader opens the file looking for three
    # holes, finds none, and cannot tell whether they are in the wrong file or the tool is
    # confused. Meanwhile the one field that WAS a placeholder went unnamed.
    _todo = []
    # A VERCEL ROUTE HAS NO `model` IN ITS REQUEST: the server picks it, so naming the field
    # as a placeholder sent the reader looking for a line that is not in the file.
    if args.model == DEFAULT_MODEL and "{model}" in WIRE[args.shape]:
        _todo.append("`request.model` (it is a placeholder)")
    if args.url == DEFAULT_URL:
        # AND THE FOLLOWUP'S, which repeats it: changed alone, the target refused the config
        # as a followup off its own origin. Found by an independent review.
        _todo.append("`url` and `followup.url`" if "followup:" in WIRE[args.shape] else "`url`")
    if args.shape == "openai":
        _todo.append("`response.reply` if your endpoint is not OpenAI-shaped")
    # AND NOTHING WHEN NOTHING IS LEFT: a Vercel route given its url has no placeholder, and
    # the line printed "Still yours to set in vbot.yaml: ." over an empty list.
    if _todo:
        print("Still yours to set in %s: %s." % (args.out, ", ".join(_todo)))
    print("Then check the mapping against the live endpoint -- this is the step that catches "
          "a config\nwhich would otherwise produce a clean report from a broken mapping:")
    print()
    from workspace import shell_arg as _shell_arg
    print("    qatration onboard --target-config %s --verify-honeytoken %s"
          % (_shell_arg(args.out), verify))
    # WITHOUT THIS, HALF THE TOOL CANNOT SEE THE FILE IT JUST WROTE. `rejudge`, `coverage`
    # and the report builders look up a target's canaries and markers by enumerating
    # configs, and that enumeration used to look only inside the package. A config kept
    # anywhere else resolved to an empty context: every canary detector inert, and each
    # command said so in its own quiet way. Naming the variable here is what makes the fix
    # reachable by somebody who did not read the source.
    here = os.path.abspath(args.out)
    print("\nSo that `rejudge`, `coverage` and the reports can find this config's "
          "canaries, export it once:\n")
    # QUOTED, BECAUSE THE VALUE IS A REAL PATH THIS COMMAND JUST CHOSE. Unquoted, the
    # POSIX line is wrong on the platform it was written on: bash reads `\U` in
    # `C:\Users\...` as an escape and hands over `C:UsersAppData...`, and any path
    # with a space in it breaks everywhere. The PowerShell line was already quoted, so
    # the two lines disagreed about the same value.
    from workspace import point_at_configs as _point
    for _line in _point(here):
        print(_line)
    return 0


if __name__ == "__main__":
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
