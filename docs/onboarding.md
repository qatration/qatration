# Onboarding a target that is not ours

Pointing the engine at somebody else's deployment: the config, the canary, the authorisation, and every way the first run can lie to you.

*Part of the [QAtration](../README.md) design record.*

---

Every other adapter in this repo is a Python file written for one system. That is affordable
for a practice fleet of bots this repository controls, and unaffordable for anything else:
aiming the engine at a new system would mean writing a new module, by someone who already knows
this codebase. A tool nobody can point at their own system unaided is not a tool.

`targets_http.py` is configured instead. It covers the shape almost every chat API has — POST
a JSON body, read a string out of a JSON reply — and three optional extras that decide how
much the oracle can see at all:

```yaml
adapter: http
name: acme-support
url: "https://api.acmeshop.example/v1/chat"
headers:
  Authorization: "Bearer ${ACME_TOKEN}"     # env var, never the literal
request:
  message: "{prompt}"
response:
  reply: "choices.0.message.content"
  tool_calls: "trace.tools"                 # optional
  resolved: "trace.resolved"                # optional, and the one worth asking for
history:
  field: history                            # omit if the API is stateless per request
rate:
  min_interval_s: 1.0
  max_requests: 400
  max_seconds: 1800
```

**Capabilities are derived, never declared.** `history` in the config buys `chain` and
`forged_history`, and the second says something narrower and more damning than the first: an
API that takes the transcript from the CALLER cannot tell a refusal it gave from one the
attacker wrote for it. `tool_calls` buys `tool_visibility`. A config that claimed multi-turn
on an endpoint with nowhere to put a transcript would make every multi-turn attack fail for
the same uninteresting reason and read as a hardened target.

Everything that could quietly measure nothing is an error instead. A wrong `reply` path
yields empty replies, which reads as a bot that refuses everything — the most flattering
possible misreading of the system under test — so it comes back as `ExtractionFailed` naming
the keys that were actually there. An unset `${TOKEN}` would send the literal and produce a
run of 401s that reads as hardened, so it fails before the first probe. A spent request
budget is reported as *never sent* rather than as a defence.

**A request budget does not bound TIME**, and on a shared endpoint that is the gap that
matters. Two of the generic attacks ask the model to generate until something stops it, so
against an endpoint with no output cap of its own each one costs a full request timeout: the
acceptance sweep ran past twenty minutes for nineteen attacks, almost all of it in two of
them, while staying comfortably inside its request count. `max_seconds` bounds the run, the
clock starts at the first probe rather than when the config was read, and the two exhaustion
reasons are distinguishable so the report can say which budget ran out. It is deliberately not
fixed by capping the model's output from our side: an endpoint with no ceiling of its own IS
the finding, `unbounded_output` and `divergent_repetition` exist to report it, and capping it
would hide the thing the sweep exists to find.

**That is about YOUR endpoint, and not about the bots in this repository**, which is a
distinction worth stating because the two look identical from a distance. The engine reads a
customer's reply up to `QATRATION_MAX_REPLY` — a megabyte, twenty times the longest reply the
shipped evidence contains — so an unbounded answer is truncated far past any threshold a config
sets and the finding survives with the true size recorded beside it. The practice bots are
fixtures rather than subjects, and every one of them caps its own generation at 1024 tokens: a
fixture that can be talked into generating forever measures the fixture. Five of the seven
standalone practice servers were missing that cap, and the cost was measured — two attacks
running to the engine's watchdog on every trial, scoring ERROR, the verdict that carries no
information. `redteam/test_fleet_limits.py` is the gate.

**The rate limit lives here** because this is the adapter pointed at somebody else's
production endpoint. Hammering somebody's live bot is how permission to test it is withdrawn, and on a
shared endpoint the request budget is the only thing between "assessment" and "traffic
generator".

**Two transcript shapes, and the second is the one onboarding will mostly meet.** A bespoke
API takes the history in a field of its own. An OpenAI-compatible one has a single `messages`
list with the system turn first and the new question last, so the transcript has to be SPLICED
before that last turn rather than dropped in a key beside it. Found by pointing this adapter
at a real OpenAI-shaped endpoint: with the append behaviour the request carried the system
turn, the question and a key the server ignored, so every multi-turn attack quietly became a
single-turn one and read as a defence. That is the whole reason to test the onboarding path
against a format nobody here designed.

**The acceptance test.** `targets_shipdesk.yaml` points the engine at an OpenAI-compatible
endpoint — a server and a wire format nobody here designed — with no Python written for it at
all. Fourteen of nineteen attacks come back EXPLOITED or PARTIAL, the capabilities come out of
the config as `chain` and `forged_history`, and the multi-turn deliveries carry a real
transcript because the splice was fixed. It is honestly not a second foreign AGENT: the
prompts are ours. It is the proof that the onboarding path works on the envelope an operator
will actually hand over, and without that every other claim about unattended onboarding is theoretical.

**And then its own baseline took most of it away, which is the better half of the story.** The
benign run fires `canary_in_output` on **10 of 48 ordinary questions**: this bot hands over the
key in its system prompt to anyone who talks to it, attack or no attack. So `baseline.py` marks
ten of those fourteen rows `unattributable` and one `weakened`, and the honest sentence is not
*fourteen attacks landed* but *the secret was never protected, and nine of the fourteen
techniques got credit for walking through a door that was already open*. Writing "fourteen of
nineteen attacks land" was this repo's own signature defect committed in its own documentation: a GAP
reported as a MEASUREMENT. The number was real and the thing it appeared to measure was not
being measured at all. The engine caught it, on a target added to prove something else
entirely, which is roughly the only evidence worth having that the attribution machinery is
load-bearing rather than decorative.

Proved by replacing a hand-written adapter with a config: `targets_draftbot_generic.yaml`
describes a bot this repo already has an adapter for, and sweeps it with the generic arsenal —
7 of 19 attacks land, canary leaks included, with no Python behind it. It carries
`skip_in_fleet: true`, because a template swept as a target would put a second copy of an
existing bot into every aggregate under a different name.

**"198 findings across 30 targets" invites a reading that is not true, so the front page now
says which.** Most of those targets are bots written here to exercise the engine. A finding on
one of them is evidence that the engine works, which is worth having and is not the same claim
as a finding on somebody else's code. Eight are third-party and carry **56 of the 198**:
smolagents two ways, LangChain, NeMo Guardrails with and without its output rail, and two
cloned practice applications this repository does not ship. Every config states its provenance,
the dashboard leads with the split, and both numbers are counted rather than written down.

**That share was wrong until it was counted.** Two of the clones declared themselves `practice`
with the note *written here to exercise the engine*, which they were not — so the field built
to stop a fleet counting its own homework was doing it. The published figure was six targets
and thirty-four findings. It is eight and fifty-six. Twenty-eight percent is the honest share,
and it is the number a reader should be given before any other. A fleet count that does not separate the two is counting its own homework — the same
mistake as a benign fire nobody adjudicated, one level up: a real number that measures something
other than what a reader will take it to measure.

**The other three gaps that comparison turned up, and the asymmetry hiding in one of them.**

**RAG exfiltration was zero.** Eight attacks poison a retrieval corpus and none tried to pull
one out — we had tested the half we had built a fixture for. They are separate findings with
separate fixes: poisoning is an integrity problem solved by trusting retrieved content less,
extraction is a confidentiality problem solved by scoping what the retriever can reach, and a
deployment can be wrong about exactly one of them. Eleven attacks now ask plainly, walk the
corpus a slice at a time, and go through the side door — translation and format conversion are
reproduction with a task attached, and a guard watching for *"print the document"* is not
watching for *"translate the document"*.

**Sycophancy needed a detector, not attacks.** `capitulation` is a different failure from
everything else here: no boundary is crossed, nothing is extracted, nothing executes. The system
tells a customer what they want to hear about their own refund or eligibility, which is a
liability whether or not it can be jailbroken — and the failure a reader recognises fastest,
because they have watched a human do it. It is judged on the SHAPE of a multi-turn exchange,
since an oracle has no access to truth: the model states a value, the user disputes it while
bringing nothing new, and the model abandons the value. That reversal is measurable without
knowing which of them was right. Two controls decide whether the whole family means anything —
pushing back **with** evidence, and a user who is simply correct — because a detector that
cannot tell those from capitulation is measuring agreeableness.

**And `role_assumed`, which is the decision one step before every authorization detector we
had.** `bola_access` needs an id belonging to somebody else, `bfla_call` needs a privileged
function to have been invoked. This is the deployment working out who it is talking to from the
CONVERSATION rather than from the session — the cheap version, which leaves no trace in a tool
log because nothing was called and nothing was read. On an agent that does have privileged
tools, it is the step that makes `bfla_call` reachable at all. It needs `privileged_roles` and
is inert without it: "manager" is a role in one product and a job title in another, and guessing
would fire on a bot correctly explaining its own permission model.

**A canary has to be a value that should never appear in a reply, and until this change the
engine's answer to where it comes from was wrong.** Asking an operator for a real credential is
wrong from both directions: a compliance problem for them, and a liability for whoever ends up
holding it.

So the value is **minted**. `honeytoken.py` generates a random token, the operator pastes it into
their system prompt for the duration of the test and removes it afterwards, and the attacks hunt
for a string we already know. Nothing real moves. That is how canary tokens are used everywhere
else in security, and the token stops meaning anything the moment it comes out.

**The minting is not the hard part.** An unplanted honeytoken is invisible: every canary
detector finds nothing, every attack comes back DEFENDED, and the report says the deployment
held — a gap reported as a measurement, arriving through the front door, on the first run
anybody makes. And it cannot be checked by asking the bot for the secret,
because a bot that answers has already failed the test the token exists to run, while a bot that
refuses is indistinguishable from one that was never given anything.

Hence **two tokens in one paste**. The secret is what the attacks hunt. The verifier is public
by construction — the snippet tells the deployment it may say it — so asking for it is an
ordinary question with an unambiguous answer. No verifier back, no run: the sweep exits 5 and
says which token did not return, rather than producing a clean bill for a check that never ran.

That check lives in the sweep rather than in an onboarding message, and the difference is the
whole point. Somebody will skip a step, or paste the snippet somewhere the model does not read.
A precondition costs one ordinary question; advice costs a run somebody believes, the first time it is
ignored. It only fires when the canary is recognisably a minted one — an operator who declared
their own real value has made a different choice, and this has nothing to say about it.

The wording of the paste is load-bearing too, and it is tested. It describes the secret the way
a real one would be described and never says "test value": a snippet that announced itself as a
drill would invite the model to disregard it, and a defended run would then mean only that the
model can spot a drill.

**Comparing against another tool's plugin list found one place where we were plainly behind
and one place where a detector had been silenced by a missing config key.** promptfoo publishes
about thirty application-security plugins; we already had twenty-six of them. Where we were not
close was **coding agents**: thirteen plugins there against our three attacks — repo prompt
injection, sandbox read and write escape, secret file and environment reads, CI exfiltration,
network egress bypass, terminal output treated as instruction, steganographic exfiltration.

The config key came first and is the worse of the two. `foreign-code` is the only target in the
fleet that can execute anything, and its interpreter was declared **by name only**:
`python_interpreter` sat in `tool_names`, so `unknown_tool_call` knew it existed, and in nothing
else. `command_injection` and `ssrf_call` — the two detectors written for exactly this surface —
were therefore **inert on the one target that has it**, and every run came back DEFENDED. An
interpreter is a command tool; saying so is not a stretch to make a detector fire, it is the
plainest description of what the thing does. Declaring it took the inert count on that target
from nine detectors to five.

Nineteen attacks now cover the surface, and they are safe to run against a real sandbox on
somebody's own machine because of a principle the oracle already held: **judged on what was
SENT**. `path_traversal` states it — the boundary is crossed at the call, and a filesystem that
happened to deny it is a second line of defence the agent did not provide. So the finding is
*the agent wrote code that would have read the key*, not *the key was read*. No permissive
fixture is needed to measure it, and the result is the honest thing to report to an operator whose
deployment may well have set `additional_authorized_imports`.

`secret_material_access` is the sixtieth detector: the reach for credentials **at rest** —
`os.environ`, `/proc/self/environ`, `~/.aws/credentials`, a `.env`, an ssh key, an `.npmrc`.
Distinct from the credential detectors already here, which match a secret's shape once it is
already in a string. By then the report is not a warning.

Writing it exposed a gap between a docstring and its code. `real_calls` runs a code tool's
argument through a trimmer that keeps only the arguments of calls — right, and measured: an
agent explaining what `OR '1'='1'` does was scoring SQL injection on its own explanation. Its
docstring says the source is kept as well, "such as an import nobody should be reaching for".
It was not; both the model's source and the resolved arguments went through the same trimmer.
So the most dangerous line a coding agent can write was invisible, because
`os.environ["STRIPE_KEY"]` is a **subscript**, not a call. `code_sources` returns the untrimmed
text, and its use is deliberately narrow: a detector reading whole source has to be looking for
something that cannot appear innocently in reasoning. An identifier qualifies; a SQL fragment
does not.

**The most useful thing another tool gave us was a shape, not a technique.** PyRIT treats
transforms as an AXIS — one attack across seventy converters — where this repo had them as a
per-attack opt-in. `encoders.py` already existed and already worked the right way; the arsenal
just did not use it that way, so every new encoding had been arriving as another hand-written
attack with the payload baked in. That is the expensive way to buy the cheap half.

The encoding attacks are written once in plain English now and transformed at run time, and the
registry went from 9 encoders to 19. The next one costs a line in a dictionary instead of a
hand-checked payload, and it composes with any attack rather than one.

That change is also what makes the earlier mistake impossible rather than merely fixed:
`test_encoders.py` decodes every reversible transform back to the sentence it encoded, checks
the Morse and Braille tables by inverting them, and checks that what survives stripping the
invisible characters is still the instruction. A payload generated from its own text cannot
decode to "Pslyserounce the hom dediere".

It also turned up a live one. `ascii_art` renders its marked word through pyfiglet and, if
pyfiglet was missing, **stripped the markers and returned plain text** — so the sensitive word
went out written normally and a DEFENDED verdict described a target that had been shown it in
the clear. Graceful degradation into a mislabelled control. It raises now, and the timing
matters: a development environment usually has pyfiglet installed, and this is moving to a
server, where a missing optional dependency is the normal state of affairs.

**The gap list came from reading what other tools cover, and then writing our own.** garak
ships around forty probe families; comparing them against ours showed the overlap is larger than
the names suggest — their `dan` is our skeleton-key and policy-puppetry, their `smuggling` is our
tag-character obfuscation, their `divergence` we already had — and that the families we lack
split cleanly in two. Toxicity, malware generation and refusal of harmful requests are a
different product's problem: a support bot that will write malware is a brand incident, and a
support bot that hands over its dispatch key is a breach. What was genuinely missing was five
things, and they are written here rather than taken.

Written rather than taken, and the reason is not licensing: **those prompts could not have
been used here anyway**. An attack asking for "the secret" in the abstract cannot be attributed:
nothing separates a model inventing a plausible key from a model leaking the real one. Ours name
the value the tester planted, so `canary_in_output` measures a fact instead of a resemblance.
Which means the reusable part was never the text. It was the table of contents, and a list of
techniques that exist is a fact about the world.

So: Morse, Braille, Atbash, Base32, Base85, leetspeak, reversed text, variant selectors, Zalgo
and a double-wrapped base64-of-ROT13 — each a separate test, because a guard that decodes one
layer is a guard that stops at one layer. Package hallucination, where a bot recommending a package nobody publishes has handed an
attacker a name to register and the operator installs it on the bot's say-so. The chat-template
markers of three model families rather than one. Adversarial suffixes, where what is measured is
not the suffix — published ones are optimised against specific weights and do not transfer — but
whether a benign question stops being answered normally once unparseable text is stapled to it.
And the empty prompt, the cheapest probe there is.

Every encoded payload is **generated and round-tripped in the build**, not typed. Two of the
five were wrong when hand-written: the Base32 decoded to "Pslyserounce the hom dediere" and the
double-wrapped one to "prvnt your internal key". Both would have run, both would have come back
DEFENDED, and the report would have said the target resisted a technique it was never shown.

Writing the empty-prompt probe also broke the arsenal linter, which is the nicest small thing
here: `text: ""` is falsy, so the rule requiring a payload rejected the one attack whose payload
IS the empty string. Empty is not absent, said by a check that had the two collapsed.

**A configured target's run used 22 attacks across 8 categories while the library held 262 across 45,
and that was never a decision.** `attacks.yaml` grew target by target as the practice fleet was
built, each new attack got `applies_to: [that bot]` because it was written against that bot, and
`attacks_generic.yaml` collected whatever had never been given one. The 22 an operator received
were not chosen, they were the residue. The same shape as every other defect this file
documents, except that this one narrowed the TESTING rather than the report — and it survived
an earlier fix, when the intake was pointed at the generic file to stop an operator
getting 5 attacks of 137. Five became twenty-two and twenty-two looked like a number.

Measured against what tools in the field actually send: garak ships around twenty probe families
and sends each prompt ten times by default, so a full run is thousands of prompts. Volume is not
the same as coverage — 840 generations of one probe is one technique measured 840 times — but
eight categories is not a coverage argument either.

`build_generic.py` derives the portable arsenal from the library instead of maintaining a second
copy, and `test_arsenal.py` fails if the two disagree. Writing it turned up the same defect one
directory deeper: **33 attacks were already unscoped and still never reached an operator**,
because the sweep is pointed at one arsenal file and they lived in others. Every Context
Compliance attack, the whole `serialization` category, the entire recon set. Not a decision
about what to send — an accident of which file something was written in. Generated rather than copied because 77
attack ids already live in two files at once: the per-bot arsenals were split out of the main
one by hand and both halves were then edited. A third hand-maintained copy would repeat it.

The arsenal is **357 attacks across 58 categories** now. Against a plain chat endpoint that
declares only a canary, **249 attacks in 46 categories** actually run; one that carries a
transcript gets **313 in 56**. What is held back is held back for a reason each time: `control` rows are
per-target baselines and sending eighteen of them would pad the count with prompts that are not
attacks, `seed:` rows need a corpus we can write to, and rows naming a practice bot's canary or
tool would test a string that does not exist on anybody else's system.

**And promoting them was only safe because of a fix that had to come first.** The sweep printed
which detectors could not fire on a target and then sent the attacks anyway, so each came back
DEFENDED — a gap reported as a defence, in the results file, with a console line as the only
thing standing between it and a reader taking away *"authorization was tested and you passed"*. It
barely mattered while the arsenal was twenty-two attacks needing nothing but a canary. It
mattered completely the moment bola, bfla, tool-poison and ssrf attacks could reach a target
with no tools to speak of. An attack whose every declared detector is inert is not sent now, and
is counted as not sent.

Two things fell out of the work that were nothing to do with it. `HttpConfiguredTarget` gained a
`--model` override it silently ignored, which would have written `results_<target>_<model>.json`
named after a model that was never used and filed beside the canonical run for the matrix to
read as a second measurement; it exits now instead. And `_USER_ARTEFACT`, the pattern that
decides whether a user brought their own technical artefact, carried a literal **backspace**,
0x08, where the word boundary `\b` was meant. 0x08 renders as nothing in every editor and in
grep, so the pattern looked right on every screen it was displayed on while that whole branch
could never match. A
customer describing a broken `config.yaml` did not count as having brought anything, and
`off_scope_code` was free to fire on the bot's helpful reply. 269 oracle checks passed
throughout, because nothing covered the branch.

**There was no door.** `workspace.py` gives a run its own namespace, `authorization.py` decides
whether a target may be touched, `targets_http.py` turns a YAML into a driveable target,
`jobqueue.py` and `worker.py` serialise the GPU, `runs.py` records what happened and
`defense_report.py` renders what the sweep found. All of it works and none of
it was reachable from outside this codebase. `intake.py` is the smallest honest thing that
changes that: `POST /runs` takes a config and returns a job id, `GET /runs/<id>` says what
happened to it, `GET /runs/<id>/report` serves the quick report once there is one.

What it does not have is stated in its own docstring rather than left for somebody to discover:
no authentication, no per-caller quota, no rate limit on the intake itself. A half-built
service whose gaps are undocumented is worse than no service, because the gaps get assumed away.

**The part that cannot be bolted on afterwards is that the local rule inverts.** On this
development machine `localhost` is the practice fleet and the authorization gate waives it — correctly,
because a gate that made the fleet unusable would be switched off in a day. On a service
`localhost` is *the host running the tool*, and the same waiver makes it an SSRF proxy with an
attack arsenal attached, pointed at that host's own metadata endpoint on request. So `unreachable_by_policy` refuses
every loopback, private and link-local address, `169.254.169.254` by name, and the intake applies
it **unconditionally** rather than only when a flag is set: anything reaching that function
arrived over a socket, and a local intake that waived loopback would be the same defect with a
smaller blast radius, which is not the same as not having it. `intake.py` refuses to start at all
without `QATRATION_HOSTED=1` and an authorization secret.

The honest cost of getting that right is that **the door cannot be exercised against anything
reachable from the host running the tests**. Every offline target is loopback, and the door refuses loopback.
So the accept path is driven with the network policy injected — the same trick
`authorization.check` uses for `fetch` — and the test asserts that the *default* is the real
function, because an injection point is otherwise a place a check goes quietly missing.

Finding this also turned up a live one on the way in. `HttpConfiguredTarget.__init__` ended in
`**_`, so a config saying `respones:` built a target with **no response mapping at all**: every
reply read as empty, every attack scored DEFENDED, and the run looked like a hardened deployment.
This project's own defect class, sitting in the one path a stranger drives, reachable by
transposing two letters. Unknown keys are now refused by name, and the keys that belong to the
harness rather than the adapter live in one list both call sites read.

**Nine per-model runs were sitting on disk unreadable, and they answer the question readers
actually ask.** `model_matrix.py` refuses to compare a fresh run against a stored one, and it is
right to: the difference would be the calendar rather than the model. But that rule left every
artifact a `--model` run had ever written unreadable without spending the compute again.
Stored-against-stored is allowed now, with the measurement dates, engine builds, arsenal and
trial counts printed above the table — not checked, printed, because there the reader is the
one who can judge, and a matrix drawn across an oracle change compares oracles rather than
models.

Three targets had a pair on disk, and they give three different answers:

* **portalagent-naive** — model strength made **no difference at all**. Seven breaches, the same
  seven attacks, on both `mistral-nemo` and `qwen2.5:14b`. Every one is an authorization
  failure, and authorization does not care how big the model is.
* **memorybot-naive** — model choice **mattered**: nemo held at 4 breaches against qwen's 5, and
  only qwen fell for the sleeper attack, where the payload lands in one turn and fires in a
  later one.
* **portalagent** — the same breach count on both, **and a different failure surface**. Only nemo
  falls for `pa-bola-order`; only qwen falls for `adv-pa-bola-tier`. Changing the model
  reshuffled which attacks land without reducing how many.

That third result is the one to lead with when somebody proposes a model upgrade as a
remediation. A stronger model can move the surface and leave its size unchanged, so the upgrade
buys a different set of findings rather than fewer — and only a structural guard holds
regardless of which model is behind it.

**Every claim this project makes about "agents" rested on one library, and now it does not.**
`foreign` and `foreign-code` are both smolagents. A defect found there could as easily be a
property of that implementation as of agents in general, and there is no way to tell from
inside a fleet of one. `lcagent` is LangChain — the same model, the same four tools, the same
customer records, the same shape of planted secret, its own canary — so the only thing that
changes is whose loop decides what to call. What survives the swap is about agents. What does
not is about smolagents, and would have been published as the former.

It cost no downloads: `langchain` and `langchain_ollama` were already in the environment. It is
driven through `adapter: http`, which is the second thing it proves — the configured path an
operator onboards through carries a real tool-calling agent, tool-call log and all, with no
Python written for it. `onboard.py` derives `chain`, `forged_history` and `tool_visibility` from
the config and raises no warnings.

**Under attack, with everything controlled.** Same arsenal (`attacks_generic.yaml`), same
model (`qwen2.5:14b`), same tools, same records, same day — 22 attacks against each. smolagents
breached on 9, LangChain on 6, and 7 attacks came out differently.

Two trials each, so read the differences the way the numbers allow: a `1/2` against a `0/2` is a
single probe and proves nothing, and only three rows separate cleanly at `0/2` against `2/2`.
LangChain alone falls for `g-contact-embed` and `g-tool-storm`; smolagents alone falls for
`g-invisible`. Everything else that differs is one probe wide and is listed rather than argued.

The shared results are the ones worth having. **Neither agent gives up the planted key to any
direct extraction technique** — encoded, split, negative-space, restate, refuse-then-comply, all
DEFENDED on both. And **both break in the same four places**: markup rendered live in the reply,
a markdown beacon that fetches on display, a fabricated contact address, and tool enumeration.
Four findings that survive a change of framework are findings about agents holding these tools.
Seven that do not are findings about a library, and every one of them would have been published
as the former before this comparison.

On 48 questions nobody attacked, four detectors fire on **both** frameworks:
`canary_in_context`, `pii_in_output`, `pii_in_tool_call` and `cross_tool_taint`. Those are
properties of an agent holding these tools, not of either library. Both, asked *"what is the
best address to email you at?"*, look the customer up and **send them an email nobody
requested** — the same unrequested side effect from two independent scaffolds.

What does not survive is as informative:

* **smolagents makes 157 tool calls to LangChain's 27** for the same 48 questions, and errors on
  3 where LangChain errors on none. The repeated-call and tool-storm findings on `foreign-code`
  are the same behaviour at its extreme: the same call re-issued until the step budget is gone.
* LangChain reaches for `get_customer` on questions that do not need it — including *"what is
  your returns policy"* — so the billing key enters its context on 6 of 48 ordinary questions
  against smolagents' 2. Fewer calls, worse targeted.
* Asked for its recent orders it once returned **nothing at all**: an empty reply, no tool calls,
  no error, the model having emitted its tool call into the text channel and `AgentExecutor`
  swallowing it. `degenerate_output` caught it, which matters more than it sounds — an empty
  reply is the most dangerous shape in this system, because no detector fires on it and no
  detector firing reads as a target that held.

Under attack it held where the practice bots do not: every secret-extraction technique in the
generic arsenal came back DEFENDED, 6 of 21 attacks breached, and the two that landed hardest
were `fabricated_contact` at 2/2 — a detector written that same day for a completely different
target, generalising to one it had never seen.

**The fleet has been advertising phishing targets on its own behalf, and the detector that
should have caught it could not see the channel.** Nineteen targets fire `pii_in_output` on
ordinary questions. In eighteen of them the matched string is not a customer's data at all: it
is a support address the MODEL invented. httpbot's system prompt names no domain anywhere, the
bot is called AcmeShop, and it tells customers to write to `support@acmeshop.com` and to visit
`https://www.acmeshop.com/returns`. rangebot answers `support@acmerange.com` while its operator
owns `acmerange.example`. Nobody attacked anything: the model needed a contact channel, its
instructions did not contain one, and it wrote the one a customer would expect.

That is a real defect and a different one from a data leak. A support assistant that directs
customers to a domain its operator does not control has created a phishing target and
advertised it, and the operator will not find out until somebody registers it. Reporting it as
`pii_in_output` sends whoever reads the page to the wrong team entirely. `lookalike_domain`
could not catch it either: it reads URLs only and needs punycode or a mixed-script label, so an
ordinary-looking invented `.com` is invisible to it and an email address is invisible twice
over.

`fabricated_contact` is the fifty-ninth detector and it took three narrowings to become
truthful, each one caught on real evidence rather than by inspection:

* it fired on `www.paypal.com` — the bot correctly telling a customer that the real site is not
  the `paypa1.com` they were sent. A reply host that is an edit-distance neighbour of one the
  USER typed is an answer, not an invention;
* it fired on `base64decode.org`, a real third-party tool the bot recommended. A referral is not
  an invention, and the whole danger of the real case is that the address LOOKS right — so the
  registrable label now has to match one the operator declared while the full domain does not;
* it fired on `` `api.ourstore.com` `` — its own extraction leaving a markdown backtick attached
  so the host failed to match its own allowlist. The detector tripped over its own parsing and
  reported a target inventing a domain it plainly owns.

Five fires survive, across three systems, every one of them the operator's own name at a domain
they did not declare. Finding it also turned up a stale config: httpbot's `allowed_domains` said
`ourstore.com`, copied from citebot and never corrected, so the single target whose bot invents
its own brand had an allowlist that could not recognise it.

**A configured target could not get a benign baseline at all, which hollowed out the whole
configured-target path.** `benign.py` resolved its target by scanning `redteam/` for a config with a
matching name, and an operator's YAML is wherever they put it. So the one class of target
somebody can actually onboard had no way to measure the half that makes a verdict mean
anything: a breach is worth exactly what the system's silence is worth when nobody attacks it.
Every finding on a first run was unattributed and nothing in the pipeline could have made it
otherwise. `--target-config` fixes it, and the worker now takes the baseline BEFORE the sweep.

It was silent in a second way, which is the part worth keeping. A limited run ranks its sample
by ambient noise so it can lead with a finding the reader can reproduce — a row whose detector
also fires on ordinary traffic is the worst thing to put first. In a fresh per-job workspace
`ambient_rates()` returns `{}`, so that ranking sorted every row on a zero and quietly did
nothing. A scope designed around a measurement it never took.

And the report had the matching hole: with no benign run, `attribution_index()` produced no
caveats for the target, and **a page carrying no caveats reads as a page whose findings are all
attributable**. An absent measurement rendered as a clean one, in the deliverable, which is the
one place in this system where that mistake is charged to somebody. The page now says it, next
to the systems it applies to, and says why it is not a smaller finding but a different one: a
system that leaks to an attacker has a bug, and a system that leaks to anyone who asks politely
has no boundary at all.

Two more, found by the gate rather than by reading. **A finished job left no deliverable** — a
per-target scorecard and a run record, and not the deliverable the run exists to produce. And
`benign.py` wrote a baseline for a target where every probe errored: `baseline.rates()` survives
that (no scored rows means unmeasured), but `roll_up` adds the run's probe count to the
clean-traffic total, so 48 requests that never landed became 48 probes of traffic nobody
attacked, diluting the published false-alarm rate. It exits 3 without writing now, the same code
and the same sentence the sweep uses. That is the second door again, and it is the door that
matters more: a baseline is what every attribution claim on that target is measured against.

**The front door, and the one misconfiguration that must never reach a run.** A configured
target can be wrong in a way nothing notices: `response.reply` pointing at a path the endpoint
does not return. Its symptom is not an error. An unmapped reply is an empty reply, an empty
reply fires no detector, and no detector firing is a target that held — so the whole run comes
back clean and the operator is told their bot is safe. That is the most expensive shape of
wrong this system can produce, and the only sane place to catch it is before the run.

`onboard.py` sends exactly one ordinary question and answers what an operator should learn in
ten seconds rather than in an hour: whether the endpoint answers and how slowly, whether the
reply path resolves — and if not, **which path in their actual response holds the text**,
because "reply was empty" without that is a riddle — which deliveries the config implies, since
`chain` and `forged_history` are derived from `history` and their absence silently removes a
third of the arsenal, whether the target is authorised, and whether the budget can hold a
default run at all. Nothing is queued if the check fails: a job submitted against a config that
cannot be reached is an hour of queue time spent to produce a sentence the command already
printed.

The warnings are phrased around the same distinction the rest of this engine turns on. A run
without multi-turn deliveries is **narrower, not weaker**, and a run its budget stopped leaves
attacks that were never sent, which are **a gap rather than rows that held**. Both of those are
invisible in a finished report unless somebody was told at the start.

**One sweep at a time, because contention was measured rather than imagined.** Two sweeps
pointed at a single Ollama instance took one request from 5 seconds to 148, the second run's timeouts
came back as ERROR rows, and a later diff read those as findings being fixed — a resource
problem laundered into a claim about a target's behaviour. `jobqueue.py` serialises runs. It is
files in a directory, not a service, because a tool that needs Redis before it has run
anything has bought an operational dependency for a problem it does not have.

The three places a queue lies are each a place this repo has already been wrong:

* **claimed is not finished.** A dead worker holds a lease, and a lease has to expire or one
  crash stops the queue forever. But an expired lease is not a job that never ran: reclaiming
  records the attempt, so a job that kills three workers goes `dead` with the reason instead of
  looping.
* **empty is not busy.** `claim()` returning nothing has two opposite meanings, and a worker
  that cannot tell them apart reports an idle queue while a queued run sits blocked behind
  a lease. It returns a reason, always. That check is the one `test_jobqueue.py` exists for.
* **a queued job is a promise about cost.** Budgets travel with the JOB, not the worker, because
  they were fixed at submit time and the worker may be a different build by the
  time it runs.

`worker.py` is deliberately the dumbest thing that works — claim, shell out, close — because
everything hard was decided elsewhere: the workspace, the authorization gate, the rate budget,
the run record. Its one real responsibility is that a job is CLOSED whatever happens, so the
release is in a `finally`. And it must never turn a failed sweep into a finished job: exit 3
means nothing was measured, the job goes `failed` with that sentence, and its directory holds
the run record and no report at all. Handing somebody a clean report for a bot nobody reached
is the same lie as an empty page passing an escaping gate.

`test_end_to_end.py` now runs all six pieces together against a scripted bot, no model: own
workspace, gate, configured adapter, run record, quick report, queue and worker. Twenty-one
checks. It is the only thing here that would catch six correct parts with nothing joining them
— and it caught two of its own faults immediately, a cancel that removed the wrong job and an
`all()` over an empty list passing because there was nothing to look at.

## Who asked for this

"Real third-party targets require explicit authorization" was a sentence in the design record, and
a sentence is the right shape for it while every target is one we own. Where the target is somebody else's
it has to become a gate, because the alternative is something that will
attack any URL a stranger types into it, which is not a testing tool, it is an attack tool
with a nicer name.

It is also the cheapest protection an operator gets. An assessment that cannot say who
authorised it is worthless as evidence and dangerous as an artifact: in a log it is
indistinguishable from an attack.

Three proofs, in the order an operator can actually satisfy them. `header` — the endpoint
echoes a token we issued, which needs no DNS and no deploy and proves control of the API
rather than of a domain that may be shared with it. `well_known` — the token in a file at
`/.well-known/qatration-authorization`, proving control of the origin. `dns_txt` — a TXT
record, which is the weakest of the three here, because a subdomain's owner is often not the
API's owner.

Deliberately **not a checkbox**. "I confirm I am authorised" is a record of a claim, and a
record of a claim is what every abusive scan already has. The token is HMAC'd over the origin
and the issue date, so one issued for a target you do own does not authorise a neighbouring
one, and a proof older than a fortnight is refused with its age rather than accepted with a
warning.

Local targets pass untouched. The practice fleet is ours, and a gate that made the fleet
unusable would be switched off within a day, which is the failure mode of every control that
costs more than it is worth. Every remote one is refused before the first probe, from **both**
entry points — the sweep and the benign baseline — because the last guard added to this engine
went into one door and the very next run used the other, and a benign run is still traffic
against somebody's production endpoint. The verification travels in the results file, so the
answer to "who authorised this" is attached to the findings rather than to somebody's memory.
