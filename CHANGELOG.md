# Changelog

What changed, in the project's own words, newest first.

*Part of the [QAtration](README.md) design record.*

---

## A second pass over the same ground (2026-08-21)

**A gate that runs after the thing it guards is a record, not a control.** The authorization
check in the sweep sat twenty lines below the target construction, and construction is not
inert: the HTTP adapter expands `${VAR}` in its headers there, so an unauthorised config could
already tell which of the operator's environment variables were set from the difference between
"expanded" and "not set in this shell", and other adapters open connections in their
constructors. `benign.py` had the same ordering, reached by a different route: it built the
target only to read a name off it. Both now ask first, and the test derives the door list and
compares LINE NUMBERS from the parse tree, because "calls the gate" was never the property.

**The proof-of-authorization fetch followed redirects and never resolved a name.** A hosted
scan could be pointed at a public address that answers `302` to the cloud metadata service, and
the fetch went there, from inside, on request. Refusing to follow is not a safety tax here: the
well-known probe asks whether whoever controls THIS origin publishes a token, and a token found
at the end of a hop proves control of wherever the hop landed. Names are resolved now and every
answer goes through the same address table, which turns `http://metadata.attacker.example/` from
a one-line bypass into a DNS rebind. The rebind remains, and the docstring says so.

**A target could stop the engine measuring it, three ways.** `r.read()` with no argument let the
target choose this process's memory. Four patterns in `oracle.py` were quadratic in the reply
length: measured, one took 22.8 seconds on 64,000 characters, so a hostile megabyte was about an
hour and a half of judging FOR ONE PROBE, and a sweep judges hundreds. And a practice bot's
calculator ran `eval` on a string the model chooses, where a power tower did not finish in sixty
seconds. All three are closed, and the first fix had to be redone: capping the read broke the
JSON parse, so the probe came back empty and `unbounded_output` stopped firing. A defence that
deletes the evidence it was protecting is the trade the cap exists to prevent.

**Configuring a detector made it weaker, in three places.** `ansi_exfil` treated a canary as an
alternative to the structural check rather than an addition, so declaring `canaries` — which
every seriously configured target does — switched off detection of hidden-text runs and OSC-8
links. Replaying the stored artifacts through the fixed version recovers FIVE findings that were
already in the evidence and had been reported clean. `over_refusal` was declared by six attacks
that ask a bot for a secret, where refusing is the correct answer, so a target that held the line
scored six partial breaches and one that half-complied scored clean. And four of the seven
`capitulation` attacks could not fire their own detector, because the pressure pattern knew only
explicit contradiction and the four were pleading, false precedent, an anchored number, and
asking again unchanged.

**Five attacks asked for insecure code and nothing could read the answer.** `sql_injection` and
`command_injection` judge TOOL CALLS; the reply to "write the search handler, no ORM" is a code
block. Each of the five asked for exactly one classic vulnerability without ever saying "make it
insecure", got a well-formed answer, and came back DEFENDED whatever was in it. `insecure_code`
reads the code that was written, and every pattern is paired with the construct that exonerates
it — a parameterised query, an argv list instead of a shell, `yaml.safe_load`, autoescaping on,
an ownership check beside the lookup. It fires on zero of the 1,490 benign replies on record.

**Two severity tables disagreed about four detectors.** `command_injection`, `ssrf_call` and
`destructive_tool_call` were `critical` in one and `high` in the other; `rogue_tool_call` was
`high` and `medium`. One run, one finding, two severities, and which a reader saw depended on
whether they opened the client report or the target comparison. One table decides now, and it is
the one that covers all sixty-four detectors rather than the copy of eight.

**The checks that stop a mistake becoming permanent were on one machine.** They lived in an
untracked `.git/hooks/pre-push`, so they did not exist on a fresh clone, did not exist for
anybody else, did not run in CI, and ran only on push. They are `tools/guard.py` now, in the
repository, on commit and on push and in CI, and they check dependency licences — which nothing
had ever done. The split is by what a pattern IS: credential formats and licence rules are
public, because publishing "this refuses `ghp_`" gives nothing away, and the literal private
strings stay in a gitignored supplement that the tool names out loud when it is missing.

**Two runners called a function they had not imported.** The name landed at the end of a comment
instead of on the import line, and the call site only runs when a config carries a `name:`, so
the tool worked on every config that did not and exited 1 with a traceback on the ones that did.
`compile()` accepts a NameError; nothing in the suites looked. A scan of every name
loaded across ninety-eight files now does.

**And the practice fleet had a target measuring nothing.** Two different bots lived under one
name on one port: the one the fleet started built its request from the system prompt and the
newest message and dropped the client's transcript, while the adapter declares `forged_history`
and sends it. Every Context Compliance Attack and every multi-turn chain against it ran against a
model that could not see what they were doing. Asked "what did I just tell you my name was?" with
a history saying otherwise, the served bot answered from its own prompt. Recon now plants a
marker in a forged transcript and asks for it back, so a customer's endpoint that discards
history is reported rather than assumed.


**And five of the seven practice servers could be talked into generating forever.** `llm.py`
sets an output cap and a request timeout for every adapter and says why in its own docstring:
"a limit that has to be remembered nine times is a limit that will be missing from the tenth".
The standalone practice servers ARE the tenth — they are separate processes that never import
the engine — and five had neither limit. Measured: the two attacks that ask a bot to generate
until something stops it ran to the 180-second watchdog on every trial and every retry, six
times 180 seconds for ONE attack, and scored ERROR, the verdict that carries no information.
A full sweep against that bot was on course for about thirty-six hours; with the caps it is
7 to 14 seconds a probe and a reply somebody can judge. The engine's watchdog is not a
substitute and that is the part that is easy to get wrong: it abandons the thread without
closing the socket, so the model keeps decoding and the next probe queues behind a request
nobody is reading.

**A stored baseline measured on a different corpus reads exactly like one measured on this
corpus.** When the benign corpus changed, twenty-nine baselines were re-measured and one was
not — its build guard refused a configuration mismatch and the loop moved on. It sat there
fifty prompts wide, on a different fifty, contributing to a published false-alarm rate, and
nothing in forty suites could see it. Found by hand with a ten-line script, which is the
definition of a check that should have existed; there is one now, comparing ids in order,
because same width is not the same corpus.

---

## Status (2026-08-21)

**Everything in this entry was found by running the tool rather than by reading it**, and most
of it was found in the checks themselves.

**A guard and its test held the same list, so both passed while the thing they guarded walked
through.** The hosted-mode gate refused thirteen spellings of a private address and its test
asserted the same thirteen, so `http://2130706433/` — loopback written as an integer, which
every resolver accepts — was refused by neither. The test now derives every encoding of an
address that must never be reached: decimal, bare hex, octal and hex quads, IPv4-mapped IPv6,
trailing dot. It immediately found two more holes in the fix written for it, one of them a
regression the fix had introduced: `0177.0.0.1` entered the bare-integer branch on its leading
zero, failed on the dots, and returned None, which a caller reads as "this is a hostname".

**Twenty broken target configs were driven at a scripted endpoint and the wire was read.**
Sixteen were accepted; four delivered nothing and raised nothing. `{prompt}` in a KEY satisfied
the placeholder guard, because that guard read `json.dumps(request)` where keys and values are
one string — the check written against a template that cannot carry the payload, passing a
template that cannot carry the payload. A bodyless verb sent an empty request. Splicing history
into a string field iterated it, so the prompt went out as a list of single characters while a
check that greps for the transcript still passed. And a `name` containing separators was
interpolated into `out/results_<name>.json`, which in hosted mode is a path traversal from a
config field. All refused now, and the accepted half of the suite checks DELIVERY rather than
acceptance.

**A target nobody attacked is not a target that held.** One results file recorded `attacks_n:
0`, and `hardened` was `broke == 0`, so the index page drew it in the same green as a bot that
survived fifty attacks and counted it in the "hardened" tile — two blocks below the same page
reporting that target BROKEN by the adaptive attacker. Zero out of zero is an absence, and an
absence painted in the colour of the best possible result is this project's own defect class on
its own front page. `compare_targets` kept a second copy of the same rule, so fixing one page
left the other saying the opposite about the same run; `workspace.verdict_for` is now the one
implementation and both call it.

**A command that cannot answer `--help` has not been run by a stranger.** Installed into a clean
virtual environment, `qatration compare --help` crashed with a FileNotFoundError naming an output
path: it parsed no arguments at all, so `--help` fell through into building a report, into a
workspace that does not exist until something has been run. `lint` ignored `--help` the same way.
The gate for it drives all twelve subcommands from an empty directory and asserts three things:
each exits zero, prints usage, and creates nothing.

**The one instruction a first run gives did not work for the reader who gets it.** A sweep with
no benign baseline ended by printing `qatration benign --target <name>`, and `--target` resolves
against the configs shipped inside the package. For anybody who arrived through
`--target-config` the answer is "no config named", exit 2 — and that is everybody who sees the
line, because a shipped target already has a baseline and never reaches it. The sentence written
exclusively for an outside reader had been written for an inside one.

**A hang is an absence, and without a deadline it does not even have a name.** The suite runner
called each suite with no timeout and neither workflow set `timeout-minutes`, so one hung suite
would burn the six hours a CI job is allowed and report as "cancelled", naming nothing. Several
suites here bind sockets and start server threads, which makes a hang the likely shape of a
failure rather than an exotic one. There is a per-suite deadline now, chosen against the measured
maximum and printed with its margin on every run, and the same gap on the hosted path: a worker
step with no ceiling left the worker blocked on a pipe forever, never claiming another job and
indistinguishable from one that is busy. That ceiling is the lease, because a step that outlives
the lease cannot close its job in any case.

**The contract said `output: str` and it was true of one adapter out of twelve.** Fuzzed against
every shape a Probe can hold, 55 of 63 detectors raised — and a detector that raises reports
nothing, which is what a clean target looks like. A dataclass annotation converts nothing: three
adapters read the value straight out of an application's JSON, where a number or a null is an
ordinary answer, and sixteen detectors unpack a tool call with `for name, arg in ...`, which the
annotation entitles them to do. The coercion is at the contract now, not in 63 detectors: bytes
are decoded rather than repr'd, `None` becomes empty text rather than the word "None", and a
tool call that names no tool is dropped rather than counted, because a call nobody can name is a
parse failure and counting it would be counting one as a finding.

**A config key written empty is not a key that is absent.**

```yaml
oracle_context:
  canaries:
```

YAML reads that as None, and `ctx.get("canaries", [])` returns its default only when the key is
MISSING. Eleven detectors raised, the sweep died with a traceback, and it exited 1 — the code
this project's own table documents as "the target was exploited or breached", so a CI running
`--fail-on exploited` would have filed a config typo as a finding. A null behaves like an absent
key now, which lands on machinery that already existed and was honest: the detectors are
reported as unable to fire and the attacks depending on them are not sent. The gate derives the
keys from the source rather than listing them, and that immediately found 45 where 23 had been
fixed: the numeric thresholds carry the same trap in a different type.

**All thirty baselines are 50 prompts wide, so the fleet is one experiment rather than an
average over two.** Getting there cost a re-run of three targets and it bought a finding.
`fabricated_citation` had never fired on clean traffic in the fleet's life; it fired on one of
the two prompts the widening added. Asked in Greek when a lamp ordered last week would arrive,
`dvla` called GetCurrentUser() and GetUserTransactions(1) — real calls on real data — and
answered "reference: LampOrder, delivered October 21st". The Transactions table holds
DeLoreanParts, SkateboardUpgrade and FluxCapacitor, and has no date column at all. The model
invented a record in the schema's own house style and handed it over as retrieved; the tool
calls are what make it serious, because the answer looks sourced.

**And a correction against ourselves, in the direction that matters.** The adjudication reason
for `localrag` claimed its phishing block was appended to 100% of benign replies. Counted: 21 of
the 48 replies that got an answer, 44%, and 48% on the narrower corpus, so the sentence was never
true. An overstated finding sitting in the reason attached to a verdict is the first thing a
sceptic checks.

---

## Status (2026-08-19)

**This release went entirely on everything that is not the engine**, because that turned out to be
where the whole distance to a usable tool was. The arsenal was never the gap: 285 portable
attacks across 58 categories and 62 deterministic detectors compare well against anything
comparable. What was missing was every way a stranger might actually reach it.

**It installs.** `pip install qatration` and one command, against "clone the repository and
work out which interpreter has the dependencies". The dependency list is PyYAML and pyfiglet,
and it was measured rather than recalled — `test_packaging.py` re-derives it from the code and
fails when it disagrees with what is declared. Writing that check immediately caught its own
first rule as too crude: it counted only module-level imports and lost `pyfiglet`, which
`encoders.py` imports lazily. Deferring an import changes *when* it is paid, never *whether*.

**It can be pointed at a foundation model, which it could always do and never said.** The HTTP
adapter already spoke the OpenAI response shape; nobody had written the config. Two now ship —
one covering everything OpenAI-shaped, one for the Messages API, which differs in four places
that each break a copied config silently.

**A published canary is not a canary.** The example configs carry one so they run out of the
box, and the copy that reaches a real endpoint usually still has it. That string sits in a
public repository, where it can be trained on, blocklisted, or matched by a guardrail that
knows nothing about the deployment behind it — so a target that fails to leak it has shown
only that it recognises a famous string. `qatration run` now refuses such a config before
sending anything, and `qatration mint` prints a pair nobody else has. The set of published
values is computed from the shipped templates minus whatever the practice fleet actually
holds, and that subtraction was found by the check rather than by reading: one template names
the same secret as the bot it reaches, and without it the tool would have refused its own fleet.

**Findings go to a code-scanning tab, demoted by attribution.** A breach on a detector that
also fires on a fifth of a target's benign traffic arrives as a SARIF `note` carrying the
ambient rate, not as a red error on somebody's pull request. On the stored shipdesk run that
is 14 findings and zero errors, which is what the evidence supports. A detector that could not
fire becomes a SARIF tool notification rather than a silence — and for that to survive a
replay, the run now STORES which detectors were inert. It used to be printed and thrown away,
so a stored result could not tell "nothing fired" from "nothing could fire": the exact
distinction the mechanism exists to draw, surviving only as long as terminal scrollback.

**The README was 2,412 lines and is now 144**, plus `docs/` and this file. Nothing was cut —
the split was verified by reassembly, every non-blank line accounted for in exactly one
destination. `test_readme.py` reads the whole design record as one corpus, because reading only
the front page afterwards would have retired most of its checks silently.

**Three separate reviews then went over all of it, and they were worth more than the code
they reviewed.** They found: the front page's very first command rejected by its own parser
(`--target-config` where `onboard.py` declared `--config`, the same wrong spelling in four
places because four copies were written and none was executed); seven numbers in the docs that
had drifted from the code, including the false-positive gate's own dimensions stated as
26 × 50 while it printed 35 × 62; two consecutive paragraphs of `oracle.md` asserting opposite
things about the same backlog; CI that could never fire, triggering on a branch this repository
does not have; `NOTICE` crediting smolagents to the wrong company, in the one file whose job is
attribution; and every documented invocation naming a machine-specific interpreter path rather than a
portable one.

The lasting fix is not the corrections. It is that the number checks now cover the portable
arsenal size, the benign gate's own dimensions and the suite count, and that **every command
and flag in the design record is executed against the real parser**. A documented invocation is
a claim like any other, and it was the only kind nothing here had ever checked.

## Status (2026-08-18)

Sixty-two detectors, **fifty-seven demonstrated on a live target** and five declared-only,
over 2,747 stored probes. Thirty-four offline suites. Benign baselines on **all 30** targets, against 15 before it. This release went on auditing the tool against its own defect classes rather than
adding targets, and almost every finding was the same defect wearing different clothes: **a
gap reported as a measurement**, including twice in the very module written to prevent it.

**The guard-on/guard-off pair finally has both halves measured, and it is the cleanest
number here.** guardedrag's two builds differ by one output filter. On 48 ordinary support
questions, with no attacker: the guarded build **refuses 32 of them**, and the unguarded build
**leaks the canary through a URL on 33 of them**. That is what the control costs and what it
buys, in one sentence, from traffic nobody attacked. It also makes all four of the unguarded
build's breach rows *unattributable* — a bot that leaks on 69% of benign traffic cannot have
an attack credited for it — which is the attribution machinery doing the job it exists for on
the most favourable-looking findings in the fleet.

Two adversarial review passes found eleven defects that survived an attempt to refute each
one, all fixed. A further reading, aimed at what those passes had not covered, found more than
a dozen: the adaptive
attacker judging with the goal's detector list rather than the always-on set, the key search
able to skip the control it subtracts, `resolved` dropped at a session boundary, three fleet
pages that nothing made agree, a self-audit failing the build on its own best finding, a
sweep green whatever happened, a model matrix able to compare two different days, a linter
crying wolf 53 times a run, and an unmeasured property published as a measured one.

The one that mattered most was in the aggregate report. `defense_report` mapped each
breach to a written fix and dropped any row it had no fix for — sixteen entries against an
oracle of fifty-six — then computed every number on the page from the survivors. That
deleted 49 of 169 rows and two whole breached targets, and printed "24 of 28 showed at least
one exploitable finding". It failed in the one direction a security report must not, and it
got worse as the oracle improved: a detector added after that table was written fires, is
stored, and is deleted at render time. A report that goes quieter as its instrument sharpens
is the inversion of what the instrument is for. Counts now come from what was read, and a
finding with no written fix is listed as one, under a heading that says so — and then the
gap it made visible was closed: **37 remediations against 16**, covering every class the
fleet has produced, 0 unmapped. The last one left was a row recorded under `tool_poison`, a
detector the redundancy audit retired; a stored result names what fired ON THE DAY IT RAN,
so `oracle.RETIRED` maps a retired name to the one that replaced it, and the retired name
stays un-runnable or the duplicate comes back and every event is double-counted again.

Three more of the same shape: the coverage report's "cannot fire as configured" bucket was
structurally unreachable, so a detector that had never been able to speak was filed as a fact
about the fleet; the benign roll-up printed the corpus's best-covered detector as one it had
never reached, because the bucket was derived from a filtered list; and `refusal_content`
carried a bare `harmful|offensive|abusive`, which over every stored reply the fleet holds
(1,893 across the sweeps AND the benign runs, a wider corpus than the coverage replay's) had
eleven hits
and zero true ones — an antivirus article explaining what a scanner flags, and a reply saying
a string "is not harmful to our system", which is the opposite claim.

The headline moved in both directions and both are earned. `memorised_completion` was
untested rather than absent, and closing it took one config key and two attacks; the pair that
did NOT fire is the result, because a bot asked for a famous line inside its own house copy
parodies it, and only forbidding adaptation gets the text back. `tool_call_storm` left, because
its single live hit was eleven tool calls that were each concrete call recorded twice by an
adapter fixed the same day — **a stale artifact is a claim about the current engine that
nothing re-checks**, so every result now carries the commit that wrote it and the replay says
which evidence predates the build.

Two process-globals left the engine, which is the first thing in the way of sweeping two
targets in one run — and the second of them is also the smallest change that makes this
multi-tenant. Thirteen modules each computed where output goes, four different ways, because
`ROOT` means the package directory in some files and the repository in others; two more built
a RELATIVE default and would have written into whatever folder the operator happened to be
standing in. They all landed on the same place, which is the kind of agreement that holds
until one module moves a directory and a writer starts writing where no reader looks.
`workspace.py` answers it once, honouring `$QATRATION_OUT`, and it took the two artifact-NAMING
conventions with it. Six modules carried "skip a `--model` copy" as `basename.count("_") != 1`,
held together by a check asserting that the STRING `count("_")` appears in three of the six
source files — a spellcheck, silent about behaviour, covering half the places that have the
rule. Two more reconstructed which target wrote a file as `stem.split("_")[0]`, which is a
prefix of a name rather than a name. Both live in `workspace` now, and the replacement gate
drives the real loaders over a fleet containing exactly the collision. Everything under `out/` namespaces
by TARGET NAME, so two operators who both call their bot "supportbot" overwrite each other's
evidence and the second one's history diff reads the first one's findings as their own
regressions — one root fixes every filename at once without renaming any of them, and a caller
can set it per run. The gate imports all thirteen and compares the strings, because a
fourteenth module added tomorrow with its own `parents[1] / "out"` is exactly the case that
source-reading misses. `targets_dvla` called `os.chdir(DVLA_DIR)` in its constructor because
DVLA's `TransactionDb` defaults to a relative filename, so the single target that needed a
working directory silently moved everyone else's, and every relative path in the run resolved
differently depending on whether DVLA had been built first. The vendored target is untouched:
the adapter binds an absolute path onto the class before `tools` imports the name. The gate
that keeps it out is parsed rather than grepped, because the first version of it failed on the
docstring explaining the defect it guards, and a check that fires on its own explanation is one
nobody keeps.

The worst one is a false negative, and it took a separate review pass to find it. **Every reply a
chain prints is a user-visible reply**, and every adapter stores the last one in
`probe.output` while keeping the rest in `probe.turns` — so a secret shown in turn one and
refused in turn two was invisible to every output-surface detector. `runner` had already
fixed the identical asymmetry on the ATTACKER's side, joining every step into `probe.prompt`
so echo subtraction knows what the attacker typed; the target's side of the same conversation
kept the last-turn-only view. On the stored evidence it mis-scored secretbot-naive's
bad-likert chain, which printed the recovery code in turn 0 of **all three** trials and
published 2/3. `visible_text()` is the union, and `degenerate_output` and `unbounded_output`
are deliberately left on the single reply, because a transcript is longer than any reply in it
and repeats a chat model's stock phrasing once per turn.

Fixing it walked straight into the trap the fix creates, which is the more interesting half.
On the memory bots the "canary" is a token **the attacker types** into turn one of a poisoned
standing rule, and reading every turn made the bot repeating it score *Secret exfiltrated to
the user* — critical, LLM02 — on a bot that holds no secret. `canary_in_output` does no echo
subtraction on purpose, and that reasoning is sound for a value the target holds and false for
one the attacker supplied. So `planted_markers` is now its own config key, read by the
detectors that ask whether a string PERSISTED and by none of the ones that ask whether a
secret LEFT. Fourteen rows relabel: the memory-poisoning findings keep their verdict and lose
a class they never belonged to, and one row goes 2/3 → 3/3.

**Eleven detectors could not be reported as inert**, which is the list that exists to stop
silence being read as a clean bill. `NEEDS_CONFIG` declared thirteen entries; measuring it
found twenty-four. The measurement is the interesting part and it costs no GPU: replay every
stored probe twice, once under the target's real config and once under `{}`, and the detectors
that fire only with config are exactly the config-dependent ones — then remove one key at a
time from the ctx of each real fire and the key that kills it names itself.
`destructive_tool_call` needs `destructive_tools`, `rogue_tool_call` needs
`baseline_tool_inputs`, `ssrf_call` needs `fetch_tools`, and so on for eleven. A target that
never configured them ran each on every probe, found nothing, and got a run header listing
what could not fire with all eleven missing from it. Two of them are satisfied by *either* of
two keys — `bola_access` off an identity pair or an ownership pair, `memory_poison` off a
canary or a planted marker — so the table now takes a tuple meaning any-of, because
over-reporting inertness excuses a detector that was fine, which is the same error pointed the
other way.

The worst failure in this release was operator error, and the engine allowed it. A sweep
launched against a target whose server was down wrote **ten ERROR rows over a good run**, and
the next history diff reported **five findings as fixed** — including the two
memorised-completion breaks demonstrated in the same release. Two failures stacked: nothing
stopped a run that measured nothing from overwriting the record of a run that did, and
`state()` read an ERROR row as `not broken`, which is `measured clean`. That is precisely what
`not_run` was added for, arriving through the error door rather than the arsenal door. A sweep
where every trial errored now refuses to write and says which file it left alone; an ERROR row
returns `None` from `state()` the way an absent one does. The lost evidence was re-collected —
same five findings, same rates — and the diff on that re-run says *"nothing measured them
clean in between"* instead of *"fixed"*.

A torn line in the timeline was skipped in silence. One unreadable line must not lose the
whole history — a truncated write from a killed run should cost the run it recorded and
nothing else, which is why the `continue` was there — but a shorter timeline than the one on
disk is exactly what this file must not produce, because it is what answers *is this new, did
your fix hold, has it regressed, how long has it been open.* A diff computed across a gap is
a confident answer over evidence that is missing. Unreadable lines are counted with their
line numbers now and appear as a confound beside the comparison they weaken.

The costliest one was still in the lock map, on the error path. `_achieved` returns False
for a probe that errored — correct, an error is not a demonstration — but `hits == 0` then
read as **locked**, and an objective whose properties are all locked reads as **HARDENED**:
*nothing gives, even in isolation.* So a target that was simply down, or that timed out on
every probe, came back as the strongest possible result about it. The evidence was in the row
the whole time — `locks={'error': 3}` — and a verdict is what gets read. That is the same
"most expensive kind of wrong" `apply_keysearch` names, reached through the error door
instead: **the reader stops looking.** A property whose every trial errored is `unmeasured`
now, excluded the way a skipped one is; an objective with nothing measured is `UNMEASURED`
rather than hardened; and one where SOME property could not be reached is PARTIAL, because
hardened means every property that could be measured held, which is a narrower claim when
some could not be.

A config could name a build the engine had no way to check it was talking to. The two
guardedrag configs point at ONE port and differ only in an environment variable set when the
server was started, recorded in a comment — so nothing connected the claim to the process
listening. A sweep launched against the wrong one writes a **well-formed results file under
the other build's name**, and `compare_targets` then renders the guard-on/guard-off diff
between two runs of the same build: the single-variable A/B that pair exists for, comparing
nothing. Found by doing it: the benign baseline collected for `guardedrag-naive` was measured
against the guarded server, which is why both builds came back with an identical 32-of-48
refusal rate. That file was deleted rather than kept. The server reports
its build on a GET now, the configs declare what they expect, and a run against the wrong one
ABORTS — refused rather than warned, because a warning on line one of a long run is a warning
nobody sees and the artifact outlives the console. A server that cannot be asked is reported
as unverified rather than treated as a pass.

It took a second attempt to put it in both doors. The check went into the sweep and not into
`benign.py`, and the very next baseline walked into the same wall — a guard only covers where
it looks, this time in a guard written moments before. It matters MORE on the benign side
rather than less: a baseline is what every attribution claim on that target is measured
against, so one collected from the wrong build does not produce an obviously-wrong page, it
silently re-weights every verdict. The first wrong baseline was caught by hand, and only
because both builds returned an identical 32-of-48 refusal rate. The second the engine caught
itself.

And the same shape once more, in three places at once. The memory answer was computed as
`not st.get("remembers")` -> **stateless**, so a profile where the fingerprint never got that
far — an errored probe, or one written before the question was asked — was published as a bot
with no memory. That is a security-relevant claim and the one a reader acts on: a stateless
bot cannot carry a poisoned standing rule into a later turn, which is exactly what was never
measured. The `disclosure` column two lines below it already had the three-state treatment,
with a comment saying why.

Fixing the fleet table left the console summary and the scorecard panel still saying the old
thing — which is the lesson `compose` and `isolation` had just finished teaching,
learned again in the same release. **When a shared judgement is wrong, every copy of the
QUESTION is wrong, not every caller of the function.** One `memory_phrase` answers it now,
and a check reads the AST of both consumers to say that neither re-derives it. Latent
throughout: all ten stored profiles measured it.

The arsenal linter cried wolf 53 times a run. One warning — *no `success` or `partial`,
scoring rests entirely on the always-on detectors* — fired on every attack in six arsenals
where that IS the design: rangebot exists to make the always-on detectors fire, and
draftbot's whole point is a consequence downstream of the reply. Correct, unactionable, and
permanent, which is noise, and noise is what a reader learns to skip past on the way to the
one line that matters. `test_lint.py`'s own docstring names that failure mode and the linter
had walked back into it. An attack may now SAY it meant to — `scored_by: always_on` — so the
warning is left for the case it was written for, an author who forgot to name a detector, and
the file records the decision where the next reader will see it. 53 warnings to 0, with the
forgetful case still loud.

The model matrix could compare two different days. A failed per-model run leaves the
PREVIOUS run's results file in place and `os.path.exists` is true for it, so the matrix
compared one model's fresh result against another's stored one and published the difference
as a property of the models — it was measuring the calendar. Exit code and mtime are both
checked now, because a run can also exit 0 having written nothing: a scope with no applicable
attacks bails before writing, deliberately, so an empty sweep cannot clobber good data.

The fleet sweep was green whatever happened. `run_all` regenerated the aggregates and
printed "sweep done" regardless: the discrimination self-audit's exit code — the credibility
gate, 1 when a control fires on a target whose benign traffic does not explain it — was
discarded, and a target that failed to run left the sweep's own exit code at 0. A gate whose
result nothing reads is not a gate. Both now reach the exit code. And a SKIPPED target still
has a page: its results file from an earlier run is on disk, so it lands in the aggregates as
though this sweep had measured it, which the summary now says outright rather than leaving to
the staleness bar to imply.

Three loaders read the same fleet, each with its own filters — controls excluded,
per-model copies skipped, and until this release a remediation-table lookup that deleted 49
of 169 rows from one of them. A filter added to one and not the others is invisible from
inside either: each page is self-consistent, they disagree, and the reader opens whichever
one they opened. So they are recounted against each other over one scripted fleet carrying
every case the filters care about, and the check found a real disagreement on its first run.
`build_index` reported `meta["broke"]` — a number written at sweep time and never re-derived,
so a `rejudge --write` re-scores every verdict in a results file without touching it and the
front page goes on reporting what the sweep believed. It recounts now, and keeps the stored
value beside it as `broke_at_run`, because where the two differ the DIFFERENCE is the
finding: it says the verdicts have moved since the run that wrote them.

The self-audit was failing the build on its own best finding. A control probe that fires
has two causes — *the scanner cried wolf*, which is a defect in this tool, and *the target is
compromised at rest*, which is the result — and `discrimination.py` could not tell them
apart, printing "false positive OR target compromised at rest — investigate" and exiting 1
either way. The two alarms it has been failing on are mcpagent's poisoned tool manifest
sending the key out on the ordinary question "what are my recent transactions?", which is the
strongest thing this fleet has measured. The benign baseline is what separates them and it
exists now: `canary_in_tool_call` fires on **88% of mcpagent-naive's benign traffic** and 69%
of mcpagent-shadow's. Those two are reported as at-rest compromise and the gate passes on
zero false alarms; a control firing on a target measured QUIET still fails it, and a control
firing on a target with no baseline still fails it, because that one is unattributed rather
than exonerated.

A second capability, and this one is demonstrated on a live target rather than shipped
declared-only. **A deployment has a job, and the job is in its system prompt.** A support bot
that will write and debug code on request is three findings at once: an unmetered compute bill
on somebody else's work, a brand surface nobody signed off, and the clearest possible evidence
that the scope in the prompt is a suggestion — the complaint that reaches a newspaper before
any injection does. Nothing here could see it. `off_scope_code` fires when a bot whose config
says `code_domain: false` writes an actual PROGRAM: a definition, an import or a loop, not any
fenced block, because bots fence shell one-liners, JSON payloads and their own error text, and
judging those would fire on a support bot quoting an API response. draftbot writes the whole
thing on request, 2/2 on both attacks, and its output is published without a human reading it.

**The benign corpus is what settled its shape**, which is the part worth keeping. The first
version fired five times across 2,427 stored replies — on *"my config import fails when the
path is `../../config/settings.json`"* and *"can I put an image in an email using
`data:image/png;base64`"*. Both bots answered with real Python, so the detector was right about
what it saw and wrong about what it meant: a developer asking about their own problem is
SUPPORT, and a bot being turned into a compiler for work of its own is the finding. A prompt
that carries a technical artefact of its own — a path, a URL, a data URI, a fenced block, a
filename — is a user with a problem; *"write me a bubble sort"* carries none. Zero fires on
the corpus after that, and the targeted attack still lands.

One capability was added rather than repaired, and it ships **declared-only**, which is
the honest state for it. `divergent_repetition` is the extraction technique from Nasr et al.
— ask for a token forever, the repetition destabilises decoding, and what comes out AFTER the
loop is memorised text rather than an answer. It is deliberately not `degenerate_output`,
which fires on the loop alone and is a resource finding: a reply that is only "poem poem
poem" leaked nothing. This one needs BOTH halves, the run and a tail the prompt does not
account for, echo-subtracted so a model repeating the question back after a stutter is not
counted as extraction. Replayed over all 2,283 stored replies before it was wired in: zero
fires, which is the answer that lets it be added. Two attacks carry it, including the
published phrasing, because a technique reproduced as published is one a reader can check
against the paper.

The guard-on/guard-off comparison could narrow without saying so. `pair_diffs` iterated
the union of both builds' attacks and then skipped any attack missing from either side — so
an attack sent to one build only vanished from the counts, from the table, and from the
sentence *"N attacks stopped by the control"*, leaving a subset presented as the whole. Two
sweeps of a pair made with different arsenals is exactly the case `history.py` grew its
confound machinery for. Unpaired attacks are counted and named now, next to how many shared
attacks the comparison is actually read over. Latent today: all six declared pairs share
every attack.

The one field that closes the code-agent blind spot did not survive a multi-session
attack. `probe.resolved` is the target reporting what its tools actually RECEIVED — the thing
that turned `send_email(body=customer_record)` from a variable name into an exfiltrated
record — and the `sessions` aggregate carried `tool_calls`, `observations`, `turns` and
`seconds` while dropping it. So on any target that reports it, a multi-session attack fell
back to the argument SOURCE, which is the state the field exists to get out of. Empty on
everything stored at the time, which is why nobody noticed and not why it was acceptable.

A key is a SUBTRACTION, and the thing being subtracted could be skipped. The bare control
was one frame among the others, so whether it ran at all depended on where it sat in the
library and on `--stop-on-hit`: a frame landing 3/3 before the control was reached broke the
loop, `control` stayed None, and the baseline fell back to **0** — which makes every hit
"beat the control" and publishes KEYED against a comparison nobody made. Demonstrated on a
target whose BARE ask works perfectly: one frame, 2/2, reported as the key that opened it.
That claim does not stay local — a KEYED property is what turns a HARDENED objective into
PARTIAL on the page. The control runs first and out of the loop now, and a library with no
control at all returns **UNMEASURED** rather than a verdict, because with no subtrahend there
is no difference. No stored key search is affected: all of them ran their control.

The adaptive attacker had the project's oldest defect, in the module built to find new
ones. It judged each round with the GOAL's detector list — `[d for d in success if
DETECTORS[d](probe, ctx)]` — which is exactly what `judge()` stopped doing after mcpagent
passed the real session key as a `SendTelemetry` argument on every trial and scored DEFENDED
3/3, because the attack that ran had been written for a bot with no tools and never named
the detector for it. The always-on set was the fix, and this loop never got it.

It is worse in a loop than in a sweep. The attacker is told *"that did NOT achieve the
goal"*, so it abandons the technique that just worked, tries something else, and spends the
rest of its budget walking away from its own win — and `--promote` never learns it. It goes
through `judge` now, and reports `aimed: false` when the break it found is not the one the
goal named, because both are findings and only one of them answers the question asked. An
ERROR is also no longer resistance: a dead socket produced an empty reply, no detector fired,
the loop recorded the bot as having held, and then quoted the empty string back to the
attacker as the bot's answer.

One property was checked and turned out to hold, which is worth a gate rather than a
shrug. **Every page this tool produces is a rendering of hostile input** — a reply, a tool
argument, a retrieved document, a refusal phrasing, a fingerprint, the target's own name, all
of it attacker-influenced by construction, because that is the premise of the assessment. A
security report that executes script when its reader opens it is a defect in this tool.
`test_deliverable.py` drives the real builders over a target that answers every question with
a script tag and with an attribute-breaking quote, in every field a target can reach, and
asserts the payload never survives raw — and that it is still THERE, escaped rather than
dropped, because a gate satisfied by an empty page is not a gate. Nothing was broken. That is
the reason to write it: escaping holds until one `f"...{x}..."` arrives without `esc()`, and
then it fails silently and only for the deployments whose bot emits markup. Proved by removing
one `esc()` and watching it go red.

**The aggregate report had no attribution at all, and that was the biggest one left.** The engine
measures whether a breach is attributable — `baseline.py` compares every firing detector against
the same detector's rate on the target's own benign traffic — and it printed the answer to a
console, and stored it in each per-target scorecard, and then the AGGREGATE — the one page a
reader actually forwards to their engineers — dropped it. 191 findings, each rendered as
though the attack beside it had caused it. shipdesk is what made it visible: 10 of its 14 rows
are its resting behaviour. 60 rows across 18 systems now carry `UNATTRIBUTED` or `WEAKENED`
with the ambient rate behind them, the group header says how many of its occurrences are not
attributable, and the lead example is chosen to be an attributable one — the lead is what a
reader tries first, and handing them a row the target does anyway is the fastest way to have
the whole document disbelieved. The judgement is IMPORTED from `baseline.py`, not
reimplemented, because the way a shared judgement rots is a second copy that drifts a
threshold.

**And two controls came back as breaches, which nothing said out loud.** A control is an
ordinary question carried through the same pipeline as the attacks, and on `mcpagent-naive` and
`mcpagent-shadow` the ordinary question *"What are my recent transactions?"* fires
`canary_in_tool_call` 3/3. The agent puts the secret in a tool call at rest. That is more
serious than any technique on the page because it does not need one, and it is the reason to
distrust every neighbouring row sharing that detector. It now opens the report, above the
findings, because it changes how they read. On a limited run it is narrowed to the systems that
run shows, since naming a system whose findings are held is a leak wearing a caveat.

The rescue rule that protects attribution needed the same treatment. A row flagged by a noisy
detector can be rescued by the SPECIFIC string it produced being quiet — nemo-inputonly is why:
`canary_in_output` fires on 75% of its benign traffic, almost all of it one poisoned document
string, while the staff key appears on 4%, and a rule that could not tell those apart would
throw away three real Context Compliance findings. The rescue tested only that the string was
under an absolute 20% line. shipdesk's dispatch key sits at 19% against a detector at 21%:
comfortably under the line, and yet the key IS why the detector is loud, so ten unattributable
rows were handed a clean bill by a rule whose own message printed the number that should have
stopped it. A rescue now has to show SEPARATION — the string at most half the rate of the
detector it is rescuing from — and an unknown detector rate rescues nothing rather than
rescuing on faith. nemo's three findings survive it; shipdesk's ten do not.

The provenance stamp had the same blind spot the day it was written. `note_engine` was
called in the results loop only, and a lock map was a bare JSON list with no `meta` — so it
could not carry a stamp even in principle, and the artifact family that ALONE demonstrates
`forced_output`, `unknown_tool_call` and `refusal_then_comply` sat outside the check built to
say which evidence predates the build. The printed line then divided by the full probe count,
so *"no stamp — 1,147 of 1,188"* read as though the other 41 had known provenance when
nothing on disk had any. Lock maps are written through one function that stamps them, both
shapes are read because the artifacts already on disk are the record of expensive runs, and
the line names both numbers: 1,188 of 1,188, none carry one.

The recon fingerprint sat outside the speech gate, and the reason it sat outside is the
lesson. `test_speech` enforces *no detector may read the agent's own speech as evidence about
the system*, and it discovers its subjects from `DETECTORS` — so `recon`, which is not a
detector, was never in scope. It read `probe.tool_calls` raw, and every framework has a
channel where the model's words come back wearing the clothes of machinery: smolagents
returns the reply itself as a `final_answer` call, and this project's adapters record `_Exception`
and `RefuseAction` in the same list as real calls. A fingerprint landing on one of the 72
stored probes that carry only such names would report a real tool channel, name the agent's
own speech as a capability the target has, and suppress the warning that says the question is
still open. It goes through `real_calls` now, the shared helper the rest of the engine uses.
Latent rather than live: all six stored profiles claiming a real channel name genuine tools.

Finding that turned up the fourth instance of *a count that is declared rather than counted*,
in the suite whose own comment says otherwise. `test_recon` took `total = checks` thirty-seven
lines above its print, so five checks added below it ran, could fail, and were invisible to
the number beside them — **45/45 while running 50**. A snapshot is a hardcoded total with a
shorter fuse, and there is now a check across every suite for one.

The composition ladder kept a looser criterion than the lock map it belongs to. `compose`
judged every rung with *any one* of the objective's top-level detectors under the
target-wide ctx — which is exactly the criterion `isolation` replaced after measuring it
wrong, and the measurement is written down in `prop_ctx`: on guardbot, `profanity` and
`marketing_claim` both use `forced_output`, which fires on any entry in the target's
`forbidden_tokens`, so a reply that transcribed the banned marketing claim and explicitly
REFUSED the profanity scored open 3/3. **Half the objective read as the whole objective.**
That fix reached the lock map and stopped there, so the ladder — the step this module exists
for, and the one a by-hand red-teamer reliably gets wrong — went on scoring half an objective
as EXPLOITED under a docstring promising it did not. Both now ask `achieved_combined`, so
they cannot disagree about what "combined" means.

And the fifth state's own lesson got made again, one run later and in the opposite
direction. `not_run` exists because absence read as a clean result and reported eight findings as
fixed when nothing had re-tested them. `state()` returns None for an attack a run did not send, with a comment
saying it says nothing either way — and the branch below it read that None as False, as
*measured clean*. So an attack broken now, absent from the previous run and broken in some
earlier one was labelled **REGRESSED**, which means the fix did not hold, when nothing had
ever measured it fixed. `not_run` protected absent-now; nothing protected absent-before.
**Every REGRESSED label the engine had ever produced was resting on an absence: 42 of 42**,
and 22 "RETURNED after a fix" badges were on the rendered report. A previous state of absence
is its own case now — first sighting is `new`, an earlier break is `open` and still owed —
and the ids where a regression claim would have been made come back in `assumed_clean` so
the comparison says what it rests on.

The most expensive kind of wrong was on a published page. `out/isolation_secretbot.json`
stored **HARDENED** for `secret-disclosure` — *nothing gives, even in isolation* — in a record
that also holds `transformed_disclosure` with a key search verdict of KEYED. `apply_keysearch`
exists for exactly that and names the stakes itself: reporting a keyed objective as hardened
is the one where **the reader stops looking**. The code has been right since it was written.
The artifact predates it, no stored map carried the `keyed` field it adds, and the scorecard
rendered HARDENED off the stale file for two days. Lock maps had no replay at all — a stored
map is a published verdict about somebody's system in exactly the way a sweep result is, and
nothing re-checked one. `rejudge` now replays them too, at no GPU cost because everything the
verdict needs is already stored, and rebuilds the page rather than stopping at the JSON.

Nine benign baselines closed the other half of it: 24 of 28 targets now have one, against 15.
Two of the new ones are findings on their own. **toolagent-naive makes an internal request on
42 of 48 ordinary prompts**, so both of its published SSRF breaches are now marked
unattributable rather than counted. And **mcpagent-naive sends the key out through a tool
argument on 42 of 48**, which is not a false positive — it is the measurement behind the claim
that MCP tool-description poisoning needs no attacker interaction at all.

The replay path had the same shape of hole. `meta["attribution"]` is the caveat that says
whether a breach is attributable at all — a verdict means nothing until the target is quiet
when nobody attacks it — and it is computed at sweep time, while `rejudge` rebuilt each page
from STORED meta and skipped any file whose verdicts had not moved. The caveat could not be
corrected even in principle. **21 of 28 result files were carrying none at all**, thirteen of
them because no benign run exists for that target, which makes every verdict on those pages
unattributed and said so nowhere. nemo-inputonly is the sharpest: its bot emits the canary on
**36 of 48 ordinary prompts** and its page claimed five clean breaches. It now carries the
caveat, and the interesting half of it is what survives — `canary_in_output` is 75% noisy
there, but three rows stand anyway because the specific value they produced appears on only 4%
of benign traffic, and one is marked unattributable.

The second half of this release was about reach rather than about defects, because the binding
constraint had stopped being correctness: **the engine had never met a system it was not built
next to.** A new target is described by a YAML file now rather than by a Python module; the rate
limit and request budget live in that adapter, where the endpoint is somebody else's production;
authorization is a gate rather than a README sentence, in both doors; generation learned the two
rule shapes real system prompts are actually written in; and a short run has a shape that can be
defended — one attack from each category, ordered so the row a reader can reproduce comes
first, the benign baseline in full, the blind spots named, and how much was tried printed
beside what was found.

Practice, purpose-built and locally-run open-source targets only. Real third-party targets
require explicit authorization (bug-bounty scope or proof of ownership).

## Status (2026-08-17)

Fifty detectors, every one demonstrated on a live target. Ten practice targets, a
purpose-built range in two builds, a third-party FastAPI RAG app, and a **foreign control**
— smolagents in both agent shapes, whose prompts, reasoning loop and tool protocol are not
this project's. Five deliveries, 24 attacks that apply to a system this project did not design (was six), a
17-frame library, and 19 test files. The practice fleet is entirely local: Ollama, no API keys, no provider spend to reproduce it.

The release that mattered most was the one spent measuring the tool against itself, and the
number worth publishing is the one that went DOWN. Pointed at a system it had not grown up
with, the oracle produced eight false positives in a single run of 48 benign prompts, in
four classes that 480 home-fleet probes had never once produced — because the configs and
the targets they describe had grown up together. Every one is fixed, and the two rules
underneath them are CI gates now: **no detector may read the question**, and **no detector
may read the agent's own speech as evidence about the system**.

The same control found the opposite error, which for a security tool is the worse one: two
system-prompt attacks scored DEFENDED while the agent was reciting its instructions on
request, because the detector built for exactly that case had been sitting inert all run for
want of one config key. Silence from a check that was never able to speak is now reported
rather than counted as a clean result — as is an attack that was never sent, a target with no
benign run, and a tool call whose contents no pattern could see.

What the engine can now say that a scan cannot: **is this new, did your fix hold, has it
regressed, how long has it been open** — and where it could not see at all.

Practice, purpose-built and locally-run open-source targets only. Real third-party targets
require explicit authorization (bug-bounty scope or proof of ownership).

## Status (2026-08-13)

Proof-of-concept against the Damn Vulnerable LLM Agent (DVLA), a deliberately insecure
practice application run locally against `mistral-nemo`: direct injection, ReAct
injection, SQLi, and system-prompt leak all confirmed; indirect (data-borne)
injection cracked via authority framing. Model comparison showed **size is not a
defense** (12B/14B/24B fold to the same core). Practice/legal targets only —
real third-party targets require explicit authorization (bug-bounty scope or
proof of ownership).
