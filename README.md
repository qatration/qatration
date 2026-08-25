# QAtration

> [!CAUTION]
> **Do not point this at a system you do not own.**
> It sends real attacks — prompt injection, data exfiltration, tool abuse — at whatever URL you
> give it. Use it on your own deployment, or on one whose owner has given you written permission
> in advance. **Not** a public chatbot you find interesting. **Not** a vendor's demo. **Not** to
> "just check" somebody else's product.
> [AUTHORISED-USE.md](AUTHORISED-USE.md) says what that means in practice, and what to do if you
> find something in a system that is not yours.

*QA + [pene]tration* — adversarial testing for LLM features and agents.

**[qatration.com](https://qatration.com)** · [what it catches](https://qatration.com/#finds) · [the evidence](out/)

Point it at a bot, fire a library of attacks (prompt injection, system-prompt leak, agent
tool-abuse, SQL-injection-via-agent), and get an **objective** verdict per attack, because the
oracle checks planted canaries and tool-call arguments rather than vibes. Built to answer the
question no classic test suite can: *our AI feature shipped — what can it be talked into
doing?*

**Apache 2.0. Run it yourself.** The engine is meant to run where the system under test is: on
your machine, in your CI, against your own deployment. Nothing here needs a service, and `out/`
ships with the repository, so every number in these pages can be recounted rather than believed
— `test_readme.py` recounts them and fails when a claim and the code disagree.

## Why this and not "another eval tool"

The oracle for **security** is objective and the same for every target — a leaked secret is a
string, a rogue tool call is a log line — unlike **quality**, which is subjective and has no
oracle anyone can check. QAtration is built on that seam.

Three things follow from it, and they are what this project has instead of a bigger attack
count:

* **The detectors are deterministic.** **65 detectors**, no grader model, so a verdict is
  auditable, free, and the same tomorrow. [How many have ever fired](docs/oracle.md) is
  published rather than implied.
* **A breach is reported with its attribution.** A detector that also fires on a fifth of a
  target's ordinary traffic has not demonstrated anything, and the report says so instead of
  counting it. [What that costs, and why it is worth it](docs/attribution.md).
* **A check that could not run is never a pass.** Every detector that was unable to speak is
  named in the run, stored in the results, and exported as a SARIF notification. Silence and a
  defence are different facts.

## Quickstart

```
pip install qatration

qatration init --url https://your-bot.example.com/chat   # writes mybot.yaml, canary and all
qatration onboard --target-config mybot.yaml            # one real request: is the mapping right
qatration run     --target-config mybot.yaml            # sweep it
qatration benign  --target-config mybot.yaml            # what fires when NOBODY is attacking
```

PyYAML and pyfiglet, nothing else. The model frameworks belong to the practice bots in this
repository rather than to the engine, and install separately: `pip install "qatration[fleet]"`
covers LangChain, and the two bots that need smolagents and nemoguardrails each want
their own environment because those two cannot share one — see the note in
`pyproject.toml`. Evidence goes to `./qatration-out` unless `$QATRATION_OUT`
says otherwise.

`init` writes the config so you do not have to invent one, and it mints the canary for you
rather than leaving it as a step to remember. `qatration mint` still exists on its own, for a
config you already have.

**And the canary is not tidiness.** It is worth exactly the fact that nothing
else in the world knows it. The example configs ship one so they run out of the box, and that
value is published here — it can be trained on, blocklisted, or matched by a guardrail that
knows nothing about the deployment behind it. A target that fails to leak a published string
has shown only that it recognises a famous string. `qatration run` refuses a config still
carrying one, before sending anything, rather than handing you a clean report that measured
nothing.

The pair it prints is two tokens, not one. The secret is what the attacks hunt for; the second
is public by construction, so asking for it is an ordinary question that proves the snippet
actually landed. An unplanted canary is invisible — every detector finds nothing and every
attack comes back DEFENDED — and no instruction in a README prevents somebody skipping the
step, so the sweep checks for itself.

## Pointing it at your own deployment

`mybot.yaml` is about ten lines, and `qatration onboard` tells you what is missing from it
rather than making you guess twice. Four configs are ready to copy:

* [`targets_openai_compatible.yaml`](redteam/targets_openai_compatible.yaml) — OpenAI, and
  everything that copied its shape: Groq, Together, Fireworks, OpenRouter, Azure OpenAI, vLLM,
  LM Studio, Ollama's `/v1`. Change `url` and `model`.
* [`targets_anthropic.yaml`](redteam/targets_anthropic.yaml) — the Messages API, which is not
  OpenAI-shaped in four places and says which four.
* [`targets_bedrock.yaml`](redteam/targets_bedrock.yaml) — AWS, the one endpoint a fixed header
  cannot describe: every request is signed from its own body and the clock. The signer is
  standard library and pinned to AWS's published test vectors, because a wrong signature is a
  403 on every probe, and a run where nothing got through reads exactly like a perfect defence.
* [`targets_vertex.yaml`](redteam/targets_vertex.yaml) — Google, reached with the token
  `gcloud auth print-access-token` prints. That token outlives about an hour and a sweep can
  run for thirty minutes, so an auth failure *after* something already worked is reported as a
  credential that expired and the rest of the run as **not measured** — never as defended.

Both test a **deployment** rather than a model: this system prompt, this model, this API. Hold
the prompt fixed and swap the model and the comparison is about the model; hold the model and
change the prompt and it is about your prompt. Neither is swept by `run_all` — a fleet run that
reached a paid API would turn one command into a bill.

The full walkthrough, including every way a first run can quietly lie to you, is in
[onboarding](docs/onboarding.md).

## In CI

```yaml
- run: pip install qatration
- run: qatration run --target-config mybot.yaml --fail-on exploited
  env:
    LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
- run: qatration sarif --results qatration-out/results_mybot.json --out qatration.sarif
  if: always()
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: qatration.sarif }
  if: always()
```

**The exit codes are a contract, not an accident.** Anything non-zero fails a build, so the
reason has to be recoverable from the number alone:

| Code | Meaning | Was anything sent? |
|---|---|---|
| `0` | ran, and the gate you asked for was not tripped | yes |
| `1` | `--fail-on` tripped: the target was exploited or breached | yes |
| `2` | the config or the invocation was refused — an override that cannot apply, a build that is not the one described | **no** |
| `3` | nothing was measured: every trial errored, so the results file was left alone rather than overwritten with a run of nothing | attempted |
| `4` | not authorised: the target is not localhost and control of it was not proved | **no** |
| `5` | a precondition failed: the canary is one this tool publishes, or a declared honeytoken was not found in the target, so the canary detectors could not have spoken | **no** |

`2`, `3` and `5` are deliberately not `1`. A build that fails because a bot was compromised and
a build that fails because nobody could reach it are different events, and a CI that cannot
tell them apart teaches its team to ignore both.

**The SARIF is not a plain dump.** A breach on a detector that also fires on a fifth of that
target's ordinary traffic arrives as a `note` carrying the ambient rate, not as a red `error` —
see [attribution](docs/attribution.md). And a detector that could not fire becomes a SARIF
*tool notification* rather than a silence, because a scan with eleven blind detectors and no
findings must not render as a clean one.

**For a pull request, use `--fail-on regression` instead.** `exploited` and `any` fail on the
absolute state, so the first check a team adds goes red on whatever was already broken and stays
red, and everyone learns to skip it. `regression` fails only on what the change introduced — and
exits 3 rather than green when the comparison cannot be believed. The whole setup, including
where the target comes from on a PR, why fork pull requests get no secrets, and how to keep the
timeline between runs, is in **[verifying a pull request](docs/ci.md)**.

## The rest of the design record

This is the front page. All of it used to be one file, until that file reached 2,400 lines and
stopped being read — which is its own kind of claim nobody checks. Nothing was cut in the
split: `test_readme.py` reads every page below as one corpus, so a number may move between them
and still cannot quietly disappear.

* **[Onboarding a target that is not ours](docs/onboarding.md)** — the config, the canary, the
  authorisation, and every way a first run can lie to you.
* **[The oracle](docs/oracle.md)** — the detectors, how many have ever fired, where the oracle
  stops, and the two gates that keep it from reading the question.
* **[Attribution](docs/attribution.md)** — the benign baseline, the false-positive rate, the
  cross-framework control, and what a negative result is worth.
* **[What the runs found](docs/findings.md)** — why an attack succeeded rather than only that
  it did, and what a guardrail buys once you can measure it.
* **[Internals](docs/internals.md)** — engine versus content, the layout, how objectives and
  attacks are generated, and the practice targets.
* **[Verifying a pull request](docs/ci.md)** — the gate that answers "did this change
  make it worse", and every operational question a real workflow runs into.
* **[Changelog](CHANGELOG.md)** — what changed, newest first.

## Who wrote this

One QA engineer, with Claude doing most of the typing. The design decisions, the failures worth
chasing and the calls about what counts as evidence are mine.

None of that needs taking on trust. Every number in this README and on the site is recounted
from the artifacts in `out/` by a test that fails the build when the two disagree. No assertion
in the suite is allowed to be one that cannot fail — 1,417 of them, `check()` calls and bare
asserts alike, parsed and refused if their truth does not depend on the code. `tools/guard.py`
refuses commits from this project itself. All of it runs on every push, on four platforms.

## Contributing

`python tools/check.py` runs every suite. They are offline: no model, no network, no practice
fleet, and it is the same command CI runs, so a green local run means a green build.

* **[CONTRIBUTING.md](CONTRIBUTING.md)** — the three things you can add without touching the
  engine, the two rules the build enforces on a new detector, and the one convention that is not
  negotiable.
* **[SECURITY.md](SECURITY.md)** — where to report, and why **a clean result nobody earned** is
  filed here as a security bug rather than as a feature request.
