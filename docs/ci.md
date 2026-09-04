# Verifying a pull request

Wiring this into CI so that every pull request gets checked, and the check stays worth reading.

*Part of the [QAtration](../README.md) design record.*

---

## The question a pull request is actually asking

Not *"is this bot secure"*. It is asking **"did this change make it worse"**, and the difference
decides whether anyone keeps looking at the check.

A gate on the absolute state — `--fail-on exploited` or `--fail-on any` — goes red on whatever
was already broken the day it is added, and stays red. Within a week the team learns that the
red mark means nothing, and from then on the check is worse than absent: it is a signal everyone
has been trained to skip past.

```
qatration run --target-config mybot.yaml --fail-on regression
```

`regression` fails **only on what this run introduced or reopened** since the previous one. It
compares against `out/history/<target>.jsonl`, which is why the history has to survive between
runs — see [persisting the timeline](#persisting-the-timeline).

**A move the trials do not agree on is not a change.** A bot is sampled, not queried, so the
same attack against the same deployment can break once in three attempts and then not at all,
with nothing between the two runs but a different seed. Measured here: two runs of this engine
against one endpoint, same config, same model, same scope, same `--trials 3`, nothing altered
between them. Six attacks moved to "introduced or reopened" and four to "fixed", and not one of
the ten broke on all three attempts in either run. That is a red build on a pull request that
changed nothing, which is precisely the outcome `regression` exists to prevent.

So a move is only counted when the side claiming it broke on **every** attempt: all trials now,
for a finding introduced or reopened; all trials before, for one called fixed. Everything else
is reported under its own heading and does not fail the build:

```
CI GATE: FAIL - 1 finding(s) this run introduced or reopened since 2026-09-02 17:46:44: d-skeleton-audience
  (4 row(s) moved, but not on every attempt, so nothing here separates them from the sampling: gt-acrostic, cite-multi-hop, d-action-batch, d-split-alternate)
```

The second line is printed on a green build too. A row that moved is still a row that moved, and
a gate that quietly dropped it would be making the same mistake in the other direction.

Two consequences worth knowing. **Raising `--trials` makes the gate stricter, not noisier**: at
3 an attack has to break three times, at 5 five, so a flaky finding is less able to reach the
count. **And at `--trials 1` the gate refuses to answer at all**, because one attempt cannot
tell a reliable break from a lucky one: a single hit is trivially "every trial", so every flip
of a coin the target was already flipping would count as a move. Measured from a fresh install
against a local model: four sweeps, same config, same model, same 45 attacks, nothing changed
between them but the sampler, and the breach count went 12, 4, 6, 7. The gate answers 3 there
and names `--trials` as the remedy. And **a row whose stored rate cannot be read is never counted** - snapshots written before
this rule are named as unsteady rather than assumed reliable, because understating a diff is the
direction this repo allows and overstating is not.

**And it refuses to answer rather than passing.** If the arsenal changed, or the model changed,
or the trial count dropped, or the stored timeline is torn, then before and after were measured
with different instruments and neither a pass nor a failure would mean anything. In that case it
exits **3**, "nothing was measured", with the reason named. A team that sees this once
re-baselines, which takes a minute and is the correct response. A green in that situation would
be a lie, and this tool has one rule above all others: a check that could not run is never a
pass.

## What do you point it at?

**A pull request cannot test a deployment that does not exist yet.** This is the first thing to
settle, and no configuration answers it for you. In practice there are three shapes:

* **A staging deployment that the PR is merged into first.** The check then answers "did staging
  get worse", which is a real question but not a per-PR one.
* **A preview environment created per pull request** (Vercel, Netlify, a review app, an ephemeral
  namespace). This is the shape that actually answers the per-PR question, because the endpoint
  under test contains this change and nothing else.
* **The system prompt only.** If the PR changes the prompt rather than the code, you can run the
  bot locally in the workflow with the new prompt and point QAtration at `localhost`. That is
  also the only shape that needs no secrets and no deployed environment.

If none of those exist yet, run it on a schedule against staging instead of per pull request.
A nightly answer to "did anything get worse today" is worth more than a per-PR check that has
nothing real to point at.

## The canary has to be in the thing being tested

`qatration mint` gives you a secret of your own, and it has to reach the **deployed** system
prompt of whatever the workflow is pointed at, not just your local copy. Whichever way you
deploy, the canary rides along the same path as the prompt.

The run checks this itself before it sends anything: it asks the deployment for its public
verifier, and if that does not come back it aborts with exit **5** rather than sweeping. An
unplanted canary makes every canary detector inert, every attack come back DEFENDED, and the
report say the deployment held — which is the single most expensive way this tool can be wrong.

Keep the secret in your CI secret store, not in the config. The config references it as
`${VAR}` and the adapter refuses to start when the variable is unset, rather than sending the
literal `${VAR}` as a bearer token and producing a run of 401s that reads exactly like a
hardened deployment.

## Pull requests from forks do not get your secrets

GitHub does not expose `secrets.*` to a `pull_request` workflow triggered from a fork. That is
correct behaviour and not something to work around casually: a fork PR can change the workflow,
and a workflow with your production key is a workflow that can send it anywhere.

So the check has to be shaped around it. Either skip the sweep on fork PRs and let it run on
merge, or use `pull_request_target` with a manual approval gate and full awareness of what that
means. **Do not** hand a live key to arbitrary forked code because the check looked red.

If the sweep is skipped, say so in the job rather than letting it pass silently — a skipped
check that renders green is the same defect as an inert detector.

## Where the timeline lives

`--fail-on regression` needs the previous run to compare against, and CI starts from nothing
every time. So the timeline has to survive, and **the best place for it is your own repository**.

A timeline is one append-only JSONL file per target, one line per run, about **2 KB a run** — a
target swept daily for a year is a 700 KB text file. Commit `qatration-out/history/` and you get
three things a cache cannot give you:

* it survives, permanently, with no expiry to think about
* **the diff shows up in the pull request** — a reviewer sees not just that something got worse
  but exactly which attack changed verdict, in the same review they are already doing
* it needs nothing from anybody else: no service, no account, no upload of your findings to a
  third party. The file is a list of what breaks in your bot, which is the last thing that
  should live on somebody else's server.

If you would rather not commit it, `actions/cache` works, with one caveat worth knowing before
it bites: GitHub evicts a cache that has not been read for seven days. A quiet week means a
cache miss, which means no baseline, which means the gate correctly reports that it cannot
answer — and everyone wonders why the check went yellow on a branch that changed nothing.

Either way the very first run has nothing to compare against and exits 3 saying so. That is
expected: a first run is a baseline, not a verdict. Run it once on your main branch to seed the
timeline, then the pull-request checks have something to answer against.

**Nothing is sent anywhere.** The engine runs where you run it and writes where you point it;
there is no account, no upload and no service in the loop. That is a deliberate design decision
rather than a missing feature — see [nothing leaves your side](#nothing-leaves-your-side).

## What a run costs, and why a sweep is the wrong shape for a pull request

| scope | attacks | requests | at 2s a request | at 4s |
|---|---|---|---|---|
| `--scope full`, 3 trials (the default) | 379 | 1,464 | ~49 min | ~98 min |
| `--scope full`, 1 trial | 379 | 488 | ~16 min | ~33 min |
| `--scope quick`, 3 trials | 60 | 225 | ~8 min | ~15 min |
| `--scope quick`, 1 trial | 60 | 75 | ~3 min | ~5 min |

**Nobody is running the top row on every pull request.** A busy repository merges ten an hour,
and forty minutes of a paid endpoint per merge is not a security practice, it is a denial of
service you are funding. Three things make this workable, and the first matters more than the
other two together.

### Only run it when the LLM feature actually changed

Most pull requests do not touch the prompt, the tools, the model or the agent loop. Sweeping a
CSS change is pure waste — and it is the waste that gets the workflow deleted.

```yaml
on:
  pull_request:
    paths:
      - "prompts/**"
      - "src/agent/**"
      - "src/tools/**"
      - "**/model_config.*"
      - "mybot.yaml"
```

Ten merges an hour becomes one or two sweeps a day, and each of those is a change that could
plausibly have moved something.

### Pick one scope and keep it

`--scope quick --trials 3` is the shape for a per-PR check: seven minutes, every category
covered once, cheapest delivery first. It is a tripwire rather than an assessment, which is the
correct job for a gate running on somebody's branch.

**But the scope has to match the baseline it is compared against, and this is the trap.** The
regression gate compares against the previous run of the same target, and `history.py`
deliberately refuses to compare runs made with different instruments. Alternate `--scope full`
on a schedule with `--scope quick` on pull requests, writing into one timeline, and every
comparison comes back:

```
CI GATE: CANNOT ANSWER — the comparison is confounded: arsenal 362 -> 58 attacks
```

Correct, and useless. The same happens for `--trials`: a run at 1 compared against a baseline at
3 is confounded, because fewer attempts give a flaky attack fewer chances and that reads as a
fix.

So **give each scope its own timeline** with `$QATRATION_OUT`, which exists for exactly this:

```yaml
env:
  QATRATION_OUT: qatration-out/pr        # quick runs compare against quick runs
```

```yaml
env:
  QATRATION_OUT: qatration-out/nightly   # full runs compare against full runs
```

Two measurements, each internally consistent, neither pretending to be the other. Seed each one
once on your main branch before anything reads it.

### The nightly run is where the full sweep belongs

A pull request asks "did this change break something obvious". A scheduled run asks "has
anything drifted", including things no pull request touched — a provider moving you to a new
model version underneath you is the common one. Different questions, different budgets.

### What it costs in money

Time is the visible cost. The token bill is the one that decides whether a check keeps
running after the first month, so it is measured here rather than waved at.

The token volumes below are measured rather than estimated: attack payloads from the corpus
itself, and reply lengths from **1,259 stored replies** in `out/`. Prices are Anthropic's, per
million tokens, as of August 2026.

| scope | your prompt is 422 chars | a realistic 4,000-char prompt |
|---|---|---|
| | haiku / sonnet / opus | haiku / sonnet / opus |
| `full` x3 (the default) | $0.89 / $2.66 / $4.43 | $2.13 / $6.39 / $10.65 |
| `full` x1 | $0.30 / $0.89 / $1.48 | $0.71 / $2.13 / $3.55 |
| `quick` x3 | $0.14 / $0.42 / $0.70 | $0.34 / $1.01 / $1.68 |
| `quick` x1 | $0.05 / $0.14 / $0.23 | $0.11 / $0.34 / $0.56 |

**The dominant cost is your own system prompt, not the attacks.** An attack payload averages 43
tokens; a production system prompt is easily a thousand, and a stateless API resends it on every
single request. At 1,407 requests that is 1.4M input tokens of your own instructions — about
85% of the input bill — before a single attack payload is counted.

Two consequences worth acting on:

* **Prompt caching pays for this outright.** If your deployment caches the system prefix, those
  repeated tokens drop to roughly a tenth, and a full Sonnet sweep goes from about $6.40 to
  around $2.60. If you were looking for a reason to turn caching on, a security sweep is one.
* **A per-PR check is cents, not dollars.** `quick` at three trials is well under a dollar on
  any of these models, which is the number to quote when someone asks whether this can run on
  every relevant pull request.

Two honest caveats. The reply lengths were measured against this project's own practice bots on
local models, so a chattier deployment costs more and a terser one less — the shape holds, the
third decimal place does not. And one attack, `g-unbounded`, deliberately asks for output until
something stops it: the longest stored reply is 45,000 characters. That is the finding, not an
accident, but it is why a deployment with no output ceiling of its own costs more to test than
one that has thought about it.

### Ten pull requests at once

`cancel-in-progress` stops one branch queueing behind itself and does nothing about ten branches
hitting one endpoint together. That endpoint's rate limit will win, and the run reports the
resulting errors as gaps rather than findings — honest, and still a check that told you nothing.

If merges are frequent, serialise rather than cancel:

```yaml
concurrency:
  group: llm-security-sweep      # one at a time, across every branch
  cancel-in-progress: false
```

## A workflow that does all of it

```yaml
name: llm-security

on:
  pull_request:
    # THE BIGGEST LEVER ON THIS PAGE. Most pull requests do not touch the LLM feature at all,
    # and sweeping them is the waste that gets the workflow deleted. Narrow this to the paths
    # that can actually change what the bot will do.
    paths:
      - "prompts/**"
      - "src/agent/**"
      - "src/tools/**"
      - "mybot.yaml"
  push:
    branches: [main]
  schedule:
    - cron: "0 3 * * *"      # the full sweep, nightly

permissions:
  contents: read
  security-events: write     # required to upload SARIF

concurrency:
  # Serialised rather than cancelled: ten branches sweeping one endpoint at once
  # will hit its rate limit, and the errors that produces are reported as gaps —
  # honest, and still a check that told you nothing.
  group: llm-security-sweep
  cancel-in-progress: false

jobs:
  sweep:
    runs-on: ubuntu-latest
    # A fork PR has no secrets. Skipping is correct; pretending it passed is not.
    if: github.event.pull_request.head.repo.full_name == github.repository || github.event_name != 'pull_request'
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - run: pip install qatration

      # Only needed if you did NOT commit qatration-out/history — see "Where the timeline
      # lives". Without one of the two, every run is a first run and the gate can never answer.
      - uses: actions/cache@v4
        with:
          path: qatration-out/*/history
          key: qatration-history-mybot-${{ github.run_id }}
          restore-keys: qatration-history-mybot-

      - name: sweep
        env:
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
          # ONE TIMELINE PER TIER. A quick run and a full run written into the same
          # history make every comparison confounded — different arsenals are different
          # instruments — and the gate then correctly refuses to answer, on every pull
          # request, forever.
          QATRATION_OUT: qatration-out/${{ github.event_name == 'schedule' && 'nightly' || 'pr' }}
        run: |
          qatration run \
            --target-config mybot.yaml \
            --fail-on regression \
            --trials 3 \
            ${{ github.event_name == 'schedule' && '--scope full' || '--scope quick' }}

      - name: findings to the security tab
        if: always()
        run: |
          qatration sarif \
            --results qatration-out/${{ github.event_name == 'schedule' && 'nightly' || 'pr' }}/results_mybot.json \
            --target-config mybot.yaml \
            --out qatration.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: qatration.sarif
```

`if: always()` on both SARIF steps is deliberate. The findings are most worth uploading on the
run that failed, and a step that only runs on success publishes exactly the results nobody
needed.

`--target-config` on the `sarif` command is what anchors each finding to a file the reviewer can
open. Without it the location defaults to a path inside this tool's own repository, which does
not exist in yours.

## Reading the exit code

| Code | What the build should conclude |
|---|---|
| `0` | this change introduced no finding the trials agree on. Rows that moved without agreeing are named under the verdict, not hidden by it |
| `1` | this change introduced or reopened a finding — the one case where red means what red usually means |
| `2` | the config or the invocation was refused, including a committed results file this run would replace. Nothing was sent, and this is a build problem rather than a security one |
| `3` | the question could not be answered: no baseline yet, or the comparison was confounded. **Not a pass** |
| `4` | not authorised: the target is not localhost and control of it was not proved |
| `5` | a precondition failed — usually the canary was never planted, so nothing could have been detected |

Only `1` is a finding. Treating `2` through `5` as security failures is how a team learns to
ignore the whole check, and treating them as passes is how a broken pipeline reports a clean
bill for months.

## What the SARIF will and will not say

A breach on a detector that also fires on that target's own ordinary traffic arrives as a
`note` carrying the ambient rate, not as a red `error`. That is deliberate: a red mark on a pull
request that a day of work cannot reproduce costs more than it is worth. Run
`qatration benign --target-config mybot.yaml` once so the tool knows what your deployment does
when nobody is attacking it — without that baseline, nothing in the log can be attributed and
the export says so.

A detector that could not fire becomes a SARIF **tool notification** rather than a silence, and
an attack that was never sent makes the whole invocation unsuccessful. A short list of findings
because the run stopped early must never read like a short list of findings because there was
little to find.

## Nothing leaves your side

There is no account to create and nowhere to log in, and that is the architecture rather than an
unfinished part of it.

Everything this tool produces is a file next to whoever ran it: `results_<target>.json`, the HTML
scorecard, `benign_<target>.json`, `history/<target>.jsonl`. All of it is a description of what
can be made to go wrong in your deployment, which makes it the most sensitive artifact your
security testing produces. Anything that stored it elsewhere would be holding a map of your
exploitable surface on a machine you do not control.

So the engine runs on your machine or in your CI, against your own endpoint, under your own key.
Consequences worth stating plainly, because they are the point:

* no production credential is ever sent anywhere — the config names an environment variable and
  the adapter refuses to start if it is unset
* the canary the attacks hunt for is one you minted and can revoke by deleting a line
* nobody can leak evidence you never gave them, and there is no account of yours to compromise
* your CI budget is the only budget involved

The one thing a local file genuinely cannot do is **compare across deployments and across time**
— whether a new model release made things worse for everyone, or only for you. That needs data
from more than one place, which this design deliberately does not collect: everything stays
on the side that ran the sweep. Nothing here depends on that changing.
