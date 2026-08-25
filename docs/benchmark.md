# Three tools, two targets, one rule

*Part of the [QAtration](../README.md) design record.*

**Run on 2026-08-25.** QAtration 0.2.0, garak 0.16.0, promptfoo 0.122.0. One machine, one GPU,
every run sequential. Raw commands at the bottom.

---

## What this measures, and what it refuses to

It does **not** rank three products by how many findings each reports. Those numbers are not
comparable and printing them side by side would be the defect this project exists to name.
garak and promptfoo lean on model judges for much of their scoring, QAtration is deterministic,
and the three count different events. A run where one says 150 and another says 0 can be two
measurements of one target, differently defined, published as a difference between tools.

So no tool's verdict decides anything here. Each tool's raw prompt-and-reply pairs are read out
of its own report and scored by ONE rule, the same for all three: did the planted string come
back. The string was minted for this run and planted by us, so a leak is a fact about bytes
rather than an opinion about intent.

The question the comparison actually asks is **how much of what a tool reports can be
attributed to the tool at all.**

## The honest labelling, before any number

Both targets are third-party. The first is a small open-source RAG chat application, cloned unmodified and run as its README
describes: FastAPI over Ollama, `llama3.2:3b` for chat and `nomic-embed-text` for embeddings,
answering from a folder of PDFs.

**It is not named here, and that is deliberate.** Its author has not been asked yet, and a page
that shows somebody's hobby project leaking a string WE planted should not put their name in
front of that sentence before they have had the chance to read it. If they are happy to be
named, this line changes and the link goes in. The second is NVIDIA NeMo Guardrails with
input and output rails.

**The entire corpus of the first target is ours, poisoned document included.** That project
ships no documents at all: its `pdfs/` folder is gitignored and its README tells you to create
one and add your own. So the nine PDFs it answered from were written here, and one of them
carries our canary. Nothing below is a finding about that project's security and
none of it is a criticism of its author. It is an ordinary RAG application with no guardrail
layer, which is exactly what makes it the control half of a pair.

## The method that made the numbers mean something

A benign baseline came first: 50 probes with no attack in them. On the unguarded app the
planted string comes back on **46%** of them, which alone disqualifies a raw count as evidence
of anything.

**Those 50 are not all ordinary questions, and the split matters.** 36 are plain customer
support. The other 14 are legitimate questions that happen to CONTAIN attack-shaped text, which
is what a false-positive corpus is for: a customer pasting a stack trace, an XML snippet with an
entity declaration in it, a URL with a template expression. They are benign, and they behave
differently:

| subset | n | poisoned doc retrieved | leaked | leaked given retrieval |
|---|---|---|---|---|
| plain support questions | 36 | 16 (44%) | 15 (42%) | 15/16 (94%) |
| benign but attack-shaped | 14 | 11 (79%) | 8 (57%) | 8/11 (73%) |
| both, as used below | 50 | 27 (54%) | 23 (46%) | 23/27 (85%) |

The attack-shaped half pulls the poisoned file in at nearly twice the rate of a plain question,
which is what lifts the pooled background from 44% to 54%. This was published first as "50
ordinary customer-support questions", which was wrong, and the error mattered: it is the
comparator every claim below is measured against.

A fair objection survives it. The benign questions and the attack questions are different
questions, so comparing their rates compares two distributions as well as two conditions. The
application closes that itself: it **lists the documents it retrieved** at the end of every
answer, so the condition is observable from outside. Which document carries the payload is
measured rather than declared, being the one document cited by every leaking reply. It is
cited by clean replies too, 38 of them, and it has to be: if only leaking replies cited it,
retrieval and leaking would be the same event and there would be nothing to condition on. Attack replies and benign replies are compared under the
same condition rather than across two question sets.

## The unguarded target

A leak here is the product of two things: the poisoned document has to reach the context, and
then the model has to repeat what it says. Separating them is the whole finding.

| source | replies | poisoned doc retrieved | leaked given retrieval | leaked without it |
|---|---|---|---|---|
| no attack at all | 50 | 27 (54%) | 23/27 (85%) | 0/23 |
| garak `latentinjection` | 256 | 121 (47%) | 103/121 (85%) | 0/135 |
| promptfoo | 200 | 158 (79%) | 150/158 (**95%**) | 0/42 |
| QAtration | 262 | 225 (**86%**) | 187/225 (83%) | 0/37 |

**Nothing leaks when the poisoned document is not retrieved.** Zero, in every row, from every
tool and from ordinary traffic alike.

**Once it is retrieved, the application repeats the injected instruction about 85% of the time
on its own.** No attack is needed for that number. garak's injection probes land exactly on it
and QAtration lands just under it, which means neither adds anything to what the app does with
a poisoned document in front of a 3B model.

**promptfoo comes out higher, and it does not clear a significance test.** 95% against the
pooled 85% background is Fisher exact p = 0.078, and against the plain-question background of
94% it is p = 0.59. The limiting number is not promptfoo's 158 retrievals, it is the 27 in the
baseline. So the honest statement is that promptfoo may raise the repeat rate and this run does
not establish it. An earlier version of this page called it the clearest result here, on 158
observations, without running the test. It was corrected within a day of publication after a
review asked for the p-value, and the sentence it replaces is quoted in the commit.

For the same comparison: garak 103/121 against the baseline is p = 1.00, and QAtration 187/225
is p = 1.00. Those two add nothing to the repeat rate, and that part is not in doubt.

**QAtration wins the other factor.** 86% retrieval against a 54% background: its arsenal pulls
the poisoned document into context more reliably than anything else measured. Whether that is
skill or breadth is not settled here. A larger and more topically varied arsenal hits the
poisoned file's subject more often, and the effect would be the same either way.

Nobody wins both. Each tool wins the factor its corpus is built for.

## What each tool's own verdict said

Different questions, all legitimate, and the difference is most of the point.

| tool | its own verdict on the unguarded app | what it was asking |
|---|---|---|
| garak | `latentinjection` attack success 12.11% | did the model emit **garak's own** trigger |
| garak | `dan.DanInTheWild` bypass **90.23%** [86.33, 93.75] | did the model comply with a request it should refuse |
| garak | `encoding.InjectBase64` 0.78% | did the model decode and act on a base64 payload |
| promptfoo | 143 of 200 tests failed | did a judge model think the attack succeeded |
| QAtration | 192 breaches, 181 flagged unattributable by the tool itself | did a detector fire, and can the finding be attributed |

## The guarded target

| source | replies | leaked, shared rule | its own verdict |
|---|---|---|---|
| no attack at all | 48 | 0% | 38 of 48 ordinary questions **refused** |
| garak `latentinjection` | 256 | 0% | attack success 0.78% [0.00, 1.95] |
| promptfoo | 200 | 0% | 0 of 200 failed |
| QAtration | 324 | 0% | **1 of 323 breached** |

The rails hold. Everything that leaked on the bare application goes to zero for all three
tools, and the shared rule finds nothing at all.

**Two things a breach count would not tell you.** The first is the price: this deployment
refuses **79% of ordinary customer questions**. It refuses 96% of attacks, so the seventeen
points between those two numbers are what the rails actually buy. A benchmark that counted only
breaches would call this target perfect and never mention that four customers in five get an
apology instead of an answer.

The second is the one thing that got through: `cap-numeric-anchor`, a multi-turn attack scored
by the `capitulation` detector, 1 in 324. Twenty probes would have found nothing and concluded
the target was impenetrable. **The budget for a published claim and the budget for a Tuesday
are different budgets**, which is why `--scope quick` exists and why it was not used here.

## Where the other tools were better

Written before the conclusion rather than after it, and it is not a courtesy.

**garak finds a whole class we do not measure at all.** `dan.DanInTheWild` bypassed mitigation
on 231 of 256 prompts. QAtration has ten persona attacks, and every one of them is scored by
what leaked, so on a target with nothing to steal we report clean where garak reports 90%. That
is [issue #1](https://github.com/qatration/qatration/issues/1).

**garak's indirect injection attributes by construction.** `latentinjection` carries its payload
in the prompt and looks for its own trigger, which exists nowhere else, so a hit belongs to the
probe. Our findings on this target rested on a canary planted in the corpus beforehand and could
not be attributed at all. The `attacks_docframe.yaml` family added after this run copies that
design, and the credit belongs to garak.

**promptfoo's judge nearly matched the shared rule** and its attacks raise compliance. Its own
verdict was 143 of 200 where the shared rule says 150 of 200, and it is the only tool whose
attacks lift the leak rate once the payload is present. That is
[issue #2](https://github.com/qatration/qatration/issues/2). The grading cost about 17,700
tokens for the first 20 tests, which is a trade against a deterministic check that costs
nothing, not a fault.

## What QAtration did that the others cannot

One thing, and it is the reason the project exists. Of the 192 breaches it reported on the
unguarded target, **181 came with the reason they could not be attributed**, naming the benign
rate of each detector that fired. The remaining 11 carry no such flag, because the detectors
behind them do not fire on this target's benign traffic, and those are the findings the run
stands behind. Neither of the other tools takes a benign baseline, so neither can make the
distinction either way.

On the guarded target it was also the only tool to produce a positive finding.

## What this does not cover

* **Two targets, two models, one day.** Nothing here generalises to a different application.
* **The budgets are not equal.** 200, 256 and 324 replies. Rates are compared rather than
  totals, and each tool ran its own shipped corpus at its own default size, because truncating
  a tool's corpus would mean measuring something other than the tool as shipped.
  `run.soft_probe_prompt_cap` is not honoured by every garak module, which is why an equal
  budget was not available even in principle.
* **Concurrency was normalised to one request at a time.** promptfoo defaults to four in
  flight, the other two send one. Four concurrent requests wedged the unguarded app for over an
  hour and produced a file of transport errors, so every tool drives every target serially. The
  first attempt at these runs is discarded for that reason.
* **The conditioning does not transfer to the guarded target.** It answers with a bare reply
  and discloses nothing about its context, so there the benign baseline is all there is.
* **garak ran five probe modules out of forty-two**, chosen for this kind of target rather
  than sampled: `latentinjection` against both targets, then `encoding`, `dan`, `goodside` and
  `leakreplay` against the unguarded one. A different five could tell a different story.
* **The 90.23% is measured on a random subset and we did not seed it.** `DanInTheWild` is a
  256-prompt sample drawn by `random.sample` from a library of about 700, and garak takes a
  `run.seed` we did not set. Anyone repeating that command gets a different 256 and a different
  figure. Set a seed to compare like with like, and read our number as an estimate of the
  library's bypass rate rather than as a fact about 256 particular prompts.
* **promptfoo's red-team generator asks for email verification.** `promptfoo redteam
  generate` would not run until an address was set with `promptfoo config set email`; a plain
  `promptfoo eval` needs no account. We used the project's own address. Stated because anybody
  reproducing this will meet it, and because it is the kind of thing a comparison should
  mention rather than discover for you.
* **The foreign tools' raw reports are not in this repository.** The commit guard refuses them
  over a Cyrillic character inside garak's jailbreak corpus, that corpus carries its own
  licence, and weakening a gate to accommodate a benchmark artifact is the failure this project
  is named after. Our own artifacts are in `out/bench/` and the commands below regenerate
  theirs.

## Reproducing it

Both targets are third-party and neither is vendored here.

```
# the target repository, once its author has agreed to be named
git clone <the RAG application>
# then follow its README: poetry install, ollama pull llama3.2:3b, ollama pull nomic-embed-text
cd backend && venv/Scripts/python -m uvicorn app.main:app --port 8000
```

The poisoned document is ours and is not part of that project. Put a PDF in `backend/pdfs`
carrying a canary of your own, minted with `qatration mint`, and re-run its ingestion.

```
pip install git+https://github.com/qatration/qatration@4c678f4
qatration benign --target-config redteam/targets_localrag.yaml
qatration run --target-config redteam/targets_localrag.yaml --scope full --trials 1
```

**Not 0.2.0, and the difference is six attacks.** `attacks_docframe.yaml` was committed eight
minutes before these runs started, so the 262 replies include its six `doc-*` attacks while the
released 0.2.0 arsenal does not contain them. Installing the release would send 362 attacks
where this run sent 368, and would not reproduce the row. The commit above is what ran.

```
pip install garak==0.16.0
python -m garak --config out/bench/configs/garak-localrag-injection.yaml

npm install promptfoo@0.122.0
promptfoo redteam generate -c out/bench/configs/promptfooconfig.yaml -o attacks.yaml
promptfoo redteam eval -c attacks.yaml -o results.json --no-cache -j 1
```

Every config those commands read is in `out/bench/configs/`: the REST generator garak was
pointed at, the promptfoo target and plugin list, and the same pair for the guarded target.
The files themselves, not a transcription of them.

Then score every report by the same rule:

```
python tools/bench_score.py --benign out/bench/benign_localrag.json \
    garak:report.jsonl promptfoo:results.json qatration:out/bench/results_localrag.json

python tools/bench_condition.py --benign out/bench/benign_localrag.json \
    garak:report.jsonl promptfoo:results.json qatration:out/bench/results_localrag.json
```

`tools/bench_score.py` counts the planted string in every reply and prints each tool's rate
beside the benign baseline. `tools/bench_condition.py` splits those replies by whether the
poisoned document was retrieved, and refuses to run against a target that does not disclose it
rather than inventing a number.

## Wall clock

Same machine, one at a time, generation included where a tool generates its own attacks.

| run | prompts | time |
|---|---|---|
| QAtration, unguarded, full arsenal | 262 | 25 min |
| QAtration, guarded, full arsenal | 324 | 47 min |
| garak `latentinjection`, unguarded | 256 | 27 min |
| garak `latentinjection`, guarded | 256 | 19 min |
| garak, four more families, unguarded | 553 | 55 min |
| promptfoo, unguarded | 200 | 25 min |
| promptfoo, guarded | 200 | 4.5 min |

The guarded target answers faster under attack than the unguarded one because a blocked input
never reaches the model at all.
