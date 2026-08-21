# Security

## Two kinds of report, and the second one is the point

**1. A vulnerability in QAtration itself.** It parses YAML you did not write, sends what that
YAML says, and renders replies from a system under attack into an HTML page. Anything that lets
a config or a target's reply reach further than it should — code execution from a config, markup
escaping the report and running in the reader's browser, a path written outside the artifact
directory, a credential turning up in a file or a log — is a vulnerability. Report it.

**2. A result the tool did not earn.** This is the report we most want, and most tools have
nowhere to file it.

The entire premise here is that a security scanner's worst failure is not a crash. It is a
**clean result nobody earned**: a detector that could not fire, a check that never ran, an
attack that was never sent, all rendered as a target that held. A report that says "defended"
about something it did not measure has done more damage than no report at all, because somebody
shipped on it.

So the following are security bugs in this project, not feature requests:

* a detector that stays silent because its configuration is missing, without `inert_for` saying
  so on the run and in the stored result
* an attack that is skipped, errors, or is never sent, and does not appear as a gap in the JSON,
  the HTML and the SARIF
* a breach reported at full confidence when the same detector also fires on that target's own
  ordinary traffic
* any number in the README, the docs, or on the site that the code no longer supports
* a misconfiguration — a wrong `response.reply` path, an unplanted canary, a missing auth header
  — that produces empty replies scored as a bot that refused

If you find one, it is worth a report even if nothing crashed. Especially if nothing crashed.

## How to report

For anything that should not be public first, write to **qatration@gmail.com**. There is no
on-call rota behind that address, so please allow time — and say in the mail if what you
found cannot wait.

Anything else is welcome as a
[GitHub issue](https://github.com/qatration/qatration/issues) — including the second kind
above, which is usually more useful in the open.

What helps, in rough order:

1. The **stored artifact**, if you have one. `out/results_<target>.json` and the matching
   `benign_<target>.json` are the evidence; `qatration rejudge` replays them against the current
   oracle with no model and no network, so a finding you can hand over as JSON is one anybody
   can reproduce in seconds.
2. The **target config**, with the auth header still as `${VAR}`. Never paste a real key.
3. `qatration --version`, and the `engine` field from the result's `meta` — a stored result is a
   statement about the engine that wrote it, not about the one you are running.
4. What you expected the tool to say, and what it said instead.

## What is not a vulnerability here

**The practice bots under `httpbot/`, `draftbot/`, `foreign-agent/`, `external/` and
`redteam/targets_*.py` are deliberately broken.** They leak keys, obey injected instructions,
and call tools they should not. That is what they are for: they are the range this engine is
sighted against. Finding a hole in one of them is not a finding, it is the exercise working.

**The attack corpus is attack payloads.** Prompt injections, encoded exfiltration, forged
transcripts, package-hallucination bait. They are in the repository on purpose and they are the
product.

## Using this tool

`AUTHORISED-USE.md` is the rule, and it is short: this sends real attacks at whatever it is
pointed at, so point it only at something you own or have written permission to test. Anything
that is not localhost has to prove control before a run — a DNS record, a file at a known path,
or a token the bot itself returns — and the run exits 4 without it rather than trusting you to
remember. Testing systems you do not own is illegal, and that is on the operator, not the tool.
