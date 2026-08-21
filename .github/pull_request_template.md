<!--
Most of what a reviewer would ask is asked by the build instead, on four platform legs, before
anybody looks at this. So this template is short: it asks for the two things a machine cannot
check, and gets out of the way.
-->

## What broke, or what could not be measured before

<!--
One or two sentences. The most useful shape here is a failure: what went wrong, or what this
tool could not see until now. "Adds X" tells a reviewer what changed; "X was reported as
DEFENDED because the detector could not fire" tells them why it matters.

A change that adjusts a number without changing what produced it is the one shape that gets
sent back — see CONTRIBUTING.md, "count it, do not declare it".
-->

## How you know it works

<!--
Not "tests pass" — the build says that. What did you point at it? If you added a detector, what
did you feed it that SHOULD NOT fire, and did it stay quiet? If you added an attack, have you
seen it work, and against what?

The convention throughout this repository is: plant a specific drift, watch the check fail; hand
it the real thing, watch it stay quiet. A gate that fires on everything passes the first half
perfectly.
-->

---

- [ ] `python tools/check.py` passes locally
- [ ] If this adds a **detector**: it is in `NEEDS_CONFIG` if it reads any config key, and it has
      cases in `test_oracle.py` — including at least one that must NOT fire
- [ ] If this adds an **attack**: `qatration lint` is clean, and it carries `applies_to:` if it
      targets a practice bot in this repository
- [ ] If this changes a **number** anyone can read — in the README, the docs, the site — the
      check that recounts it was updated with it
- [ ] Nothing here is business, pricing or commercial reasoning. Comments about mechanisms, yes;
      commercial reasoning, no
