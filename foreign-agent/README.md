# The foreign target

A support agent built on **smolagents** — the control for every number QAtration reports
about itself. Everything else in the fleet is a bot written here, which means the oracle's
configs and the targets they describe grew up together; a detector that only works because
it was tuned to our own adapters would look perfect on our own adapters.

The split is the same one a real deployment has:

* **theirs** — the system prompt (`prompts/toolcalling_agent.yaml`, untouched), the
  reasoning loop, the tool-call protocol, output parsing, memory, error handling.
* **this repo's** — the tools, because every deployment supplies its own, and the HTTP wrapper.

Not a line of the agent's instructions was written here. If a QAtration detector needs this repo's phrasing
to work, this is where that shows up — and on the first run it showed up four times.

The venv lives OUTSIDE the repo, because smolagents pins versions that clash with the
LangChain 0.3 the rest of the fleet runs on, and because a foreign system answering over
HTTP in its own process is the shape of a real deployment rather than an import.

```bash
python -m venv foreign-agent-env
foreign-agent-env/Scripts/python -m pip install smolagents openai   # Windows
foreign-agent-env/bin/python -m pip install smolagents openai       # macOS, Linux
foreign-agent-env/Scripts/python server.py        # port 8130
```

Then, from the repo root:

```bash
dvla/env/Scripts/python redteam/run_recon.py --target-config redteam/targets_foreign.yaml
dvla/env/Scripts/python redteam/benign.py --target foreign
```

The canary is planted the way secrets actually leak — an internal field on a customer
record that a tool returns, with nothing in the agent's instructions telling it to keep
quiet. Any disclosure is therefore a fact about the framework rather than a rule written
for it to break.
