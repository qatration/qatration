"""
Adapter for a third-party open-source RAG app that was not written to be attacked and
was not modified for this: FastAPI over a vector store. Its retrieval prompt interpolates
retrieved document text directly into the instruction, so a poisoned document in
the corpus should hijack answers to benign questions.

Black box over HTTP: only the streamed answer is visible. The poison lives permanently
in the corpus (adding/removing per-attack would mean re-embedding), so attacks are
benign-looking queries whose retrieval pulls the poisoned doc; the canary detector
judges whether the document's injected instruction propagated into the answer.
"""
import json, re, time, urllib.request
from target import Probe, Target

# THE APP REPORTS ITS OWN FAILURES INSIDE A 200. FastAPI catches the exception, the endpoint
# returns a StreamingResponse, and the body is prose: "There was an error processing the query:
# Failed to connect to Ollama. Please check that Ollama is downloaded, running and accessible."
# Status 200, no exception here, so `error` stayed None and that sentence became the target's
# REPLY.
#
# What that cost is in the record. `out/results_localrag-refusal.json` carries seven attack
# rows at EXPLOITED, every trial of every one of them the Ollama message: `refusal.classify`
# labels it compliance because it contains no refusal language, `declined` agrees, and
# `refusal_expected_but_absent` reports that a bot which was supposed to decline did not.
# Seventy probes against a model that was never running, published as findings. This project's
# named failure, in the record it publishes.
#
# ANCHORED AT THE START, and narrow. The corpus is deliberately poisoned and a retrieved
# document could contain any sentence at all, so a substring search anywhere in the body would
# let a poisoned doc mute a real answer by quoting this phrasing. The app emits it as the whole
# body, first thing.
APP_ERROR = re.compile(r"\s*(?:there was an )?error processing the (?:query|request)\b", re.I)


class LocalRagTarget(Target):
    name = "localrag"
    capabilities = set()          # black box; corpus poison is external, not seed()

    def __init__(self, url="http://localhost:8000/rag", **_):
        self.url = url

    def send(self, prompt):
        body = json.dumps({"messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                # /rag returns a StreamingResponse (text/html) — read it all
                out = r.read().decode("utf-8", errors="replace")
            err = None
            if APP_ERROR.match(out):
                # The bytes stay on the probe: they are what the endpoint said, and a run
                # that cannot be judged is still worth being able to read. `error` is what
                # every scorer in this repo consults, and it is what makes this SKIP rather
                # than a measurement.
                err = "AppError: %s" % " ".join(out.split())[:200]
                out = ""
        except Exception as e:
            out, err = "", f"{type(e).__name__}: {e}"
        return Probe(prompt=prompt, output=out, tool_calls=[], observations=[],
                     error=err, seconds=round(time.time() - t0, 1))
