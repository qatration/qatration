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
from targets_http import read_capped as _read_capped
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
                # /rag returns a StreamingResponse (text/html), so there is no length to
                # trust and nothing to parse -- which made "read it all" look harmless. It is
                # the same sentence as everywhere else: with no argument the target chooses
                # this process's memory. Text rather than JSON, so the truncated bytes are
                # simply the reply, and the size travels beside them.
                _body_l, _over_l = _read_capped(r, seconds=180)
                out = _body_l.decode("utf-8", errors="replace")
            err = None
            if APP_ERROR.match(out):
                # The bytes stay on the probe: they are what the endpoint said, and a run
                # that cannot be judged is still worth being able to read. `error` is what
                # every scorer in this repo consults, and it is what makes this SKIP rather
                # than a measurement.
                err = "AppError: %s" % " ".join(out.split())[:200]
                out = ""
        except Exception as e:
            out, err, _over_l = "", f"{type(e).__name__}: {e}", None
        _p_l = Probe(prompt=prompt, output=out, tool_calls=[], observations=[],
                     error=err, seconds=round(time.time() - t0, 1))
        # THE SIZE IS EVIDENCE, not an accident of the cap. `unbounded_output` judges how
        # much a target produced, and a truncation that also hid the size would defend the
        # engine by deleting the finding -- which is the trade `read_capped` exists to
        # refuse. Same field `targets_http` uses.
        if _over_l:
            try:
                object.__setattr__(_p_l, "reply_bytes", _over_l)
            except Exception:
                pass
        return _p_l
