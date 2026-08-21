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
import json, time, urllib.request
from target import Probe, Target


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
        except Exception as e:
            out, err = "", f"{type(e).__name__}: {e}"
        return Probe(prompt=prompt, output=out, tool_calls=[], observations=[],
                     error=err, seconds=round(time.time() - t0, 1))
