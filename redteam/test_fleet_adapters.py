"""
The practice-fleet adapters, and the one question none of them was asked: what happens when
the deployment answers 200 and the answer is a failure?

TEN OF THESE MODULES ARE NAMED BY NO SUITE. That was not a gap in coverage so much as a gap
in the record: `out/results_localrag-refusal.json` carries SEVEN attack rows at EXPLOITED
where every trial of every row reads "There was an error processing the query: Failed to
connect to Ollama." FastAPI caught the exception, the endpoint still returned 200, the adapter
read the body as the reply, and from there nothing downstream could know. `refusal.classify`
labels prose with no refusal in it `compliance`; `declined` agrees; `refusal_expected_but_absent`
reports that a bot which was supposed to decline did not. Seventy probes against a model that
was never running, published as findings — this project's named failure, in the record it
publishes.

So this file asks every adapter that reads an HTTP body the same three questions, against a
server it controls: does a healthy reply survive, does a failure delivered inside a 200 become
`probe.error`, and does the reply text stay out of the way once it has. `error` is the field
every scorer in this repo consults, and it is what makes a dead backend a SKIP rather than a
measurement.

AND WHICH ADAPTERS THOSE ARE IS SCANNED, not listed. A new adapter that opens a socket joins
this suite by existing; if it has no error channel it fails here, with the reason, rather than
in somebody's report six months later.

    python test_fleet_adapters.py
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import io
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# What the server should answer next. Set by each case, read by the handler.
REPLY = {"status": 200, "body": "", "content_type": "application/json"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        body = REPLY["body"].encode("utf-8")
        self.send_response(REPLY["status"])
        self.send_header("Content-Type", REPLY["content_type"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# An adapter that reaches a network, and the channel it must read a failure from. Kept here
# rather than in each module because the point is that ONE of them was missing it.
#
# `_OPENER.open` is in here because leaving it out is the same mistake one level up: the scan
# found three of the four adapters that open a socket, `targets_http` builds its own opener to
# refuse redirects, and the exemption written for it then read as stale. Caught by the
# non-emptiness line below, which is the only reason it is there.
READS_A_BODY = re.compile(r"urlopen\(|_OPENER\.open\(|requests\.(?:post|get)\(")

# Adapters whose failure channel is not a body this suite can drive, WITH THE REASON. Checked
# in both directions below: an entry naming a module that no longer needs it is as wrong as a
# module that needs one and has none.
NO_BODY_TO_READ = {
    "targets_http": "the configured adapter; `response.error` is a config key and "
                    "test_http_adapter drives it against its own server",
}


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/x"

    try:
        # --- targets_localrag: the app reports its own failure as prose, inside a 200 ------
        import targets_localrag
        t = targets_localrag.LocalRagTarget(url=url)

        REPLY.update(status=200, content_type="text/html",
                     body="The refund window is 30 days from delivery.")
        p = t.send("when can I get a refund?")
        check("localrag: a healthy reply is a reply",
              p.output.startswith("The refund window") and p.error is None,
              f"{p.output!r} / {p.error!r}")

        REPLY["body"] = ("There was an error processing the query: Failed to connect to "
                         "Ollama. Please check that Ollama is downloaded, running and "
                         "accessible. https://ollama.com/download")
        p = t.send("when can I get a refund?")
        check("localrag: a dead backend inside a 200 is an error, not a reply",
              (p.error or "").startswith("AppError:"), repr(p.error))
        check("...and it names what the endpoint said", "Ollama" in (p.error or ""),
              repr(p.error))
        check("...and leaves no output for a detector to score",
              p.output == "", repr(p.output))

        # THE CORPUS IS DELIBERATELY POISONED, so a retrieved document can contain any
        # sentence at all — including this one. Anchored at the start for that reason: a
        # substring search anywhere in the body would hand every attacker a way to mute a
        # real answer by quoting the app's own error text.
        REPLY["body"] = ("Our policy document notes: there was an error processing the query "
                         "in the old system, which is why refunds now take 30 days.")
        p = t.send("when can I get a refund?")
        check("localrag: a document QUOTING the error text is still a reply",
              p.error is None and "refunds now take 30 days" in p.output,
              f"{p.error!r} / {p.output[:60]!r}")

        # --- targets_httpbot: the same 200, in JSON ---------------------------------------
        import targets_httpbot
        h = targets_httpbot.HttpTarget(url=url)

        REPLY.update(content_type="application/json",
                     body=json.dumps({"reply": "Standard shipping takes 3-5 days."}))
        p = h.send("how long is shipping?")
        check("httpbot: a healthy reply is a reply",
              p.output.startswith("Standard shipping") and p.error is None,
              f"{p.output!r} / {p.error!r}")

        REPLY["body"] = json.dumps({"reply": "", "error": "model backend unavailable"})
        p = h.send("how long is shipping?")
        check("httpbot: an error field inside a 200 is an error",
              (p.error or "").startswith("AppError:"), repr(p.error))
        check("...and quotes the endpoint", "backend unavailable" in (p.error or ""),
              repr(p.error))

        # A NULL IS NOT AN ERROR. Endpoints that always carry the key and leave it null on
        # success are the common case, and reading presence rather than truthiness would turn
        # every successful probe into an error.
        REPLY["body"] = json.dumps({"reply": "Standard shipping takes 3-5 days.",
                                    "error": None})
        p = h.send("how long is shipping?")
        check("httpbot: a null error is a success",
              p.error is None and p.output.startswith("Standard shipping"),
              f"{p.error!r} / {p.output!r}")

        # --- targets_foreign: already read its error channel; this pins it ----------------
        import targets_foreign
        f = targets_foreign.ForeignAgentTarget(url=url)
        REPLY["body"] = json.dumps({"reply": "", "error": "agent step limit exceeded"})
        p = f.send("hello")
        check("foreign: an error field inside a 200 is an error",
              bool(p.error) and "step limit" in str(p.error), repr(p.error))

        # --- AND THE SET IS SCANNED, so the next adapter joins by existing ----------------
        opens_socket, unchecked = [], []
        for fn in sorted(os.listdir(HERE)):
            if not (fn.startswith("targets_") and fn.endswith(".py")):
                continue
            src = io.open(os.path.join(HERE, fn), encoding="utf-8").read()
            if not READS_A_BODY.search(src):
                continue
            stem = fn[:-3]
            opens_socket.append(stem)
            if stem in NO_BODY_TO_READ:
                continue
            # An error channel means one of: a declared error key, or a recognised failure
            # body. A `try/except` alone is not one — that is the transport, and the whole
            # defect here was a failure that raised nothing.
            if not re.search(r'\.get\(\s*["\']error["\']|APP_ERROR|error_path', src):
                unchecked.append(stem)

        check("the adapters that open a socket can be enumerated", len(opens_socket) >= 4,
              str(opens_socket))
        check("every one of them reads a failure delivered inside a 200",
              not unchecked, str(unchecked))
        stale = sorted(set(NO_BODY_TO_READ) - set(opens_socket))
        check("no exemption outlives the module it was written for", not stale, str(stale))

    finally:
        srv.shutdown()

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        print("\nFAILURES:")
        for f in fails:
            print(" ", f)
        return 1
    print("\nOK — a dead backend is a skip, not a finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
