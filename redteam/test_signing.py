"""Request signing, pinned to AWS's own published test vectors.

A WRONG SIGNATURE IS THE MOST FLATTERING BUG THIS PROJECT COULD SHIP. It is not an error that
looks like an error: it is a 403 on every request, so nothing gets through, so nothing is
reported — which in a scorecard is indistinguishable from a deployment that refused every
attack. The tool would announce a perfect defence caused entirely by its own arithmetic.

And it cannot be checked against a live endpoint, because there "the signature is right" and
"this account has no permission for this model" both come back 403. So it is checked against
the vectors AWS publishes for exactly this purpose, with the clock pinned: same credentials,
same timestamp, same expected string, byte for byte.

Offline. No network, no credentials, no model.
"""

import datetime
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import signing  # noqa: E402

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS  " + label)
    else:
        FAIL += 1
        print("FAIL  " + label + (("  " + detail) if detail else ""))


# AWS's documented example credentials. Not secrets: they are published so that an
# implementation can be checked without one.
KEY = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
WHEN = datetime.datetime(2015, 8, 30, 12, 36, 0, tzinfo=datetime.timezone.utc)

VECTORS = [
    # name, method, url, body, expected signature
    ("get-vanilla", "GET", "https://example.amazonaws.com/", b"",
     "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
    ("post-vanilla", "POST", "https://example.amazonaws.com/", b"",
     "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"),
    # Query parameters are sorted AFTER encoding, not before. Getting this backwards produces a
    # signature that is merely different, and different is 403.
    ("get-vanilla-query-order-key-case", "GET",
     "https://example.amazonaws.com/?Param2=value2&Param1=value1", b"",
     "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"),
]

for name, method, url, body, want in VECTORS:
    got = signing.authorization(method, url, {}, body, service="service", region="us-east-1",
                                access_key=KEY, secret_key=SECRET, when=WHEN)
    sig = got["Authorization"].rsplit("Signature=", 1)[-1]
    check("AWS test vector: %s" % name, sig == want, "got %s, want %s" % (sig, want))

head = signing.authorization("GET", "https://example.amazonaws.com/", {}, b"",
                             service="service", region="us-east-1",
                             access_key=KEY, secret_key=SECRET, when=WHEN)
check("the credential scope names date, region and service, in that order",
      "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request" in head["Authorization"])
check("the signed timestamp travels as its own header", head["X-Amz-Date"] == "20150830T123600Z")

# A temporary credential's token has to be both signed over and sent, or the request is signed
# for a principal the service will not recognise.
tok = signing.authorization("GET", "https://example.amazonaws.com/", {}, b"",
                            service="service", region="us-east-1", access_key=KEY,
                            secret_key=SECRET, session_token="TEMP/TOKEN", when=WHEN)
check("a session token is sent", tok.get("X-Amz-Security-Token") == "TEMP/TOKEN")
check("...and is covered by the signature, not merely attached",
      "x-amz-security-token" in tok["Authorization"])
check("...which makes it a different signature from the same request without one",
      tok["Authorization"].rsplit("Signature=", 1)[-1]
      != head["Authorization"].rsplit("Signature=", 1)[-1])

# The body is signed. Two probes with different payloads must not share a signature, or the
# signer is ignoring the thing that changes on every single request this tool makes.
a = signing.authorization("POST", "https://example.amazonaws.com/", {}, b'{"prompt":"one"}',
                          service="service", region="us-east-1", access_key=KEY,
                          secret_key=SECRET, when=WHEN)
b = signing.authorization("POST", "https://example.amazonaws.com/", {}, b'{"prompt":"two"}',
                          service="service", region="us-east-1", access_key=KEY,
                          secret_key=SECRET, when=WHEN)
check("the request body is covered by the signature",
      a["Authorization"] != b["Authorization"])

# The caller's headers must survive. `authorization()` returns headers to ADD; if it mutated or
# replaced what it was given, an api-key or a content-type would vanish from the request.
mine = {"Content-Type": "application/json", "X-Custom": "keep me"}
before = dict(mine)
signing.authorization("POST", "https://example.amazonaws.com/", mine, b"{}",
                      service="service", region="us-east-1", access_key=KEY,
                      secret_key=SECRET, when=WHEN)
check("the caller's headers are not mutated", mine == before, str(mine))

# --- and the failure that would read as a defence -----------------------------------------
check("a 401 before anything worked is called a configuration problem",
      "configuration problem" in signing.expired_credential(401, seen_success=False))
check("a 401 AFTER something worked is called an expired credential",
      "expired mid-run" in signing.expired_credential(401, seen_success=True))
check("...and says the rest of the run was not measured",
      "NOT measured" in signing.expired_credential(403, seen_success=True))
check("...and warns against reading it as a defence",
      "not read the rest of this run as a defence" in signing.expired_credential(403, True))
check("an ordinary status is not mistaken for an auth failure",
      signing.expired_credential(500, seen_success=True) == ""
      and signing.expired_credential(200, seen_success=False) == "")

# --- the adapter refuses what it cannot do, rather than sending unsigned -------------------
import targets_http  # noqa: E402

try:
    targets_http.HttpConfiguredTarget(url="https://x.example/y", auth={"type": "oauth"})
    check("an unsupported auth type is refused", False, "it was accepted")
except SystemExit as e:
    check("an unsupported auth type is refused", "not supported" in str(e))

try:
    targets_http.HttpConfiguredTarget(url="https://x.example/y",
                                      auth={"type": "sigv4", "service": "bedrock"})
    check("an incomplete sigv4 block is refused", False, "it was accepted")
except SystemExit as e:
    check("an incomplete sigv4 block is refused", "is required" in str(e))

os.environ.setdefault("QAT_TEST_AWS_KEY", "AKIDEXAMPLE")
os.environ.setdefault("QAT_TEST_AWS_SECRET", SECRET)
t = targets_http.HttpConfiguredTarget(
    url="https://bedrock-runtime.us-east-1.amazonaws.com/model/m/invoke",
    auth={"type": "sigv4", "service": "bedrock", "region": "us-east-1",
          "access_key": "${QAT_TEST_AWS_KEY}", "secret_key": "${QAT_TEST_AWS_SECRET}"})
check("a sigv4 config expands its credentials from the environment",
      t.auth["access_key"] == "AKIDEXAMPLE" and t.auth["secret_key"] == SECRET)
check("...and a target starts having seen no success, so the first 401 is a config problem",
      t._seen_success is False)

try:
    targets_http.HttpConfiguredTarget(
        url="https://x.example/y",
        auth={"type": "sigv4", "service": "bedrock", "region": "us-east-1",
              "access_key": "${QAT_DEFINITELY_UNSET_KEY}", "secret_key": "x"})
    check("an unset credential variable is refused, not sent as a literal", False, "accepted")
except SystemExit as e:
    check("an unset credential variable is refused, not sent as a literal",
          "not set" in str(e))

print("\n%d/%d passed" % (PASS, PASS + FAIL))
if FAIL:
    sys.exit(1)
print("\nOK — the signature matches AWS's own vectors, and a rejected credential is not a "
      "finding about the target.")
