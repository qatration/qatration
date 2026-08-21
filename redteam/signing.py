"""Request signing, for the two endpoints a static header cannot reach.

The HTTP adapter builds its headers once, at construction, and after `${ENV}` expansion they
never change again. That covers almost everything — a bearer token, an `x-api-key` — and it
covers nothing at AWS or Google, where the credential is computed per request from the body and
the clock. Those are the two major cloud paths, and they were simply out of reach.

WHY THIS MATTERS MORE THAN A MISSING FEATURE USUALLY DOES. A wrong signature is not an error
that looks like an error. It is a 403 on every single request, and a run of 403s is a run where
nothing got through — which is indistinguishable, in a report, from a deployment that refused
every attack. The most flattering possible result, produced by a bug in this file. So this
is checked against AWS's own published test vectors rather than against a live endpoint, where
"it worked" and "the account has no permissions anyway" look the same.

Standard library only. `boto3` would be a large dependency for one hash chain, and this is one
hash chain: SHA-256 four times over strings whose exact bytes are the entire specification.

    auth:
      type: sigv4
      service: bedrock
      region: us-east-1
      access_key: "${AWS_ACCESS_KEY_ID}"
      secret_key: "${AWS_SECRET_ACCESS_KEY}"
      session_token: "${AWS_SESSION_TOKEN}"   # optional, for temporary credentials

Google Vertex is deliberately NOT here. Its credential is an OAuth2 access token, and minting
one needs an RS256 signature over a service-account key — which needs a crypto library this
project does not otherwise want. `gcloud auth print-access-token` produces the same token in one
command, so Vertex is reached as an ordinary bearer header, and the honest caveat is that the
token expires in about an hour. See `expired_credential()`, which is what keeps that caveat from
turning into a false clean report.
"""

import datetime
import hashlib
import hmac
import urllib.parse

ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def canonical_request(method, url, headers, payload):
    """The first of the four strings. Every rule here is a place to get it silently wrong.

    Header names lowercased and sorted; values stripped and inner runs of whitespace collapsed;
    the query string sorted by key AFTER percent-encoding, not before. Any one of those wrong
    produces a signature that is merely different, and different is 403.
    """
    parts = urllib.parse.urlsplit(url)
    path = urllib.parse.quote(parts.path or "/", safe="/~")

    query = ""
    if parts.query:
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query = "&".join("%s=%s" % (urllib.parse.quote(k, safe="~"),
                                    urllib.parse.quote(v, safe="~"))
                         for k, v in sorted(pairs))

    lowered = {}
    for k, v in headers.items():
        lowered[k.lower().strip()] = " ".join(str(v).split())
    names = sorted(lowered)
    canon_headers = "".join("%s:%s\n" % (n, lowered[n]) for n in names)
    signed = ";".join(names)

    body_hash = _sha256(payload if payload is not None else b"")
    return "\n".join([method.upper(), path, query, canon_headers, signed, body_hash]), signed


def authorization(method, url, headers, payload, service, region,
                  access_key, secret_key, session_token=None, when=None):
    """-> the headers to ADD. Returns a new dict; the caller's headers are not mutated.

    `when` exists so the test vectors can pin the clock. Nothing else should pass it.
    """
    now = when or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    stamp = now.strftime("%Y%m%d")

    host = urllib.parse.urlsplit(url).netloc
    signing_headers = dict(headers)
    signing_headers.setdefault("host", host)
    signing_headers["x-amz-date"] = amz_date
    if session_token:
        signing_headers["x-amz-security-token"] = session_token

    canon, signed_names = canonical_request(method, url, signing_headers, payload)
    scope = "%s/%s/%s/aws4_request" % (stamp, region, service)
    to_sign = "\n".join([ALGORITHM, amz_date, scope, _sha256(canon)])

    key = ("AWS4" + secret_key).encode("utf-8")
    for step in (stamp, region, service, "aws4_request"):
        key = _hmac(key, step)
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {"X-Amz-Date": amz_date,
           "Authorization": "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                            % (ALGORITHM, access_key, scope, signed_names, signature)}
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


def expired_credential(status, seen_success):
    """Is this 401/403 a credential that ran out, rather than a target that refused?

    THE ONE THING THAT TURNS A CAVEAT INTO A FALSE REPORT. A Vertex access token lasts about an
    hour and a full sweep can run for thirty minutes, so a token minted shortly before a run can
    expire in the middle of one. Every request after that is a 401, every probe after that is an
    error, and a report that scores those as anything other than "not measured" is claiming a
    defence for the half of the arsenal that was never seen.

    `seen_success` is what makes it decidable: an auth failure from the first request is a
    misconfiguration, and an auth failure AFTER something worked is a credential that expired.
    Those want different sentences, and neither of them is about the target.
    """
    if status not in (401, 403):
        return ""
    if not seen_success:
        return ("the endpoint rejected the credential on the first request (HTTP %d). This is a "
                "configuration problem, not a finding: check the header, the environment "
                "variable, and that the key has permission for this model." % status)
    return ("the endpoint accepted earlier requests and now returns HTTP %d, so the credential "
            "expired mid-run. Everything after this point was NOT measured — an expiring token "
            "produces a wall of refusals that reads exactly like a hardened deployment. Mint a "
            "fresh one and re-run; do not read the rest of this run as a defence." % status)
