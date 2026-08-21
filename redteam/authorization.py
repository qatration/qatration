"""Proof that the person asking for a scan controls the thing being scanned.

Everything in this repo so far has run against the practice targets it ships, and the README says so in the
one place it matters: *real third-party targets require explicit authorization (bug-bounty
scope or proof of ownership)*. That sentence is a promise made to a reader. In a tool
anyone can point at anything, it has to become a gate, because the alternative is something that
will attack any URL a stranger types into it — and the first abuse report ends the project.

It is also the cheapest possible protection for the operator. An assessment that cannot show
who authorised it is worthless as evidence and dangerous as an artifact: it is
indistinguishable, in a log or a court, from an attack.

Three proofs, in the order a real operator can actually satisfy them:

  * `header`   — the target echoes a token this tool issued, on a header or in its config. Best for
                 an API: no DNS, no deploy, and it proves control of the ENDPOINT rather than
                 of a domain, which is the thing actually being tested.
  * `well_known` — a file at `/.well-known/qatration-authorization` containing the token.
                 Proves control of the origin serving it.
  * `dns_txt`  — a TXT record. Proves control of the DOMAIN, which is the weakest of the three
                 for this purpose: a subdomain's owner is often not the API's owner.

Deliberately NOT a checkbox. "I confirm I am authorised" is a record of a claim, and a record
of a claim is what every abusive scan already has.

An expired proof is not a proof: the token carries the run it was issued for and the day it
was issued, and a stale one is refused with the reason rather than accepted with a warning.
"""
import datetime, hashlib, hmac, json, os, re, urllib.request

TOKEN_RE = re.compile(r"^qat-[0-9a-f]{32}$")
WELL_KNOWN = "/.well-known/qatration-authorization"
MAX_AGE_DAYS = 14


def issue(target_url, secret, issued=None):
    """A token bound to the ORIGIN, not to the full URL.

    Bound to the origin because that is what an operator can prove control of, and because a
    token that changed with every path would make a proof file useless the moment a run
    covered two endpoints on the same host.
    """
    origin = origin_of(target_url)
    day = (issued or datetime.date.today()).isoformat()
    mac = hmac.new(str(secret).encode(), f"{origin}|{day}".encode(), hashlib.sha256)
    return f"qat-{mac.hexdigest()[:32]}", day


def origin_of(url):
    from urllib.parse import urlparse
    u = urlparse(url)
    if not u.scheme or not u.netloc:
        raise ValueError(f"not a URL: {url!r}")
    return f"{u.scheme}://{u.netloc}"


def _fresh(day):
    try:
        issued = datetime.date.fromisoformat(day)
    except Exception:
        return False, "the issue date is unreadable"
    age = (datetime.date.today() - issued).days
    if age < 0:
        return False, f"issued in the future ({day})"
    if age > MAX_AGE_DAYS:
        return False, f"issued {age} days ago; proofs expire after {MAX_AGE_DAYS}"
    return True, ""


def check(cfg, secret, fetch=None):
    """-> (ok, sentence). Never raises: the caller decides what a failure means.

    `fetch(url) -> str` is injected so this is testable without a network, which matters more
    here than anywhere else in the repo: a gate that can only be exercised against the live
    internet is a gate nobody runs.
    """
    auth = cfg.get("authorization") or {}
    url = cfg.get("url") or ""
    method = auth.get("method")
    if not method:
        return False, ("no `authorization` block in the target config — a scan of somebody "
                       "else's system needs proof they asked for it, and a checkbox is a "
                       "record of a claim rather than a proof")
    token, day = auth.get("token"), auth.get("issued")
    if not token or not TOKEN_RE.match(str(token)):
        return False, f"authorization.token is missing or malformed: {token!r}"
    ok, why = _fresh(str(day))
    if not ok:
        return False, f"the proof is stale: {why}"

    expected, _ = issue(url, secret, datetime.date.fromisoformat(str(day)))
    if not hmac.compare_digest(str(token), expected):
        return False, (f"the token does not match this origin ({origin_of(url)}) and issue "
                       f"date — a token issued for one target does not authorise another")

    fetch = fetch or _http_get
    if method == "header":
        # The endpoint itself hands it back. Proves control of the API, which is the thing
        # being tested, rather than of a domain that may be shared with it.
        got = (auth.get("echoed") or "").strip()
        if got != token:
            return False, ("authorization.method=header, but the endpoint did not echo the "
                           "token; set it on the target and re-run")
        return True, f"the endpoint echoed a token issued for {origin_of(url)} on {day}"
    if method == "well_known":
        probe = origin_of(url) + WELL_KNOWN
        try:
            body = (fetch(probe) or "").strip()
        except Exception as e:
            return False, f"could not read {probe}: {type(e).__name__}: {e}"
        if token not in body:
            return False, f"{probe} does not contain the token issued for this origin"
        return True, f"{probe} carries a token issued on {day}"
    if method == "dns_txt":
        records = auth.get("records")
        if records is None:
            return False, ("authorization.method=dns_txt needs the TXT records to check; "
                           "this build does not resolve DNS itself, so pass them in")
        if not any(token in str(r) for r in records):
            return False, "no TXT record carries the token issued for this origin"
        return True, f"a TXT record carries a token issued on {day}"
    return False, f"unknown authorization.method: {method!r}"


def _http_get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def record(cfg, sentence, secret_id="local"):
    """What goes beside the results: who authorised this, how, and when it was checked.

    An assessment that cannot say who authorised it is worthless as evidence and dangerous as
    an artifact — indistinguishable, in a log, from an attack. This travels in the results
    file so the answer is attached to the findings rather than to somebody's memory.
    """
    auth = cfg.get("authorization") or {}
    return {"target": cfg.get("name"), "origin": origin_of(cfg.get("url", "")),
            "method": auth.get("method"), "issued": auth.get("issued"),
            "checked_at": datetime.datetime.now().isoformat(" ", "seconds"),
            "verified_by": secret_id, "detail": sentence}


LOCAL = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def is_local(url):
    """A practice target on this machine. Everything else is somebody's system."""
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "") in LOCAL
    except Exception:
        return False


def hosted():
    """Is this engine running as a SERVICE, taking URLs from strangers?"""
    return os.environ.get("QATRATION_HOSTED", "").strip().lower() in ("1", "true", "yes")


# Ranges that are never a target endpoint and always somebody's inside. 169.254.169.254 is
# the cloud metadata service, which on most providers hands out credentials to anything that
# asks — a target list containing it turns this engine into the exact tool it is built to find.
_BLOCKED_NETS = (
    "127.", "10.", "192.168.", "169.254.", "0.",
    *(f"172.{n}." for n in range(16, 32)),
)
_BLOCKED_SUFFIX = (".local", ".internal", ".localdomain", ".cluster.local")


def _as_address(host):
    """The address this host IS, for every spelling a resolver accepts. None if it is a name.

    `ipaddress` is strict on purpose and refuses two forms the operating system still resolves:
    leading-zero octal (`0177.0.0.1`) and a bare integer (`2130706433`). A policy that parses
    with the strict reader and a socket that connects with the lenient one disagree exactly
    where it matters, so both are normalised here before the parser sees them.
    """
    import ipaddress

    h = host.strip().rstrip(".")          # a trailing dot is a root anchor, not a different host
    if not h:
        return None

    # An IPv4-mapped or IPv4-compatible IPv6 address is the IPv4 address, and `.is_loopback`
    # on the v6 object is False — so ::ffff:127.0.0.1 walks past a naive property check.
    try:
        ip = ipaddress.ip_address(h)
        # `ipv4_mapped` and `sixtofour` exist on IPv6Address only, so ask the object rather
        # than assuming: an IPv4Address has neither and is already the address it is.
        return (getattr(ip, "ipv4_mapped", None)
                or getattr(ip, "sixtofour", None)
                or ip)
    except ValueError:
        pass

    # A BARE INTEGER, in any base a resolver accepts. 2130706433, 0x7f000001 and 017700000001
    # are all 127.0.0.1 to the operating system and all a ValueError to `ipaddress`. The hex
    # form was missed by the first version of this function and found by the generated-spelling
    # test in test_authorization.py, which is the argument for generating them: a list of
    # encodings can only hold the ones somebody remembered.
    # `"." not in h` is doing real work: without it `0177.00.00.01` enters the octal branch on
    # its leading zero, fails on the dots, and returns None BEFORE the dotted-quad reader below
    # ever sees it — a guard that refuses to answer reads to the caller exactly like a hostname.
    if "." not in h:
        for base, ok in ((16, h[:2].lower() == "0x"),
                         (8, h[:1] == "0" and len(h) > 1),
                         (10, h.isdigit())):
            if not ok:
                continue
            try:
                return ipaddress.ip_address(int(h, base))
            except (ValueError, OverflowError):
                return None

    # Dotted quad with octal or hex parts: 0177.0.0.1, 0x7f.0.0.1, and mixtures.
    parts = h.split(".")
    if 2 <= len(parts) <= 4 and all(parts):
        try:
            nums = [int(p, 16) if p.lower().startswith("0x")
                    else int(p, 8) if p.startswith("0") and p.strip("0") else int(p)
                    for p in parts]
        except ValueError:
            return None
        if all(0 <= n <= 255 for n in nums) and len(nums) == 4:
            try:
                return ipaddress.ip_address(".".join(str(n) for n in nums))
            except ValueError:
                return None
    return None


def unreachable_by_policy(url):
    """Why a hosted service must refuse this URL, or None.

    THE LOCAL RULE INVERTS THE MOMENT THIS IS A SERVICE, and getting that backwards would be
    the worst defect this project could ship. On a workstation `localhost` is the practice
    fleet and needs no proof of ownership; on a host taking URLs from strangers `localhost` is
    THAT HOST'S infrastructure, and an intake that accepts it is a fully-featured SSRF proxy
    with an attack arsenal attached — pointed at its own metadata endpoint, on request.

    IT ASKS WHAT THE ADDRESS IS, NOT HOW IT WAS SPELLED. The first version compared string
    prefixes — `host.startswith("127.")` — which refuses one spelling of loopback and admits
    every other: `2130706433`, `0177.0.0.1`, `0x7f000001`, `::ffff:127.0.0.1`, `[::]`,
    `[0:0:0:0:0:0:0:1]`. Twelve such URLs went through it and twelve were allowed. Spelling is
    the attacker's choice; the address is not, so the address is what is checked.

    NAMES ARE NOT RESOLVED, and that is a real hole rather than a design. DNS can answer
    differently the second time, so resolving here would be a check the network can invalidate
    between this call and the connection. There is no socket-level defence in this repository
    to fall back on: a name that resolves into private space is accepted. Say so in any config
    review rather than implying the gate covers it.
    """
    from urllib.parse import urlparse
    try:
        u = urlparse(url)
    except Exception:
        return "not a URL"
    if u.scheme not in ("http", "https"):
        return f"scheme {u.scheme!r} is not http(s)"
    host = (u.hostname or "").lower().strip("[]")
    if not host:
        return "no host"

    if host.rstrip(".") in LOCAL or host.rstrip(".") == "localhost":
        return "a loopback address is this machine, not the target endpoint"

    ip = _as_address(host)
    if ip is not None:
        if ip.is_loopback or ip.is_unspecified:
            return "a loopback address is this machine, not the target endpoint"
        if ip.is_link_local:
            return ("link-local, and 169.254.169.254 is the cloud metadata service — the one "
                    "address a scanner must never be pointed at")
        if ip.is_private or ip.is_reserved or ip.is_multicast:
            return "a private address is inside somebody's network, not on it"
        # Two ranges `ipaddress` does not call private and a scanner still must not reach:
        # 100.64.0.0/10 is carrier-grade NAT, where the neighbours are other customers of the
        # same ISP, and 198.18.0.0/15 is reserved for benchmarking. Both are somebody's inside.
        import ipaddress as _ip
        for net in ("100.64.0.0/10", "198.18.0.0/15"):
            if ip.version == 4 and ip in _ip.ip_network(net):
                return "a private address is inside somebody's network, not on it"
        return None

    if host.rstrip(".").endswith(_BLOCKED_SUFFIX):
        return "an internal name resolves inside a network this service should not reach"
    return None


def gate(cfg, where):
    """Refuse to probe a REMOTE target without proof, and say what is missing.

    Called from every entry point that drives a target, which is the whole point: the last
    guard added to this engine went into the sweep and not into `benign.py`, and the very next
    run used the other door. A benign baseline is not the lesser case either — it is still
    traffic against somebody's production endpoint, and it is what every attribution claim is
    measured against.

    Local targets pass untouched. The practice fleet is local, and a gate that made it
    unusable would be turned off within a day, which is the failure mode of every security
    control that costs more than it is worth.
    """
    import sys
    url = cfg.get("url") or ""
    # Hosted first, because here the local case is the DANGEROUS one rather than the exempt
    # one, and a waiver evaluated before the refusal would let it through.
    if hosted():
        why = unreachable_by_policy(url)
        if why:
            print(f"ABORT — {where}: refusing {url!r}: {why}. Nothing was sent.",
                  file=sys.stderr)
            sys.exit(4)
    elif not url or is_local(url):
        return None
    if not url:
        return None
    secret = os.environ.get("QATRATION_AUTH_SECRET")
    if not secret:
        print(f"ABORT — {where}: {cfg.get('name')} is a remote target and "
              f"QATRATION_AUTH_SECRET is not set, so no proof of authorization can be "
              f"verified. Nothing was sent.", file=sys.stderr)
        sys.exit(4)
    ok, why = check(cfg, secret)
    if not ok:
        print(f"ABORT — {where}: not authorised to probe {cfg.get('name')} "
              f"({origin_of(url)}): {why}. Nothing was sent.", file=sys.stderr)
        sys.exit(4)
    return record(cfg, why)
