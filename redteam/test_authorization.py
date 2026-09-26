"""The gate that says somebody asked for this — no model, no network.

On an endpoint anyone can submit to, "real third-party targets require explicit
authorization" stops being a sentence in a README and becomes the only thing between a
security tool and something that will attack any URL a stranger types into it. Nothing about
the traffic distinguishes the two; only the gate does.

So the checks below are about the ways a gate can look like a gate and not be one: a token
that authorises a different target, a proof that expired, a checkbox standing in for
evidence, a config that simply omits the block. Each has to be refused with a reason, and the
refusals have to be readable, because the person who hits one is an operator trying to get a
run started.

    python test_authorization.py    # exits 1 on any failure (CI gate)
"""
import sys, os, datetime
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import authorization as az

SECRET = "test-secret"
URL = "https://api.acmeshop.example/v1/chat"
OTHER = "https://api.someone-else.example/v1/chat"


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- A URL WITH NO HOST IS REFUSED FOR HAVING NO HOST ------------------------------
    #
    # `http:///path`, `http://` and `https://:8080/x` all parse, and all have an empty
    # hostname. `if not host: return "no host"` is what answers them, and nothing was
    # driving it: deleting the line left every suite green, because the empty name then
    # goes to the RESOLVER and the machine this ran on resolved it to its own link-local
    # address. Still refused -- by accident, in a sentence that begins with a blank where
    # the host should be:
    #
    #     " resolves to fe80::..., and link-local, and 169.254.169.254 is the cloud
    #      metadata service"
    #
    # Two things wrong with earning the right answer that way. The sentence names no host,
    # so an operator cannot see that their URL was malformed rather than internal. And the
    # gate performs a DNS lookup for a URL it could refuse by reading it -- on a resolver
    # that answers the empty name with something public, the refusal disappears entirely.
    #
    # Found by mutating the guards `tools/unguarded.py` skips by design.
    for _u_h in ("http:///path", "http://", "https://:8080/x", "http://@/x"):
        _why_h = az.unreachable_by_policy(_u_h)
        check("a URL with no host is refused (%s)" % _u_h, bool(_why_h), repr(_why_h))
        check("...for having no host, rather than for where the empty name resolved",
              _why_h == "no host", repr(_why_h))
    # AND A URL THAT HAS ONE IS STILL JUDGED ON IT, or the rule above is a gate that
    # refuses every address there is.
    check("a public host is not refused for having no host",
          az.unreachable_by_policy("https://example.com/x") != "no host",
          repr(az.unreachable_by_policy("https://example.com/x")))

    today = datetime.date.today()
    token, day = az.issue(URL, SECRET)

    def cfg(method, **extra):
        base = {"name": "acme", "url": URL,
                "authorization": {"method": method, "token": token, "issued": day}}
        base["authorization"].update(extra)
        return base

    # --- the three proofs, each satisfied ---------------------------------------------
    ok, why = az.check(cfg("header", echoed=token), SECRET)
    check("a token the endpoint echoes is a proof", ok, why)
    ok, why = az.check(cfg("well_known"), SECRET, fetch=lambda u: f"  {token}\n")
    check("a token at /.well-known is a proof", ok, why)
    ok, why = az.check(cfg("dns_txt", records=[f"v=spf1 ...", token]), SECRET)
    check("a token in a TXT record is a proof", ok, why)

    # --- and every way of looking like one -------------------------------------------
    ok, why = az.check({"name": "acme", "url": URL}, SECRET)
    check("no authorization block at all is refused", not ok, why)
    check("...and the refusal says why a checkbox is not enough",
          "checkbox" in why or "claim" in why, why)

    # A BLOCK WITH NO METHOD IS NOT NO BLOCK. `init`'s template carried `scope` and
    # `authorised_by`; uncommented, the reader was told there was no block at all.
    ok, why = az.check({"name": "acme", "url": URL,
                        "authorization": {"scope": URL, "authorised_by": "me"}}, SECRET)
    check("a block without a method is refused", not ok, why)
    check("...as a block that names no method, not as a missing block",
          "names no `method`" in why and "no `authorization` block" not in why, why)
    check("...naming what it has, so the reader can see which keys were not read",
          "authorised_by" in why and "scope" in why, why)

    # AND THE GATE SAYS HOW TO COMPLETE IT, with the token this origin needs. Nothing a
    # reader could type issued one: `issue` was reachable only by importing this module.
    # Driven through `gate`, and the printed block is then pasted back and must PASS: a
    # remedy that does not satisfy the check it is printed by is the defect in a new place.
    import contextlib as _cl, io as _io_a, yaml as _yaml_a
    _prev = os.environ.get("QATRATION_AUTH_SECRET")
    os.environ["QATRATION_AUTH_SECRET"] = SECRET
    _err = _io_a.StringIO()
    try:
        with _cl.redirect_stderr(_err):
            try:
                az.gate({"name": "acme", "url": URL,
                         "authorization": {"scope": URL}}, "test")
                _raised = False
            except az.NotAuthorised:
                _raised = True
    finally:
        if _prev is None:
            os.environ.pop("QATRATION_AUTH_SECRET", None)
        else:
            os.environ["QATRATION_AUTH_SECRET"] = _prev
    _said = _err.getvalue()
    check("the gate still refuses a block without a method", _raised, _said[-300:])
    check("...and prints the token issued for this origin today",
          az.issue(URL, SECRET)[0] in _said, _said[-400:])
    _lines = _said.splitlines()
    _start = [i for i, l in enumerate(_lines) if l.strip() == "authorization:"]
    _block = {}
    if _start:
        _txt = "\n".join(_lines[_start[0]:_start[0] + 4])
        _block = (_yaml_a.safe_load(_txt) or {}).get("authorization") or {}
    _tok = _block.get("token")
    ok, why = az.check({"name": "acme", "url": URL, "authorization": _block}, SECRET,
                       fetch=lambda u: str(_tok))
    check("...and the block it prints, pasted back with the token served, passes the gate",
          ok, "%s | %s" % (why, _block))
    check("...and names where the well-known proof is served",
          (az.origin_of(URL) + az.WELL_KNOWN) in _said, _said[-300:])
    # THE REMEDY IS FOR THE ORIGIN IN THE CONFIG, not a fixed example: the same printed block
    # against another origin must fail, or the check above would pass for a hard-coded token.
    ok, why = az.check({"name": "acme", "url": OTHER, "authorization": _block}, SECRET,
                       fetch=lambda u: str(_tok))
    check("...and it does not authorise a different origin", not ok, why)
    # NOT ON A SERVER. Hosted, the secret is the service's and the requester is a stranger,
    # who could hand a printed token back as `echoed` under `method: header`. The address
    # policy is stubbed open so the call reaches `check` -- otherwise this would pass by being
    # refused one step earlier, which is a check that cannot fail.
    _saved_pol, _saved_h = az.unreachable_by_policy, os.environ.get("QATRATION_HOSTED")
    az.unreachable_by_policy = lambda u: ""
    os.environ["QATRATION_HOSTED"] = "1"
    os.environ["QATRATION_AUTH_SECRET"] = SECRET
    _errh = _io_a.StringIO()
    try:
        with _cl.redirect_stderr(_errh):
            try:
                az.gate({"name": "acme", "url": URL, "authorization": {"scope": URL}}, "test")
            except az.NotAuthorised:
                pass
    finally:
        az.unreachable_by_policy = _saved_pol
        if _saved_h is None:
            os.environ.pop("QATRATION_HOSTED", None)
        else:
            os.environ["QATRATION_HOSTED"] = _saved_h
        if _prev is None:
            os.environ.pop("QATRATION_AUTH_SECRET", None)
        else:
            os.environ["QATRATION_AUTH_SECRET"] = _prev
    check("hosted, the refusal reaches the proof check",
          "names no `method`" in _errh.getvalue(), _errh.getvalue()[-300:])
    check("...and prints no token for a stranger to hand back",
          az.issue(URL, SECRET)[0] not in _errh.getvalue(), "the token was printed")

    # AND ONE STEP EARLIER: with no secret there is no token to print, and the refusal said
    # the variable was unset without saying what it is.
    _prev = os.environ.pop("QATRATION_AUTH_SECRET", None)
    _err0 = _io_a.StringIO()
    try:
        with _cl.redirect_stderr(_err0):
            try:
                az.gate({"name": "acme", "url": URL}, "test")
            except az.NotAuthorised:
                pass
    finally:
        if _prev is not None:
            os.environ["QATRATION_AUTH_SECRET"] = _prev
    check("with no secret set, the refusal says what the secret is for",
          "the key proof tokens are issued with" in _err0.getvalue(), _err0.getvalue()[-300:])

    # A MALFORMED URL IS NOT A REMOTE TARGET. `localhost:8000/chat` -- the scheme left off --
    # was told it needed QATRATION_AUTH_SECRET, and so were `not a url` and `http://`.
    for _bad_u, _says in (("localhost:8000/chat", "did you mean http://localhost:8000/chat"),
                          ("not a url", "no scheme"), ("ftp://x/y", "'ftp'"),
                          ("http://", "no host")):
        check("url_problem names what is wrong with %r" % _bad_u,
              _says in (az.url_problem(_bad_u) or ""), az.url_problem(_bad_u))
    check("...and says nothing about a real one, or an empty one the adapter answers for",
          [az.url_problem(u) for u in ("https://api.acmeshop.example/v1/chat",
                                        "http://127.0.0.1:9/x", "")] == [None, None, None],
          "")
    _prev_s = os.environ.pop("QATRATION_AUTH_SECRET", None)
    try:
        try:
            az.gate({"name": "typo", "url": "localhost:8000/chat"}, "test")
            _gx = None
        except SystemExit as _e_g:
            _gx = _e_g
    finally:
        if _prev_s is not None:
            os.environ["QATRATION_AUTH_SECRET"] = _prev_s
    check("the gate refuses a malformed url as a config problem, not an authorisation one",
          _gx is not None and not isinstance(_gx, az.NotAuthorised)
          and "not a URL a target can be reached at" in str(_gx)
          and "QATRATION_AUTH_SECRET" not in str(_gx), str(_gx))

    ok, why = az.check(cfg("header", echoed="qat-" + "0" * 32), SECRET)
    check("an echoed value that is not the issued token is refused", not ok, why)

    # A TOKEN FOR ANOTHER TARGET IS THE ONE THAT MATTERS: it is what an attacker with a
    # legitimate account of their own would try.
    mine, myday = az.issue(OTHER, SECRET)
    other_cfg = {"name": "acme", "url": URL,
                 "authorization": {"method": "header", "token": mine, "issued": myday,
                                   "echoed": mine}}
    ok, why = az.check(other_cfg, SECRET)
    check("a token issued for a DIFFERENT origin does not authorise this one", not ok, why)
    check("...and the refusal names the origin it was checked against",
          "acmeshop" in why, why)

    stale_day = (today - datetime.timedelta(days=az.MAX_AGE_DAYS + 1)).isoformat()
    stale, _ = az.issue(URL, SECRET, datetime.date.fromisoformat(stale_day))
    ok, why = az.check({"name": "acme", "url": URL,
                        "authorization": {"method": "header", "token": stale,
                                          "issued": stale_day, "echoed": stale}}, SECRET)
    check("an expired proof is refused, not accepted with a warning", not ok, why)
    check("...and says how old it is", "days ago" in why, why)

    future = (today + datetime.timedelta(days=2)).isoformat()
    fut, _ = az.issue(URL, SECRET, datetime.date.fromisoformat(future))
    ok, why = az.check({"name": "acme", "url": URL,
                        "authorization": {"method": "header", "token": fut,
                                          "issued": future, "echoed": fut}}, SECRET)
    check("a proof dated in the future is refused", not ok, why)

    ok, why = az.check(cfg("header", token="not-a-token", echoed="not-a-token"), SECRET)
    check("a malformed token is refused", not ok, why)

    ok, why = az.check(cfg("well_known"), SECRET, fetch=lambda u: "nothing here")
    check("a well-known file without the token is refused", not ok, why)
    ok, why = az.check(cfg("well_known"), SECRET,
                       fetch=lambda u: (_ for _ in ()).throw(OSError("connection refused")))
    check("a well-known file that cannot be read is refused, not assumed", not ok, why)
    check("...and the reason is the fetch failure, not a guess", "OSError" in why, why)

    ok, why = az.check(cfg("dns_txt"), SECRET)
    check("dns_txt with no records to check is refused rather than trusted", not ok, why)
    # AND RECORDS THAT ARE THERE AND CARRY NOTHING. `well_known` has had this case since it
    # was written -- a file fetched that does not hold the token -- and the DNS branch, which
    # is the same question one transport over, had only "no records at all". Deleting
    # `if not any(token in str(r) for r in records)` left every suite green, and with it gone
    # ANY non-empty record set authorises a scan of somebody else's system: the operator who
    # added the TXT record to the wrong zone, or added none and passed their SPF line, is told
    # the proof holds.
    #
    # Found by mutating the guards `tools/unguarded.py` skips by design: 30 of them in this
    # module, which carries no documented guard at all and is the one that decides whether a
    # target may be attacked.
    ok, why = az.check(cfg("dns_txt", records=["v=spf1 include:example.com ~all"]), SECRET)
    check("a TXT record set that does not carry the token is refused", not ok, why)
    check("...and the reason names the token rather than the records", "token" in (why or ""),
          why)
    # AN EMPTY LIST IS A MEASUREMENT AND `None` IS NOT, and the two refusals differ: one
    # says the records were looked at and hold nothing, the other that none were supplied.
    ok, why_empty = az.check(cfg("dns_txt", records=[]), SECRET)
    check("...and an empty record set is refused too", not ok, why_empty)
    check("...with a different sentence from `no records were supplied`",
          why_empty != az.check(cfg("dns_txt"), SECRET)[1], why_empty)
    # AND A TOKEN THAT IS NOT A TOKEN IS REFUSED FOR THAT, not for failing to match. The
    # shape check in front of the comparison is a message rather than a wall -- a malformed
    # token fails `compare_digest` too -- and a wall that reports the wrong reason sends the
    # operator to re-issue a token when what they have is a truncated one.
    for _bad in (None, "", "not a token", token[:-4]):
        _ok_b, _why_b = az.check(cfg("header", token=_bad, echoed=_bad), SECRET)
        check("a malformed token (%r) is refused" % (_bad,), not _ok_b, _why_b)
        check("...for being malformed rather than for not matching",
              "missing or malformed" in (_why_b or ""), _why_b)
    ok, why = az.check(cfg("smoke-signal"), SECRET)
    check("an unknown method is refused", not ok, why)

    # --- AN ANSWER FROM THE RESOLVER THAT IS NOT AN ADDRESS ----------------------------
    #
    # `unreachable_by_policy` walks every record `getaddrinfo` returns and skips the ones it
    # cannot parse: `if addr is None or str(addr) in seen: continue`. Delete that line and
    # `_address_refused(None)` is `AttributeError: 'NoneType' object has no attribute
    # 'is_loopback'` -- a traceback out of the gate, which fails closed and is still the
    # wrong answer to give an operator about their own config.
    #
    # A resolver is injectable here precisely so this can be asked without a network, and
    # nothing was asking it. Found by mutating the guards `tools/unguarded.py` skips.
    _junk = [(2, 1, 6, "", ("not-an-address", 443))]
    _crash = ""
    try:
        _why_junk = az.unreachable_by_policy("https://api.acme.example/chat",
                                             resolve=lambda h, p: _junk)
    except Exception as _e_j:
        _crash, _why_junk = "%s: %s" % (type(_e_j).__name__, _e_j), None
    check("a resolver answer that is not an address does not crash the gate", not _crash,
          _crash)
    check("...and a name that resolved to nothing usable is refused, not waved through",
          bool(_why_junk) and "no usable address" in _why_junk, str(_why_junk))
    # AND A GOOD ANSWER BESIDE A JUNK ONE STILL DECIDES, or the skip above could swallow the
    # whole answer set and call a public name unresolvable.
    _mixed = [(2, 1, 6, "", ("not-an-address", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
    _why_mixed = az.unreachable_by_policy("https://api.acme.example/chat",
                                          resolve=lambda h, p: _mixed)
    check("...while a usable address beside it is still judged",
          bool(_why_mixed) and "loopback" in _why_mixed, str(_why_mixed))
    # AND A RECORD RETURNED TWICE CHANGES NO ANSWER, which is a property worth asserting and
    # is NOT a test of the `str(addr) in seen` half of that line: `_address_refused` is a pure
    # function, so walking the same address twice gives the same verdict either way. Deleting
    # the dedup is an equivalent mutation and is named here rather than counted. What `seen`
    # is load-bearing for is the `no usable address` sentence above, which the junk case does
    # drive.
    _dupe = [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("93.184.216.34", 443))]
    check("...and a record returned twice is not two answers",
          az.unreachable_by_policy("https://api.acme.example/chat",
                                   resolve=lambda h, p: _dupe) is None,
          "a duplicate record changed the verdict")

    # A DIFFERENT SECRET must not validate: the token is ours to issue, not the caller's.
    ok, why = az.check(cfg("header", echoed=token), "some-other-secret")
    check("a token this deployment did not issue is refused", not ok, why)

    # --- the record that travels with the findings ------------------------------------
    ok, why = az.check(cfg("header", echoed=token), SECRET)
    rec = az.record(cfg("header", echoed=token), why)
    check("the record names the origin, the method and when it was checked",
          rec["origin"] == "https://api.acmeshop.example" and rec["method"] == "header"
          and len(rec["checked_at"]) >= 16, str(rec))
    check("...and carries the detail, so the file explains itself",
          rec["detail"] == why, str(rec))

    # --- WHO SAW THE PROOF, and the record used to answer that wrongly -----------------
    #
    # `header` compares `authorization.echoed` against `authorization.token`, two fields of
    # the same config file, and `dns_txt` reads `authorization.records` from that same file —
    # its own error message says "this build does not resolve DNS itself, so pass them in".
    # Only `well_known` fetches anything.
    #
    # Neither is an open door: the token is an HMAC over origin and issue date, so forging
    # one needs the signing secret whatever the method says. What was wrong is the RECORD.
    # `check` returned "the endpoint echoed a token issued for <origin>" and that sentence was
    # written into the results file as the authorisation evidence — a network fact, asserted,
    # that nothing here observed. In the one file whose purpose is to say who asked for this
    # scan, an unobserved claim in the vocabulary of an observation is this project's own
    # failure class aimed at its own provenance.
    check("a proof read back out of the config says it was asserted, not observed",
          rec["evidence"] == "asserted in the target config", str(rec))
    check("...and its sentence does not claim the endpoint was asked",
          "echoed a token" not in why and "possession of the signing secret" in why, why)
    _dns_cfg = cfg("dns_txt", records=[f"qatration={token}"])
    _dok, _dwhy = az.check(_dns_cfg, SECRET)
    check("...and the DNS proof says the same about itself",
          _dok and az.record(_dns_cfg, _dwhy)["evidence"] == "asserted in the target config"
          and "does not resolve DNS" in _dwhy, _dwhy)
    # ...while the one proof this build really does fetch says so, or the distinction is
    # a label nobody can act on.
    _wk_cfg = cfg("well_known")
    _wok, _wwhy = az.check(_wk_cfg, SECRET, fetch=lambda u: f"qatration={token}")
    check("a proof this run fetched for itself is marked observed",
          _wok and az.record(_wk_cfg, _wwhy)["evidence"] == "observed by this run"
          and "was fetched" in _wwhy, _wwhy)

    # --- origins ----------------------------------------------------------------------
    check("an origin drops the path", az.origin_of(URL) == "https://api.acmeshop.example")
    check("a port is part of the origin",
          az.origin_of("http://localhost:8102/chat") == "http://localhost:8102")
    # AN IPv6 LITERAL KEEPS ITS BRACKETS, or two different origins become one string and a
    # token issued for one authorises the other.
    check("two different IPv6 origins stay two",
          az.origin_of("http://[::1]:8080/v1") != az.origin_of("http://[::1:8080]/v1"),
          "%s vs %s" % (az.origin_of("http://[::1]:8080/v1"),
                        az.origin_of("http://[::1:8080]/v1")))
    check("...and an IPv6 origin is still a URL",
          az.origin_of("https://[2001:db8::1]:8443/x") == "https://[2001:db8::1]:8443",
          az.origin_of("https://[2001:db8::1]:8443/x"))
    try:
        az.origin_of("not a url")
        check("a non-URL is rejected", False, "it was accepted")
    except ValueError:
        check("a non-URL is rejected", True)

    # --- the gate itself, in every door -------------------------------------------------
    # The practice fleet is ours and passes untouched: a gate that made the fleet unusable
    # would be switched off within a day, which is the failure mode of every control costing
    # more than it is worth.
    check("a target on this machine needs no proof",
          az.gate({"name": "draftbot", "url": "http://localhost:8102/chat"}, "t") is None)
    check("...and so does one with no url at all, which is an in-process adapter",
          az.gate({"name": "dvla"}, "t") is None)
    check("localhost, 127.0.0.1 and ::1 are all local",
          all(az.is_local(u) for u in ("http://localhost:1/", "http://127.0.0.1:1/",
                                       "http://[::1]:1/")))
    check("a customer's endpoint is not local",
          not az.is_local("https://api.acmeshop.example/v1/chat"))

    # AND EVERY OTHER SPELLING OF THIS MACHINE. `is_local` was a membership test against
    # five strings, two hundred lines above `_as_address`, which exists for exactly the
    # spellings a resolver accepts and a strict parser does not -- and whose own docstring
    # says a policy that reads one way while the socket reads the other disagrees exactly
    # where it matters. Every address below is 127.0.0.1 to `socket.inet_aton` and was
    # answered "somebody else's system", which in `gate` is the difference between a
    # practice bot that runs and exit 4 about `QATRATION_AUTH_SECRET`.
    #
    # NOT ASSERTED AS A LIST OF STRINGS THAT HAPPENS TO PASS: each one is cross-checked
    # against the reader that decides, so the pair moves together or this goes red.
    for _spelling in ("127.0.0.2", "127.1", "127.0.1", "0177.0.0.1", "2130706433",
                      "::ffff:127.0.0.1"):
        _host = "[%s]" % _spelling if ":" in _spelling else _spelling
        _addr = az._as_address(_spelling)
        check("%s is this machine to the reader that decides" % _spelling,
              _addr is not None and _addr.is_loopback, repr(_addr))
        check("...and `is_local` agrees with it", az.is_local("http://%s:1/" % _host),
              "%s was called somebody else's system" % _spelling)

    # AND THE EXEMPTION DOES NOT WIDEN PAST LOOPBACK. This is the branch that skips proving
    # authorisation, so every address it accepts is traffic nobody is asked about.
    for _not_ours in ("10.0.0.5", "169.254.169.254", "192.168.1.1", "8.8.8.8",
                      "100.64.0.1"):
        check("%s is not this machine" % _not_ours,
              not az.is_local("http://%s:1/" % _not_ours), _not_ours)
    # A NAME THAT RESOLVES HERE IS STILL NOT LOCAL, deliberately: `_as_address` answers None
    # for names because a name can be pointed elsewhere between this check and the socket.
    check("a name is not exempted by what it resolves to today",
          not az.is_local("http://bot.example:1/"), "bot.example")
    check("...and an empty host is not this machine either",
          not az.is_local("not a url at all"), "an unparseable url")

    # --- ONE TABLE OF DEFAULT PORTS ------------------------------------------------------
    #
    # `targets_http._GuardedRedirect` refuses a redirect that moves the port, because a port
    # is a different service; the first version of that rule arrived carrying its own copy of
    # `DEFAULT_PORT`. A second table of the same three facts is the arrangement this
    # repository keeps finding and calling a defect, and it is the kind that stays true for
    # years and then does not.
    from urllib.parse import urlparse as _up_p
    check("a default port is filled in from the scheme",
          az.effective_port(_up_p("http://h/x")) == 80
          and az.effective_port(_up_p("https://h/x")) == 443,
          "%r / %r" % (az.effective_port(_up_p("http://h/x")),
                       az.effective_port(_up_p("https://h/x"))))
    check("...and one written out is the one that is used",
          az.effective_port(_up_p("http://h:8080/x")) == 8080,
          repr(az.effective_port(_up_p("http://h:8080/x"))))
    check("...so a port written out is not a different origin from the default",
          az.effective_port(_up_p("http://h:80/x"))
          == az.effective_port(_up_p("http://h/x")),
          "80 and the default disagree")
    check("...and a scheme nobody has a default for answers nothing rather than guessing",
          az.effective_port(_up_p("ftp://h/x")) is None,
          repr(az.effective_port(_up_p("ftp://h/x"))))
    # AND THE REDIRECT GUARD READS THIS ONE. Named by import rather than by a grep, so a
    # copy reappearing in that file is what fails here.
    import ast as _ast_p
    with open(os.path.join(HERE, "targets_http.py"), encoding="utf-8") as _fh_p:
        _th_src = _fh_p.read()
    _th_tree = _ast_p.parse(_th_src)
    _asks = [n for n in _ast_p.walk(_th_tree)
             if isinstance(n, _ast_p.ImportFrom) and n.module == "authorization"
             and any(a.name == "effective_port" for a in n.names)]
    check("the redirect guard asks this file for the table", len(_asks) == 1,
          "%d import(s) of effective_port" % len(_asks))
    check("...and keeps no table of its own",
          "DEFAULT_PORT" not in _th_src.replace("from authorization import", ""),
          "targets_http.py still spells out a port table")

    # EVERY entry point that drives a target, which is the point: the last guard added to this
    # engine went into the sweep and not into benign.py, and the very next run used the other
    # door. A benign baseline is still traffic against somebody's production endpoint, and it
    # is what every attribution claim on that target is measured against.
    # DERIVED, not listed. The version above this one named two files, under this same comment
    # saying EVERY, and while it watched those two the gate was missed by `run_recon.py`,
    # `run_isolation.py`, `run_generate.py` and `run_adaptive.py` — four more commands that take
    # a target config and send real traffic, one of which the documentation tells a reader to
    # run first. A list covers the doors somebody remembered; this covers the ones that exist.
    import glob as _glob
    import ast as _ast
    # WHAT BUILDS A TARGET: the two builders, and constructing an adapter class outright --
    # any call to a name ending in `Target`. `onboard` does the second: it takes
    # `--target-config`, constructs `HttpConfiguredTarget` itself and sends a probe, and it
    # was not a door to this gate at all, because doors were found by the SUBSTRINGS of the
    # two builder names. It gates correctly today. Nothing here would have said so the day it
    # stopped.
    GATES = ("_auth_gate", "gate")
    BUILDERS = ("_build_target", "load_target", "load_target_or_explain")

    def _fn_name(call):
        f = call.func
        return f.id if isinstance(f, _ast.Name) else getattr(f, "attr", None)

    def _is_builder(call):
        _n = _fn_name(call) or ""
        return _n in BUILDERS or (_n.endswith("Target") and _n[:1].isupper())

    def _calls(node, pick):
        return sorted(n.lineno for n in _ast.walk(node)
                      if isinstance(n, _ast.Call) and pick(n))

    def _doors_and_faults(sources):
        """(name, source) pairs -> (doors, [fault]) under the rule below."""
        _doors, _faults = [], []
        for _name, _src in sources:
            if _name.startswith("test_"):
                continue
            try:
                _tree = _ast.parse(_src)
            except SyntaxError:
                continue
            # A DOOR IS A MODULE THAT CAN SEND, not one that can be handed a config. Taking
            # `--target-config` alone caught `sarif.py`, which reads a stored result and never
            # opens a socket. What makes a door is BUILDING a target -- the object with
            # `.send()` on it -- or spawning a sweep.
            _takes = '"--target-config"' in _src or "'--target-config'" in _src
            _builds = bool(_calls(_tree, _is_builder))
            _spawn_calls = _calls(_tree, lambda c: _fn_name(c) in (
                "run", "Popen", "call", "check_call", "check_output"))
            _spawns = bool(_spawn_calls) and "run_redteam.py" in _src
            if not (_takes and (_builds or _spawns)):
                continue
            _doors.append(_name)
            # ASKS MEANS A CALL. "_auth_gate(" as a substring was satisfied by a comment, and
            # the ordering check below skips any function with no gate call in it -- so a door
            # whose only mention of the gate was prose passed both.
            _asks = bool(_calls(_tree, lambda c: _fn_name(c) in GATES))
            if not (_asks or _spawns):
                _faults.append("%s neither calls the gate nor spawns run_redteam.py" % _name)
            # AND EVERY FUNCTION THAT BUILDS ASKS FIRST -- ITSELF. Scoped per function, so the
            # builder's own definition (`load_target` calling `_build_target` in its body) is
            # not read as a use before the gate. This used to skip any function with no gate
            # call in it, so a module that asked in `main` passed while a second function in
            # it built and sent without asking at all. Two things are not that: a builder's
            # own definition, and a call to a function in the same module that itself asks
            # before it builds -- `run_isolation.main` builds through its own gated
            # `load_target`, which is exactly the shape this has to allow.
            _fns = [n for n in _ast.walk(_tree)
                    if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))]
            _gated = set()
            for _fn in _fns:
                _g = _calls(_fn, lambda c: _fn_name(c) in GATES)
                if _g and not [x for x in _calls(_fn, _is_builder) if x < _g[0]]:
                    _gated.add(_fn.name)
            for _fn in _fns:
                if _fn.name in BUILDERS:
                    continue
                _g = _calls(_fn, lambda c: _fn_name(c) in GATES)
                _raw = _calls(_fn, lambda c: _is_builder(c) and _fn_name(c) not in _gated)
                if _raw and not _g:
                    _faults.append("%s: %s() builds at line(s) %s and never asks"
                                   % (_name, _fn.name, _raw))
                elif _g and [x for x in _raw if x < _g[0]]:
                    _faults.append("%s: %s() builds at line(s) %s, gate at %d"
                                   % (_name, _fn.name, [x for x in _raw if x < _g[0]],
                                      _g[0]))
        return _doors, _faults

    # ON PLANTED MODULES FIRST: a door whose gate is only prose, a door that constructs an
    # adapter directly before asking, and one that asks first -- which must pass.
    _cfg = "ap.add_argument(\"--target-config\")\n"
    _pd, _pf = _doors_and_faults([
        ("prose.py", "# calls _auth_gate( before anything\ndef main(ap, cfg):\n    "
                     + _cfg + "    t = load_target(cfg)\n    t.send('x')\n"),
        ("late.py", "def main(ap, cfg):\n    " + _cfg
                    + "    t = HttpConfiguredTarget(**cfg)\n    authorization.gate(cfg, 'p')\n"),
        ("early.py", "def main(ap, cfg):\n    " + _cfg
                     + "    authorization.gate(cfg, 'p')\n    t = HttpConfiguredTarget(**cfg)\n"),
        ("second.py", "def main(ap, cfg):\n    " + _cfg
                      + "    authorization.gate(cfg, 'p')\n\n"
                      + "def probe(cfg):\n    HttpConfiguredTarget(**cfg).send('x')\n"),
        ("wrapped.py", "def load_target(cfg):\n    authorization.gate(cfg, 'p')\n"
                       + "    return _build_target(cfg)\n\n"
                       + "def main(ap, cfg):\n    " + _cfg + "    load_target(cfg)\n")])
    check("a door whose only gate is a comment is named, not passed",
          any(_f.startswith("prose.py neither") for _f in _pf), str(_pf))
    check("...a door that constructs an adapter itself is a door, and building first is named",
          "late.py" in _pd and any(_f.startswith("late.py: main()") for _f in _pf), str(_pf))
    check("...and one that asks before it constructs is not named",
          "early.py" in _pd and not any(_f.startswith("early.py") for _f in _pf), str(_pf))
    check("...while a SECOND function that builds without asking is, though main asks",
          any(_f.startswith("second.py: probe()") for _f in _pf), str(_pf))
    check("...and one that builds through its own module's gated loader is not",
          "wrapped.py" in _pd and not any(_f.startswith("wrapped.py") for _f in _pf),
          str(_pf))

    _srcs_a = [(os.path.basename(_p), open(_p, encoding="utf-8").read())
               for _p in sorted(_glob.glob(os.path.join(HERE, "*.py")))]
    doors, _faults_a = _doors_and_faults(_srcs_a)
    check("more than one entry point was found to check", len(doors) > 1, str(doors))
    # `onboard` BY NAME, because it is the door the substring scan could not see, and a
    # scan that stops seeing it again would otherwise pass in silence.
    check("...and the one that constructs its adapter directly is among them",
          "onboard.py" in doors, str(doors))
    check("every door gates the target before it builds one, or hands it to something "
          "that does (%d doors)" % len(doors), not _faults_a, "; ".join(_faults_a))

    rr = open(os.path.join(HERE, "run_redteam.py"), encoding="utf-8").read()
    check("the sweep stores the authorization record beside the findings",
          '"authorization": _auth' in rr)

    # --- THE LOCAL RULE INVERTS WHEN THIS IS A SERVICE -------------------------------------
    #
    # On a workstation `localhost` is the practice fleet and needs no proof of ownership. On a
    # host taking URLs from strangers, `localhost` is THAT HOST'S infrastructure, and an intake that
    # accepts it is a fully-featured SSRF proxy with an attack arsenal attached — pointed at
    # its own metadata endpoint, on request. The same predicate that waives the gate in
    # one mode has to refuse in the other, which is the kind of inversion that gets shipped
    # backwards, so it is gated here rather than reasoned about.
    # A RESOLVER THAT ANSWERS OFFLINE. `.example` does not resolve anywhere — that is what the
    # TLD is for — and a CI runner resolves nothing at all, so a suite that let the real
    # resolver run here would fail on the runner and pass on a laptop, which is worse than not
    # testing it. The seam is the resolver alone; every address still goes through the shipped
    # policy, and the shipped default is pinned two checks below so a stub here cannot become
    # the stub in production.
    #
    # 8.8.8.8 rather than a documentation address: 203.0.113.0/24 and 198.51.100.0/24 are both
    # `is_private` to `ipaddress`, so a stub returning one would prove the opposite of what it
    # was written to prove.
    def resolves_to(*addrs):
        def _r(host, port):
            return [(2, 1, 6, "", (a, port)) for a in addrs]
        return _r

    PUBLIC = resolves_to("8.8.8.8")

    ALLOW = ("https://api.acme.example/chat", "http://172.15.0.1/ok",
             "https://11.0.0.1/v1/chat")
    REFUSE = ("http://localhost:8140/chat", "http://127.0.0.1/x", "http://[::1]:9/x",
              "http://0.0.0.0/x", "http://10.0.0.5/api", "http://192.168.1.1/",
              "http://172.16.0.1/a", "http://172.31.255.254/a", "http://build.internal/api",
              "http://db.cluster.local/q", "file:///etc/passwd", "ftp://h/x", "notaurl")
    for u in ALLOW:
        check(f"hosted: a customer endpoint is reachable — {u}",
              az.unreachable_by_policy(u, PUBLIC) is None,
              str(az.unreachable_by_policy(u, PUBLIC)))
    for u in REFUSE:
        check(f"hosted: refused — {u}", az.unreachable_by_policy(u, PUBLIC) is not None)

    # --- DOCUMENTATION SPACE IS NOT SOMEBODY'S INSIDE --------------------------------------
    #
    # `ipaddress` calls RFC 5737's three ranges private, and they are not: they are reserved
    # for examples, so nothing is listening there. The refusal was right and its reason was
    # wrong twice over -- wrong about the address, and useless about the mistake, which is
    # almost always that the address from a sample config was left in place.
    for _doc in ("203.0.113.5", "192.0.2.1", "198.51.100.7"):
        _why = az.unreachable_by_policy("http://%s/chat" % _doc, PUBLIC)
        check("hosted: documentation space is refused — %s" % _doc, _why is not None,
              str(_why))
        check("...and named as documentation space rather than as somebody's network",
              "RFC 5737" in (_why or ""), str(_why))
        check("...and the message says why it cannot be the endpoint",
              "nothing is listening there" in (_why or ""), str(_why))
        check("...and points at the mistake it usually is",
              "sample config" in (_why or ""), str(_why))
    # AND THE RANGES THAT REALLY ARE SOMEBODY'S INSIDE STILL SAY SO, or this is a rename
    # rather than a distinction.
    for _priv in ("10.0.0.5", "192.168.1.1", "172.16.0.1", "100.64.0.1"):
        _why = az.unreachable_by_policy("http://%s/chat" % _priv, PUBLIC)
        check("hosted: a private address still reads as one — %s" % _priv,
              "inside somebody's network" in (_why or ""), str(_why))

    # --- A NAME IS AN ADDRESS SOMEBODY ELSE CHOOSES ----------------------------------------
    #
    # Every entry in REFUSE spells its address in the URL, and the gate used to check only what
    # was spelled. `http://metadata.attacker.example/` with an A record of 169.254.169.254 is a
    # one-line walk around that whole table — no timing, no second answer, nothing to race. The
    # name resolves and every answer goes through the same address check.
    check("hosted: a name resolving to the metadata address is refused",
          az.unreachable_by_policy("https://metadata.attacker.example/x",
                                   resolves_to("169.254.169.254")) is not None)
    check("hosted: a name resolving into private space is refused",
          az.unreachable_by_policy("https://vpn.acme.example/x",
                                   resolves_to("10.1.2.3")) is not None)
    # The half that a single-answer check misses: one good record and one bad one is still a
    # request the service must not make, and `getaddrinfo` returns both.
    check("hosted: one public answer does not excuse a private one",
          az.unreachable_by_policy("https://split.acme.example/x",
                                   resolves_to("8.8.8.8", "127.0.0.1")) is not None)
    # ABSENT IS NOT CLEAN. A resolver that cannot answer has said nothing about where the name
    # points, and "no answer" read as "no problem" is this project's own defect class.
    def _dead(host, port):
        raise OSError("no answer")
    check("hosted: a name that does not resolve is refused, not waved through",
          az.unreachable_by_policy("https://nowhere.acme.example/x", _dead) is not None)
    check("hosted: ...and a name resolving to nothing at all is refused",
          az.unreachable_by_policy("https://empty.acme.example/x", resolves_to()) is not None)

    # THE STUB ABOVE MUST NOT BE THE PRODUCTION PATH. Every check in this section supplies its
    # own resolver, so nothing here would notice if the shipped default were removed, made
    # permissive, or left as a stub after a debugging session.
    import socket as _socket
    check("the shipped resolver is the real one",
          az._resolve.__module__ == az.__name__
          and _socket.getaddrinfo.__name__ in az._resolve.__code__.co_names,
          f"_resolve calls {az._resolve.__code__.co_names}")

    # --- THE SPELLING IS GENERATED, NOT REMEMBERED ------------------------------------------
    #
    # The list above is thirteen forms somebody thought of, and the gate used to be thirteen
    # string prefixes built from the same thinking. Both passed while `http://2130706433/` —
    # loopback written as an integer, which every resolver accepts — walked straight through,
    # along with `::ffff:127.0.0.1`, `0177.0.0.1` and `[::]`.
    #
    # An attacker picks the spelling; the address is not their choice. So the address is fixed
    # and every way of writing it is derived, which is a test that can find what nobody listed.
    def spellings(a, b, c, d):
        """One IPv4 address, in the forms an operating system will resolve."""
        n = (a << 24) | (b << 16) | (c << 8) | d
        return [
            f"{a}.{b}.{c}.{d}",                                   # dotted quad
            str(n),                                               # bare integer
            f"0x{n:08x}",                                         # hex integer
            f"0{a:o}.0{b:o}.0{c:o}.0{d:o}",                       # octal quad
            f"0x{a:02x}.0x{b:02x}.0x{c:02x}.0x{d:02x}",           # hex quad
            f"[::ffff:{a}.{b}.{c}.{d}]",                          # IPv4-mapped IPv6
            f"[::ffff:{n >> 16:04x}:{n & 0xffff:04x}]",           # the same, in hex groups
            f"{a}.{b}.{c}.{d}.",                                  # trailing root dot
        ]

    MUST_REFUSE = {
        "loopback": (127, 0, 0, 1),
        "cloud metadata": (169, 254, 169, 254),
        "private 10/8": (10, 0, 0, 5),
        "private 192.168/16": (192, 168, 1, 1),
        "private 172.16/12": (172, 20, 0, 1),
        "carrier-grade NAT": (100, 64, 0, 1),
    }
    slipped = []
    tried = 0
    for label, quad in MUST_REFUSE.items():
        for host in spellings(*quad):
            tried += 1
            if az.unreachable_by_policy(f"http://{host}/latest/meta-data/", PUBLIC) is None:
                slipped.append(f"{label}: {host}")
    check(f"every spelling of an address that must never be reached is refused ({tried} forms)",
          not slipped, str(slipped[:6]))

    # IPv6 forms that have no dotted-quad equivalent, and are the same three addresses.
    V6 = ["[::1]", "[0:0:0:0:0:0:0:1]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
          "[::]", "[fd00::1]", "[fe80::1]"]
    v6_slipped = [h for h in V6 if az.unreachable_by_policy(f"http://{h}/x", PUBLIC) is None]
    check("...and the IPv6 spellings of loopback, unspecified, ULA and link-local",
          not v6_slipped, str(v6_slipped))

    # THE OTHER DIRECTION, and it matters as much: a gate that refuses everything passes every
    # refuse-only test and breaks every real user on their first run.
    REACHABLE = ["https://api.openai.com/v1/chat", "https://api.anthropic.com/v1/messages",
                 "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke",
                 "https://bot.acme.example/chat", "http://8.8.8.8/x", "https://1.1.1.1/x"]
    # Through the stub, like every other check in this section. These are real names and this
    # machine resolves them; a CI runner with no DNS does not, and a suite that passes on a
    # laptop and fails on the runner is how a gate gets switched off. The names stay because
    # they say what the check is about — these are the endpoints a customer actually points at.
    wrongly = [(u, az.unreachable_by_policy(u, PUBLIC)) for u in REACHABLE
               if az.unreachable_by_policy(u, PUBLIC) is not None]
    check("a real endpoint is still reachable", not wrongly, str(wrongly[:3]))

    # The one address that matters most, called out by name because a generic "link-local"
    # refusal reads as tidiness and this is the whole reason the check exists.
    why = az.unreachable_by_policy("http://169.254.169.254/latest/meta-data/") or ""
    check("hosted: the cloud metadata service is refused, and the reason says why",
          "metadata" in why, why)

    # 172.16/12 has edges on both sides and an off-by-one here is a private network reachable
    # from a public service.
    check("hosted: the 172.16/12 block is refused at both edges but not outside it",
          az.unreachable_by_policy("http://172.16.0.1/") and
          az.unreachable_by_policy("http://172.31.0.1/") and
          not az.unreachable_by_policy("http://172.32.0.1/") and
          not az.unreachable_by_policy("http://172.15.0.1/"))

    # And the mode itself, since a control that is never switched on is not a control.
    import importlib
    old_env = os.environ.get("QATRATION_HOSTED")
    try:
        os.environ["QATRATION_HOSTED"] = "1"
        importlib.reload(az)
        check("the hosted flag turns the mode on", az.hosted())
        # FAIL CLOSED: a value nobody listed is ON, and only what says off is off.
        _hv = {}
        for _v in ("on", "enabled", "Y", "2", "0", "false", "OFF", "no", " "):
            os.environ["QATRATION_HOSTED"] = _v
            _hv[_v] = az.hosted()
        check("an unlisted value turns hosted mode ON; only an off-word turns it off",
              _hv == {"on": True, "enabled": True, "Y": True, "2": True, "0": False,
                      "false": False, "OFF": False, "no": False, " ": False}, str(_hv))
        os.environ["QATRATION_HOSTED"] = "1"
        rc = None
        try:
            az.gate({"name": "x", "url": "http://localhost:8140/chat"}, "intake")
        except SystemExit as e:
            rc = e.code
        check("hosted: the gate REFUSES a local target instead of waiving it", rc == 4, str(rc))
        os.environ.pop("QATRATION_HOSTED")
        importlib.reload(az)
        check("...and without the flag the same target passes untouched",
              az.gate({"name": "x", "url": "http://localhost:8140/chat"}, "t") is None)
    finally:
        if old_env is None:
            os.environ.pop("QATRATION_HOSTED", None)
        else:
            os.environ["QATRATION_HOSTED"] = old_env
        importlib.reload(az)

    # --- THE REFUSAL CARRIES ITS REASON, NOT JUST ITS CODE ---------------------------------
    #
    # `gate` printed its sentence to stderr and raised `SystemExit(4)`. Uncaught that is
    # right. CAUGHT, it is everything a caller needs minus the part that says why:
    # `str(SystemExit(4))` is the string "4", and `onboard` wrote it into its report as
    #
    #     PROBLEM   not authorised: 4
    #
    # with the sentence explaining it twenty-nine lines above, on the other stream, over a
    # full report nobody would connect it to.
    _na = None
    try:
        az.gate({"name": "remotebot", "url": "https://not-a-real-bot.example.com/chat"},
                "test")
    except az.NotAuthorised as _e:
        _na = _e
    except SystemExit as _e:
        _na = _e
    check("a remote target with no secret is refused", _na is not None, "it passed")
    check("...as the exception that carries a reason",
          isinstance(_na, az.NotAuthorised), type(_na).__name__)
    check("...whose code is still the one the table reserves", getattr(_na, "code", None) == 4,
          str(getattr(_na, "code", None)))
    check("...and whose reason names the target and what is missing",
          "remotebot" in getattr(_na, "why", "")
          and "QATRATION_AUTH_SECRET" in getattr(_na, "why", ""),
          getattr(_na, "why", "")[:160])
    # AND IT IS STILL A `SystemExit`, which is what the eight commands that do NOT catch it
    # depend on: they let it out, and `workspace.run_command` returns `e.code` unchanged.
    check("...and an uncaught refusal still exits rather than raising something new",
          isinstance(_na, SystemExit), type(_na).__name__)

    # AND THE ONE COMMAND THAT CATCHES IT SAYS BOTH. Driven, because the defect was in what
    # a reader sees and in what a pipeline reads, and neither is visible from the function.
    import subprocess as _sp_a
    import tempfile as _tf_a
    _aw = _tf_a.mkdtemp()
    _aenv = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8",
                 QATRATION_OUT=_tf_a.mkdtemp())
    _aenv.pop("QATRATION_AUTH_SECRET", None)
    _sp_a.run([sys.executable, os.path.join(HERE, "cli.py"), "init"],
              capture_output=True, text=True, env=_aenv, cwd=_aw, timeout=180)
    _acfg = os.path.join(_aw, "mybot.yaml")
    _atxt = open(_acfg, encoding="utf-8").read().replace(
        'url: "http://localhost:8000/chat"', 'url: "https://not-a-real-bot.example.com/chat"')
    open(_acfg, "w", encoding="utf-8", newline="").write(_atxt)
    _ap = _sp_a.run([sys.executable, os.path.join(HERE, "cli.py"), "onboard",
                     "--target-config", _acfg],
                    capture_output=True, text=True, env=_aenv, cwd=_aw, timeout=180)
    _aout = (_ap.stdout or "") + (_ap.stderr or "")
    _aproblem = [l for l in _aout.splitlines() if "not authorised" in l and "PROBLEM" in l]
    check("onboard's report says why it is not authorised",
          bool(_aproblem) and "QATRATION_AUTH_SECRET" in _aproblem[0],
          str(_aproblem[:1]) or _aout[-200:])
    check("...and not the exit code in place of the reason",
          bool(_aproblem) and not _aproblem[0].rstrip().endswith(": 4"),
          str(_aproblem[:1]))
    # ONE CAUSE, ONE CODE. `run` exits 4 for this exact refusal; this door exited 2, so a
    # pipeline asking "may I test this target" got `refused or crashed` from one and `not
    # authorised` from the other.
    check("...and the shell is told `not authorised`, the code `run` uses for the same cause",
          _ap.returncode == 4, "exit %s" % _ap.returncode)
    # AND NOT FOR EVERY REFUSAL, or the code stops meaning anything: an ordinary broken
    # config is still `the invocation was refused`.
    _bad = os.path.join(_aw, "broken.yaml")
    open(_bad, "w", encoding="utf-8", newline="").write(
        "adapter: http\nname: localbot\nurl: \"http://127.0.0.1:9/chat\"\n"
        "request: {message: \"{prompt}\"}\nresponse: {reply: reply}\n"
        "oracle_context:\n  canaries: \"ACME-9931\"\n")
    _bp = _sp_a.run([sys.executable, os.path.join(HERE, "cli.py"), "onboard",
                     "--target-config", _bad],
                    capture_output=True, text=True, env=_aenv, cwd=_aw, timeout=180)
    check("a config that is merely wrong still exits 2", _bp.returncode == 2,
          "exit %s: %s" % (_bp.returncode,
                           ((_bp.stdout or "") + (_bp.stderr or "")).strip()[-160:]))

    # --- EVERY DOOR, WALKED, NOT GREPPED ----------------------------------------------------
    #
    # The two checks above ask whether a file CONTAINS a gate call and whether the gate's line
    # number is above the builder's. Both passed while `benign.py` shipped an ungated path,
    # because the gate sat inside `if args.target_config:` and `--target NAME` went down the
    # `else:`. A string is in the file either way, and a line number cannot see a branch.
    #
    # `--target` resolves through `_ctx_for`, which scans THIS package's own `targets_*.yaml`,
    # and four of those carry live third-party URLs. So the ungated door pointed at
    # api.anthropic.com by default. What follows walks each door with the gate stubbed and
    # asks whether it was reached, which is the property the other two were standing in for.
    import importlib as _il

    def _walks_the_gate(argv, label):
        """-> (gate calls, things built) for one invocation of `benign.main`."""
        import benign as _bn
        _il.reload(_bn)
        seen, built = [], []
        _bn.load_target = lambda cfg: built.append(cfg.get("url"))
        import authorization as _azm
        _real = _azm.gate

        def _stub(cfg, why):
            seen.append(cfg.get("url"))
            raise SystemExit("gate reached")
        _azm.gate = _stub
        old = sys.argv
        try:
            sys.argv = argv
            _bn.main()
        except SystemExit:
            pass
        except Exception as e:                       # a door that dies before the gate is a
            seen.append(f"!{type(e).__name__}: {e}")  # failure to report, not to hide
        finally:
            sys.argv = old
            _azm.gate = _real
        return seen, built

    _named, _built = _walks_the_gate(
        ["benign", "--target", "anthropic-messages", "--trials", "1"], "--target")
    check("benign --target reaches the authorization gate",
          len(_named) == 1 and str(_named[0] or "").startswith("http"),
          f"gate saw {_named!r}")
    check("...and builds nothing before it", not _built, f"built {_built!r}")

    import tempfile as _tf
    _fd, _cfgp = _tf.mkstemp(suffix=".yaml")
    with os.fdopen(_fd, "w", encoding="utf-8") as _f:
        _f.write("name: gate-probe\nadapter: http\nurl: https://api.acmeshop.example/v1/chat\n")
    try:
        _cfg, _cbuilt = _walks_the_gate(
            ["benign", "--target-config", _cfgp, "--trials", "1"], "--target-config")
        check("benign --target-config reaches the authorization gate",
              len(_cfg) == 1 and str(_cfg[0] or "").startswith("http"),
              f"gate saw {_cfg!r}")
        check("...and builds nothing before it either", not _cbuilt, f"built {_cbuilt!r}")
    finally:
        os.unlink(_cfgp)

    # --- THE PROOF FETCH RUNS BEFORE ANYBODY HAS VOUCHED FOR THE HOST -------------------
    #
    # `_http_get` reads /.well-known/qatration-authorization from the target itself, and it
    # is the one request this module makes before it knows whether the target may be
    # touched at all. Two rules protect it and both were written with a reason and kept by
    # nothing:
    #
    #   `_NoRedirect` -- a proof has to come from the origin it is a proof about. Following
    #   a redirect means the fetch lands somewhere the config never named, on the
    #   instruction of the host being checked. The token is an HMAC over the origin, so a
    #   forged one still needs the signing secret, but a pre-authorisation request steered
    #   by the target is the shape `unreachable_by_policy` calls an SSRF proxy.
    #
    #   `_MAX_WELL_KNOWN` -- reading to EOF lets the origin under test decide how much
    #   memory the gate uses, before the gate has decided anything about it.
    #
    # Driven through `_http_get` against a real server, so this covers the opener the code
    # actually uses rather than the handler class in isolation.
    import threading as _th, io as _io2
    from http.server import BaseHTTPRequestHandler as _BH, ThreadingHTTPServer as _TS

    _mode = {"m": "ok", "to": ""}

    class _WK(_BH):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            if _mode["m"] == "redirect":
                self.send_response(302)
                self.send_header("location", _mode["to"])
                self.send_header("content-length", "0")
                self.end_headers()
                return
            _b = (b"token-from-the-origin" if _mode["m"] == "ok"
                  else b"A" * (az._MAX_WELL_KNOWN * 50))
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(_b)))
            self.end_headers()
            self.wfile.write(_b)

    _s1 = _TS(("127.0.0.1", 0), _WK)
    _s2 = _TS(("127.0.0.1", 0), _WK)
    for _s in (_s1, _s2):
        _th.Thread(target=_s.serve_forever, daemon=True).start()
    try:
        _url = "http://127.0.0.1:%d%s" % (_s1.server_address[1], az.WELL_KNOWN)

        # THE FIXTURE HAS TO REACH THE PROPERTY: a fetch that cannot succeed would make
        # both refusals below true for the wrong reason.
        _mode["m"] = "ok"
        _got = az._http_get(_url)
        check("the proof fetch reads what the origin serves",
              "token-from-the-origin" in _got, repr(_got[:60]))

        _mode["m"] = "huge"
        _big = az._http_get(_url)
        check("...and a body the origin sizes is capped rather than read to EOF",
              len(_big) == az._MAX_WELL_KNOWN, str(len(_big)))

        _mode["m"] = "redirect"
        _mode["to"] = "http://127.0.0.1:%d/elsewhere" % _s2.server_address[1]
        try:
            _r = az._http_get(_url)
            _why = "FOLLOWED: %r" % (_r[:60],)
        except Exception as _e:
            _why = "%s: %s" % (type(_e).__name__, _e)
        check("...and a redirect off the origin is refused, not followed",
              "redirected to" in _why, _why[:120])
    finally:
        _s1.shutdown()
        _s2.shutdown()

    # --- ONE TABLE, AND NO DEAD ONE BESIDE IT -------------------------------------------
    #
    # `_BLOCKED_NETS` listed `127.`, `10.`, `192.168.`, `169.254.`, `0.` and the sixteen `172.`
    # ranges as string prefixes, under a comment explaining that 169.254.169.254 is the cloud
    # metadata service -- so it read as the policy. Nothing read it. The policy is
    # `_address_refused`, which asks `ipaddress` for the properties, and the two never had to
    # agree because only one of them ran.
    #
    # A dead table beside a live one is a second thing to keep true and it looks enforced. It is
    # gone; this is the check that keeps it gone, and the one that says the live table is wider
    # than the dead one ever was.
    import authorization as _auth_t
    check("no second table of blocked networks lives beside the live one",
          not hasattr(_auth_t, "_BLOCKED_NETS"),
          "authorization._BLOCKED_NETS is back")
    from authorization import unreachable_by_policy as _ubp_t
    # CARRIER-GRADE NAT never appeared in the dead list and `is_private` covers it, which is
    # the argument for the properties in one line.
    check("a range the dead table never listed is still refused",
          "private" in (_ubp_t("http://100.64.0.1/x") or ""),
          str(_ubp_t("http://100.64.0.1/x")))
    for _u in ("http://10.0.0.1/x", "http://172.16.0.1/x", "http://192.168.1.1/x",
               "http://169.254.169.254/x", "http://127.0.0.1/x"):
        check("...and every range it did list still is: %s" % _u,
              _ubp_t(_u) is not None, str(_ubp_t(_u)))
    check("...while the range just outside 172.16/12 is not refused for being nearby",
          _ubp_t("http://172.32.0.1/x") is None, str(_ubp_t("http://172.32.0.1/x")))
    # AND THE NAMES, which no property can answer and which is why that half stayed.
    for _u in ("http://x.internal/y", "http://x.cluster.local/y", "http://x.local/y"):
        check("an internal name is refused before it is resolved: %s" % _u,
              "internal name" in (_ubp_t(_u) or ""), str(_ubp_t(_u)))

    # --- THE SHORT DOTTED FORMS, WHICH THE READER PARSED AND THREW AWAY -----------------
    #
    # `_as_address` accepts two to four parts, converts each, and used to end on
    # `len(nums) == 4` -- so `127.1` came back as None, which tells the caller `this is a
    # hostname`. `socket.inet_aton` reads it as 127.0.0.1 and so does every resolver:
    # `a.b` means a.0.0.b and `a.b.c` means a.b.0.c, with the last part carrying the bytes
    # the missing ones would have held.
    #
    # The outcome was safe on both platforms for different reasons, which is why nothing
    # caught it: on Linux the name resolution that follows returns 127.0.0.1 and the same
    # table refuses it there; on Windows `getaddrinfo` fails and the gate refuses with
    # `does not resolve here, so where it points is unknown` -- a refusal carrying a
    # sentence that is wrong about an address whose destination is not in doubt.
    from authorization import _as_address as _aa
    for _s, _want in (("127.1", "127.0.0.1"), ("127.0.1", "127.0.0.1"),
                      ("10.1", "10.0.0.1"), ("1.16777215", "1.255.255.255"),
                      ("1.2.65535", "1.2.255.255"), ("0x7f.1", "127.0.0.1")):
        check("a short dotted form is the address a resolver reads: %s" % _s,
              str(_aa(_s)) == _want, str(_aa(_s)))
    # AND THE RANGES ARE inet_aton's, not `all(n <= 255)`: only the leading parts are single
    # bytes, and one part too large is not an address at all.
    for _s in ("256.1", "1.16777216", "1.2.65536", "1.2.3.4.5"):
        check("...and one that overflows its span is not an address: %s" % _s,
              _aa(_s) is None, str(_aa(_s)))

    # PINNED TO THE RESOLVER RATHER THAN TO A LIST SOMEBODY REMEMBERED. The hex form was
    # missed by the first version of this function and found by generating spellings; the
    # short forms were missed by the second and are the same lesson. `socket.inet_aton` IS
    # the lenient reader the socket will use, so it is the thing to agree with.
    import socket as _sock_a, random as _rnd_a
    _rnd_a.seed(11)
    _spellings = ["127.1", "127.0.1", "1.2.3.4", "0177.0.0.1", "0x7f.0.0.1",
                  "2130706433", "8.8.8.8", "0.0.0.0", "255.255.255.255"]
    for _ in range(120):
        _spellings.append("%d.%d" % (_rnd_a.randint(0, 255), _rnd_a.randint(0, 16777215)))
        _spellings.append("%d.%d.%d" % (_rnd_a.randint(0, 255), _rnd_a.randint(0, 255),
                                        _rnd_a.randint(0, 65535)))
        _spellings.append("%d.%d.%d.%d" % tuple(_rnd_a.randint(0, 255) for _ in range(4)))
    _off = []
    for _s in _spellings:
        try:
            _want = _sock_a.inet_ntoa(_sock_a.inet_aton(_s))
        except OSError:
            _want = None
        _got = _aa(_s)
        _got = str(_got) if _got is not None else None
        if _got != _want:
            _off.append("%s: inet_aton=%s ours=%s" % (_s, _want, _got))
    check("every IPv4 spelling reads the same as the socket would read it",
          not _off, "; ".join(_off[:4]))
    check("...over enough spellings to be worth saying", len(_spellings) >= 300,
          str(len(_spellings)))

    # AND THE GATE REFUSES THEM, which is the point of parsing them at all.
    from authorization import unreachable_by_policy as _ubp
    for _u, _word in (("http://127.1/x", "loopback"), ("http://127.0.1/x", "loopback"),
                      ("http://10.1/x", "private"), ("http://0x7f.1/x", "loopback")):
        check("the gate refuses %s as %s" % (_u, _word),
              _word in (_ubp(_u) or ""), str(_ubp(_u)))
    check("...and still allows an ordinary public address",
          _ubp("http://8.8.8.8/x") is None, str(_ubp("http://8.8.8.8/x")))

    # --- ONE HOST IS ONE ORIGIN ---------------------------------------------------------
    #
    # `origin_of` returned the netloc verbatim, and a netloc is not a normal form.
    # `https://API.Example.com` and `https://api.example.com` are the same host -- DNS has
    # been case-insensitive since RFC 1035 -- and `https://host:443` is the same origin as
    # `https://host`, because a scheme's default port is not part of one. Each pair came
    # out as two.
    #
    # THE QUEUE RUNS ON THIS. `jobqueue.contended_resource` asks what two jobs collide over,
    # so two configs spelling one endpoint differently were allowed to sweep it at once --
    # which that module calls rude to the operator and corrupting to the measurement, since
    # their latency and rate limits get attributed to the attacks.
    from authorization import origin_of as _oo
    for _a, _b, _why in ((("https://API.Example.com/x", "https://api.example.com/y"),
                          None, "the host is case-insensitive"),
                         (("https://api.example.com:443/x", "https://api.example.com/x"),
                          None, "443 is what https means"),
                         (("http://api.example.com:80/x", "http://api.example.com/x"),
                          None, "80 is what http means"),
                         (("HTTPS://Api.Example.COM:443/a", "https://api.example.com/b"),
                          None, "and the scheme is case-insensitive too")):
        check("one endpoint, one answer: %s" % _why, _oo(_a[0]) == _oo(_a[1]),
              "%s != %s" % (_oo(_a[0]), _oo(_a[1])))

    # AND NOTHING ELSE COLLAPSES WITH IT. A normalisation that admits a host it should not
    # is the same defect pointed at authorisation, where the origin is what a token binds to.
    for _a, _b, _why in ((("https://a.example.com/x", "https://b.example.com/x"),
                          None, "a different host"),
                         (("https://api.example.com:8443/x", "https://api.example.com/x"),
                          None, "a non-default port"),
                         (("http://api.example.com/x", "https://api.example.com/x"),
                          None, "a different scheme"),
                         (("https://api.example.com:80/x", "https://api.example.com/x"),
                          None, "80 under https is not the default")):
        check("still two: %s" % _why, _oo(_a[0]) != _oo(_a[1]),
              "%s == %s" % (_oo(_a[0]), _oo(_a[1])))

    # THE USERINFO IS LEFT ALONE. RFC 3986 makes scheme and host case-insensitive and says
    # nothing of the kind about a username, so lowercasing the whole netloc would rewrite a
    # credential.
    check("a username keeps its case",
          _oo("https://User:Pw@API.Example.com:443/x") == "https://User:Pw@api.example.com",
          _oo("https://User:Pw@API.Example.com:443/x"))
    # AND A PORT THAT IS NOT A NUMBER IS NOT GUESSED AT: kept as written, so two of them
    # still compare equal to each other and to nothing else.
    check("an unparseable port is kept rather than invented",
          _oo("https://host:notaport/x") == _oo("https://host:notaport/y"),
          _oo("https://host:notaport/x"))

    # AND THE TOKEN BINDS TO THE NORMALISED ORIGIN, both sides through the same function, so
    # a proof written for one spelling verifies against the other.
    from authorization import issue as _issue
    _t1, _d1 = _issue("https://API.Example.com:443/a", "s3cret")
    _t2, _d2 = _issue("https://api.example.com/b", "s3cret")
    check("a proof for one spelling is a proof for the other", _t1 == _t2,
          "%s vs %s" % (_t1, _t2))
    _t3, _ = _issue("https://other.example.com/a", "s3cret")
    check("...and not for a different host", _t1 != _t3, "%s == %s" % (_t1, _t3))

    # AND THE QUEUE ASKS THIS FUNCTION, rather than keeping its own idea of an endpoint.
    import ast as _ast_o, io as _io_o, os as _os_o
    _jq = _ast_o.parse(_io_o.open(
        _os_o.path.join(_os_o.path.dirname(_os_o.path.abspath(__file__)), "jobqueue.py"),
        encoding="utf-8").read())
    check("the queue names its contended resource through origin_of",
          any(isinstance(_n, _ast_o.Call) and isinstance(_n.func, _ast_o.Name)
              and _n.func.id == "origin_of" for _n in _ast_o.walk(_jq)),
          "jobqueue has its own idea of an endpoint")

    # --- FINDINGS OF AN INDEPENDENT REVIEW OF THE PROOFS ---------------------------------
    # A TOKEN SOMEWHERE IN A PAGE IS NOT THE PAGE HOLDING IT.
    for _body in ("garbage-before%sgarbage-after" % token, "<html>comment: %s</html>" % token):
        _okb, _whyb = az.check(cfg("well_known"), SECRET, fetch=lambda u, b=_body: b)
        check("a well-known page merely containing the token is refused (%s...)" % _body[:8],
              not _okb, _whyb)
    _okd, _whyd = az.check(cfg("dns_txt", records=["prefix%ssuffix" % token]), SECRET)
    check("...and so is a TXT record merely containing it", not _okd, _whyd)
    # WRONGLY TYPED PROOF FIELDS ARE REFUSED, not raised on.
    for _bad in ({"method": "header", "echoed": 5}, {"method": "dns_txt", "records": 5}):
        try:
            _okt, _whyt = az.check(cfg(_bad["method"], **{k: v for k, v in _bad.items()
                                                          if k != "method"}), SECRET)
            _raised = None
        except Exception as _e:
            _okt, _raised = None, _e
        check("a %s proof with a wrongly typed field is refused, not raised on" % _bad["method"],
              _raised is None and _okt is False, repr(_raised))
    # THE WHOLE FETCH HAS ONE DEADLINE, not one per byte.
    import threading as _th_a, time as _tm_a
    from http.server import BaseHTTPRequestHandler as _BH, ThreadingHTTPServer as _TS

    class _Drip(_BH):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "50")
            self.end_headers()
            for _i in range(50):
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                except Exception:
                    return
                _tm_a.sleep(0.3)

        def log_message(self, *a):
            pass
    _srv_a = _TS(("127.0.0.1", 0), _Drip)
    _th_a.Thread(target=_srv_a.serve_forever, daemon=True).start()
    try:
        _t0 = _tm_a.monotonic()
        try:
            az._http_get("http://127.0.0.1:%d/x" % _srv_a.server_address[1], timeout=1)
            _got = "returned"
        except Exception as _e:
            _got = type(_e).__name__
        _took = _tm_a.monotonic() - _t0
    finally:
        _srv_a.shutdown()
    check("a well-known file dripping a byte at a time stops at the deadline",
          _took < 3 and _got != "returned", "%s after %.1fs" % (_got, _took))
    # 6TO4 IS NOT THIS MACHINE.
    check("a 6to4 address embedding 127.0.0.1 is not waived as local",
          not az.is_local("http://[2002:7f00:1::1]/"), "waived")
    # CREDENTIALS IN THE URL are refused: nothing here can connect to one, and the password
    # would be written into the queue's job record.
    check("a URL carrying user:password@ is refused with a reason",
          bool(az.url_problem("http://user:pw@api.example.com/chat")),
          repr(az.url_problem("http://user:pw@api.example.com/chat")))
    # A PORT THAT IS NOT A PORT IS A REFUSAL, not a ValueError.
    for _pu in ("http://example.com:abc/chat", "http://example.com:99999/chat"):
        try:
            _pw = az.unreachable_by_policy(_pu, resolve=lambda h, p: [])
            _pr = None
        except Exception as _e:
            _pw, _pr = None, _e
        check("a port that is not a port is refused by the policy (%s)" % _pu.split(":")[-1][:5],
              _pr is None and bool(_pw), repr(_pr or _pw))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a scan can say who asked for it.")


if __name__ == "__main__":
    main()
