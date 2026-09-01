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
    ok, why = az.check(cfg("smoke-signal"), SECRET)
    check("an unknown method is refused", not ok, why)

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
    doors = []
    for _p in sorted(_glob.glob(os.path.join(HERE, "*.py"))):
        _name = os.path.basename(_p)
        if _name.startswith("test_"):
            continue
        _src = open(_p, encoding="utf-8").read()
        # A DOOR IS A MODULE THAT CAN SEND, not one that can be handed a config. Taking
        # `--target-config` alone caught `sarif.py`, which reads a stored result and quotes the
        # oracle context into a notification without ever opening a socket. What makes a door
        # is BUILDING a target — that is the object with `.send()` on it — or spawning a sweep.
        _takes_cfg = '"--target-config"' in _src or "'--target-config'" in _src
        _builds = "_build_target(" in _src or "load_target(" in _src
        _spawns = "run_redteam.py" in _src and "subprocess" in _src
        if _takes_cfg and (_builds or _spawns):
            doors.append((_name, _src))
    check("more than one entry point was found to check", len(doors) > 1, str(len(doors)))
    # A door is gated if it asks, OR if it hands the target to something that asks.
    # `run_all.py` and `model_matrix.py` take a target config and send nothing themselves:
    # they spawn `run_redteam.py`, which gates per target. Requiring a second gate in the
    # parent would be a check nobody can satisfy honestly, and a check that cannot be
    # satisfied is one somebody deletes.
    for entry, src in doors:
        asks = "_auth_gate(" in src or "authorization.gate(" in src
        delegates = "run_redteam.py" in src and "subprocess" in src
        check(f"{entry} gates the target, or hands it to something that does",
              asks or delegates,
              "neither calls authorization.gate nor spawns run_redteam.py")
    # --- AND IT ASKS BEFORE IT BUILDS -------------------------------------------------------
    #
    # "Calls the gate" is not the property; "calls the gate before doing anything the gate is
    # meant to prevent" is. In `run_redteam.py` the call sat twenty lines below the
    # construction, and construction is not inert: the HTTP adapter expands `${VAR}` in its
    # headers there, so an unauthorised config could already tell which of the operator's
    # environment variables were set from the difference between "expanded" and "not set in this
    # shell", and other adapters here open connections and start processes in their constructors.
    #
    # By line number from the parse tree, not by string position, so a paragraph like this one
    # naming `_build_target(` cannot move the answer.
    import ast as _ast
    GATES = ("_auth_gate", "gate")
    BUILDERS = ("_build_target", "load_target", "load_target_or_explain")

    def _calls(node, names):
        out = []
        for n in _ast.walk(node):
            if not isinstance(n, _ast.Call):
                continue
            f = n.func
            nm = f.id if isinstance(f, _ast.Name) else getattr(f, "attr", None)
            if nm in names:
                out.append(n.lineno)
        return sorted(out)

    for entry, src in doors:
        try:
            tree = _ast.parse(src)
        except SyntaxError:
            continue
        # SCOPED TO THE FUNCTION THAT GATES, because a module-wide minimum answers the wrong
        # question: `load_target_or_explain` is itself defined in `run_redteam.py` and calls
        # `load_target` inside its own body, at a line number far above `main`. That is the
        # definition of the builder, not a use of it before the gate, and reporting it would
        # be a false positive — which in a gate is not a small cost. It is the reason people
        # stop reading one.
        for fn in [n for n in _ast.walk(tree)
                   if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))]:
            gates = _calls(fn, GATES)
            if not gates:
                continue
            builds = [b for b in _calls(fn, BUILDERS) if b < gates[0]]
            check(f"{entry}: {fn.name}() asks before it builds a target",
                  not builds, f"builds at line(s) {builds}, gate at {gates[0]}")

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

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — a scan can say who asked for it.")


if __name__ == "__main__":
    main()
