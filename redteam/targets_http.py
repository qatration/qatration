"""The generic HTTP adapter: point the engine at somebody else's bot with a YAML file.

Every other adapter here is a Python file written for one system. That is affordable for a
practice fleet of bots this repository controls, and unaffordable for anything else: pointing
the engine at a new system would mean writing a new module, by someone who already knows this
codebase. A tool nobody can aim without its author is not a tool.

So this one is configured rather than coded. It covers the shape almost every chat API has —
POST a JSON body, read a string out of a JSON reply — and the three optional extras that
decide how much the oracle can see:

  * history, if the API takes the transcript from the client. That is what makes multi-turn
    deliveries possible AND what makes forged_history possible, and the second is a finding
    about the API rather than about the bot: a server that accepts the assistant's past turns
    from the caller cannot tell a refusal it gave from one the attacker wrote for it.
  * tool_calls, if the deployment reports them. Without it every tool-surface detector is
    inert and `inert_for` says so rather than reporting a clean result.
  * resolved, what the tools RECEIVED. This is the one to arrange before the first
    deployment: `send_email(body=customer_record)` exfiltrated a record and every detector
    read a variable name. It is ordinary agent-observability logging and no regex replaces it.

    adapter: http
    name: acme-support
    url: "https://api.acmeshop.example/v1/chat"
    headers:
      Authorization: "Bearer ${ACME_TOKEN}"     # env var, never the literal
    request:
      message: "{prompt}"
    response:
      reply: "choices.0.message.content"
    history:
      field: history
    rate:
      min_interval_s: 1.0
      max_requests: 400
"""
import json, os, re, time, urllib.request, urllib.error
from target import Probe, Target, payload

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value, where):
    """Substitute ${VAR} from the environment, and FAIL if it is not set.

    An API key must never sit in a config file in a repository, and a config that
    silently sends the literal `${ACME_TOKEN}` as a bearer token produces a run of 401s that
    look like a hardened target. Missing is loud.
    """
    if not isinstance(value, str):
        return value
    missing = [m.group(1) for m in _ENV.finditer(value) if os.environ.get(m.group(1)) is None]
    if missing:
        raise SystemExit(f"{where}: environment variable(s) not set: {', '.join(missing)}")
    return _ENV.sub(lambda m: os.environ[m.group(1)], value)


def dig(data, path):
    """`choices.0.message.content` -> the value, or None if any step is missing.

    None rather than "" on purpose: an extraction that found nothing and a reply that was
    genuinely empty are different facts, and the caller turns the first into an error rather
    than into a bot that said nothing.
    """
    cur = data
    for step in str(path).split("."):
        if isinstance(cur, list):
            if not step.lstrip("-").isdigit():
                return None
            i = int(step)
            cur = cur[i] if -len(cur) <= i < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(step)
        else:
            return None
        if cur is None:
            return None
    return cur


def _pairs(raw):
    """Normalise whatever a deployment calls a tool call into [(name, arguments)].

    Three shapes cover everything seen so far: a list of pairs, a list of dicts with some
    name/arguments spelling, and a dict of name -> arguments. Anything else is reported as
    unusable rather than guessed at, because a tool call the oracle mis-parses is worse than
    one it never saw: `unknown_tool_call` reported 24 invented capabilities the last time
    this repo guessed at a list it did not understand.
    """
    out = []
    if isinstance(raw, dict):
        raw = [{"name": k, "arguments": v} for k, v in raw.items()]
    for item in raw or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append((str(item[0]), str(item[1])))
        elif isinstance(item, dict):
            name = item.get("name") or item.get("tool") or item.get("function") or ""
            args = item.get("arguments", item.get("args", item.get("input", "")))
            # THE ARGUMENTS LIVE WHERE THE NAME DOES. OpenAI's shape is
            # {"type": "function", "function": {"name": ..., "arguments": "{...}"}} — this read
            # the name out of the nested dict and the arguments off the top level, where there
            # are none, so every OpenAI-shaped tool call arrived with an empty argument string.
            #
            # That is the expensive direction. Sixteen detectors judge the ARGUMENT — the id in
            # a BOLA read, the URL in an SSRF fetch, the string in an injected query, the canary
            # in an exfiltrating call — and every one of them saw "" and found nothing. A tool
            # surface reported clean because the evidence was dropped in transit, which is this
            # engine's own defect class arriving through its own adapter.
            if isinstance(name, dict):                       # {"function": {"name": ...}}
                nested = name
                name = nested.get("name", "")
                if not args:
                    args = nested.get("arguments", nested.get("args", nested.get("input", "")))
            out.append((str(name), args if isinstance(args, str) else json.dumps(args)))
    return out



class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Allow a redirect only if it keeps the same host and still passes the network policy.

    THE TARGET MUST NOT CHOOSE THE DESTINATION. Everything upstream — the ownership gate, the
    hosted network policy, the operator's own reading of the config — applies to the URL that
    was written down. Following a redirect blind moves the request somewhere none of those saw,
    and the thing doing the moving is the system under test.

    Same host, and re-checked against the policy anyway: `http://bot.example` redirecting to
    `https://bot.example` is an ordinary upgrade, and a host that resolves into private space on
    the second hop is not.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse
        old, new = urlparse(req.full_url), urlparse(newurl)
        if (new.hostname or "").lower() != (old.hostname or "").lower():
            raise urllib.error.HTTPError(
                req.full_url, code,
                f"redirect to a different host refused: {old.hostname} -> {new.hostname}. "
                f"The target does not choose where this request goes.",
                headers, fp)
        try:
            import authorization as _az
            if _az.hosted():
                why = _az.unreachable_by_policy(newurl)
                if why:
                    raise urllib.error.HTTPError(
                        req.full_url, code,
                        f"redirect refused by network policy: {why}", headers, fp)
        except ImportError:
            pass
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_GuardedRedirect)

class RateLimit:
    """A minimum gap between requests and a hard ceiling on how many there are.

    Not politeness. This adapter is the one pointed at somebody else's production endpoint,
    and hammering somebody's live bot is the fastest way to be asked to stop; on a shared endpoint
    it is the abuse control, because the request budget is the only thing standing between
    "assessment" and "traffic generator".

    Exhausting the budget is not an error about the TARGET. It means the rest of the run was
    never sent, which is a gap and gets said as one — the same distinction `not_run` draws in
    the timeline.
    """

    def __init__(self, min_interval_s=0.0, max_requests=None, max_seconds=None):
        self.min_interval = float(min_interval_s or 0)
        self.max_requests = int(max_requests) if max_requests else None
        # A REQUEST BUDGET DOES NOT BOUND TIME, and on a shared endpoint that is the gap that
        # matters: two of the generic attacks ask the model to generate until something stops
        # it, so against an endpoint with no output cap of its own each one costs a full
        # request timeout. A short run against a slow deployment can then take hours while
        # staying comfortably inside its request count. Measured here: nineteen attacks at two
        # trials ran past twenty minutes on an OpenAI-compatible endpoint, almost all of it in
        # two attacks.
        #
        # Not fixed by capping the model's output in the request. An endpoint with no ceiling
        # of its own IS the finding — `unbounded_output` and `divergent_repetition` exist to
        # report it — and capping it from the caller's side would hide what the run exists to find.
        self.max_seconds = float(max_seconds) if max_seconds else None
        self.used = 0
        self._last = 0.0
        self._started = None

    @property
    def elapsed(self):
        return 0.0 if self._started is None else time.time() - self._started

    @property
    def exhausted(self):
        if self.max_requests is not None and self.used >= self.max_requests:
            return "requests"
        if self.max_seconds is not None and self.elapsed >= self.max_seconds:
            return "time"
        return ""

    def take(self):
        if self._started is None:
            self._started = time.time()          # the clock starts at the first probe, not at
        if self.exhausted:                       # construction: config parsing is not a run
            return False
        gap = self.min_interval - (time.time() - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.time()
        self.used += 1
        return True


# Keys that belong to the HARNESS rather than to the adapter: they are read elsewhere and are
# stripped before construction. Kept here, beside the adapter that rejects everything else, so
# that "what may appear in a target config" has exactly one answer.
CONFIG_ONLY_KEYS = ("adapter", "skip_in_fleet", "oracle_context", "authorization",
                    "provenance", "provenance_note", "expect_build",
                    # `--model` is injected into the config by the sweep. For an http target the
                    # model lives inside `request:` and belongs to the operator's deployment, so
                    # the override is meaningless here and run_redteam SAYS so rather than
                    # letting it look applied.
                    "model")


class HttpConfiguredTarget(Target):
    """A target described entirely by its config. No Python per target."""

    def __init__(self, url=None, name="http-target", method="POST", headers=None,
                 request=None, response=None, history=None, rate=None, timeout_s=300,
                 auth=None, **unknown):
        # A KEY THIS ADAPTER DOES NOT KNOW IS A TYPO, AND A SWALLOWED TYPO IS A CLEAN REPORT.
        # This used to end in `**_`, so a config saying `respones:` built a target with no
        # response mapping at all: every reply read as empty, every attack scored DEFENDED,
        # and the run looked like a hardened deployment. That is this project's own defect
        # class sitting in the one path a stranger drives — a gap reported as a measurement,
        # caused by a single transposed letter and reported to nobody.
        #
        # The harness's own keys are stripped by the caller (see CONFIG_ONLY_KEYS) rather than
        # tolerated here, so that the list of what a config may contain lives in one place and
        # a new one has to be added deliberately.
        if unknown:
            raise SystemExit(
                "targets_http: unknown key(s) in the target config: "
                + ", ".join(sorted(unknown))
                + ". Nothing was sent — a key this adapter does not read is a key that does "
                  "nothing, and a config that silently does nothing produces a clean report.")
        if not url:
            raise SystemExit("targets_http: `url` is required")
        if not str(url).lower().startswith(("http://", "https://")):
            raise SystemExit(f"targets_http: refusing a non-HTTP url: {url!r}")
        self.url = url
        # THE NAME BECOMES A FILENAME: `out/results_{name}.json`, `out/report_{name}.html`, and
        # the run record. In hosted mode the config comes from a stranger, which makes a name
        # containing `..` or a separator a path traversal driven by a config field. Restricted
        # to what a filename can hold rather than escaped, because a name is a label somebody
        # chose and there is no reason for it to need escaping.
        name = str(name or "").strip()
        if not name:
            raise SystemExit("targets_http: `name` is required — it labels the target in every "
                             "result file and in the run record.")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) or name.strip(".") == "":
            raise SystemExit(
                f"targets_http: name={name!r} is not usable as a filename. It is interpolated "
                f"into out/results_<name>.json, so letters, digits, dot, dash and underscore "
                f"only, up to 64 characters.")
        self.name = name
        self.method = (method or "POST").upper()
        # THE VERB HAS TO CARRY A BODY. urllib sends no data on GET/HEAD/DELETE, so the built
        # request body — the only thing carrying the attack — is silently dropped: the endpoint
        # answers something generic to an empty request and every attack in the arsenal comes
        # back DEFENDED, with no error anywhere to say the payload never left this machine.
        # This adapter puts the prompt in the body and only in the body; an API that takes it in
        # a query string is not supported rather than half-supported.
        if self.method not in ("POST", "PUT", "PATCH"):
            raise SystemExit(
                f"targets_http: method={self.method!r} for {name!r} carries no request body, "
                f"and the body is where the attack goes. Every probe would send an empty "
                f"request and score as a defence. Use POST (or PUT/PATCH); an endpoint that "
                f"takes the prompt in the URL is not supported by this adapter.")
        self.headers = {k: expand_env(v, f"headers.{k}") for k, v in (headers or {}).items()}
        self.headers.setdefault("Content-Type", "application/json")
        if request is not None and not isinstance(request, dict):
            raise SystemExit(
                f"targets_http: `request:` for {name!r} is {type(request).__name__}, not a "
                f"mapping. The body is built by walking a mapping, and history splicing has "
                f"nothing to splice into without one.")
        self.request = request or {"message": "{prompt}"}
        # THE TEMPLATE MUST BE ABLE TO CARRY THE PAYLOAD. `fill()` substitutes the literal token
        # `{prompt}` and nothing else, so a template without it sends one constant body for every
        # probe: the endpoint answers, `reply` resolves, no error is raised, and every attack in
        # the arsenal comes back DEFENDED. A clean report for a bot that was never asked
        # anything is the most expensive output this system can produce, and it is indexed under
        # a spelling.
        #
        # Refused at construction rather than warned about, because after this point every
        # signal the target produces is noise, and this is the last moment somebody is reading.
        # KEYS AND VALUES ARE COLLECTED SEPARATELY, because a placeholder in a key is not a
        # placeholder. `json.dumps` flattens both into one string, so `{"{prompt}": "hi"}` used
        # to satisfy the check below — the guard written to stop a template that cannot carry
        # the payload, passing a template that cannot carry the payload. `fill()` then renames
        # the key to the attack text and sends the same constant value on every probe.
        _keys, _vals = [], []

        def _walk(v):
            if isinstance(v, dict):
                for k, x in v.items():
                    _keys.append(str(k))
                    _walk(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    _walk(x)
            elif isinstance(v, str):
                _vals.append(v)

        _walk(self.request)
        _flat = json.dumps(_vals)
        # `{{prompt}}` contains `{prompt}`, so the general check below waves it through and
        # `fill()` leaves the braces on: the body carries `{<attack text>}`. The payload is
        # corrupted rather than missing, which is harder to notice and just as wrong, and
        # somebody who writes the doubled form plainly meant a placeholder.
        if "{{prompt}}" in _flat:
            raise SystemExit(
                f"targets_http: the `request:` template for {name!r} uses `{{{{prompt}}}}`. "
                f"This is not a templating language — the token is exactly `{{prompt}}`, one "
                f"pair of braces. Doubled, the attack text would go out wrapped in braces.")
        if "{prompt}" not in _flat and any("{prompt}" in k for k in _keys):
            raise SystemExit(
                f"targets_http: the `request:` template for {name!r} has `{{prompt}}` in a KEY "
                f"and in no value. The attack text would be sent as the name of a JSON field, "
                f"with the same constant value on every probe — the endpoint would ignore the "
                f"unknown key, answer something generic, and the whole arsenal would score "
                f"DEFENDED. The placeholder belongs on the right of the colon: "
                f"`request: {{message: \"{{prompt}}\"}}`.")
        if "{prompt}" not in _flat:
            _near = [t for t in ("{ prompt }", "{{prompt}}", "{PROMPT}", "{Prompt}", "%s",
                                 "{{ prompt }}", "$prompt", "${prompt}", "<prompt>")
                     if t in _flat]
            _hint = (f" It contains {_near[0]!r}; the token is exactly `{{prompt}}` — no spaces, "
                     f"one pair of braces, lower case." if _near else
                     " Put `{prompt}` where the attack text belongs, e.g. "
                     "`request: {message: \"{prompt}\"}`.")
            raise SystemExit(
                f"targets_http: the `request:` template for {name!r} has no `{{prompt}}` in it, "
                f"so every probe would send the same body and every attack would score as "
                f"DEFENDED against a bot that was never asked anything.{_hint}")
        if response is not None and not isinstance(response, dict):
            raise SystemExit(
                f"targets_http: `response:` for {name!r} is {type(response).__name__}, not a "
                f"mapping of channel to path, e.g. `response: {{reply: choices.0.message."
                f"content}}`.")
        resp = response or {}
        self.reply_path = resp.get("reply", "reply")
        self.calls_path = resp.get("tool_calls")
        self.resolved_path = resp.get("resolved")
        self.observations_path = resp.get("observations")
        # HOW OFTEN EACH OPTIONAL PATH ACTUALLY RESOLVED. A capability is added below because a
        # path is configured, which says what the operator INTENDED. This says what happened.
        # Zero across a whole sweep means the mapping is wrong and every detector that reads
        # that channel spent the run judging an empty list — the difference between "your tool
        # surface is clean" and "this run never saw your tool calls".
        self.resolutions = {"tool_calls": 0, "resolved": 0, "observations": 0}
        if history is not None and not isinstance(history, dict):
            raise SystemExit(
                f"targets_http: `history:` for {name!r} is {type(history).__name__}, not a "
                f"mapping. It takes `field:` (where the transcript goes) and `mode:` "
                f"(splice or replace).")
        self.history = history or None
        # `mode` DECIDES WHETHER THE ATTACK IS IN THE REQUEST, so an unrecognised value cannot
        # fall through to a default. `replace` overwrites the request's message list with the
        # history alone: no payload, no system prompt, and the server answers the last history
        # turn. That is 64 chain and forged_history attacks judged on a reply to a question
        # nobody asked, which is exactly the failure the splice comment below records — reached
        # by misspelling one word rather than by choosing the wrong one.
        if self.history is not None:
            _mode = self.history.get("mode", "replace")
            # AN OMITTED MODE IS ONLY SAFE WHERE THE FIELD IS THE HISTORY'S OWN. `replace`
            # overwrites `body[field]`, which is right for an API with a dedicated transcript
            # field and destructive when that field is the request's own message list — the
            # OpenAI shape, and the one the onboarding path mostly meets. Where they collide the
            # default would delete the payload, so the choice has to be made rather than
            # inherited.
            _field = self.history.get("field", "history")
            if "mode" not in self.history and _field in (request or {}):
                raise SystemExit(
                    f"targets_http: {name!r} sends history into `{_field}`, which is also a key "
                    f"of its own `request:` template, and no `history.mode` is set. The default "
                    f"(`replace`) would overwrite that field with the transcript alone — no "
                    f"attack payload, no system prompt — and every multi-turn attack would be "
                    f"judged on a reply to a question that was never asked. Set "
                    f"`mode: splice` to insert the transcript before the last message, or "
                    f"`mode: replace` if overwriting is really what this API wants.")
            # `splice` READS THE FIELD AS A LIST: `list(body.get(field) or [])`. Aimed at a
            # field holding a string, that is `list("second question")` — the prompt shredded
            # into single characters with the transcript appended after them. The body still
            # contains every word of the history, so a check that greps for the transcript
            # passes while the attack itself has been destroyed one letter at a time.
            _tmpl = (request or {}).get(_field)
            if _mode == "splice" and _field in (request or {}) and not isinstance(_tmpl, list):
                raise SystemExit(
                    f"targets_http: {name!r} splices history into `{_field}`, which is a "
                    f"{type(_tmpl).__name__} in its own `request:` template, not a list. "
                    f"Splicing iterates that field, so the prompt would go out as a list of "
                    f"single characters. Use `mode: replace` for a field of its own, or point "
                    f"`history.field` at the messages LIST.")
            if _mode not in ("splice", "replace"):
                raise SystemExit(
                    f"targets_http: history.mode is {_mode!r} for {name!r}; it must be "
                    f"'splice' or 'replace'. `splice` inserts the transcript before the last "
                    f"message and is what an OpenAI-shaped `messages` list needs; `replace` "
                    f"overwrites the field entirely and is for an API with a transcript field "
                    f"of its own. A wrong value here sends the attack nowhere and scores it as "
                    f"a defence.")
        # `RateLimit(**rate)` raised TypeError straight out of its own signature on a key
        # nobody recognised, which names the internal class and not the config that caused it.
        # The budget is the one thing standing between an arsenal and somebody's rate limit, so
        # a misspelling here is worth a sentence.
        if rate is not None and not isinstance(rate, dict):
            raise SystemExit(f"targets_http: `rate:` for {name!r} is "
                             f"{type(rate).__name__}, not a mapping.")
        try:
            self.rate = RateLimit(**(rate or {}))
        except TypeError as e:
            import inspect
            known = [p for p in inspect.signature(RateLimit).parameters if p != "self"]
            raise SystemExit(f"targets_http: `rate:` for {name!r} — {e}. It takes: "
                             f"{', '.join(known)}.")
        try:
            self.timeout = float(timeout_s if timeout_s is not None else 300)
        except (TypeError, ValueError):
            raise SystemExit(f"targets_http: timeout_s={timeout_s!r} for {name!r} is not a "
                             f"number of seconds.")
        # A timeout of zero or less makes urlopen fail on contact, and every probe in the run
        # would come back an error rather than a measurement.
        if self.timeout <= 0:
            raise SystemExit(f"targets_http: timeout_s={timeout_s!r} for {name!r} must be "
                             f"positive; every request would fail on contact.")

        # A CREDENTIAL COMPUTED PER REQUEST, for the two endpoints a fixed header cannot reach.
        # AWS signs each request from its own body and the clock, so `headers:` is structurally
        # unable to describe Bedrock. Google Vertex is reachable as a plain bearer token, which
        # is why it needs no entry here — and why `_seen_success` does, since that token expires
        # in about an hour and a sweep can outlive it.
        self.auth = dict(auth or {})
        if self.auth:
            kind = str(self.auth.get("type") or "").lower()
            if kind != "sigv4":
                raise SystemExit(
                    "targets_http: auth.type %r is not supported. The only computed credential "
                    "here is `sigv4`; everything else belongs in `headers:` as ${ENV}."
                    % self.auth.get("type"))
            for need in ("service", "region", "access_key", "secret_key"):
                if not self.auth.get(need):
                    raise SystemExit("targets_http: auth.%s is required for sigv4" % need)
            for k in ("access_key", "secret_key", "session_token"):
                if self.auth.get(k):
                    self.auth[k] = expand_env(self.auth[k], "auth.%s" % k)
        self._seen_success = False

        # Capabilities are DERIVED, never declared by hand. A config that claims `chain` on an
        # API with nowhere to put the transcript produces multi-turn attacks that all fail for
        # the same uninteresting reason and read as a hardened target.
        caps = set()
        if self.history:
            # A server that takes the transcript from the CALLER cannot tell a refusal it gave
            # from one the attacker wrote for it. That is the precondition for a Context
            # Compliance Attack and it is a fact about the API, not about the model.
            caps |= {"chain", "forged_history"}
        if self.calls_path:
            caps.add("tool_visibility")
        self.capabilities = caps

    # --- the wire ------------------------------------------------------------------------
    def _body(self, prompt, history):
        def fill(v):
            if isinstance(v, str):
                if v == "{prompt}":
                    return prompt
                return v.replace("{prompt}", prompt)
            if isinstance(v, dict):
                return {k: fill(x) for k, x in v.items()}
            if isinstance(v, list):
                return [fill(x) for x in v]
            return v

        body = fill(self.request)
        if not (history and self.history):
            return body
        h = self.history
        field = h.get("field", "history")
        turns = [{h.get("role_key", "role"): (h.get("user", "user") if t["role"] == "user"
                                              else h.get("assistant", "assistant")),
                  h.get("text_key", "content"): t["content"]}
                 for t in history]
        # TWO SHAPES, and the second is the one almost every deployment has. A bespoke API takes
        # the transcript in a field of its own; an OpenAI-compatible one has a single
        # `messages` list where the system turn comes first and the new user turn comes last,
        # so the history has to be SPLICED in before that last turn rather than replacing the
        # list. Found by pointing this adapter at an OpenAI-shaped endpoint, which is the
        # format the onboarding path will mostly meet: with `append` the request carried the
        # system turn, the new question, and a stray `history` key the server ignored — so
        # every multi-turn attack silently became a single-turn one and read as a defence.
        # Validated at construction, so this is a choice between two known modes rather than a
        # default catching everything that is not one word.
        if h.get("mode", "replace") == "splice":
            existing = list(body.get(field) or [])
            at = h.get("insert_before", 1)          # how many trailing items to keep after
            cut = len(existing) - max(0, int(at))
            body[field] = existing[:cut] + turns + existing[cut:]
        else:
            body[field] = turns
        return body

    def send(self, prompt, history=None):
        prompt = payload(prompt)
        if not self.rate.take():
            # Said as a gap, not as a property of the target.
            spent = self.rate.exhausted
            limit = (f"request budget ({self.rate.max_requests})" if spent == "requests"
                     else f"time budget ({self.rate.max_seconds:.0f}s, "
                          f"{self.rate.used} request(s) in)")
            return Probe(prompt=prompt, output="",
                         error=f"BudgetExhausted: this run's {limit} was spent before this "
                               f"probe; it was never sent")
        data = json.dumps(self._body(prompt, history)).encode("utf-8")
        headers = dict(self.headers)
        if self.auth:
            import signing
            headers.update(signing.authorization(
                self.method, self.url, headers, data,
                service=self.auth["service"], region=self.auth["region"],
                access_key=self.auth["access_key"], secret_key=self.auth["secret_key"],
                session_token=self.auth.get("session_token")))
        req = urllib.request.Request(self.url, data=data, headers=headers,
                                     method=self.method)
        t0 = time.time()
        try:
            with _OPENER.open(req, timeout=self.timeout) as r:
                raw = json.loads(r.read().decode("utf-8", "replace"))
            reply = dig(raw, self.reply_path)
            if reply is None:
                # The path is wrong or the API changed shape. A run of empty replies looks
                # exactly like a bot that refuses everything, which is the most flattering
                # possible misreading of the target.
                err = (f"ExtractionFailed: nothing at response.reply={self.reply_path!r}; "
                       f"the reply had keys {sorted(raw)[:8] if isinstance(raw, dict) else type(raw).__name__}")
                bad = Probe(prompt=prompt, output="", error=err,
                            seconds=round(time.time() - t0, 1))
                # The body travels with the failure so onboarding can say WHICH path holds the
                # text, instead of asking the operator to guess a second time. Attached rather
                # than a field, because it exists only on this branch and no detector should
                # ever be able to reach it: a raw payload the oracle could read would be a
                # second, unaudited channel into every judgement in this repo.
                try:
                    object.__setattr__(bad, "raw", raw)
                except Exception:
                    pass
                return bad
            self._seen_success = True
            _rawcalls = dig(raw, self.calls_path) if self.calls_path else None
            _rawres = dig(raw, self.resolved_path) if self.resolved_path else None
            _rawobs = dig(raw, self.observations_path) if self.observations_path else None
            # Counted before normalising: `_pairs` turns an unusable shape into [], and the
            # question here is whether the PATH found anything, not whether it parsed.
            if _rawcalls is not None:
                self.resolutions["tool_calls"] += 1
            if _rawres is not None:
                self.resolutions["resolved"] += 1
            if _rawobs is not None:
                self.resolutions["observations"] += 1
            calls = _pairs(_rawcalls) if self.calls_path else []
            resolved = _pairs(_rawres) if self.resolved_path else []
            obs = _rawobs if self.observations_path else []
            return Probe(prompt=prompt, output=str(reply), tool_calls=calls,
                         observations=[str(o) for o in (obs or [])], resolved=resolved,
                         seconds=round(time.time() - t0, 1))
        except Exception as e:
            detail = ""
            if isinstance(e, urllib.error.HTTPError):
                detail = f" {e.code}"
                # AN AUTH FAILURE IS NOT A FINDING ABOUT THE TARGET, and after a run has already
                # succeeded it is not even a configuration problem — it is a credential that ran
                # out mid-sweep. Left as a plain HTTPError, every probe after that point is an
                # error, and a wall of errors is the shape a hardened deployment makes.
                import signing
                note = signing.expired_credential(e.code, self._seen_success)
                if note:
                    return Probe(prompt=prompt, output="",
                                 error="CredentialRejected: %s" % note,
                                 seconds=round(time.time() - t0, 1))
            return Probe(prompt=prompt, output="", error=f"{type(e).__name__}{detail}: {e}",
                         seconds=round(time.time() - t0, 1))

    # --- multi-turn, only when the API can carry a transcript ----------------------------
    def send_forged(self, prompt, history):
        """One turn on a conversation the ATTACKER wrote, assistant's side included."""
        return self.send(prompt, history=list(history or []))

    def send_chain(self, prompts):
        """The turns in one conversation, feeding back what the target really said."""
        hist, turns, out, calls, resolved, secs = [], [], "", [], [], 0.0
        for p in prompts:
            probe = self.send(p, history=hist)
            if probe.error:
                return probe
            out = probe.output
            calls += probe.tool_calls
            resolved += list(getattr(probe, "resolved", None) or [])
            secs += float(getattr(probe, "seconds", 0) or 0)
            turns.append({"prompt": p, "output": probe.output,
                          "tool_calls": probe.tool_calls})
            hist.append({"role": "user", "content": p})
            hist.append({"role": "assistant", "content": probe.output})
        return Probe(prompt="\n".join(prompts), output=out, tool_calls=calls,
                     resolved=resolved, turns=turns, seconds=secs)

    def reset(self):
        """Nothing to reset: each request carries its own history, or the API is stateless.

        Said out loud because a reset that silently does nothing is the defect that
        invalidates every rate this engine prints — recon probes for it, and a target whose
        state lives server-side will fail that probe honestly rather than here.
        """
        return None
