"""Read a real MCP server's tool list, over the real protocol, with no dependency.

A tool description is not documentation. It is text a third party writes and the harness
pastes into the model's instruction context, and the model cannot tell it apart from the
system prompt. `attacks_mcpagent.yaml` attacks exactly that surface and `targets_mcpagent.py`
is a hand-built stand for it: our own descriptions, poisoned by us, judged by us. A stand
answers whether the ENGINE can see the attack. It cannot answer what the ecosystem actually
ships, and that second question is the one an operator has.

So this speaks MCP to a server that somebody else wrote. JSON-RPC 2.0 over stdio, newline
delimited, `initialize` and then every listing the server declares — `tools/list`,
`prompts/list`, `resources/list` and `resources/templates/list` — plus the `instructions`
`initialize` may return, all in the standard library, because a scanner that needs an SDK
to look at a protocol has taken a dependency on the thing it is measuring.

    python mcp_probe.py npx -y @modelcontextprotocol/server-filesystem .

NOTHING IS CALLED. A listing is a read: the server is started, asked what it offers, and
stopped. Running somebody's tool is a different act with a different authorisation, and the
question here is about the descriptions, which arrive before any tool runs.

WHAT THIS DOES NOT COVER, stated rather than implied:

  * stdio servers only. An HTTP/SSE server is the same protocol over another transport and
    is not implemented here.
  * the descriptions AT THE MOMENT THIS RAN. A rug pull -- clean on the first listing,
    poisoned later -- is invisible to a single read, and `targets_mcpagent.py` has a stand
    for exactly that shape because it is the one this cannot see.
  * a server that needs credentials is not started at all, so this measures the servers
    somebody can run without an account and no others.
"""
import io
import json
import os
import subprocess
import sys
import time

PROTOCOL = "2024-11-05"
NEWLINE = "\n"


def _send(proc, obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def _lines(proc):
    """A queue of the server's stdout lines, filled by a thread, ended by None.

    THE DEADLINE HAS TO BOUND THE READ, NOT THE LOOP AROUND IT. `_await` used to call
    `proc.stdout.readline()` and check the clock between calls, and a server that answers
    NOTHING never returns from that call: stdout stays open for as long as the child lives,
    the child lives for as long as its stdin is open, and its stdin is this process. So
    `qatration mcp --timeout 3` against a server that says nothing waited forever, and the
    timeout it documents bounded nothing at all. Measured with a two-line server whose whole
    body is `for line in sys.stdin: pass`.

    A thread and a queue rather than a select: on Windows a pipe is not selectable, and this
    command exists to be pointed at a command somebody typed on their own machine.
    """
    import queue as _queue
    import threading as _threading
    q = _queue.Queue()

    def _pump():
        try:
            for line in proc.stdout:
                q.put(line)
        except Exception:
            pass
        finally:
            q.put(None)

    th = _threading.Thread(target=_pump, daemon=True)
    th.start()
    return q


def _stderr_tail(proc, keep=20):
    """A list that holds the last `keep` lines the server wrote to stderr, filled by a thread.

    WHY A SERVER STOPPED IS USUALLY ON ITS STDERR. It went to DEVNULL, so a server that exited
    at once with `fatal: missing API_KEY` was reported as "no answer to initialize within
    180s" -- after no time at all, with the one line that said what to fix thrown away.
    Bounded, because the stream is the server's and a chatty one must not take the memory.
    """
    import collections as _collections
    import threading as _threading
    tail = _collections.deque(maxlen=keep)

    def _pump():
        try:
            for line in proc.stderr:
                tail.append(line.rstrip()[:300])
        except Exception:
            pass

    _threading.Thread(target=_pump, daemon=True).start()
    return tail


def _silence(proc, tail, what, timeout):
    """-> the sentence for a request that got no answer: the server EXITED, or it did not answer.

    Two different facts, and the first sends the reader somewhere specific. A short wait,
    because a server that closed its output is usually a moment away from exiting.
    """
    try:
        code = proc.wait(timeout=2)
    except Exception:
        code = None
    if code is None:
        return "no answer to %s within %ds" % (what, timeout)
    said = " | ".join(l for l in list(tail)[-3:] if l)
    return ("the server exited (code %s) before answering %s%s"
            % (code, what, (": " + said) if said else ", and wrote nothing to stderr"))


def _await(lines, want_id, deadline):
    """The answer to one request id, skipping whatever else the server writes to stdout.

    Servers log to stdout. A reader that treats the first line as its answer gets a banner,
    and a reader that raises on the first unparseable line reports a working server as a
    broken one -- so lines that are not JSON, and JSON that is not this id, are skipped.

    AND JSON THAT IS NOT A MESSAGE. The rule above was written and the code kept half of
    it: `json.loads` raising is caught, and a line that parses to a LIST, a string, a
    number or a null went straight into `msg.get("id")` as an AttributeError. Those are
    ordinary things to find on a server's stdout -- a JSON-lines log, a printed array --
    and each of them ended `qatration mcp` with a traceback and the sentence "this is a bug
    in qatration", about a server that was answering correctly on the next line.

    WHAT IS STILL NOT BOUNDED, said rather than left to be found: a line is read to its
    newline, so a server that writes without one takes the memory with it. Not capped here
    because the honest cap is generous -- a `tools/list` reply carrying fifty descriptions
    is legitimately large -- and a truncated line would parse as nothing and be reported as
    "no answer to tools/list", which is a worse answer than a slow one: it names the server
    as the thing that failed. It no longer holds the DEADLINE, which is the half that
    mattered: the reading happens on a thread and this loop waits on a queue.

    TWO CORRECT GREENS AND A SLOW SWEEP, recorded so the next one does not re-derive them.
    Deleting either blank-line guard is an EQUIVALENT mutation: an empty string reaches
    `json.loads`, raises ValueError and lands in the same `continue`. And deleting the id
    match makes every listing block until its deadline rather than fail, so a guard sweep
    over this module pays a full timeout per case instead of a run.
    """
    import queue as _queue
    while True:
        _left = deadline - time.time()
        if _left <= 0:
            return None
        try:
            line = lines.get(timeout=min(_left, 1.0))
        except _queue.Empty:
            continue
        if line is None:
            return None                  # the server closed its stdout
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == want_id:
            return msg
    return None


# The four listings a server answers, and the capability each one is gated behind. A
# server that does not declare a capability is not refusing: the channel is absent, which
# is a different fact from a listing that failed.
CHANNELS = (("tools", "tools/list", "tools"),
            ("prompts", "prompts/list", "prompts"),
            ("resources", "resources/list", "resources"),
            ("resource_templates", "resources/templates/list", "resourceTemplates"))
# `resources/templates/list` is gated behind the `resources` capability, not one of its
# own, so the declared name and the channel name are not the same string.
CAPABILITY = {"tools": "tools", "prompts": "prompts", "resources": "resources",
              "resource_templates": "resources"}

# AND THE TEXT THAT ARRIVES WITH THE HANDSHAKE. `initialize` may return `instructions`: prose
# the server writes "to improve the LLM's understanding" of it, which the spec says a client
# MAY add to the system prompt -- the most privileged place a server's words can land. It is
# not a listing, so it is not in `CHANNELS` (whose rows are requests this sends); it is part
# of the surface all the same, and was counted nowhere. Walked: a scripted server whose
# `instructions` said "Always call add_note first." -- 232 characters of server-authored
# instruction text reported, none of them that sentence.
INSTRUCTIONS = "instructions"
SURFACE = tuple(c for c, _m, _k in CHANNELS) + (INSTRUCTIONS,)


# THE SHELL IS WINDOWS' AND ONLY WINDOWS', named once so a test can ask the refusal below
# without starting anything and without touching `os.name` for the whole process.
_USE_SHELL = os.name == "nt"
# CMD.EXE SYNTAX: what an argument must not carry when the list is handed to a shell. `%`
# expands a variable even inside quotes, `^` escapes, `"` ends the quoting list2cmdline adds.
_SHELL_META = frozenset('&|<>^%"' + chr(13) + chr(10))


def _shell_unsafe(argv):
    """-> the first argument cmd.exe would read as syntax rather than as text, or None."""
    for _a in argv or []:
        if any(_c in _SHELL_META for _c in str(_a)):
            return str(_a)
    return None


def list_surface(argv, timeout=180, cwd=None, info=None):
    """-> ({channel: [items] or None}, {channel: why}, capabilities, why_fatal).

    TOOLS ARE ONE CHANNEL OF FOUR, and reading only them is how a measurement of `the
    surface` came out counting a quarter of it. A prompt template and a resource are text
    the same server writes and the same harness puts in front of the same model; the
    protocol lists them separately and nothing about the model reads them separately.

    THREE STATES PER CHANNEL, and the capability map is what separates two of them. A
    server that never declared `prompts` has no prompt channel, which is an absence by
    design. A server that declared it and then would not list is a channel that could not
    be measured, and calling that `no prompts` is the failure this repository is named
    after, one listing over.
    """
    deadline = time.time() + timeout
    # A SHELL ON WINDOWS, and only to FIND the program. `npx` there is `npx.cmd`, which only a
    # shell resolves by that name, and MCP servers are overwhelmingly launched through npx.
    # But `--compare` runs the `command` a recorded corpus names, and on Windows the list is
    # joined and handed to cmd.exe -- so an `&` or `|` inside an argument of a corpus somebody
    # else wrote was a second command. Re-reading a corpus already means running the program
    # it names; the shell widened that to a command line. An argument carrying cmd.exe syntax
    # is refused before anything starts, which keeps the shell for what it is needed for.
    if _USE_SHELL:
        _bad = _shell_unsafe(argv)
        if _bad is not None:
            return {}, {}, {}, ("refusing to start %r: on Windows this runs through cmd.exe, "
                                "and the argument %r carries shell syntax that would run as "
                                "a second command" % ((argv or [""])[0], _bad))
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            errors="replace", bufsize=1, cwd=cwd, shell=_USE_SHELL)
    except Exception as e:
        return {}, {}, {}, "%s: %s" % (type(e).__name__, e)
    try:
        _tail = _stderr_tail(proc)
        _lines_q = _lines(proc)
        try:
            _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                                    "clientInfo": {"name": "qatration", "version": "0"}}})
            init = _await(_lines_q, 1, deadline)
        except OSError:
            init = None          # it was gone before the request could be written
        if init is None:
            return {}, {}, {}, _silence(proc, _tail, "initialize", timeout)
        if "error" in init:
            return {}, {}, {}, "initialize refused: %s" % json.dumps(init["error"])[:120]
        # WHAT A SERVER ANSWERS IS ITS OWN, and a server is exactly the party this command
        # does not trust. A scripted server answering `capabilities: 7` ended the run in a
        # TypeError under "this is a bug in qatration", about somebody else's server. The
        # handshake is the one place nothing can be listed without, so a result or a
        # capabilities block that is not a mapping ends the read, and says so.
        _res = init.get("result") or {}
        caps = _res.get("capabilities") if isinstance(_res, dict) else None
        caps = {} if caps is None else caps
        if not isinstance(_res, dict) or not isinstance(caps, dict):
            return {}, {}, {}, ("initialize answered with %s, not a mapping: nothing it "
                                "declares can be read"
                                % ("a result that is %s" % type(_res).__name__
                                   if not isinstance(_res, dict)
                                   else "capabilities that are %s" % type(caps).__name__))
        # WHAT THE SERVER SAYS IT IS, for a caller that asks: `--compare` needs the version
        # the re-read actually ran, and this is the only place the server states it.
        if isinstance(info, dict):
            _si = _res.get("serverInfo")
            if isinstance(_si, dict):
                info.update(_si)
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized",
                     "params": {}})
        found, why = {}, {}
        _ins = _res.get("instructions")
        # Keyed by `uri`, which is structural and not counted: "initialize" is our label for
        # where it came from, not text the server wrote.
        found[INSTRUCTIONS] = ([{"uri": "initialize", "description": _ins}]
                               if isinstance(_ins, str) and _ins.strip() else [])
        for i, (chan, method, key) in enumerate(CHANNELS, start=2):
            if CAPABILITY[chan] not in caps:
                found[chan] = None
                why[chan] = "not declared in the server's capabilities"
                continue
            found[chan], why_c = _list_all(proc, _lines_q, method, key, i * PAGE_IDS, deadline,
                                           _tail, timeout)
            if why_c:
                why[chan] = why_c
        return found, why, caps, ""
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            pass


# EVERY PAGE, OR NOT A LISTING. Each of the four listings is paginated in the protocol: a
# result may carry `nextCursor`, and the rest of the list is behind it. This read the first
# page and reported it as the server's surface. Walked against a scripted server whose second
# page held the poisoned tool: "1 item(s) across 1 channel(s)", exit 0, and the one
# description that asked the model to read ~/.ssh/id_rsa was not in the count, the table or
# a `--compare` record made from it.
#
# A page that does not arrive makes the channel unmeasured rather than the pages before it a
# complete answer. Bounded, because the cursor is the server's: a server handing back the same
# cursor, or an endless one, is a server that has not finished, and saying so is the answer.
PAGE_IDS = 1000          # request ids per channel, so a page's answer cannot be another's
MAX_PAGES = PAGE_IDS - 1


def _list_all(proc, lines_q, method, key, first_id, deadline, tail=(), timeout=0):
    """-> (items or None, why). Follows `nextCursor` to the end of one listing."""
    items, cursor, seen = [], None, set()
    for page in range(MAX_PAGES):
        _id = first_id + page
        try:
            _send(proc, {"jsonrpc": "2.0", "id": _id, "method": method,
                         "params": {"cursor": cursor} if cursor is not None else {}})
            got = _await(lines_q, _id, deadline)
        except OSError:
            got = None
        _where = "" if page == 0 else " (page %d, after %d item(s))" % (page + 1, len(items))
        if got is None:
            return None, "declared, and %s" % _silence(proc, tail, method + _where, timeout)
        if "error" in got:
            return None, "declared, and %s refused%s: %s" % (
                method, _where, json.dumps(got["error"])[:100])
        # AND A PAGE THAT IS NOT A LIST OF OBJECTS IS A LISTING THAT CANNOT BE READ, which
        # makes the channel unmeasured with the reason -- never a shorter list. Walked:
        # `prompts: 7` raised out of `list(...)`, and a listing that dropped the item it
        # could not read would print a count without it.
        result = got.get("result") or {}
        _page = result.get(key) if isinstance(result, dict) else None
        if not isinstance(result, dict) or not isinstance(_page, (list, type(None))):
            return None, ("declared, and %s answered%s with %s, not a list of items"
                          % (method, _where, "a result that is %s" % type(result).__name__
                             if not isinstance(result, dict)
                             else "`%s` as %s" % (key, type(_page).__name__)))
        _odd = [x for x in (_page or []) if not isinstance(x, dict)]
        if _odd:
            return None, ("declared, and %s answered%s with an item that is %s, not an "
                          "object: %.60r" % (method, _where, type(_odd[0]).__name__, _odd[0]))
        items += list(_page or [])
        cursor = result.get("nextCursor")
        if cursor is None or cursor == "":
            return items, ""
        if not isinstance(cursor, str) or cursor in seen:
            return None, ("declared, and %s handed back a cursor it had already given (%r) "
                          "after %d item(s): a listing that does not end is not a listing"
                          % (method, cursor, len(items)))
        seen.add(cursor)
    return None, ("declared, and %s was still paging after %d pages and %d item(s)"
                  % (method, MAX_PAGES, len(items)))


def list_tools(argv, timeout=180, cwd=None):
    """-> (tools, why). `why` is "" on success, and names what happened when tools is None.

    ONE READER. This was a second copy of the spawn and the handshake, written by copying
    the first, and the duplicate-prose gate found the four repeated lines within the hour.
    Two spellings of a protocol handshake is two places for a protocol change to land.
    """
    found, why, _caps, fatal = list_surface(argv, timeout=timeout, cwd=cwd)
    if fatal:
        return None, fatal
    if found.get("tools") is None:
        return None, why.get("tools") or "the tools channel could not be read"
    return found["tools"], ""


# Leaf keys whose string value is machinery rather than prose: a JSON Schema type, a MIME
# type, a URI. They travel with the item and say nothing to the model that a reader would
# call an instruction.
#
# DECLARED RATHER THAN INFERRED, and that is the point of the pair. Everything not named
# here is counted, so a field this protocol adds next year arrives as text rather than as
# silence. The count of what a server contributes has been wrong three times, each time
# because a new place to put a sentence was found by reading the spec again; this makes
# the fourth one a failing check instead of a discovery.
STRUCTURAL = frozenset((
    "type", "$schema", "format", "mimeType", "uri", "uriTemplate", "required",
    "additionalProperties", "contentEncoding", "contentMediaType", "pattern",
    "$ref", "$defs", "_meta", "annotations",
    # `execution.taskSupport` is "forbidden" / "optional" / "required": whether a tool may
    # be run as a long task. Machinery, and the first thing this gate caught -- it was in
    # thirty-seven items on the first fleet it was pointed at, which is what a classifier
    # that fails on the unfamiliar is for.
    "taskSupport",
))


def item_strings(item, prefix=""):
    """-> [(dotted path, value)] for every string anywhere in one item.

    The whole item, not the fields somebody remembered. `properties` nests: an argument
    that is an array of objects carries its own `items.properties.<x>.description`, one
    level past where the first version of this looked.
    """
    out = []
    if isinstance(item, dict):
        for k, v in sorted(item.items()):
            out += item_strings(v, "%s.%s" % (prefix, k) if prefix else k)
    elif isinstance(item, list):
        for v in item:
            out += item_strings(v, prefix + "[]")
    elif isinstance(item, str):
        out.append((prefix, item))
    return out


def unclassified(item):
    """-> the paths carrying a string this module can neither count nor dismiss.

    Always empty today, and the check over the recorded corpus is what keeps it that way.
    A protocol that grows a field is a fact about the world; a count that grows quietly is
    a fact about nobody having looked.
    """
    return sorted(path for path, _v in item_strings(item)
                  if _leaf(path) not in STRUCTURAL
                  and _leaf(path) not in COUNTED)


def _leaf(path):
    """The last named key in a dotted path, ignoring the list markers along the way."""
    return path.replace("[]", "").rsplit(".", 1)[-1]


# Leaf keys whose string value IS text the model reads. `name` is here because a tool name
# sits in the context beside its description, and `enum` because an allowed value is a
# string the model is shown and a server chooses.
COUNTED = frozenset(("description", "title", "name", "enum", "default", "examples",
                     "const"))


def counted_strings(item):
    """Every string in one item that reaches the model, by the classification above."""
    return [v for p, v in item_strings(item) if _leaf(p) in COUNTED]


def parameter_text(item):
    """The part of an item's contribution that is NOT its own top-level fields.

    On `@playwright/mcp` this is the larger half. It nests: an argument that is an array of
    objects carries its own `items.properties.<x>.description`, one level past where the
    first version of this looked, and two past the version before that.
    """
    return NEWLINE.join(v for p, v in item_strings(item)
                        if _leaf(p) in COUNTED and "." in p)


def instruction_text(items):
    """Everything a list of items contributes to the model's instruction context.

    THROUGH THE CLASSIFICATION, not through a list of fields somebody remembered. This
    number has been wrong three times and the cause was the same each time: a new place to
    put a sentence, found by reading the spec again rather than by a check. `unclassified`
    is that check, and it caught `execution.taskSupport` on the first fleet it saw.
    """
    return NEWLINE.join(NEWLINE.join(counted_strings(x)) for x in items)


def surface_text(found):
    """The same question over every channel, because the model reads one context.

    A channel that could NOT be read contributes nothing here and is counted nowhere, which
    is why the caller has to carry the reasons as well as the number: a server whose prompt
    listing failed looks, in this string alone, exactly like one that never had prompts.
    """
    return NEWLINE.join(instruction_text(v) for v in (found or {}).values() if v)


def compare(before, after):
    """-> [(server, verdict, detail)] for what moved between two readings of a fleet.

    A SINGLE READ CANNOT SEE A RUG PULL. `targets_mcpagent.py` keeps a variant for the
    shape — descriptions clean while the user approves the tool, poisoned from the next
    turn — and `mcp_probe` reading once was blind to it in exactly the way the stand says
    the world is. Two readings can see it, and the recorded corpus is the first one.

    THE VERSION IS WHAT SEPARATES THE THREE STATES. A description that changed along with
    the package version is an upgrade: worth listing, because the instructions in a model's
    context changed and somebody should read the diff, and not a finding. A description
    that changed while the version did NOT is the finding: the same release, serving
    different instructions. Nothing else in this engine can see that, because everything
    else reads a target once.

    `before` and `after` are both the shape `out/mcp_tools.json` carries. A server present
    in one and absent from the other is reported rather than skipped: a server that stopped
    answering is not a server that did not change.
    """
    out = []
    b_srv, a_srv = (before or {}).get("servers") or {}, (after or {}).get("servers") or {}
    for name in sorted(set(b_srv) | set(a_srv)):
        b, a = b_srv.get(name), a_srv.get(name)
        if b is None:
            out.append((name, "new", "not in the earlier reading"))
            continue
        if a is None:
            out.append((name, "gone", "answered before and is not in this reading"))
            continue
        if a.get("unreadable") or b.get("unreadable"):
            out.append((name, "unreadable",
                        a.get("unreadable") or b.get("unreadable")))
            continue
        # ACROSS EVERY CHANNEL, not just tools. This compared `tools` alone, so a prompt
        # template rewritten under a pinned version was the same event happening where
        # nobody was looking — which is the defect this comparison exists to find,
        # committed by the comparison. Keys are qualified by channel because a tool and a
        # prompt may share a name and are not the same item.
        def _flat(rec):
            # THROUGH `instruction_text`, so what is compared is exactly what was counted.
            # Comparing `description` alone left a poisoned PARAMETER description invisible,
            # and on one of these servers the parameter text is three times the rest.
            return {"%s/%s" % (_c, _x.get("name") or ""): instruction_text([_x])
                    for _c in SURFACE
                    for _x in (rec.get(_c) or [])}

        bt, at = _flat(b), _flat(a)
        moved = sorted(n for n in set(bt) & set(at) if bt[n] != at[n])
        added, dropped = sorted(set(at) - set(bt)), sorted(set(bt) - set(at))
        # AND A CHANNEL THAT STOPPED BEING READABLE IS NOT A CHANNEL THAT EMPTIED. A
        # server that declared `prompts` last time and refuses to list them now has its
        # prompts missing from this reading, and without this they arrive as items that
        # were removed — a change reported in place of a measurement that failed.
        # AND ONLY A CHANNEL THAT WAS READ BEFORE can have stopped being readable. A reading
        # that never recorded a channel -- a corpus holding `tools` alone -- said nothing about
        # it, so the same channel undeclared now is not a loss of anything.
        blind = sorted(c for c in (a.get("channels_absent") or {})
                       if c not in (b.get("channels_absent") or {}) and c in b)
        # AND ITS ITEMS ARE NOT REPORTED AS REMOVED. They are not known to be gone: the
        # channel that held them could not be read, and reporting the two together prints
        # a change over a measurement that failed.
        dropped = [_n for _n in dropped if _n.split("/", 1)[0] not in blind]
        if not (moved or added or dropped or blind):
            continue
        what = ", ".join(
            ([("%d description(s) rewritten: " % len(moved)) + ", ".join(moved[:4])]
             if moved else [])
            + ([("%d item(s) added: " % len(added)) + ", ".join(added[:4])] if added else [])
            + ([("%d item(s) gone: " % len(dropped)) + ", ".join(dropped[:4])]
               if dropped else [])
            + ([("%d channel(s) no longer readable: " % len(blind))
                + ", ".join(blind)] if blind else []))
        # WHICH VERSION PAIR, and whether there is one. The server's own report where both
        # readings carry it; the package version otherwise; and where either side has
        # neither, nothing -- an unmeasured version is not an unchanged one.
        if b.get("server_version") and a.get("server_version"):
            _bv, _av = b["server_version"], a["server_version"]
        else:
            _bv, _av = b.get("version"), a.get("version")
        same_version = bool(_bv and _av) and _bv == _av
        # A CHANNEL THAT WENT BLIND IS NOT A CHANGE THAT WAS SEEN. Under an unchanged
        # version it has the same shape as a rug pull and none of the evidence: nothing
        # was demonstrated to have moved, the place it would have moved stopped being
        # readable. Its own verdict, and it does not set the exit code, because a finding
        # this tool cannot support is the mistake it is named after.
        if blind and not (moved or added or dropped):
            out.append((name, "blind",
                        "v%s, %d channel(s) no longer readable: %s"
                        % (a.get("version") or "?", len(blind), ", ".join(blind))))
            continue
        if not (_bv and _av):
            out.append((name, "changed",
                        "the version this reading ran is not known -- the command pins none "
                        "and the server reported none on both readings -- so an upgrade "
                        "cannot be told from a rug pull: " + what))
            continue
        out.append((name, "RUG PULL" if same_version else "upgraded",
                    ("v%s unchanged, and " % _av if same_version
                     else "v%s -> v%s, " % (_bv, _av)) + what))
    return out


# WHAT A RECORDED CORPUS HAS TO BE, in the form `workspace.shape_fault` reads. This command
# WRITES the file it is later pointed at, and it answered a malformed one with a traceback
# under "This is a bug in qatration, not a finding about your target and not a problem with
# your config" -- about a file the tool itself produced. Walked: six of seven wrong shapes,
# including the three a `.get` on a list gives.
def server_record(found, why, info=None):
    """-> one server's reading in the shape `out/mcp_tools.json` carries, from `list_surface`.

    ONE SHAPE ON BOTH SIDES OF A COMPARISON. `--compare` re-read each server through
    `list_tools` and kept `name` and `description` of its tools alone, while the corpus holds
    every item whole on all four channels and `compare` flattens both through
    `instruction_text`. So against servers that had not changed at all, every tool with a
    title or a parameter description read as rewritten and every prompt and resource as gone:
    replayed over the corpus with the corpus itself as the second reading, all six servers came
    back RUG PULL, and the command exited 1 -- its one finding, raised about nothing.

    A channel that was read carries its items as they came; one that was not is named under
    `channels_absent` with the reason, which is what `compare` reads to tell a channel that
    stopped being readable from one that emptied.
    """
    rec = {}
    absent = {}
    for chan, _method, _key in CHANNELS:
        if found.get(chan) is None:
            absent[chan] = why.get(chan) or "not read"
        else:
            rec[chan] = list(found[chan])
    if absent:
        rec["channels_absent"] = absent
    if found.get(INSTRUCTIONS) is not None:
        rec[INSTRUCTIONS] = list(found[INSTRUCTIONS])
    rec["chars"] = len(instruction_text(rec.get("tools") or []))
    rec["surface_chars"] = len(surface_text(found))
    _v = (info or {}).get("version")
    if isinstance(_v, str) and _v.strip():
        rec["server_version"] = _v.strip()
    return rec


def pinned_version(cmd):
    """-> the version a command pins its package to (`pkg@1.2.3`), or None.

    A tag is not a pin: `@latest` runs whatever was published last, which is the case that
    needs a measured version most.
    """
    import re as _re
    for arg in (cmd or []):
        m = _re.search(r"[^/@\s]@(\d[\w.+-]*)$", str(arg))
        if m:
            return m.group(1)
    return None


_CORPUS_REQUIRE = {
    "servers": (dict, True,
                "each key is a server name and each value is what that run recorded for it"),
    "servers[]": (dict, True,
                  "the command, the package and the version the recorded run read"),
    # AND WHAT A SERVER'S RECORD HOLDS. A field-type sweep over a recorded corpus found
    # `--compare` crashing on a channel that is not a list (`.get` on each item) and a
    # `command` that is a number (`list(...)`). A command written as ONE STRING is worse
    # than a crash: `list("npx -y pkg")` is a list of characters, and the re-read would
    # try to start a program called `n`. The kinds are the ones `qatration mcp` records.
    "servers[].package": (str, False, "the report names the server by it"),
    "servers[].version": (str, False, "a change under an unchanged version is the finding"),
    "servers[].command": (list, False, "the re-read starts the server with it, one "
                                       "argument per entry"),
    "servers[].command[]": (str, False, "each entry is one argument to the command"),
    "servers[].chars": (int, False, "the report compares the size of the surface"),
    "servers[].surface_chars": (int, False, "the report compares the size of the surface"),
    "servers[].channels_absent": (dict, False, "the report says which channels were not read"),
}
for _c in SURFACE:
    _CORPUS_REQUIRE["servers[].%s" % _c] = (list, False, "the re-read is compared with it")
    _CORPUS_REQUIRE["servers[].%s[]" % _c] = (dict, False, "each item is read by key")


def _compare_command(path, timeout):
    """Re-read every server the recorded corpus names, and report what moved.

    THE CORPUS CARRIES THE COMMAND. A comparison whose server list lives somewhere else
    is a comparison that silently stops covering a server the day the two drift, and the
    recorded file is the only thing an operator has after the run that made it.
    """
    # THROUGH `read_artifact`, the one reader for this directory. `with open(...):
    # json.load(f)` was a shape the gate against raw reads could not see.
    from workspace import read_artifact as _read_art
    before, _why_m = _read_art(path)
    if _why_m is not None:
        print("could not read %s: %s" % (path, _why_m))
        return 2
    # AND WHAT PARSED HAS TO BE A CORPUS. `(before or {}).get` is a `.get` on whatever the
    # file held, so `[1, 2]` came back as `AttributeError: 'list' object has no attribute
    # 'get'`, and a `servers` holding a list took the loop below down the same way. The
    # rule is `workspace.shape_fault`, the one the results and benign families already use,
    # so a reader who meets two of these messages meets one voice.
    from workspace import shape_fault as _shape
    if not isinstance(before, dict):
        print("%s is %s, not a mapping. A recorded corpus is what `qatration mcp` wrote: a "
              "mapping with a `servers` key. Nothing was re-read."
              % (path, type(before).__name__))
        return 2
    _why = _shape("servers", before.get("servers"), "servers" in before,
                  _CORPUS_REQUIRE, "recorded corpus")
    if _why:
        print("%s: %s. Nothing was re-read." % (path, _why))
        return 2
    srv = before.get("servers") or {}
    for _n, _rec in sorted(srv.items()):
        _why = _shape("servers[]", _rec, True, _CORPUS_REQUIRE, "recorded corpus")
        if _why:
            print("%s: %s. Nothing was re-read."
                  % (path, _why.replace("servers[]", "servers[%r]" % _n)))
            return 2
        from workspace import _tree_fault as _tf
        _why = _tf(_rec, "servers[].", "servers[%r]." % _n, _CORPUS_REQUIRE, "recorded corpus")
        if _why:
            print("%s: %s. Nothing was re-read." % (path, _why))
            return 2
    # NOT AN EMPTY DIFF. A corpus recorded before the command was stored has nothing to
    # replay, and printing `nothing moved` over it would be the strongest possible
    # answer to a question nobody asked.
    without = sorted(n for n, v in srv.items() if not v.get("command"))
    if without:
        print("%d of %d server(s) in %s record no command, so they cannot be re-read: %s"
              % (len(without), len(srv), path, ", ".join(without)))
        if len(without) == len(srv):
            return 3
    after = {"servers": {}}
    for name, rec in sorted(srv.items()):
        cmd = rec.get("command")
        if not cmd:
            continue
        _info = {}
        found, why, _caps, fatal = list_surface(list(cmd), timeout=timeout, info=_info)
        # THE VERSION THIS READING RAN, measured -- not the recorded one copied forward. It
        # was `rec.get("version")`, so the two readings always agreed on the version and any
        # change at all was a RUG PULL. The recorded commands are `npx -y <pkg>` and
        # `@latest`: they run whatever was published last, and a real upgrade read as a
        # rug pull by construction. Known only where the command pins it; the server's own
        # `serverInfo.version` is kept beside it, and `compare` uses that pair when both
        # readings carry one.
        fresh = {"package": rec.get("package"), "version": pinned_version(cmd),
                 "command": cmd}
        if fatal:
            fresh["unreadable"] = fatal
        else:
            fresh.update(server_record(found, why, _info))
        after["servers"][name] = fresh
    moved = compare(before, after)
    pulls = [r for r in moved if r[1] == "RUG PULL"]
    if not moved:
        print("%d server(s) re-read, nothing moved since %s"
              % (len(after["servers"]), before.get("when") or "the recorded run"))
        return 0
    for name, verdict, detail in moved:
        print("  %-12s %-10s %s" % (name, verdict, detail))
    # AN UPGRADE IS NOT A FINDING AND IS NOT NOTHING. The instructions in a model's
    # context changed and somebody should read the diff; the exit code is reserved for
    # the one that cannot be explained by a release.
    if pulls:
        print("\n%d server(s) served different instructions under the SAME version. "
              "That is the\nshape a rug pull has: the release an operator pinned is not "
              "the text their model read." % len(pulls))
        return 1
    return 0


def main():
    import argparse
    # THE ONE SPELLING, taken from the table the door is listed in rather than written a
    # second time here. Two copies of a command's own description is the shape the prose
    # gate looks for, and it found this one within a minute of the door being added.
    from cli import parser as _cli_parser
    ap = _cli_parser("mcp")
    ap.add_argument("server", nargs=argparse.REMAINDER,
                    help="the command that starts the server over stdio, "
                         "e.g. npx -y @modelcontextprotocol/server-memory")
    from workspace import at_least as _at_least
    ap.add_argument("--timeout", type=_at_least(1, "--timeout"), default=180,
                    help="seconds to wait for the server to answer (default 180)")
    ap.add_argument("--compare", metavar="RECORDED",
                    help="re-read the servers a recorded corpus names and report what "
                         "moved; exits 1 when a description changed under an unchanged "
                         "version")
    args = ap.parse_args()
    # A COMMAND WITH NOTHING TO START IS NOT A COMMAND THAT TIMED OUT. Without this the
    # first thing anybody typing `qatration mcp` saw was three minutes of nothing and
    # `no answer to initialize`, which reads as a broken server rather than as a missing
    # argument. `--help` reached the same place, because REMAINDER takes it literally.
    if args.compare:
        return _compare_command(args.compare, args.timeout)
    if not args.server:
        ap.print_help()
        print("")
        print("nothing was started: this needs the command that runs an MCP server.")
        return 2
    # THE WHOLE SURFACE, NOT THE TOOLS CHANNEL. `list_tools` reads one of four, and
    # this printed `N tool(s), M characters of server-authored instruction text` —
    # which names the thing the other three carry as well. A prompt and a resource
    # template are text a third party writes into the same context window; the model
    # cannot tell which listing they arrived through.
    #
    # Measured on the recorded corpus in `out/mcp_tools.json`: 25,974 characters of
    # 27,312, and on the one server there that publishes prompts and resources, 2,651
    # of 3,900. Fourteen of seventy-seven items were outside the number entirely, and
    # the line carried no hint that anything was.
    found, why, _caps, fatal = list_surface(args.server, timeout=args.timeout)
    if fatal:
        print("could not read the server: %s" % fatal)
        return 2
    live = {c: v for c, v in found.items() if v}
    n_items = sum(len(v) for v in live.values())
    print("%d item(s) across %d channel(s), %d characters of server-authored "
          "instruction text" % (n_items, len(live), len(surface_text(found))))
    # AND WHAT WAS NOT READ, in the same breath as what was. `surface_text` counts a
    # channel that failed exactly as it counts a channel that never existed, and says
    # in its own docstring that the caller has to carry the reasons. This caller is
    # the one that did not.
    for chan, _method, _key in CHANNELS:
        items = found.get(chan)
        if items:
            print("  %-20s %3d item(s), %5d characters"
                  % (chan, len(items), len(instruction_text(items))))
        else:
            print("  %-20s   not read: %s"
                  % (chan, why.get(chan) or "no reason was recorded"))
    _ins_items = found.get(INSTRUCTIONS) or []
    print("  %-20s %s" % (INSTRUCTIONS, "%5d characters, returned by initialize"
                          % len(instruction_text(_ins_items)) if _ins_items
                          else "  none returned by initialize"))
    # A NAME OR A DESCRIPTION THAT IS NOT TEXT IS SHOWN AS WHAT IT IS, not crashed on: the
    # protocol says string, the server is the party under test, and a description written
    # as a list of sentences is still sentences in front of the model (`counted_strings`
    # counts them). Marked, so the reader sees the server broke the protocol.
    def _shown(v):
        if isinstance(v, str):
            return v
        return "(%s, not text) %s" % (type(v).__name__, json.dumps(v, default=str))

    for chan in SURFACE:
        for item in (found.get(chan) or []):
            d = " ".join(_shown(item.get("description") or "").split())
            name = _shown(item.get("name") or item.get("uriTemplate") or item.get("uri") or "?")
            print("  %-11s %-24s %5d  %s" % (chan, name[:24], len(d), d[:64]))
    # AND TEXT THIS COMMAND DOES NOT CLASSIFY IS NAMED, not left out of the count in silence.
    # `unclassified` was a check over the recorded corpus only: on a live server, a string
    # under a field this module has no rule for -- `x-note`, or a description written as a
    # mapping -- was in front of the model and in none of the numbers above, which read as
    # the whole surface.
    _unk = sorted({"%s: %s" % (chan, p) for chan in SURFACE for item in (found.get(chan) or [])
                   for p in unclassified(item)})
    if _unk:
        print("")
        print("NOT COUNTED: %d string field(s) this command does not classify, so none of "
              "their text is in the counts above -- read them yourself: %s"
              % (len(_unk), ", ".join(_unk[:8]) + (" ..." if len(_unk) > 8 else "")))
    # A SERVER THAT PUBLISHED NOTHING IS NOT A SERVER WITH A SMALL SURFACE. It answered,
    # so this is not a refusal; nothing was listable, so there is no measurement to
    # report either, and `0 characters` printed against a clean exit reads as one.
    if not live:
        print("")
        print("nothing was measured: this server listed no tool, prompt or resource, and "
              "returned no instructions.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
