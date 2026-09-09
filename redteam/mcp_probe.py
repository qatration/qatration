"""Read a real MCP server's tool list, over the real protocol, with no dependency.

A tool description is not documentation. It is text a third party writes and the harness
pastes into the model's instruction context, and the model cannot tell it apart from the
system prompt. `attacks_mcpagent.yaml` attacks exactly that surface and `targets_mcpagent.py`
is a hand-built stand for it: our own descriptions, poisoned by us, judged by us. A stand
answers whether the ENGINE can see the attack. It cannot answer what the ecosystem actually
ships, and that second question is the one an operator has.

So this speaks MCP to a server that somebody else wrote. JSON-RPC 2.0 over stdio, newline
delimited, `initialize` then `tools/list`, in the standard library, because a scanner that
needs an SDK to look at a protocol has taken a dependency on the thing it is measuring.

    python mcp_probe.py npx -y @modelcontextprotocol/server-filesystem .

NOTHING IS CALLED. `tools/list` is a read: the server is started, asked what it offers, and
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


def _await(proc, want_id, deadline):
    """The answer to one request id, skipping whatever else the server writes to stdout.

    Servers log to stdout. A reader that treats the first line as its answer gets a banner,
    and a reader that raises on the first unparseable line reports a working server as a
    broken one -- so lines that are not JSON, and JSON that is not this id, are skipped.

    TWO CORRECT GREENS AND A SLOW SWEEP, recorded so the next one does not re-derive them.
    Deleting either blank-line guard is an EQUIVALENT mutation: an empty string reaches
    `json.loads`, raises ValueError and lands in the same `continue`. And deleting the id
    match makes every listing block until its deadline rather than fail, so a guard sweep
    over this module pays a full timeout per case instead of a run.
    """
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("id") == want_id:
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


def list_surface(argv, timeout=180, cwd=None):
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
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            errors="replace", bufsize=1, cwd=cwd, shell=(os.name == "nt"))
    except Exception as e:
        return {}, {}, {}, "%s: %s" % (type(e).__name__, e)
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                                "clientInfo": {"name": "qatration", "version": "0"}}})
        init = _await(proc, 1, deadline)
        if init is None:
            return {}, {}, {}, "no answer to initialize within %ds" % timeout
        if "error" in init:
            return {}, {}, {}, "initialize refused: %s" % json.dumps(init["error"])[:120]
        caps = ((init.get("result") or {}).get("capabilities") or {})
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized",
                     "params": {}})
        found, why = {}, {}
        for i, (chan, method, key) in enumerate(CHANNELS, start=2):
            if CAPABILITY[chan] not in caps:
                found[chan] = None
                why[chan] = "not declared in the server's capabilities"
                continue
            _send(proc, {"jsonrpc": "2.0", "id": i, "method": method, "params": {}})
            got = _await(proc, i, deadline)
            if got is None:
                found[chan] = None
                why[chan] = "declared, and no answer to %s" % method
            elif "error" in got:
                found[chan] = None
                why[chan] = "declared, and %s refused: %s" % (
                    method, json.dumps(got["error"])[:100])
            else:
                found[chan] = list((got.get("result") or {}).get(key) or [])
        return found, why, caps, ""
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            pass


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
                    for _c, _m, _k in CHANNELS
                    for _x in (rec.get(_c) or [])}

        bt, at = _flat(b), _flat(a)
        moved = sorted(n for n in set(bt) & set(at) if bt[n] != at[n])
        added, dropped = sorted(set(at) - set(bt)), sorted(set(bt) - set(at))
        # AND A CHANNEL THAT STOPPED BEING READABLE IS NOT A CHANNEL THAT EMPTIED. A
        # server that declared `prompts` last time and refuses to list them now has its
        # prompts missing from this reading, and without this they arrive as items that
        # were removed — a change reported in place of a measurement that failed.
        blind = sorted(set(a.get("channels_absent") or {})
                       - set(b.get("channels_absent") or {}))
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
        same_version = (b.get("version") or "?") == (a.get("version") or "??")
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
        out.append((name, "RUG PULL" if same_version else "upgraded",
                    ("v%s unchanged, and " % (a.get("version") or "?") if same_version
                     else "v%s -> v%s, " % (b.get("version"), a.get("version"))) + what))
    return out


def _compare_command(path, timeout):
    """Re-read every server the recorded corpus names, and report what moved.

    THE CORPUS CARRIES THE COMMAND. A comparison whose server list lives somewhere else
    is a comparison that silently stops covering a server the day the two drift, and the
    recorded file is the only thing an operator has after the run that made it.
    """
    try:
        before = json.load(io.open(path, encoding="utf-8"))
    except Exception as e:
        print("could not read %s: %s: %s" % (path, type(e).__name__, e))
        return 2
    srv = (before or {}).get("servers") or {}
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
        tools, why = list_tools(list(cmd), timeout=timeout)
        fresh = {"package": rec.get("package"), "version": rec.get("version"),
                 "command": cmd}
        if why:
            fresh["unreadable"] = why
        else:
            fresh["tools"] = [{"name": x.get("name"),
                               "description": x.get("description") or ""}
                              for x in tools]
            fresh["chars"] = len(instruction_text(tools))
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
    from cli import COMMANDS as _CMDS
    ap = argparse.ArgumentParser(prog="qatration mcp",
                                 description=_CMDS["mcp"][1])
    ap.add_argument("server", nargs=argparse.REMAINDER,
                    help="the command that starts the server over stdio, "
                         "e.g. npx -y @modelcontextprotocol/server-memory")
    ap.add_argument("--timeout", type=int, default=180,
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
    tools, why = list_tools(args.server, timeout=args.timeout)
    if why:
        print("could not read the tool list: %s" % why)
        return 2
    text = instruction_text(tools)
    print("%d tool(s), %d characters of server-authored instruction text"
          % (len(tools), len(text)))
    for t in tools:
        d = " ".join((t.get("description") or "").split())
        print("  %-30s %5d  %s" % (t.get("name"), len(d), d[:80]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
