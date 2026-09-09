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


def _send(proc, obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def _await(proc, want_id, deadline):
    """The answer to one request id, skipping whatever else the server writes to stdout.

    Servers log to stdout. A reader that treats the first line as its answer gets a banner,
    and a reader that raises on the first unparseable line reports a working server as a
    broken one -- so lines that are not JSON, and JSON that is not this id, are skipped.
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


def list_tools(argv, timeout=180, cwd=None):
    """-> (tools, why). `why` is "" on success, and names what happened when tools is None.

    THREE STATES, like everything else here: a list of tools, an empty list from a server
    that offers none, and None with a reason. A server that would not start and a server
    with no tools are not the same fact about an operator's workspace.
    """
    deadline = time.time() + timeout
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            errors="replace", bufsize=1, cwd=cwd,
            # `npx` and friends are batch files on Windows and are not executable
            # images, so the shell is how they start there and nowhere else.
            shell=(os.name == "nt"))
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                                "clientInfo": {"name": "qatration", "version": "0"}}})
        init = _await(proc, 1, deadline)
        if init is None:
            return None, "no answer to initialize within %ds" % timeout
        if "error" in init:
            return None, "initialize refused: %s" % json.dumps(init["error"])[:120]
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        got = _await(proc, 2, deadline)
        if got is None:
            return None, "no answer to tools/list within %ds" % timeout
        if "error" in got:
            return None, "tools/list refused: %s" % json.dumps(got["error"])[:120]
        return list((got.get("result") or {}).get("tools") or []), ""
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            pass


def instruction_text(tools):
    """Everything a server contributes to the model's instruction context, as one string.

    The unit an operator cares about is not the tool count. It is how much text somebody
    else wrote that the model will read as instructions, and it is invisible: a server with
    one tool can contribute more of it than a server with twenty-four.
    """
    return "\n".join((t.get("description") or "") for t in tools)


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
        bt = {x["name"]: x.get("description") or "" for x in (b.get("tools") or [])}
        at = {x["name"]: x.get("description") or "" for x in (a.get("tools") or [])}
        moved = sorted(n for n in set(bt) & set(at) if bt[n] != at[n])
        added, dropped = sorted(set(at) - set(bt)), sorted(set(bt) - set(at))
        if not (moved or added or dropped):
            continue
        what = ", ".join(
            ([("%d description(s) rewritten: " % len(moved)) + ", ".join(moved[:4])]
             if moved else [])
            + ([("%d tool(s) added: " % len(added)) + ", ".join(added[:4])] if added else [])
            + ([("%d tool(s) gone: " % len(dropped)) + ", ".join(dropped[:4])]
               if dropped else []))
        same_version = (b.get("version") or "?") == (a.get("version") or "??")
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
