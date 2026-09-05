# -*- coding: utf-8 -*-
"""Refuse a connection to anywhere but this machine, for the duration of a suite.

`tools/check.py` opens by saying every suite here is offline -- no model, no network, no
practice fleet -- and that this "is asserted rather than assumed". It was assumed. Nothing
looked, and the claim is the reason the whole suite is expected to pass on a runner with no
GPU and no fleet: a suite that quietly reaches a real host passes on the machine that has one
and fails on the machine that does not, which is the worst place to learn it.

LOOPBACK IS NOT THE NETWORK. Nine suites bind a socket and drive their own HTTP server on
127.0.0.1; that is how `test_http_adapter` proves an adapter reads a reply and how
`test_fleet_adapters` proves a 200 carrying an error becomes an error. Blocking those would
delete the checks rather than the dependency. So the rule is exactly: this machine, yes;
anything else, no.

PYTHONPATH RATHER THAN AN IMPORT IN EVERY SUITE. Python imports `sitecustomize` on startup if
it is importable, so `check.py` putting this directory on the child's PYTHONPATH arms it for
the suite and for anything the suite starts, with nothing to remember and nothing to add to a
new file. A suite that wanted to opt out would have to say so.

Refused with the address in the message, because "connection refused" from a patched socket
and one from a firewall look identical in a traceback, and the difference decides whether
somebody spends an afternoon on their proxy settings.
"""
import socket

_ALLOWED = {"127.0.0.1", "::1", "localhost", "", "0.0.0.0", "::"}
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _host_of(address):
    """The host out of whatever shape this family uses. Unix sockets are a path, not a host."""
    if isinstance(address, (bytes, str)):
        return None                      # AF_UNIX: a filesystem path, never the network
    try:
        return address[0]
    except Exception:
        return None


def _local(address):
    host = _host_of(address)
    if host is None:
        return True
    return str(host) in _ALLOWED


def _refuse(address):
    raise OSError(
        "QATRATION_OFFLINE: this suite tried to connect to %r. The offline suites are the "
        "ones that run on a machine with no model, no fleet and no network, and that "
        "property is what lets them run in CI at all -- so reaching a real host is refused "
        "here rather than discovered on somebody else's laptop. Loopback is allowed; if this "
        "check genuinely needs a network, it does not belong in `tools/check.py`."
        % (address,))


def _connect(self, address):
    if not _local(address):
        _refuse(address)
    return _real_connect(self, address)


def _connect_ex(self, address):
    if not _local(address):
        _refuse(address)
    return _real_connect_ex(self, address)


socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex
