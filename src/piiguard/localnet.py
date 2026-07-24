"""Loopback-only network access -- the one auditable place piiguard may open a
socket.

Every other layer is pure computation: the no-egress test proves a full
scan/redact/verify cycle touches no socket at all. Layer 3 breaks that, but
only just: it talks to a model server running on this same machine (Ollama),
which is a socket to loopback and nothing else.

So the guarantee is refined, not abandoned. "Never leaves your machine"
becomes "never leaves loopback," and that stays a property under test: this
module permits 127.0.0.0/8 and ::1, and raises on anything else. A hostname
that would need DNS to resolve is treated as non-local and refused outright --
resolving it is itself a network act that could leak the query.
"""

from __future__ import annotations

import http.client
import ipaddress

DEFAULT_TIMEOUT = 5.0


class EgressError(RuntimeError):
    """Raised when a connection to a non-loopback address is attempted."""


def is_loopback_host(host: str | None) -> bool:
    """True only for the loopback literals or the name 'localhost'.

    A DNS name (other than 'localhost') returns False: we will not resolve it,
    because the lookup itself is egress and its result cannot be trusted to
    stay on the machine.
    """
    if not host:
        return False
    h = host.strip().strip("[]")
    if h.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def local_connection(
    host: str, port: int, *, timeout: float = DEFAULT_TIMEOUT
) -> http.client.HTTPConnection:
    """Build an HTTP connection, but only to a loopback host.

    Construction does not open the socket (that happens on the first request),
    so the guard runs before any network I/O. Non-loopback hosts never get a
    connection object at all.
    """
    if not is_loopback_host(host):
        raise EgressError(
            f"refusing to connect to non-loopback host {host!r}; piiguard only "
            "talks to a model server on this machine"
        )
    return http.client.HTTPConnection(host, port, timeout=timeout)
