"""The load-bearing test of this project.

"It runs locally" is a promise. This turns it into a property that CI enforces:
during a full scan + redact + verify cycle, any attempt to create a socket,
resolve a hostname, or open an HTTP connection raises immediately.

If someone later adds a detector that phones home -- a telemetry ping, a model
download, an "anonymous" usage counter -- this test fails and they have to
argue for it in review instead of shipping it quietly.
"""

from __future__ import annotations

import http.client
import socket

import pytest

from piiguard.localnet import EgressError, is_loopback_host, local_connection
from piiguard.pipeline import Pipeline
from piiguard.policy import Policy

SAMPLE = """
From: alice.chen@northwind.example
Phone: 415-555-0142
SSN: 078-05-1120
Card: 4111 1111 1111 1111
Host: 73.140.22.9
"""


class EgressAttempt(AssertionError):
    """Raised the moment anything tries to touch the network."""


@pytest.fixture
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        raise EgressAttempt(
            "piiguard attempted network I/O; this tool must be fully local"
        )

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "gethostbyname", deny)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", deny)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", deny)
    yield


def test_scan_makes_no_network_calls(no_network):
    spans = Pipeline().scan(SAMPLE)
    assert spans, "sanity: the sample should produce findings"


def test_redact_makes_no_network_calls(no_network):
    result = Pipeline(policy=Policy(default="label")).redact(SAMPLE)
    assert result.clean


def test_pseudonymize_makes_no_network_calls(no_network):
    result = Pipeline(policy=Policy(default="pseudonymize")).redact(SAMPLE)
    assert result.clean


def test_guard_itself_works(no_network):
    """The fixture must actually block, or the tests above prove nothing."""
    with pytest.raises(EgressAttempt):
        socket.socket()


# -- the loopback carve-out for layer 3 ---------------------------------
#
# The default pipeline opens no socket at all (above). Layer 3 will talk to a
# local model server, so the guarantee is refined to "never leaves loopback."
# These pin both halves of that: loopback is permitted, everything else is not.


@pytest.mark.parametrize("host", ["127.0.0.1", "127.5.9.1", "::1", "[::1]", "localhost", "LOCALHOST"])
def test_loopback_hosts_are_allowed(host):
    assert is_loopback_host(host)


@pytest.mark.parametrize(
    "host",
    ["8.8.8.8", "0.0.0.0", "example.com", "api.openai.com", "169.254.169.254", "", None],
)
def test_non_loopback_hosts_are_rejected(host):
    assert not is_loopback_host(host)


def test_local_connection_permits_loopback():
    """A loopback target yields a connection object (no socket opened yet)."""
    conn = local_connection("127.0.0.1", 11434)
    assert isinstance(conn, http.client.HTTPConnection)
    assert conn.host == "127.0.0.1" and conn.port == 11434


def test_local_connection_refuses_egress():
    """Anything not on loopback raises before any network I/O happens."""
    for host in ("example.com", "8.8.8.8", "169.254.169.254"):
        with pytest.raises(EgressError):
            local_connection(host, 443)
