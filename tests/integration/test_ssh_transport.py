"""
Integration tests — SSH Transport (paramiko mocked).
Run: pytest tests/integration/
"""
from __future__ import annotations

import sys
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

import paramiko

from kit_mcp.config import ServerConfig
from kit_mcp.enums import AuthType, TransportType, KeyAlgorithm
from kit_mcp.errors import (
    BadPasswordError, ConnectionRefusedError, ConnectTimeoutError,
    DNSFailureError, HostKeyMismatchError, KeepaliveError,
    NegotiationError, NonZeroExitError, PermissionDeniedError,
)
from kit_mcp.transport import SSHTransport, CommandResult


# ─────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────

def _make_config(auth=AuthType.NONE, **kwargs) -> ServerConfig:
    base = dict(
        host="10.0.0.1", port=22, transport=TransportType.SSH,
        user="pi", name="test", auth=auth,
        no_host_check=True,
    )
    base.update(kwargs)
    return ServerConfig(**base)


def _mock_exec(stdout_text="ok", exit_code=0, stderr_text=""):
    stdin  = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.read.return_value = stdout_text.encode()
    stderr.read.return_value = stderr_text.encode()
    stdout.channel.recv_exit_status.return_value = exit_code
    return stdin, stdout, stderr


# ─────────────────────────────────────────────
#  Happy path
# ─────────────────────────────────────────────

class TestSSHTransportHappyPath:
    @patch("paramiko.SSHClient")
    def test_connect_and_exec(self, MockSSH):
        client = MockSSH.return_value
        client.get_transport.return_value = MagicMock(is_active=lambda: True)
        client.exec_command.return_value = _mock_exec("hello world")

        cfg = _make_config()
        t   = SSHTransport(cfg)
        t.connect()
        result = t.exec("echo hello world")

        assert result.ok
        assert result.stdout == "hello world"
        assert result.exit_code == 0

    @patch("paramiko.SSHClient")
    def test_exec_non_zero_exit(self, MockSSH):
        client = MockSSH.return_value
        client.get_transport.return_value = MagicMock(is_active=lambda: True)
        client.exec_command.return_value = _mock_exec("", exit_code=1, stderr_text="not found")

        cfg = _make_config()
        t   = SSHTransport(cfg)
        t.connect()
        result = t.exec("false")

        assert not result.ok
        assert result.exit_code == 1
        assert "not found" in result.stderr

    @patch("paramiko.SSHClient")
    def test_close_cleans_up(self, MockSSH):
        client = MockSSH.return_value
        client.get_transport.return_value = MagicMock(is_active=lambda: True)

        cfg = _make_config()
        t   = SSHTransport(cfg)
        t.connect()
        t.close()

        client.close.assert_called_once()
        assert t._client is None


# ─────────────────────────────────────────────
#  Auth failures
# ─────────────────────────────────────────────

class TestSSHAuthErrors:
    @patch("paramiko.SSHClient")
    def test_bad_password(self, MockSSH):
        MockSSH.return_value.connect.side_effect = (
            paramiko.AuthenticationException("password auth failed")
        )
        cfg = _make_config(auth=AuthType.PASSWORD, password="wrong")
        t   = SSHTransport(cfg)
        with pytest.raises(BadPasswordError):
            t.connect()

    @patch("paramiko.SSHClient")
    def test_permission_denied(self, MockSSH):
        MockSSH.return_value.connect.side_effect = (
            paramiko.AuthenticationException("Permission denied")
        )
        cfg = _make_config()
        t   = SSHTransport(cfg)
        with pytest.raises(PermissionDeniedError):
            t.connect()

    @patch("paramiko.SSHClient")
    def test_host_key_mismatch(self, MockSSH):
        MockSSH.return_value.connect.side_effect = (
            paramiko.BadHostKeyException("10.0.0.1", MagicMock(), MagicMock())
        )
        cfg = _make_config(no_host_check=False)
        t   = SSHTransport(cfg)
        with pytest.raises(HostKeyMismatchError):
            t.connect()


# ─────────────────────────────────────────────
#  Network failures
# ─────────────────────────────────────────────

class TestSSHNetworkErrors:
    @patch("paramiko.SSHClient")
    def test_connection_refused(self, MockSSH):
        MockSSH.return_value.connect.side_effect = (
            paramiko.ssh_exception.NoValidConnectionsError({("10.0.0.1", 22): Exception()})
        )
        cfg = _make_config()
        t   = SSHTransport(cfg)
        with pytest.raises(ConnectionRefusedError):
            t.connect()

    @patch("paramiko.SSHClient")
    def test_connect_timeout(self, MockSSH):
        MockSSH.return_value.connect.side_effect = socket.timeout("timed out")
        cfg = _make_config()
        t   = SSHTransport(cfg)
        with pytest.raises(ConnectTimeoutError):
            t.connect()

    @patch("paramiko.SSHClient")
    def test_dns_failure(self, MockSSH):
        MockSSH.return_value.connect.side_effect = socket.gaierror("Name or service not known")
        cfg = _make_config()
        t   = SSHTransport(cfg)
        with pytest.raises(DNSFailureError):
            t.connect()

    @patch("paramiko.SSHClient")
    def test_negotiation_error(self, MockSSH):
        MockSSH.return_value.connect.side_effect = (
            paramiko.ssh_exception.SSHException("Unable to negotiate kex algorithm")
        )
        cfg = _make_config()
        t   = SSHTransport(cfg)
        with pytest.raises(NegotiationError):
            t.connect()

    @patch("paramiko.SSHClient")
    def test_keepalive_lost_during_exec(self, MockSSH):
        client = MockSSH.return_value
        transport_mock = MagicMock()
        transport_mock.is_active.return_value = True
        client.get_transport.return_value = transport_mock
        client.exec_command.side_effect = EOFError("Transport endpoint closed")

        cfg = _make_config()
        t   = SSHTransport(cfg)
        t.connect()

        with pytest.raises(KeepaliveError):
            t.exec("ls")
