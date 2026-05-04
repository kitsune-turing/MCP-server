"""
KIT-MCP Server — Transport Layer
Abstract base + SSH implementation.  Future: Telnet, TCP, Serial.
"""
from __future__ import annotations

import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import paramiko

from kit_mcp.config import ServerConfig
from kit_mcp.enums import AuthType, ConnectionState, ErrorCode, KeyAlgorithm
from kit_mcp.errors import (
    AuthTimeoutError,
    BadKeyError,
    BadPasswordError,
    BannerTimeoutError,
    CommandTimeoutError,
    ConnectTimeoutError,
    ConnectionRefusedError,
    ConnectionResetError,
    DNSFailureError,
    HostKeyMismatchError,
    HostUnreachableError,
    KeepaliveError,
    KitMCPError,
    NegotiationError,
    NonZeroExitError,
    PermissionDeniedError,
    KeyNotFoundError,
)


# ─────────────────────────────────────────────
#  Result type
# ─────────────────────────────────────────────

@dataclass
class CommandResult:
    exit_code   : int
    stdout      : str
    stderr      : str
    duration_ms : int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


# ─────────────────────────────────────────────
#  Abstract base
# ─────────────────────────────────────────────

class BaseTransport(ABC):
    """
    Protocol-agnostic interface every concrete transport must implement.

    Lifecycle:
        connect()  →  exec(cmd)  →  …  →  close()
    """

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.state  = ConnectionState.DISCONNECTED
        self._lock  = threading.Lock()

    # ── Required ─────────────────────────────

    @abstractmethod
    def connect(self) -> None:
        """Establish the underlying connection and authenticate."""

    @abstractmethod
    def exec(self, command: str) -> CommandResult:
        """Execute *command* on the remote host and return the result."""

    @abstractmethod
    def close(self) -> None:
        """Release all resources associated with this transport."""

    # ── Optional overrides ───────────────────

    def is_alive(self) -> bool:
        """Return True if the connection is believed to be active."""
        return self.state == ConnectionState.AUTHENTICATED

    def reconnect(self) -> None:
        """Close and re-establish the connection."""
        self.close()
        self.connect()

    # ── Context manager ──────────────────────

    def __enter__(self) -> "BaseTransport":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ─────────────────────────────────────────────
#  SSH Transport
# ─────────────────────────────────────────────

_PARAMIKO_KEY_LOADERS: dict[KeyAlgorithm, type[paramiko.PKey]] = {
    KeyAlgorithm.ED25519 : paramiko.Ed25519Key,
    KeyAlgorithm.RSA     : paramiko.RSAKey,
    KeyAlgorithm.ECDSA   : paramiko.ECDSAKey,
    KeyAlgorithm.DSA     : paramiko.DSSKey,
}

_AUTO_LOADERS = list(_PARAMIKO_KEY_LOADERS.values())  # try all when algo is unknown


class SSHTransport(BaseTransport):
    """
    Paramiko-backed SSH transport.

    Key features:
    - Supports password, key-file, and SSH-agent auth.
    - Automatic retry on transient SSH errors.
    - Keepalive thread to detect silent drops.
    - Typed exceptions for every failure path.
    """

    def __init__(self, config: ServerConfig) -> None:
        super().__init__(config)
        self._client: Optional[paramiko.SSHClient] = None

    # ── Auth helpers ─────────────────────────

    def _load_key(self) -> paramiko.PKey:
        cfg = self.config
        path = cfg.key_path
        if not path:
            raise KeyNotFoundError("No key path configured.")

        loaders = (
            [_PARAMIKO_KEY_LOADERS[cfg.key_algorithm]]
            if cfg.key_algorithm and cfg.key_algorithm in _PARAMIKO_KEY_LOADERS
            else _AUTO_LOADERS
        )

        last_exc: Exception | None = None
        for loader in loaders:
            try:
                return loader.from_private_key_file(str(path))
            except paramiko.ssh_exception.PasswordRequiredException as e:
                from kit_mcp.errors import KeyPassphraseError
                raise KeyPassphraseError(
                    f"Key {path} requires a passphrase.",
                    context={"key_path": str(path)},
                    cause=e,
                )
            except paramiko.ssh_exception.SSHException as e:
                last_exc = e

        raise BadKeyError(
            f"Could not load key {path} with any supported algorithm.",
            context={"key_path": str(path)},
            cause=last_exc,
        )

    # ── connect() ────────────────────────────

    def connect(self) -> None:
        cfg = self.config
        self.state = ConnectionState.CONNECTING

        client = paramiko.SSHClient()

        if cfg.no_host_check:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict = {
            "hostname"       : cfg.host,
            "port"           : cfg.port,
            "username"       : cfg.user,
            "timeout"        : cfg.connect_timeout,
            "banner_timeout" : cfg.connect_timeout,
            "auth_timeout"   : cfg.connect_timeout,
        }

        if cfg.auth == AuthType.PASSWORD:
            connect_kwargs["password"]      = cfg.password
            connect_kwargs["allow_agent"]   = False
            connect_kwargs["look_for_keys"] = False

        elif cfg.auth == AuthType.KEY_FILE:
            connect_kwargs["pkey"]          = self._load_key()
            connect_kwargs["allow_agent"]   = False
            connect_kwargs["look_for_keys"] = False

        elif cfg.auth == AuthType.KEY_AGENT:
            connect_kwargs["allow_agent"]   = True
            connect_kwargs["look_for_keys"] = False

        elif cfg.auth == AuthType.NONE:
            connect_kwargs["allow_agent"]   = False
            connect_kwargs["look_for_keys"] = False

        try:
            client.connect(**connect_kwargs)
        except paramiko.AuthenticationException as e:
            msg = str(e).lower()
            if "password" in msg:
                raise BadPasswordError(str(e), cause=e,
                                       context={"host": cfg.host, "user": cfg.user})
            raise PermissionDeniedError(str(e), cause=e,
                                        context={"host": cfg.host, "user": cfg.user})
        except paramiko.BadHostKeyException as e:
            raise HostKeyMismatchError(str(e), cause=e, context={"host": cfg.host})
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            raise ConnectionRefusedError(str(e), cause=e,
                                         context={"host": cfg.host, "port": cfg.port})
        except paramiko.ssh_exception.SSHException as e:
            msg = str(e).lower()
            if "negotiate" in msg or "cipher" in msg or "kex" in msg:
                raise NegotiationError(str(e), cause=e)
            if "banner" in msg:
                raise BannerTimeoutError(str(e), cause=e,
                                         context={"host": cfg.host, "port": cfg.port})
            raise KitMCPError(str(e), cause=e)
        except socket.timeout as e:
            raise ConnectTimeoutError(
                f"Connection to {cfg.host}:{cfg.port} timed out after {cfg.connect_timeout}s.",
                cause=e, context={"host": cfg.host, "port": cfg.port,
                                  "timeout": cfg.connect_timeout},
            )
        except socket.gaierror as e:
            raise DNSFailureError(f"Cannot resolve '{cfg.host}'.", cause=e,
                                  context={"host": cfg.host})
        except ConnectionRefusedError:
            raise ConnectionRefusedError(
                f"Connection refused on {cfg.host}:{cfg.port}.",
                context={"host": cfg.host, "port": cfg.port},
            )
        except OSError as e:
            raise HostUnreachableError(str(e), cause=e,
                                       context={"host": cfg.host, "port": cfg.port})

        # Keepalive
        if cfg.keepalive > 0:
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(cfg.keepalive)

        self._client = client
        self.state   = ConnectionState.AUTHENTICATED

    # ── exec() ───────────────────────────────

    def exec(self, command: str) -> CommandResult:
        start = time.time()

        if not self._client or not self.is_alive():
            self.reconnect()

        assert self._client is not None

        # Determine if we need PTY for interactive sudo password handling
        needs_sudo = command.strip().startswith("sudo") and self.config.sudo_password

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=self.config.command_timeout,
                get_pty=needs_sudo,  # Enable PTY for sudo password prompt
            )

            # If sudo with password configured, send it to stdin
            if needs_sudo:
                stdin.write(self.config.sudo_password + "\n")
                stdin.flush()
            else:
                stdin.close()

            out       = stdout.read().decode("utf-8", errors="replace").strip()
            err       = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()
        except socket.timeout as e:
            raise CommandTimeoutError(
                f"Command timed out after {self.config.command_timeout}s.",
                cause=e,
                context={"command": command[:200],
                         "timeout": self.config.command_timeout},
            )
        except (paramiko.ssh_exception.SSHException, EOFError, OSError) as e:
            self._reset()
            raise KeepaliveError(
                "Transport lost during command execution.",
                cause=e,
                context={"command": command[:200]},
            )

        duration_ms = int((time.time() - start) * 1000)
        return CommandResult(
            exit_code   = exit_code,
            stdout      = out,
            stderr      = err,
            duration_ms = duration_ms,
        )

    # ── close() ──────────────────────────────

    def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        self.state = ConnectionState.CLOSED

    def _reset(self) -> None:
        self.close()
        self.state = ConnectionState.DISCONNECTED

    def is_alive(self) -> bool:
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()


# ─────────────────────────────────────────────
#  Transport factory
# ─────────────────────────────────────────────

from kit_mcp.enums import TransportType
from kit_mcp.errors import UnsupportedTransportError


def create_transport(config: ServerConfig) -> BaseTransport:
    """Instantiate the correct transport for *config.transport*."""
    if config.transport == TransportType.SSH:
        return SSHTransport(config)

    # Telnet / TCP / Serial → future implementations
    raise UnsupportedTransportError(
        f"Transport '{config.transport.value}' is not yet implemented.",
        context={"transport": config.transport.value},
    )
