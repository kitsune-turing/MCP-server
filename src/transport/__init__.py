"""
KIT-MCP Server — Transport Layer
Abstract base + SSH implementation.  Future: Telnet, TCP, Serial.

Security features:
- ISO 27001/27002: Audit logging, connection tracking
- MITRE ATT&CK: Rate limiting (T1110), command auditing (T1021)
- NIST CSF: Detect and respond to security events
"""
from __future__ import annotations

import logging
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
from kit_mcp.audit import get_audit_logger, AuditEventType, AuditSeverity
from kit_mcp.security import sanitize_command

log = logging.getLogger("kit_mcp.transport")


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
    - Security auditing (ISO 27001/27002, MITRE, NIST)
    - Rate limiting and connection tracking
    """

    # Class-level rate limiting (prevent brute force attacks)
    _FAILED_AUTH_THRESHOLD = 5  # Max failed auth attempts
    _RATE_LIMIT_WINDOW = 300    # 5 minutes (seconds)
    _failed_attempts: dict[str, list[float]] = {}  # key: "host:port:user"
    _rate_limit_lock = threading.Lock()

    def __init__(self, config: ServerConfig) -> None:
        super().__init__(config)
        self._client: Optional[paramiko.SSHClient] = None
        self._audit = get_audit_logger()
        self._auth_attempts = 0

    @classmethod
    def _check_rate_limit(cls, host: str, port: int, user: str) -> bool:
        """
        Check if this host:port:user combination has exceeded auth attempts.
        Returns True if ALLOWED, False if RATE LIMITED.
        """
        key = f"{host}:{port}:{user}"
        now = time.time()
        
        with cls._rate_limit_lock:
            if key not in cls._failed_attempts:
                cls._failed_attempts[key] = []
            
            # Clean old attempts outside window
            cls._failed_attempts[key] = [
                t for t in cls._failed_attempts[key]
                if now - t < cls._RATE_LIMIT_WINDOW
            ]
            
            # Check threshold
            if len(cls._failed_attempts[key]) >= cls._FAILED_AUTH_THRESHOLD:
                return False  # RATE LIMITED
            
            return True  # ALLOWED

    @classmethod
    def _record_failed_attempt(cls, host: str, port: int, user: str) -> None:
        """Record a failed auth attempt for rate limiting."""
        key = f"{host}:{port}:{user}"
        with cls._rate_limit_lock:
            if key not in cls._failed_attempts:
                cls._failed_attempts[key] = []
            cls._failed_attempts[key].append(time.time())

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

        # Security: Check rate limiting (MITRE T1110 - Brute Force)
        if not self._check_rate_limit(cfg.host, cfg.port, cfg.user):
            self._audit.log_security_event(
                host=cfg.host,
                port=cfg.port,
                user=cfg.user,
                transport=cfg.transport.value,
                event_type=AuditEventType.SECURITY_WARNING,
                severity=AuditSeverity.CRITICAL,
                detail=f"Rate limited: Too many failed auth attempts on {cfg.host}:{cfg.port}",
            )
            raise PermissionDeniedError(
                f"Too many failed authentication attempts. Retry in {self._RATE_LIMIT_WINDOW}s."
            )

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
            # Audit successful connection
            self._audit.log_auth(
                host=cfg.host,
                port=cfg.port,
                user=cfg.user,
                transport=cfg.transport.value,
                auth_method=cfg.auth.value,
                success=True,
            )
        except paramiko.AuthenticationException as e:
            # Security: Record failed auth attempt (MITRE T1110)
            self._record_failed_attempt(cfg.host, cfg.port, cfg.user)
            self._auth_attempts += 1
            
            # Audit failed auth
            msg = str(e).lower()
            if "password" in msg:
                self._audit.log_auth(
                    host=cfg.host,
                    port=cfg.port,
                    user=cfg.user,
                    transport=cfg.transport.value,
                    auth_method="password",
                    success=False,
                    error_code="AUTH_BAD_PASSWORD",
                )
                raise BadPasswordError(str(e), cause=e,
                                       context={"host": cfg.host, "user": cfg.user})
            
            self._audit.log_auth(
                host=cfg.host,
                port=cfg.port,
                user=cfg.user,
                transport=cfg.transport.value,
                auth_method=cfg.auth.value,
                success=False,
                error_code="AUTH_PERMISSION_DENIED",
            )
            raise PermissionDeniedError(str(e), cause=e,
                                        context={"host": cfg.host, "user": cfg.user})
        except paramiko.BadHostKeyException as e:
            self._audit.log_security_event(
                host=cfg.host,
                port=cfg.port,
                user=cfg.user,
                transport=cfg.transport.value,
                event_type=AuditEventType.HOST_KEY_MISMATCH,
                severity=AuditSeverity.CRITICAL,
                detail=str(e),
            )
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

        # Security: Sanitize command (prevent some injection patterns)
        try:
            command = sanitize_command(command)
        except ValueError as e:
            self._audit.log_command(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                transport=self.config.transport.value,
                command=command[:200],
                success=False,
                sudo_attempted=command.strip().startswith("sudo"),
            )
            raise

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
            
            # Audit command execution
            self._audit.log_command(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                transport=self.config.transport.value,
                command=command[:200],
                success=(exit_code == 0),
                exit_code=exit_code,
                duration_ms=int((time.time() - start) * 1000),
                sudo_attempted=needs_sudo,
            )
        except socket.timeout as e:
            self._audit.log_command(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                transport=self.config.transport.value,
                command=command[:200],
                success=False,
                sudo_attempted=needs_sudo,
            )
            raise CommandTimeoutError(
                f"Command timed out after {self.config.command_timeout}s.",
                cause=e,
                context={"command": command[:200],
                         "timeout": self.config.command_timeout},
            )
        except (paramiko.ssh_exception.SSHException, EOFError, OSError) as e:
            self._reset()
            self._audit.log_security_event(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                transport=self.config.transport.value,
                event_type=AuditEventType.CONNECTION_RESET,
                severity=AuditSeverity.HIGH,
                detail="Transport lost during command execution",
            )
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
