#!/usr/bin/env python3
"""
KIT-MCP Server — Standalone Monolithic Version
All components in a single file for deployment simplicity.

This is a consolidated version that includes:
- Enums and constants
- Error hierarchy
- Security utilities
- Audit logging
- Configuration parsing
- Transport abstraction (SSH)
- MCP server endpoint

Usage:
    python kit_mcp_standalone.py --host 10.0.0.1 --user admin --auth password --password secret

Deployment:
    This single file contains all necessary code. Requires only:
    - Python 3.11+
    - paramiko (for SSH)
    - mcp[cli] (for MCP framework)

Security & Compliance:
    - ISO 27001/27002: Audit logging, credential protection
    - MITRE ATT&CK: Rate limiting, command auditing
    - NIST CSF: Comprehensive event logging
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import string
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import paramiko
from mcp.server.fastmcp import FastMCP

# ═════════════════════════════════════════════════════════════════════════════
#  ENUMS & CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════


class TransportType(str, Enum):
    """Supported transport protocols."""
    SSH     = "ssh"
    TELNET  = "telnet"
    SERIAL  = "serial"
    TCP     = "tcp"
    UDP     = "udp"


class AuthType(str, Enum):
    """Authentication mechanisms."""
    PASSWORD    = "password"
    KEY_FILE    = "key_file"
    KEY_AGENT   = "key_agent"
    CERTIFICATE = "certificate"
    NONE        = "none"


class KeyAlgorithm(str, Enum):
    """Supported SSH key algorithms."""
    ED25519 = "ed25519"
    RSA     = "rsa"
    ECDSA   = "ecdsa"


class ConnectionState(str, Enum):
    """Lifecycle state of a server connection."""
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    AUTHENTICATED = "authenticated"
    FAILED       = "failed"
    CLOSED       = "closed"


class ErrorCategory(str, Enum):
    """Top-level error classification."""
    CONNECTION  = "connection"
    AUTH        = "auth"
    TIMEOUT     = "timeout"
    COMMAND     = "command"
    CONFIG      = "config"
    TRANSPORT   = "transport"
    UNKNOWN     = "unknown"


class ErrorCode(str, Enum):
    """Fine-grained error codes for programmatic handling."""
    # Connection
    CONNECTION_REFUSED          = "CONNECTION_REFUSED"
    CONNECTION_TIMEOUT          = "CONNECTION_TIMEOUT"
    CONNECTION_RESET            = "CONNECTION_RESET"
    CONNECTION_HOST_UNREACHABLE = "CONNECTION_HOST_UNREACHABLE"
    CONNECTION_DNS_FAILURE      = "CONNECTION_DNS_FAILURE"
    # Auth
    AUTH_BAD_PASSWORD           = "AUTH_BAD_PASSWORD"
    AUTH_BAD_KEY                = "AUTH_BAD_KEY"
    AUTH_KEY_NOT_FOUND          = "AUTH_KEY_NOT_FOUND"
    AUTH_KEY_PASSPHRASE         = "AUTH_KEY_PASSPHRASE"
    AUTH_HOST_KEY_MISMATCH      = "AUTH_HOST_KEY_MISMATCH"
    AUTH_PERMISSION_DENIED      = "AUTH_PERMISSION_DENIED"
    AUTH_MFA_REQUIRED           = "AUTH_MFA_REQUIRED"
    # Timeout
    TIMEOUT_CONNECT             = "TIMEOUT_CONNECT"
    TIMEOUT_COMMAND             = "TIMEOUT_COMMAND"
    TIMEOUT_BANNER              = "TIMEOUT_BANNER"
    TIMEOUT_AUTH                = "TIMEOUT_AUTH"
    # Command
    COMMAND_NON_ZERO_EXIT       = "COMMAND_NON_ZERO_EXIT"
    COMMAND_SIGNAL_KILLED       = "COMMAND_SIGNAL_KILLED"
    COMMAND_PTY_FAILED          = "COMMAND_PTY_FAILED"
    # Config
    CONFIG_MISSING_HOST         = "CONFIG_MISSING_HOST"
    CONFIG_MISSING_USER         = "CONFIG_MISSING_USER"
    CONFIG_INVALID_PORT         = "CONFIG_INVALID_PORT"
    CONFIG_MISSING_CREDENTIAL   = "CONFIG_MISSING_CREDENTIAL"
    CONFIG_UNSUPPORTED_TRANSPORT = "CONFIG_UNSUPPORTED_TRANSPORT"
    # Transport
    TRANSPORT_NEGOTIATION       = "TRANSPORT_NEGOTIATION"
    TRANSPORT_KEEPALIVE_LOST    = "TRANSPORT_KEEPALIVE_LOST"
    # Generic
    UNKNOWN_ERROR               = "UNKNOWN_ERROR"


class ServerOS(str, Enum):
    """Operating system hint."""
    LINUX   = "linux"
    BSD     = "bsd"
    MACOS   = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class ServerRole(str, Enum):
    """Semantic role of the target server."""
    GENERIC      = "generic"
    RASPBERRY_PI = "raspberry_pi"
    ROUTER       = "router"
    DATABASE     = "database"
    WEB          = "web"
    EMBEDDED     = "embedded"


class AuditEventType(str, Enum):
    """Security audit event classifications."""
    CONNECT_SUCCESS              = "connect_success"
    CONNECT_FAILURE              = "connect_failure"
    AUTH_ATTEMPT                 = "auth_attempt"
    AUTH_SUCCESS                 = "auth_success"
    AUTH_FAILURE                 = "auth_failure"
    COMMAND_EXEC                 = "command_exec"
    COMMAND_SUCCESS              = "command_success"
    COMMAND_FAILURE              = "command_failure"
    SUDO_ATTEMPT                 = "sudo_attempt"
    HOST_KEY_MISMATCH            = "host_key_mismatch"
    CONNECTION_RESET             = "connection_reset"
    TIMEOUT                      = "timeout"
    SECURITY_WARNING             = "security_warning"


class AuditSeverity(str, Enum):
    """Event severity levels."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ═════════════════════════════════════════════════════════════════════════════
#  ERROR HIERARCHY
# ═════════════════════════════════════════════════════════════════════════════


class KitMCPError(Exception):
    """Root exception for all KIT-MCP errors."""

    code: ErrorCode = ErrorCode.UNKNOWN_ERROR
    category: ErrorCategory = ErrorCategory.UNKNOWN

    def __init__(
        self,
        detail: str = "",
        *,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        self.detail = detail or self.__class__.__doc__ or ""
        self.context: dict[str, Any] = context or {}
        self.cause = cause
        super().__init__(self._format())

    def _format(self) -> str:
        parts = [f"[{self.code.value}] {self.detail}"]
        if self.context:
            ctx_str = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            parts.append(f"  context: {ctx_str}")
        if self.cause:
            parts.append(f"  caused by: {type(self.cause).__name__}: {self.cause}")
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.code.value,
            "category": self.category.value,
            "detail": self.detail,
            "context": self.context,
        }


class ConnectionError(KitMCPError):
    category = ErrorCategory.CONNECTION


class ConnectionRefusedError(ConnectionError):
    code = ErrorCode.CONNECTION_REFUSED


class ConnectionTimeoutError(ConnectionError):
    code = ErrorCode.CONNECTION_TIMEOUT


class ConnectionResetError(ConnectionError):
    code = ErrorCode.CONNECTION_RESET


class HostUnreachableError(ConnectionError):
    code = ErrorCode.CONNECTION_HOST_UNREACHABLE


class DNSFailureError(ConnectionError):
    code = ErrorCode.CONNECTION_DNS_FAILURE


class AuthError(KitMCPError):
    category = ErrorCategory.AUTH


class BadPasswordError(AuthError):
    code = ErrorCode.AUTH_BAD_PASSWORD


class BadKeyError(AuthError):
    code = ErrorCode.AUTH_BAD_KEY


class KeyNotFoundError(AuthError):
    code = ErrorCode.AUTH_KEY_NOT_FOUND


class KeyPassphraseError(AuthError):
    code = ErrorCode.AUTH_KEY_PASSPHRASE


class HostKeyMismatchError(AuthError):
    code = ErrorCode.AUTH_HOST_KEY_MISMATCH


class PermissionDeniedError(AuthError):
    code = ErrorCode.AUTH_PERMISSION_DENIED


class MFARequiredError(AuthError):
    code = ErrorCode.AUTH_MFA_REQUIRED


class TimeoutError(KitMCPError):
    category = ErrorCategory.TIMEOUT


class ConnectTimeoutError(TimeoutError):
    code = ErrorCode.TIMEOUT_CONNECT


class CommandTimeoutError(TimeoutError):
    code = ErrorCode.TIMEOUT_COMMAND


class BannerTimeoutError(TimeoutError):
    code = ErrorCode.TIMEOUT_BANNER


class AuthTimeoutError(TimeoutError):
    code = ErrorCode.TIMEOUT_AUTH


class CommandError(KitMCPError):
    category = ErrorCategory.COMMAND


class NonZeroExitError(CommandError):
    code = ErrorCode.COMMAND_NON_ZERO_EXIT

    def __init__(
        self,
        detail: str = "",
        *,
        exit_code: int = -1,
        stderr: str = "",
        **kwargs: Any,
    ) -> None:
        ctx = kwargs.pop("context", {})
        ctx.update({"exit_code": exit_code, "stderr": stderr[:500]})
        super().__init__(detail, context=ctx, **kwargs)


class SignalKilledError(CommandError):
    code = ErrorCode.COMMAND_SIGNAL_KILLED


class PTYFailedError(CommandError):
    code = ErrorCode.COMMAND_PTY_FAILED


class ConfigError(KitMCPError):
    category = ErrorCategory.CONFIG


class MissingHostError(ConfigError):
    code = ErrorCode.CONFIG_MISSING_HOST


class MissingUserError(ConfigError):
    code = ErrorCode.CONFIG_MISSING_USER


class InvalidPortError(ConfigError):
    code = ErrorCode.CONFIG_INVALID_PORT


class MissingCredentialError(ConfigError):
    code = ErrorCode.CONFIG_MISSING_CREDENTIAL


class UnsupportedTransportError(ConfigError):
    code = ErrorCode.CONFIG_UNSUPPORTED_TRANSPORT


class TransportError(KitMCPError):
    category = ErrorCategory.TRANSPORT


class NegotiationError(TransportError):
    code = ErrorCode.TRANSPORT_NEGOTIATION


class KeepaliveError(TransportError):
    code = ErrorCode.TRANSPORT_KEEPALIVE_LOST


# ═════════════════════════════════════════════════════════════════════════════
#  SECURITY UTILITIES
# ═════════════════════════════════════════════════════════════════════════════


def pbkdf2_hash(
    password: str,
    iterations: int = 100_000,
    salt: Optional[bytes] = None,
) -> tuple[str, str]:
    """Hash credential using PBKDF2-SHA256. Returns (salt_hex, hash_hex)."""
    if salt is None:
        salt = secrets.token_bytes(32)
    hash_obj = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    return salt.hex(), hash_obj.hex()


def verify_pbkdf2(
    password: str,
    stored_salt: str,
    stored_hash: str,
    iterations: int = 100_000,
) -> bool:
    """Verify a password against stored PBKDF2 hash."""
    _, computed_hash = pbkdf2_hash(
        password,
        iterations=iterations,
        salt=bytes.fromhex(stored_salt),
    )
    return hmac.compare_digest(computed_hash, stored_hash)


def validate_hostname(hostname: str, max_length: int = 253) -> bool:
    """Validate hostname per RFC 1123."""
    if not hostname or len(hostname) > max_length:
        return False
    allowed = set(string.ascii_letters + string.digits + ".-")
    if not all(c in allowed for c in hostname):
        return False
    for label in hostname.split("."):
        if not label or label[0] == "-" or label[-1] == "-":
            return False
    return True


def validate_username(username: str, max_length: int = 32) -> bool:
    """Validate username (POSIX character set, typical UNIX constraints)."""
    if not username or len(username) > max_length:
        return False
    allowed = set(string.ascii_letters + string.digits + "_-")
    if not all(c in allowed for c in username):
        return False
    if username[0].isdigit():
        return False
    return True


def sanitize_command(command: str, max_length: int = 10000) -> str:
    """Basic command sanitization."""
    if not command or len(command) > max_length:
        raise ValueError(f"Command too long (max {max_length}): {len(command)} chars")
    return command.strip()


def validate_port(port: int) -> bool:
    """Validate port number is in valid range."""
    return 1 <= port <= 65535


def check_credential_leakage(password: Optional[str], env_var: str) -> bool:
    """Check if credential exposed in both CLI and environment."""
    return password is not None and os.environ.get(env_var) is not None


# ═════════════════════════════════════════════════════════════════════════════
#  AUDIT LOGGING
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class AuditEvent:
    """Security audit event record."""
    timestamp: str
    event_type: str
    severity: str
    host: str
    port: int
    user: str
    transport: str
    detail: str = ""
    command: Optional[str] = None
    exit_code: Optional[int] = None
    error_code: Optional[str] = None
    error_category: Optional[str] = None
    duration_ms: Optional[int] = None
    remote_ip: Optional[str] = None
    auth_method: Optional[str] = None
    sudo_attempted: bool = False
    privilege_elevation_failed: bool = False
    session_id: Optional[str] = None
    request_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """Centralized audit event recorder."""

    def __init__(self, name: str = "kit_mcp.audit"):
        self.logger = logging.getLogger(name)
        self.events: list[AuditEvent] = []

    def _record(self, event: AuditEvent) -> None:
        self.events.append(event)
        log_level = {
            AuditSeverity.LOW.value: logging.INFO,
            AuditSeverity.MEDIUM.value: logging.WARNING,
            AuditSeverity.HIGH.value: logging.ERROR,
            AuditSeverity.CRITICAL.value: logging.CRITICAL,
        }.get(event.severity, logging.WARNING)
        self.logger.log(log_level, event.to_json())

    def log_connect(
        self,
        host: str,
        port: int,
        user: str,
        transport: str,
        auth_method: str,
        success: bool = True,
        detail: str = "",
    ) -> None:
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=(
                AuditEventType.CONNECT_SUCCESS.value
                if success
                else AuditEventType.CONNECT_FAILURE.value
            ),
            severity=AuditSeverity.MEDIUM.value if not success else AuditSeverity.LOW.value,
            host=host,
            port=port,
            user=user,
            transport=transport,
            detail=detail,
            auth_method=auth_method,
        )
        self._record(event)

    def log_auth(
        self,
        host: str,
        port: int,
        user: str,
        transport: str,
        auth_method: str,
        success: bool = True,
        error_code: Optional[str] = None,
    ) -> None:
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=(
                AuditEventType.AUTH_SUCCESS.value
                if success
                else AuditEventType.AUTH_FAILURE.value
            ),
            severity=AuditSeverity.MEDIUM.value if not success else AuditSeverity.LOW.value,
            host=host,
            port=port,
            user=user,
            transport=transport,
            auth_method=auth_method,
            error_code=error_code,
        )
        self._record(event)

    def log_command(
        self,
        host: str,
        port: int,
        user: str,
        transport: str,
        command: str,
        success: bool = True,
        exit_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
        sudo_attempted: bool = False,
    ) -> None:
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=(
                AuditEventType.COMMAND_SUCCESS.value
                if success
                else AuditEventType.COMMAND_FAILURE.value
            ),
            severity=AuditSeverity.MEDIUM.value if not success else AuditSeverity.LOW.value,
            host=host,
            port=port,
            user=user,
            transport=transport,
            command=command[:200] if command else None,
            exit_code=exit_code,
            duration_ms=duration_ms,
            sudo_attempted=sudo_attempted,
        )
        self._record(event)

    def log_security_event(
        self,
        host: str,
        port: int,
        user: str,
        transport: str,
        event_type: AuditEventType,
        severity: AuditSeverity,
        detail: str,
        error_code: Optional[str] = None,
    ) -> None:
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type.value,
            severity=severity.value,
            host=host,
            port=port,
            user=user,
            transport=transport,
            detail=detail,
            error_code=error_code,
        )
        self._record(event)


_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_PORTS: dict[TransportType, int] = {
    TransportType.SSH: 22,
    TransportType.TELNET: 23,
    TransportType.TCP: 9000,
    TransportType.UDP: 9000,
    TransportType.SERIAL: 0,
}

DEFAULT_CONNECT_TIMEOUT = 15
DEFAULT_COMMAND_TIMEOUT = 120
DEFAULT_KEEPALIVE = 15


@dataclass
class ServerConfig:
    """Fully-typed configuration for one server connection."""

    # Network
    host: str
    port: int
    transport: TransportType

    # Identity
    user: str
    name: str

    # Auth
    auth: AuthType
    password: Optional[str] = field(default=None, repr=False)
    sudo_password: Optional[str] = field(default=None, repr=False)
    key_path: Optional[Path] = None
    key_algorithm: Optional[KeyAlgorithm] = None
    no_host_check: bool = False

    # Timeouts / keepalive
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT
    command_timeout: int = DEFAULT_COMMAND_TIMEOUT
    keepalive: int = DEFAULT_KEEPALIVE

    # Hints
    server_os: ServerOS = ServerOS.UNKNOWN
    server_role: ServerRole = ServerRole.GENERIC

    # Misc
    verbose: bool = False

    def __post_init__(self) -> None:
        if not self.host:
            raise MissingHostError("Host is required.")
        if not self.user:
            raise MissingUserError("User is required.")
        if not (1 <= self.port <= 65535):
            raise InvalidPortError(
                f"Port {self.port} is out of range (1–65535).",
                context={"port": self.port},
            )
        if self.auth == AuthType.PASSWORD and not self.password:
            raise MissingCredentialError(
                "Auth method is 'password' but --password was not supplied."
            )
        if self.auth == AuthType.KEY_FILE:
            if not self.key_path:
                raise MissingCredentialError(
                    "Auth method is 'key_file' but --key was not supplied."
                )
            if not self.key_path.exists():
                raise MissingCredentialError(
                    f"Key file not found: {self.key_path}",
                    context={"key_path": str(self.key_path)},
                )

    def redacted(self) -> dict:
        """Return a loggable dict with credentials stripped."""
        return {
            "host": self.host,
            "port": self.port,
            "transport": self.transport.value,
            "user": self.user,
            "name": self.name,
            "auth": self.auth.value,
            "key_path": str(self.key_path) if self.key_path else None,
            "sudo_password": "<set>" if self.sudo_password else None,
            "connect_timeout": self.connect_timeout,
            "command_timeout": self.command_timeout,
            "keepalive": self.keepalive,
            "server_os": self.server_os.value,
            "server_role": self.server_role.value,
            "no_host_check": self.no_host_check,
            "verbose": self.verbose,
        }


def parse_args(argv: list[str] | None = None) -> ServerConfig:
    """Parse CLI arguments into a validated ServerConfig."""
    parser = argparse.ArgumentParser(
        prog="kit-mcp",
        description="KIT-MCP — Generic MCP server for remote shell access.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Network
    net = parser.add_argument_group("Network")
    net.add_argument("--host", required=True, help="Hostname or IP address")
    net.add_argument("--port", type=int, default=None, help="Port number")
    net.add_argument(
        "--transport",
        default=TransportType.SSH.value,
        choices=[t.value for t in TransportType],
        help="Transport type",
    )

    # Identity
    identity = parser.add_argument_group("Identity")
    identity.add_argument("--user", required=True, help="Username for authentication")
    identity.add_argument("--name", default=None, help="Human-readable server label")

    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument(
        "--auth",
        required=True,
        choices=[a.value for a in AuthType],
        help="Auth method",
    )
    auth.add_argument("--password", default=None, help="Password")
    auth.add_argument("--sudo-password", default=None, dest="sudo_password", help="Sudo password")
    auth.add_argument("--key", default=None, help="Path to private key file")
    auth.add_argument(
        "--key-algo",
        default=None,
        dest="key_algo",
        choices=[k.value for k in KeyAlgorithm],
        help="Key algorithm",
    )
    auth.add_argument(
        "--no-host-check", action="store_true", default=False, help="Disable host-key verification"
    )

    # Timing
    timing = parser.add_argument_group("Timeouts & keepalive")
    timing.add_argument("--timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT, help="Connection timeout")
    timing.add_argument("--cmd-timeout", type=int, default=DEFAULT_COMMAND_TIMEOUT, dest="cmd_timeout", help="Command timeout")
    timing.add_argument("--keepalive", type=int, default=DEFAULT_KEEPALIVE, help="Keepalive interval")

    # Hints
    hints = parser.add_argument_group("Server hints")
    hints.add_argument("--os", default=ServerOS.UNKNOWN.value, choices=[o.value for o in ServerOS], help="OS hint")
    hints.add_argument("--role", default=ServerRole.GENERIC.value, choices=[r.value for r in ServerRole], help="Server role")

    parser.add_argument("--verbose", "-v", action="store_true", default=False, help="Verbose logging")

    ns = parser.parse_args(argv)
    transport = TransportType(ns.transport)
    port = ns.port if ns.port is not None else DEFAULT_PORTS[transport]
    password = ns.password or os.environ.get("KIT_MCP_PASSWORD")
    sudo_password = ns.sudo_password or os.environ.get("KIT_MCP_SUDO_PASSWORD")

    # Security: Validate hostname/username
    if not validate_hostname(ns.host):
        raise MissingHostError(f"Invalid hostname: {ns.host}")
    if not validate_username(ns.user):
        raise MissingUserError(f"Invalid username: {ns.user}")

    # Security: Check for credential leakage
    if check_credential_leakage(ns.password, "KIT_MCP_PASSWORD"):
        logging.warning("Credential in both CLI and KIT_MCP_PASSWORD")
    if check_credential_leakage(ns.sudo_password, "KIT_MCP_SUDO_PASSWORD"):
        logging.warning("Sudo password in both CLI and KIT_MCP_SUDO_PASSWORD")
    if ns.no_host_check:
        logging.warning("Host key verification disabled (dev only)")

    name = ns.name or f"{ns.user}@{ns.host}"

    return ServerConfig(
        host=ns.host,
        port=port,
        transport=transport,
        user=ns.user,
        name=name,
        auth=AuthType(ns.auth),
        password=password,
        sudo_password=sudo_password,
        key_path=Path(ns.key).expanduser() if ns.key else None,
        key_algorithm=KeyAlgorithm(ns.key_algo) if ns.key_algo else None,
        no_host_check=ns.no_host_check,
        connect_timeout=ns.timeout,
        command_timeout=ns.cmd_timeout,
        keepalive=ns.keepalive,
        server_os=ServerOS(ns.os),
        server_role=ServerRole(ns.role),
        verbose=ns.verbose,
    )


# ═════════════════════════════════════════════════════════════════════════════
#  TRANSPORT LAYER
# ═════════════════════════════════════════════════════════════════════════════

log = logging.getLogger("kit_mcp")


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class BaseTransport(ABC):
    """Protocol-agnostic transport interface."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.state = ConnectionState.DISCONNECTED
        self._lock = threading.Lock()

    @abstractmethod
    def connect(self) -> None:
        pass

    @abstractmethod
    def exec(self, command: str) -> CommandResult:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    def is_alive(self) -> bool:
        return self.state == ConnectionState.AUTHENTICATED

    def reconnect(self) -> None:
        self.close()
        self.connect()

    def __enter__(self) -> "BaseTransport":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


_PARAMIKO_KEY_LOADERS: dict[KeyAlgorithm, type[paramiko.PKey]] = {
    KeyAlgorithm.ED25519: paramiko.Ed25519Key,
    KeyAlgorithm.RSA: paramiko.RSAKey,
    KeyAlgorithm.ECDSA: paramiko.ECDSAKey,
}

_AUTO_LOADERS = list(_PARAMIKO_KEY_LOADERS.values())


class SSHTransport(BaseTransport):
    """Paramiko-backed SSH transport with security hardening."""

    _FAILED_AUTH_THRESHOLD = 5
    _RATE_LIMIT_WINDOW = 300
    _failed_attempts: dict[str, list[float]] = {}
    _rate_limit_lock = threading.Lock()

    def __init__(self, config: ServerConfig) -> None:
        super().__init__(config)
        self._client: Optional[paramiko.SSHClient] = None
        self._audit = get_audit_logger()
        self._auth_attempts = 0

    @classmethod
    def _check_rate_limit(cls, host: str, port: int, user: str) -> bool:
        """Check if host:port:user exceeds auth attempts."""
        key = f"{host}:{port}:{user}"
        now = time.time()
        with cls._rate_limit_lock:
            if key not in cls._failed_attempts:
                cls._failed_attempts[key] = []
            cls._failed_attempts[key] = [
                t for t in cls._failed_attempts[key] if now - t < cls._RATE_LIMIT_WINDOW
            ]
            return len(cls._failed_attempts[key]) < cls._FAILED_AUTH_THRESHOLD

    @classmethod
    def _record_failed_attempt(cls, host: str, port: int, user: str) -> None:
        key = f"{host}:{port}:{user}"
        with cls._rate_limit_lock:
            if key not in cls._failed_attempts:
                cls._failed_attempts[key] = []
            cls._failed_attempts[key].append(time.time())

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
                raise KeyPassphraseError(
                    f"Key {path} requires a passphrase.",
                    context={"key_path": str(path)},
                    cause=e,
                )
            except paramiko.ssh_exception.SSHException as e:
                last_exc = e

        raise BadKeyError(
            f"Could not load key {path}.",
            context={"key_path": str(path)},
            cause=last_exc,
        )

    def connect(self) -> None:
        cfg = self.config
        self.state = ConnectionState.CONNECTING

        if not self._check_rate_limit(cfg.host, cfg.port, cfg.user):
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
            "hostname": cfg.host,
            "port": cfg.port,
            "username": cfg.user,
            "timeout": cfg.connect_timeout,
            "banner_timeout": cfg.connect_timeout,
            "auth_timeout": cfg.connect_timeout,
        }

        if cfg.auth == AuthType.PASSWORD:
            connect_kwargs["password"] = cfg.password
            connect_kwargs["allow_agent"] = False
            connect_kwargs["look_for_keys"] = False
        elif cfg.auth == AuthType.KEY_FILE:
            connect_kwargs["pkey"] = self._load_key()
            connect_kwargs["allow_agent"] = False
            connect_kwargs["look_for_keys"] = False
        elif cfg.auth == AuthType.KEY_AGENT:
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = False
        elif cfg.auth == AuthType.NONE:
            connect_kwargs["allow_agent"] = False
            connect_kwargs["look_for_keys"] = False

        try:
            client.connect(**connect_kwargs)
            self._audit.log_auth(
                host=cfg.host,
                port=cfg.port,
                user=cfg.user,
                transport=cfg.transport.value,
                auth_method=cfg.auth.value,
                success=True,
            )
        except paramiko.AuthenticationException as e:
            self._record_failed_attempt(cfg.host, cfg.port, cfg.user)
            self._auth_attempts += 1
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
                raise BadPasswordError(str(e), cause=e, context={"host": cfg.host, "user": cfg.user})
            self._audit.log_auth(
                host=cfg.host,
                port=cfg.port,
                user=cfg.user,
                transport=cfg.transport.value,
                auth_method=cfg.auth.value,
                success=False,
                error_code="AUTH_PERMISSION_DENIED",
            )
            raise PermissionDeniedError(str(e), cause=e, context={"host": cfg.host, "user": cfg.user})
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
            raise ConnectionRefusedError(str(e), cause=e, context={"host": cfg.host, "port": cfg.port})
        except paramiko.ssh_exception.SSHException as e:
            msg = str(e).lower()
            if "negotiate" in msg or "cipher" in msg or "kex" in msg:
                raise NegotiationError(str(e), cause=e)
            if "banner" in msg:
                raise BannerTimeoutError(str(e), cause=e, context={"host": cfg.host, "port": cfg.port})
            raise KitMCPError(str(e), cause=e)
        except socket.timeout as e:
            raise ConnectTimeoutError(
                f"Connection to {cfg.host}:{cfg.port} timed out after {cfg.connect_timeout}s.",
                cause=e,
                context={"host": cfg.host, "port": cfg.port, "timeout": cfg.connect_timeout},
            )
        except socket.gaierror as e:
            raise DNSFailureError(f"Cannot resolve '{cfg.host}'.", cause=e, context={"host": cfg.host})
        except Exception as e:
            raise HostUnreachableError(str(e), cause=e, context={"host": cfg.host, "port": cfg.port})

        if cfg.keepalive > 0:
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(cfg.keepalive)

        self._client = client
        self.state = ConnectionState.AUTHENTICATED

    def exec(self, command: str) -> CommandResult:
        start = time.time()

        if not self._client or not self.is_alive():
            self.reconnect()

        assert self._client is not None

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

        needs_sudo = command.strip().startswith("sudo") and self.config.sudo_password

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=self.config.command_timeout,
                get_pty=needs_sudo,
            )

            if needs_sudo:
                stdin.write(self.config.sudo_password + "\n")
                stdin.flush()
            else:
                stdin.close()

            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()

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
                context={"command": command[:200], "timeout": self.config.command_timeout},
            )
        except (paramiko.ssh_exception.SSHException, EOFError, OSError) as e:
            self._reset()
            raise KeepaliveError(
                "Transport lost during command execution.",
                cause=e,
                context={"command": command[:200]},
            )

        duration_ms = int((time.time() - start) * 1000)
        return CommandResult(exit_code=exit_code, stdout=out, stderr=err, duration_ms=duration_ms)

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


def create_transport(config: ServerConfig) -> BaseTransport:
    """Instantiate the correct transport for config.transport."""
    if config.transport == TransportType.SSH:
        return SSHTransport(config)
    raise UnsupportedTransportError(
        f"Transport '{config.transport.value}' is not yet implemented.",
        context={"transport": config.transport.value},
    )


# ═════════════════════════════════════════════════════════════════════════════
#  MCP SERVER
# ═════════════════════════════════════════════════════════════════════════════

mcp = FastMCP("KIT Generic MCP Server")

_lock: threading.Lock = threading.Lock()
_transport: BaseTransport | None = None
_config: ServerConfig | None = None


def _get_transport() -> BaseTransport:
    global _transport, _config
    with _lock:
        if _config is None:
            raise RuntimeError("Server not initialised. Call init_server(config) before running.")
        if _transport is None or not _transport.is_alive():
            if _transport is not None:
                try:
                    _transport.close()
                except Exception:
                    pass
            _transport = create_transport(_config)
            _transport.connect()
        return _transport


def _reset_transport() -> None:
    global _transport
    with _lock:
        if _transport is not None:
            try:
                _transport.close()
            except Exception:
                pass
            _transport = None


def init_server(config: ServerConfig) -> None:
    """Attach a ServerConfig to this MCP server."""
    global _config
    _config = config
    if config.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    log.info("KIT-MCP initialised: %s", config.redacted())


def _serialise(result: CommandResult) -> dict[str, Any]:
    return {
        "exit_code": result.exit_code,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_ms": result.duration_ms,
    }


def _error_response(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, KitMCPError):
        return {
            "ok": False,
            "error": exc.code.value,
            "category": exc.category.value,
            "detail": exc.detail,
            "context": exc.context,
        }
    return {"ok": False, "error": "UNKNOWN_ERROR", "detail": str(exc)}


@mcp.tool()
def run_command(command: str) -> dict[str, Any]:
    """Run an arbitrary shell command on the configured remote server."""
    try:
        transport = _get_transport()
        result = transport.exec(command)
        log.debug("exec %r → exit=%d (%dms)", command[:80], result.exit_code, result.duration_ms)
        return _serialise(result)
    except KitMCPError as e:
        log.warning("KitMCPError during exec: %s", e)
        _reset_transport()
        return _error_response(e)
    except Exception as e:
        log.exception("Unexpected error during exec")
        _reset_transport()
        return _error_response(e)


@mcp.tool()
def connect_server(prompt: str) -> dict[str, Any]:
    """Convenience alias: executes *prompt* as a shell command."""
    return run_command(prompt)


@mcp.tool()
def server_status() -> dict[str, Any]:
    """Check reachability and return connection metadata."""
    if _config is None:
        return {"reachable": False, "detail": "Server not initialised."}

    ping_result = run_command("echo ok")

    base: dict[str, Any] = {
        "reachable": ping_result.get("ok", False),
        "name": _config.name,
        "host": _config.host,
        "port": _config.port,
        "transport": _config.transport.value,
        "auth": _config.auth.value,
        "user": _config.user,
        "server_os": _config.server_os.value,
        "server_role": _config.server_role.value,
    }

    if _config.key_path:
        base["ssh_key"] = str(_config.key_path)

    if not ping_result.get("ok"):
        base["error"] = ping_result.get("error")
        base["category"] = ping_result.get("category")
        base["detail"] = ping_result.get("detail")

    return base


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Main entry point."""
    config = parse_args()
    init_server(config)
    mcp.run()


if __name__ == "__main__":
    main()
