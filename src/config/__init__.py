"""
KIT-MCP Server — Configuration
Parses CLI flags into a typed ServerConfig dataclass.

Usage
-----
  python -m kit_mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_rpi5
  python -m kit_mcp --host 10.0.0.5 --user admin --auth password --password s3cr3t --port 2222
  python -m kit_mcp --host serial:///dev/ttyUSB0 --transport serial --user root --auth none
"""
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from kit_mcp.enums import (
    AuthType,
    CLI_FLAG_DESCRIPTIONS,
    KeyAlgorithm,
    ServerOS,
    ServerRole,
    TransportType,
)
from kit_mcp.errors import (
    InvalidPortError,
    MissingCredentialError,
    MissingHostError,
    MissingUserError,
    UnsupportedTransportError,
)
from kit_mcp.security import (
    validate_hostname,
    validate_username,
    validate_port,
    check_credential_leakage,
)
from kit_mcp.audit import get_audit_logger, AuditEventType, AuditSeverity

import logging

log = logging.getLogger("kit_mcp.config")


# ─────────────────────────────────────────────
#  Defaults
# ─────────────────────────────────────────────

DEFAULT_PORTS: dict[TransportType, int] = {
    TransportType.SSH   : 22,
    TransportType.TELNET: 23,
    TransportType.TCP   : 9000,
    TransportType.UDP   : 9000,
    TransportType.SERIAL: 0,  # N/A for serial
}

DEFAULT_CONNECT_TIMEOUT  = 15   # seconds
DEFAULT_COMMAND_TIMEOUT  = 120  # seconds
DEFAULT_KEEPALIVE        = 15   # seconds


# ─────────────────────────────────────────────
#  Dataclass
# ─────────────────────────────────────────────

@dataclass
class ServerConfig:
    """
    Fully-typed configuration for one server connection.

    All values are resolved and validated at construction time.
    Mutate nothing after creation — treat as immutable.
    """

    # Network
    host          : str
    port          : int
    transport     : TransportType

    # Identity
    user          : str
    name          : str               # Human-readable label

    # Auth
    auth          : AuthType
    password      : Optional[str]     = field(default=None, repr=False)
    sudo_password : Optional[str]     = field(default=None, repr=False)
    key_path      : Optional[Path]    = None
    key_algorithm : Optional[KeyAlgorithm] = None
    no_host_check : bool              = False

    # Timeouts / keepalive
    connect_timeout : int  = DEFAULT_CONNECT_TIMEOUT
    command_timeout : int  = DEFAULT_COMMAND_TIMEOUT
    keepalive       : int  = DEFAULT_KEEPALIVE

    # Hints (optional, for command adaptation)
    server_os   : ServerOS   = ServerOS.UNKNOWN
    server_role : ServerRole = ServerRole.GENERIC

    # Misc
    verbose : bool = False

    # ── Post-init validation ──────────────────

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
            "host"           : self.host,
            "port"           : self.port,
            "transport"      : self.transport.value,
            "user"           : self.user,
            "name"           : self.name,
            "auth"           : self.auth.value,
            "key_path"       : str(self.key_path) if self.key_path else None,
            "sudo_password"  : "<set>" if self.sudo_password else None,
            "connect_timeout": self.connect_timeout,
            "command_timeout": self.command_timeout,
            "keepalive"      : self.keepalive,
            "server_os"      : self.server_os.value,
            "server_role"    : self.server_role.value,
            "no_host_check"  : self.no_host_check,
            "verbose"        : self.verbose,
        }


# ─────────────────────────────────────────────
#  CLI parser
# ─────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kit-mcp",
        description=(
            "KIT-MCP — Generic MCP server for remote shell access.\n"
            "Connect to any SSH / Telnet / TCP server via typed CLI flags.\n\n"
            "Examples:\n"
            "  kit-mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_ed25519\n"
            "  kit-mcp --host 10.0.0.5 --user admin --auth password --password s3cr3t --port 2222\n"
            "  kit-mcp --host 172.16.0.1 --user admin --transport telnet --auth none\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    D = CLI_FLAG_DESCRIPTIONS  # shorthand

    net = p.add_argument_group("Network")
    net.add_argument("--host",      required=True,  help=D["--host"])
    net.add_argument("--port",      type=int,        default=None, help=D["--port"])
    net.add_argument("--transport", default=TransportType.SSH.value,
                     choices=[t.value for t in TransportType], help=D["--transport"])

    identity = p.add_argument_group("Identity")
    identity.add_argument("--user",      required=True,  help=D["--user"])
    identity.add_argument("--name",      default=None,   help="Human-readable server label")

    auth = p.add_argument_group("Authentication")
    auth.add_argument("--auth",     required=True,
                      choices=[a.value for a in AuthType], help=D["--auth"])
    auth.add_argument("--password", default=None, help=D["--password"])
    auth.add_argument("--sudo-password", default=None, dest="sudo_password",
                      help="Password for sudo commands (separate from login password)")
    auth.add_argument("--key",      default=None, help=D["--key"])
    auth.add_argument("--key-algo", default=None, dest="key_algo",
                      choices=[k.value for k in KeyAlgorithm], help=D["--key-algo"])
    auth.add_argument("--no-host-check", action="store_true",
                      default=False, help=D["--no-host-check"])

    timing = p.add_argument_group("Timeouts & keepalive")
    timing.add_argument("--timeout",     type=int, default=DEFAULT_CONNECT_TIMEOUT,
                         help=D["--timeout"])
    timing.add_argument("--cmd-timeout", type=int, default=DEFAULT_COMMAND_TIMEOUT,
                         dest="cmd_timeout", help=D["--cmd-timeout"])
    timing.add_argument("--keepalive",   type=int, default=DEFAULT_KEEPALIVE,
                         help=D["--keepalive"])

    hints = p.add_argument_group("Server hints (optional)")
    hints.add_argument("--os",   default=ServerOS.UNKNOWN.value,
                       choices=[o.value for o in ServerOS], help=D["--os"])
    hints.add_argument("--role", default=ServerRole.GENERIC.value,
                       choices=[r.value for r in ServerRole], help=D["--role"])

    p.add_argument("--verbose", "-v", action="store_true", default=False, help=D["--verbose"])

    return p


def parse_args(argv: list[str] | None = None) -> ServerConfig:
    """
    Parse *argv* (or sys.argv[1:]) into a validated :class:`ServerConfig`.

    Raises typed :class:`~kit_mcp.errors.ConfigError` sub-classes on
    validation failures.
    
    Security checks:
    - ISO 27001/27002: Credential validation, hostname verification
    - NIST: Input validation to prevent injection attacks
    """
    parser = _build_parser()
    ns     = parser.parse_args(argv)

    # Security: Validate hostname
    if not validate_hostname(ns.host):
        raise MissingHostError(
            f"Invalid hostname: {ns.host}. Must be valid FQDN or IP address."
        )

    # Security: Validate username
    if not validate_username(ns.user):
        raise MissingUserError(
            f"Invalid username: {ns.user}. Use alphanumeric + _ (max 32 chars)."
        )

    # Security: Validate port
    if not validate_port(ns.port if ns.port is not None else 22):
        raise InvalidPortError("Port is out of valid range.")

    transport = TransportType(ns.transport)

    # Resolve port: explicit flag > transport default
    port = ns.port if ns.port is not None else DEFAULT_PORTS[transport]

    # Password: flag > env variable KIT_MCP_PASSWORD
    password = ns.password or os.environ.get("KIT_MCP_PASSWORD")
    sudo_password = ns.sudo_password or os.environ.get("KIT_MCP_SUDO_PASSWORD")

    # Security: Check for credential leakage (both CLI and env set)
    if check_credential_leakage(ns.password, "KIT_MCP_PASSWORD"):
        log.warning(
            "Credential set in both CLI flag and KIT_MCP_PASSWORD environment variable. "
            "CLI flag will be used. Environment variable should be cleared."
        )
        # Audit this security event
        audit = get_audit_logger()
        audit.log_security_event(
            host=ns.host,
            port=port,
            user=ns.user,
            transport=transport.value,
            event_type=AuditEventType.SECURITY_WARNING,
            severity=AuditSeverity.MEDIUM,
            detail="Password specified in both CLI flag and environment variable",
        )

    if check_credential_leakage(ns.sudo_password, "KIT_MCP_SUDO_PASSWORD"):
        log.warning(
            "Sudo password set in both CLI flag and KIT_MCP_SUDO_PASSWORD environment variable. "
            "CLI flag will be used. Environment variable should be cleared."
        )
        # Audit this security event
        audit = get_audit_logger()
        audit.log_security_event(
            host=ns.host,
            port=port,
            user=ns.user,
            transport=transport.value,
            event_type=AuditEventType.SECURITY_WARNING,
            severity=AuditSeverity.MEDIUM,
            detail="Sudo password specified in both CLI flag and environment variable",
        )

    # Security: Warn about --no-host-check
    if ns.no_host_check:
        log.warning(
            "Host key verification disabled (--no-host-check). "
            "This allows MITM attacks. Only use in development/testing."
        )
        audit = get_audit_logger()
        audit.log_security_event(
            host=ns.host,
            port=port,
            user=ns.user,
            transport=transport.value,
            event_type=AuditEventType.SECURITY_WARNING,
            severity=AuditSeverity.HIGH,
            detail="Host key verification disabled (--no-host-check)",
        )

    # Name defaults to user@host
    name = ns.name or f"{ns.user}@{ns.host}"

    return ServerConfig(
        host            = ns.host,
        port            = port,
        transport       = transport,
        user            = ns.user,
        name            = name,
        auth            = AuthType(ns.auth),
        password        = password,
        sudo_password   = sudo_password,
        key_path        = Path(ns.key).expanduser() if ns.key else None,
        key_algorithm   = KeyAlgorithm(ns.key_algo) if ns.key_algo else None,
        no_host_check   = ns.no_host_check,
        connect_timeout = ns.timeout,
        command_timeout = ns.cmd_timeout,
        keepalive       = ns.keepalive,
        server_os       = ServerOS(ns.os),
        server_role     = ServerRole(ns.role),
        verbose         = ns.verbose,
    )
