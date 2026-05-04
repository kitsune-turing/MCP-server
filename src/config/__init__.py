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
    """
    parser = _build_parser()
    ns     = parser.parse_args(argv)

    transport = TransportType(ns.transport)

    # Resolve port: explicit flag > transport default
    port = ns.port if ns.port is not None else DEFAULT_PORTS[transport]

    # Password: flag > env variable KIT_MCP_PASSWORD
    password = ns.password or os.environ.get("KIT_MCP_PASSWORD")
    sudo_password = ns.sudo_password or os.environ.get("KIT_MCP_SUDO_PASSWORD")

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
