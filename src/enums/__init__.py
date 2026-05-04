"""
KIT-MCP Server — Enums
All typed constants used across the MCP server framework.
"""
from __future__ import annotations

from enum import Enum, auto


# ─────────────────────────────────────────────
#  Transport / Protocol
# ─────────────────────────────────────────────

class TransportType(str, Enum):
    """Supported transport protocols."""
    SSH    = "ssh"
    TELNET = "telnet"
    SERIAL = "serial"
    TCP    = "tcp"
    UDP    = "udp"


# ─────────────────────────────────────────────
#  Authentication
# ─────────────────────────────────────────────

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
    DSA     = "dsa"


# ─────────────────────────────────────────────
#  Connection State
# ─────────────────────────────────────────────

class ConnectionState(str, Enum):
    """Lifecycle state of a server connection."""
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    AUTHENTICATED = "authenticated"
    FAILED       = "failed"
    CLOSED       = "closed"


# ─────────────────────────────────────────────
#  Error Category
# ─────────────────────────────────────────────

class ErrorCategory(str, Enum):
    """Top-level error classification."""
    CONNECTION   = "connection"   # Network / socket level
    AUTH         = "auth"         # Credential / key issues
    TIMEOUT      = "timeout"      # Command or connect timeout
    COMMAND      = "command"      # Remote execution errors
    CONFIG       = "config"       # Bad flags / missing values
    TRANSPORT    = "transport"    # Protocol-level errors
    UNKNOWN      = "unknown"


class ErrorCode(str, Enum):
    """
    Fine-grained error codes for programmatic handling.
    Format: CATEGORY_DETAIL
    """
    # Connection
    CONNECTION_REFUSED       = "CONNECTION_REFUSED"
    CONNECTION_TIMEOUT       = "CONNECTION_TIMEOUT"
    CONNECTION_RESET         = "CONNECTION_RESET"
    CONNECTION_HOST_UNREACHABLE = "CONNECTION_HOST_UNREACHABLE"
    CONNECTION_DNS_FAILURE   = "CONNECTION_DNS_FAILURE"

    # Auth
    AUTH_BAD_PASSWORD        = "AUTH_BAD_PASSWORD"
    AUTH_BAD_KEY             = "AUTH_BAD_KEY"
    AUTH_KEY_NOT_FOUND       = "AUTH_KEY_NOT_FOUND"
    AUTH_KEY_PASSPHRASE      = "AUTH_KEY_PASSPHRASE"
    AUTH_HOST_KEY_MISMATCH   = "AUTH_HOST_KEY_MISMATCH"
    AUTH_PERMISSION_DENIED   = "AUTH_PERMISSION_DENIED"
    AUTH_MFA_REQUIRED        = "AUTH_MFA_REQUIRED"

    # Timeout
    TIMEOUT_CONNECT          = "TIMEOUT_CONNECT"
    TIMEOUT_COMMAND          = "TIMEOUT_COMMAND"
    TIMEOUT_BANNER           = "TIMEOUT_BANNER"
    TIMEOUT_AUTH             = "TIMEOUT_AUTH"

    # Command
    COMMAND_NON_ZERO_EXIT    = "COMMAND_NON_ZERO_EXIT"
    COMMAND_SIGNAL_KILLED    = "COMMAND_SIGNAL_KILLED"
    COMMAND_PTY_FAILED       = "COMMAND_PTY_FAILED"

    # Config
    CONFIG_MISSING_HOST      = "CONFIG_MISSING_HOST"
    CONFIG_MISSING_USER      = "CONFIG_MISSING_USER"
    CONFIG_INVALID_PORT      = "CONFIG_INVALID_PORT"
    CONFIG_MISSING_CREDENTIAL = "CONFIG_MISSING_CREDENTIAL"
    CONFIG_UNSUPPORTED_TRANSPORT = "CONFIG_UNSUPPORTED_TRANSPORT"

    # Transport
    TRANSPORT_NEGOTIATION    = "TRANSPORT_NEGOTIATION"
    TRANSPORT_KEEPALIVE_LOST = "TRANSPORT_KEEPALIVE_LOST"

    # Generic
    UNKNOWN_ERROR            = "UNKNOWN_ERROR"


# ─────────────────────────────────────────────
#  Server / OS hints (informational)
# ─────────────────────────────────────────────

class ServerOS(str, Enum):
    """Operating system hint — used for command adaptation."""
    LINUX   = "linux"
    BSD     = "bsd"
    MACOS   = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class ServerRole(str, Enum):
    """Semantic role of the target server."""
    GENERIC        = "generic"
    RASPBERRY_PI   = "raspberry_pi"
    ROUTER         = "router"
    DATABASE       = "database"
    WEB            = "web"
    EMBEDDED       = "embedded"


# ─────────────────────────────────────────────
#  Flag aliases (CLI help text)
# ─────────────────────────────────────────────

CLI_FLAG_DESCRIPTIONS: dict[str, str] = {
    "--host"        : "Hostname or IP address of the target server",
    "--port"        : "Port number (default: 22 for SSH, 23 for Telnet)",
    "--user"        : "Username for authentication",
    "--transport"   : f"Transport type: {', '.join(t.value for t in TransportType)}",
    "--auth"        : f"Auth method: {', '.join(a.value for a in AuthType)}",
    "--password"    : "Password (use with --auth password). Prefer key auth.",
    "--key"         : "Path to private key file (use with --auth key_file)",
    "--key-algo"    : f"Key algorithm hint: {', '.join(k.value for k in KeyAlgorithm)}",
    "--timeout"     : "Connection timeout in seconds (default: 15)",
    "--cmd-timeout" : "Per-command execution timeout in seconds (default: 120)",
    "--keepalive"   : "SSH keepalive interval in seconds (default: 15, 0 = disabled)",
    "--os"          : f"OS hint: {', '.join(o.value for o in ServerOS)}",
    "--role"        : f"Server role hint: {', '.join(r.value for r in ServerRole)}",
    "--name"        : "Human-readable label for this server (used in logs)",
    "--no-host-check": "Disable host-key verification (insecure, dev only)",
    "--verbose"     : "Enable verbose logging",
}
