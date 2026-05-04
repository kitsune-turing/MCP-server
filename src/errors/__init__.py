"""
KIT-MCP Server — Error Hierarchy
Every failure surfaces as a typed, categorized exception with an ErrorCode.
"""
from __future__ import annotations

from typing import Any

from kit_mcp.enums import ErrorCategory, ErrorCode


# ─────────────────────────────────────────────
#  Base
# ─────────────────────────────────────────────

class KitMCPError(Exception):
    """
    Root exception for all KIT-MCP errors.

    Attributes:
        code     : Fine-grained machine-readable code (ErrorCode enum).
        category : Broad error bucket (ErrorCategory enum).
        detail   : Human-readable explanation.
        context  : Optional extra data for debugging (host, port, …).
        cause    : Original exception that triggered this error.
    """

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


# ─────────────────────────────────────────────
#  Connection errors
# ─────────────────────────────────────────────

class ConnectionError(KitMCPError):
    """Could not establish a network connection to the server."""
    category = ErrorCategory.CONNECTION


class ConnectionRefusedError(ConnectionError):
    """Server actively refused the connection on the given port."""
    code = ErrorCode.CONNECTION_REFUSED


class ConnectionTimeoutError(ConnectionError):
    """Network connection attempt timed out before a response was received."""
    code = ErrorCode.CONNECTION_TIMEOUT


class ConnectionResetError(ConnectionError):
    """An existing connection was unexpectedly reset by the peer."""
    code = ErrorCode.CONNECTION_RESET


class HostUnreachableError(ConnectionError):
    """No route to host (ICMP unreachable or routing failure)."""
    code = ErrorCode.CONNECTION_HOST_UNREACHABLE


class DNSFailureError(ConnectionError):
    """Hostname could not be resolved to an IP address."""
    code = ErrorCode.CONNECTION_DNS_FAILURE


# ─────────────────────────────────────────────
#  Authentication errors
# ─────────────────────────────────────────────

class AuthError(KitMCPError):
    """Authentication to the remote server failed."""
    category = ErrorCategory.AUTH


class BadPasswordError(AuthError):
    """The supplied password was rejected by the server."""
    code = ErrorCode.AUTH_BAD_PASSWORD


class BadKeyError(AuthError):
    """The private key is malformed, encrypted, or incompatible."""
    code = ErrorCode.AUTH_BAD_KEY


class KeyNotFoundError(AuthError):
    """The specified key file does not exist or is not readable."""
    code = ErrorCode.AUTH_KEY_NOT_FOUND


class KeyPassphraseError(AuthError):
    """The key file requires a passphrase that was not supplied or was wrong."""
    code = ErrorCode.AUTH_KEY_PASSPHRASE


class HostKeyMismatchError(AuthError):
    """
    The remote host key does not match the known_hosts record.
    This may indicate a MITM attack or a legitimate server change.
    """
    code = ErrorCode.AUTH_HOST_KEY_MISMATCH


class PermissionDeniedError(AuthError):
    """Server denied the authentication attempt (wrong user or disallowed method)."""
    code = ErrorCode.AUTH_PERMISSION_DENIED


class MFARequiredError(AuthError):
    """Server requires multi-factor authentication which is not yet configured."""
    code = ErrorCode.AUTH_MFA_REQUIRED


# ─────────────────────────────────────────────
#  Timeout errors
# ─────────────────────────────────────────────

class TimeoutError(KitMCPError):
    """An operation exceeded its configured time limit."""
    category = ErrorCategory.TIMEOUT


class ConnectTimeoutError(TimeoutError):
    """TCP/SSH handshake did not complete within the connection timeout."""
    code = ErrorCode.TIMEOUT_CONNECT


class CommandTimeoutError(TimeoutError):
    """A remote command ran for longer than the command timeout."""
    code = ErrorCode.TIMEOUT_COMMAND


class BannerTimeoutError(TimeoutError):
    """Server did not send the SSH banner within the banner timeout."""
    code = ErrorCode.TIMEOUT_BANNER


class AuthTimeoutError(TimeoutError):
    """Authentication exchange did not complete within the auth timeout."""
    code = ErrorCode.TIMEOUT_AUTH


# ─────────────────────────────────────────────
#  Command errors
# ─────────────────────────────────────────────

class CommandError(KitMCPError):
    """Remote command execution problem."""
    category = ErrorCategory.COMMAND


class NonZeroExitError(CommandError):
    """The remote command exited with a non-zero status code."""
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
    """The remote command was killed by a signal (e.g. OOM killer, SIGKILL)."""
    code = ErrorCode.COMMAND_SIGNAL_KILLED


class PTYFailedError(CommandError):
    """Failed to allocate a pseudo-terminal on the remote side."""
    code = ErrorCode.COMMAND_PTY_FAILED


# ─────────────────────────────────────────────
#  Config / CLI errors
# ─────────────────────────────────────────────

class ConfigError(KitMCPError):
    """Bad or missing configuration / CLI flag."""
    category = ErrorCategory.CONFIG


class MissingHostError(ConfigError):
    """The --host flag was not provided."""
    code = ErrorCode.CONFIG_MISSING_HOST


class MissingUserError(ConfigError):
    """The --user flag was not provided."""
    code = ErrorCode.CONFIG_MISSING_USER


class InvalidPortError(ConfigError):
    """The port number is not a valid integer in the range 1–65535."""
    code = ErrorCode.CONFIG_INVALID_PORT


class MissingCredentialError(ConfigError):
    """No credential was supplied (need --password or --key)."""
    code = ErrorCode.CONFIG_MISSING_CREDENTIAL


class UnsupportedTransportError(ConfigError):
    """The requested transport type is not supported or not installed."""
    code = ErrorCode.CONFIG_UNSUPPORTED_TRANSPORT


# ─────────────────────────────────────────────
#  Transport / protocol errors
# ─────────────────────────────────────────────

class TransportError(KitMCPError):
    """Low-level transport / protocol failure."""
    category = ErrorCategory.TRANSPORT


class NegotiationError(TransportError):
    """Protocol negotiation failed (e.g. no shared cipher suite)."""
    code = ErrorCode.TRANSPORT_NEGOTIATION


class KeepaliveError(TransportError):
    """Connection was silently dropped; keepalive detected the failure."""
    code = ErrorCode.TRANSPORT_KEEPALIVE_LOST


# ─────────────────────────────────────────────
#  Factory helper
# ─────────────────────────────────────────────

_EXCEPTION_MAP: dict[ErrorCode, type[KitMCPError]] = {
    ErrorCode.CONNECTION_REFUSED          : ConnectionRefusedError,
    ErrorCode.CONNECTION_TIMEOUT          : ConnectionTimeoutError,
    ErrorCode.CONNECTION_RESET            : ConnectionResetError,
    ErrorCode.CONNECTION_HOST_UNREACHABLE : HostUnreachableError,
    ErrorCode.CONNECTION_DNS_FAILURE      : DNSFailureError,
    ErrorCode.AUTH_BAD_PASSWORD           : BadPasswordError,
    ErrorCode.AUTH_BAD_KEY                : BadKeyError,
    ErrorCode.AUTH_KEY_NOT_FOUND          : KeyNotFoundError,
    ErrorCode.AUTH_KEY_PASSPHRASE         : KeyPassphraseError,
    ErrorCode.AUTH_HOST_KEY_MISMATCH      : HostKeyMismatchError,
    ErrorCode.AUTH_PERMISSION_DENIED      : PermissionDeniedError,
    ErrorCode.AUTH_MFA_REQUIRED           : MFARequiredError,
    ErrorCode.TIMEOUT_CONNECT             : ConnectTimeoutError,
    ErrorCode.TIMEOUT_COMMAND             : CommandTimeoutError,
    ErrorCode.TIMEOUT_BANNER              : BannerTimeoutError,
    ErrorCode.TIMEOUT_AUTH                : AuthTimeoutError,
    ErrorCode.COMMAND_NON_ZERO_EXIT       : NonZeroExitError,
    ErrorCode.COMMAND_SIGNAL_KILLED       : SignalKilledError,
    ErrorCode.COMMAND_PTY_FAILED          : PTYFailedError,
    ErrorCode.CONFIG_MISSING_HOST         : MissingHostError,
    ErrorCode.CONFIG_MISSING_USER         : MissingUserError,
    ErrorCode.CONFIG_INVALID_PORT         : InvalidPortError,
    ErrorCode.CONFIG_MISSING_CREDENTIAL   : MissingCredentialError,
    ErrorCode.CONFIG_UNSUPPORTED_TRANSPORT: UnsupportedTransportError,
    ErrorCode.TRANSPORT_NEGOTIATION       : NegotiationError,
    ErrorCode.TRANSPORT_KEEPALIVE_LOST    : KeepaliveError,
}


def raise_for_code(
    code: ErrorCode,
    detail: str = "",
    *,
    context: dict[str, Any] | None = None,
    cause: BaseException | None = None,
) -> None:
    """Raise the typed exception corresponding to *code*."""
    exc_class = _EXCEPTION_MAP.get(code, KitMCPError)
    raise exc_class(detail, context=context, cause=cause)
