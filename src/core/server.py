"""
KIT-MCP Server — MCP Entry Point
Exposes connect_server, run_command, server_status as MCP tools.
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from mcp.server.fastmcp import FastMCP

from kit_mcp.config import ServerConfig
from kit_mcp.errors import KitMCPError
from kit_mcp.transport import BaseTransport, CommandResult, create_transport

log = logging.getLogger("kit_mcp.server")

mcp = FastMCP("KIT Generic MCP Server")

# ─────────────────────────────────────────────
#  Singleton transport (thread-safe)
# ─────────────────────────────────────────────

_lock      : threading.Lock            = threading.Lock()
_transport : BaseTransport | None      = None
_config    : ServerConfig | None       = None


def _get_transport() -> BaseTransport:
    global _transport, _config
    with _lock:
        if _config is None:
            raise RuntimeError(
                "Server not initialised. Call init_server(config) before running."
            )
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
    """Attach a :class:`~kit_mcp.config.ServerConfig` to this MCP server."""
    global _config
    _config = config
    if config.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    log.info("KIT-MCP initialised: %s", config.redacted())


# ─────────────────────────────────────────────
#  Result serialiser
# ─────────────────────────────────────────────

def _serialise(result: CommandResult) -> dict[str, Any]:
    return {
        "exit_code"  : result.exit_code,
        "ok"         : result.ok,
        "stdout"     : result.stdout,
        "stderr"     : result.stderr,
        "duration_ms": result.duration_ms,
    }


def _error_response(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, KitMCPError):
        return {
            "ok"      : False,
            "error"   : exc.code.value,
            "category": exc.category.value,
            "detail"  : exc.detail,
            "context" : exc.context,
        }
    return {
        "ok"    : False,
        "error" : "UNKNOWN_ERROR",
        "detail": str(exc),
    }


# ─────────────────────────────────────────────
#  MCP Tools
# ─────────────────────────────────────────────

@mcp.tool()
def run_command(command: str) -> dict[str, Any]:
    """
    Run an arbitrary shell command on the configured remote server.

    Args:
        command: Shell command string to execute remotely.

    Returns:
        Dict with keys: ok, exit_code, stdout, stderr, duration_ms.
        On error: ok=False, error (ErrorCode), category, detail, context.
    """
    try:
        transport = _get_transport()
        result    = transport.exec(command)
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
    """
    Convenience alias: executes *prompt* as a shell command.

    Identical to run_command; kept for backward-compatibility with
    MCP clients that call this tool by name.

    Args:
        prompt: Shell command to execute on the remote server.
    """
    return run_command(prompt)


@mcp.tool()
def server_status() -> dict[str, Any]:
    """
    Check reachability and return connection metadata.

    Returns:
        Dict with: reachable, host, port, transport, auth, name, server_os,
        server_role, ssh_key (if applicable), error details on failure.
    """
    if _config is None:
        return {"reachable": False, "detail": "Server not initialised."}

    ping_result = run_command("echo ok")

    base: dict[str, Any] = {
        "reachable" : ping_result.get("ok", False),
        "name"      : _config.name,
        "host"      : _config.host,
        "port"      : _config.port,
        "transport" : _config.transport.value,
        "auth"      : _config.auth.value,
        "user"      : _config.user,
        "server_os" : _config.server_os.value,
        "server_role": _config.server_role.value,
    }

    if _config.key_path:
        base["ssh_key"] = str(_config.key_path)

    if not ping_result.get("ok"):
        base["error"]    = ping_result.get("error")
        base["category"] = ping_result.get("category")
        base["detail"]   = ping_result.get("detail")

    return base
