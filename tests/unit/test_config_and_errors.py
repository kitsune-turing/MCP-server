"""
Unit tests — Config parsing, Enums, and Error hierarchy.
Run: pytest tests/unit/
"""
from __future__ import annotations

import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Adjust import path when running directly
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from kit_mcp.enums import (
    AuthType, ConnectionState, ErrorCategory, ErrorCode,
    KeyAlgorithm, ServerOS, ServerRole, TransportType,
)
from kit_mcp.errors import (
    BadKeyError, BadPasswordError, ConfigError,
    ConnectionRefusedError, KitMCPError, MissingHostError,
    MissingUserError, InvalidPortError, MissingCredentialError,
    raise_for_code,
)
from kit_mcp.config import parse_args, ServerConfig, DEFAULT_PORTS


# ─────────────────────────────────────────────
#  Enums
# ─────────────────────────────────────────────

class TestEnums:
    def test_transport_type_values(self):
        assert TransportType.SSH.value    == "ssh"
        assert TransportType.TELNET.value == "telnet"
        assert TransportType.TCP.value    == "tcp"

    def test_auth_type_values(self):
        assert AuthType.PASSWORD.value  == "password"
        assert AuthType.KEY_FILE.value  == "key_file"
        assert AuthType.NONE.value      == "none"

    def test_error_code_is_string_enum(self):
        code = ErrorCode.AUTH_BAD_PASSWORD
        assert isinstance(code, str)
        assert code == "AUTH_BAD_PASSWORD"

    def test_connection_state_lifecycle(self):
        states = list(ConnectionState)
        assert ConnectionState.DISCONNECTED in states
        assert ConnectionState.AUTHENTICATED in states
        assert ConnectionState.CLOSED in states

    def test_key_algorithm_coverage(self):
        algos = {a.value for a in KeyAlgorithm}
        assert "ed25519" in algos
        assert "rsa" in algos

    def test_server_role_generic_default(self):
        assert ServerRole.GENERIC.value == "generic"


# ─────────────────────────────────────────────
#  Error hierarchy
# ─────────────────────────────────────────────

class TestErrors:
    def test_base_error_fields(self):
        e = KitMCPError("something went wrong", context={"host": "10.0.0.1"})
        assert "UNKNOWN_ERROR" in str(e)
        assert e.category == ErrorCategory.UNKNOWN
        assert e.context["host"] == "10.0.0.1"

    def test_bad_password_is_auth_category(self):
        e = BadPasswordError("wrong password")
        assert e.category == ErrorCategory.AUTH
        assert e.code == ErrorCode.AUTH_BAD_PASSWORD

    def test_bad_key_is_auth_category(self):
        e = BadKeyError("malformed key")
        assert e.category == ErrorCategory.AUTH
        assert e.code == ErrorCode.AUTH_BAD_KEY

    def test_connection_refused_category(self):
        e = ConnectionRefusedError("port 22 refused")
        assert e.category == ErrorCategory.CONNECTION
        assert e.code == ErrorCode.CONNECTION_REFUSED

    def test_to_dict(self):
        e = BadPasswordError("bad pass", context={"user": "pi"})
        d = e.to_dict()
        assert d["error"]    == "AUTH_BAD_PASSWORD"
        assert d["category"] == "auth"
        assert d["context"]["user"] == "pi"

    def test_raise_for_code_dispatches(self):
        with pytest.raises(BadPasswordError):
            raise_for_code(ErrorCode.AUTH_BAD_PASSWORD, "test")

    def test_raise_for_code_unknown_falls_back(self):
        with pytest.raises(KitMCPError):
            raise_for_code(ErrorCode.UNKNOWN_ERROR, "test")

    def test_config_errors_are_subclass(self):
        assert issubclass(MissingHostError, ConfigError)
        assert issubclass(MissingUserError, ConfigError)
        assert issubclass(InvalidPortError, ConfigError)


# ─────────────────────────────────────────────
#  Config / CLI parsing
# ─────────────────────────────────────────────

class TestConfigParsing:
    BASE = ["--host", "10.0.0.1", "--user", "admin"]

    def test_ssh_key_auth(self, tmp_path):
        key = tmp_path / "id_ed25519"
        key.write_text("fake-key-content")
        cfg = parse_args([*self.BASE, "--auth", "key_file", "--key", str(key)])
        assert cfg.host == "10.0.0.1"
        assert cfg.auth == AuthType.KEY_FILE
        assert cfg.key_path == key
        assert cfg.transport == TransportType.SSH
        assert cfg.port == DEFAULT_PORTS[TransportType.SSH]

    def test_password_auth(self):
        cfg = parse_args([*self.BASE, "--auth", "password", "--password", "s3cr3t"])
        assert cfg.auth == AuthType.PASSWORD
        assert cfg.password == "s3cr3t"

    def test_custom_port(self):
        cfg = parse_args([*self.BASE, "--auth", "none", "--port", "2222"])
        assert cfg.port == 2222

    def test_transport_telnet_default_port(self):
        cfg = parse_args([*self.BASE, "--auth", "none", "--transport", "telnet"])
        assert cfg.transport == TransportType.TELNET
        assert cfg.port == DEFAULT_PORTS[TransportType.TELNET]

    def test_name_defaults_to_user_at_host(self):
        cfg = parse_args([*self.BASE, "--auth", "none"])
        assert cfg.name == "admin@10.0.0.1"

    def test_name_custom(self):
        cfg = parse_args([*self.BASE, "--auth", "none", "--name", "MyServer"])
        assert cfg.name == "MyServer"

    def test_missing_password_raises(self):
        with pytest.raises(MissingCredentialError):
            parse_args([*self.BASE, "--auth", "password"])

    def test_missing_key_path_raises(self):
        with pytest.raises(MissingCredentialError):
            parse_args([*self.BASE, "--auth", "key_file"])

    def test_key_not_found_raises(self):
        with pytest.raises(MissingCredentialError):
            parse_args([*self.BASE, "--auth", "key_file", "--key", "/nonexistent/id_rsa"])

    def test_invalid_port_raises(self):
        with pytest.raises(InvalidPortError):
            parse_args([*self.BASE, "--auth", "none", "--port", "99999"])

    def test_server_os_hint(self):
        cfg = parse_args([*self.BASE, "--auth", "none", "--os", "linux"])
        assert cfg.server_os == ServerOS.LINUX

    def test_server_role_hint(self):
        cfg = parse_args([*self.BASE, "--auth", "none", "--role", "raspberry_pi"])
        assert cfg.server_role == ServerRole.RASPBERRY_PI

    def test_redacted_hides_nothing_sensitive(self):
        cfg = parse_args([*self.BASE, "--auth", "none"])
        d = cfg.redacted()
        assert "password" not in d
        assert d["host"] == "10.0.0.1"

    def test_timeout_flags(self):
        cfg = parse_args([*self.BASE, "--auth", "none",
                          "--timeout", "30", "--cmd-timeout", "60", "--keepalive", "10"])
        assert cfg.connect_timeout == 30
        assert cfg.command_timeout == 60
        assert cfg.keepalive == 10

    def test_password_from_env(self, monkeypatch):
        monkeypatch.setenv("KIT_MCP_PASSWORD", "env_secret")
        cfg = parse_args([*self.BASE, "--auth", "password"])
        assert cfg.password == "env_secret"
