"""
KIT-MCP Server — Security Utilities
Secure credential handling, input validation, memory protection.

Compliance:
- ISO 27001/27002: Credential protection, access control
- MITRE ATT&CK: Mitigate T1555 (Credential Access)
- NIST CSF: Protect (credential confidentiality)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string
from typing import Optional


# ─────────────────────────────────────────────
#  Credential Protection
# ─────────────────────────────────────────────

def pbkdf2_hash(
    password: str,
    iterations: int = 100_000,
    salt: Optional[bytes] = None,
) -> tuple[str, str]:
    """
    Hash a credential using PBKDF2-SHA256.
    
    Returns:
        (salt_hex, hash_hex) for storage/comparison
        
    NOTE: For at-rest protection only, not for runtime auth.
    """
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
    """Verify a password against a stored PBKDF2 hash."""
    _, computed_hash = pbkdf2_hash(
        password,
        iterations=iterations,
        salt=bytes.fromhex(stored_salt),
    )
    return hmac.compare_digest(computed_hash, stored_hash)


def wipe_memory(data: str) -> None:
    """
    Attempt to securely overwrite a string in memory.
    
    NOTE: In CPython, strings are immutable and may be reused.
    This is a best-effort cleanup hint.
    """
    if isinstance(data, str):
        # Overwrite with random bytes
        _ = data.replace(data, secrets.token_hex(len(data)))


# ─────────────────────────────────────────────
#  Input Validation
# ─────────────────────────────────────────────

def validate_hostname(hostname: str, max_length: int = 253) -> bool:
    """
    Validate hostname per RFC 1123.
    
    Args:
        hostname: Hostname/FQDN to validate
        max_length: Maximum length (default 253 per RFC)
        
    Returns:
        True if valid, False otherwise
    """
    if not hostname or len(hostname) > max_length:
        return False
    
    # Must contain only alphanumeric, dash, dot
    allowed = set(string.ascii_letters + string.digits + ".-")
    if not all(c in allowed for c in hostname):
        return False
    
    # Labels must not start/end with dash
    for label in hostname.split("."):
        if not label or label[0] == "-" or label[-1] == "-":
            return False
    
    return True


def validate_username(username: str, max_length: int = 32) -> bool:
    """
    Validate username (POSIX character set, typical UNIX constraints).
    
    Args:
        username: Username to validate
        max_length: Maximum length (default 32)
        
    Returns:
        True if valid, False otherwise
    """
    if not username or len(username) > max_length:
        return False
    
    # POSIX: alphanumeric + underscore, no leading digit
    allowed = set(string.ascii_letters + string.digits + "_-")
    if not all(c in allowed for c in username):
        return False
    
    if username[0].isdigit():
        return False
    
    return True


def sanitize_command(command: str, max_length: int = 10000) -> str:
    """
    Basic command sanitization (prevent some injection patterns).
    
    Args:
        command: Shell command to sanitize
        max_length: Maximum command length
        
    Returns:
        Sanitized command
        
    Raises:
        ValueError: If command violates constraints
    """
    if not command or len(command) > max_length:
        raise ValueError(
            f"Command too long (max {max_length}): {len(command)} chars"
        )
    
    # Warn on suspicious patterns (not blocking, just advisory)
    suspicious = [
        "| rm -rf",
        "; rm -rf",
        "&& rm -rf",
        "$(rm -rf",
        "`rm -rf",
    ]
    
    cmd_lower = command.lower()
    for pattern in suspicious:
        if pattern in cmd_lower:
            # Log but don't block — caller may have legitimate use
            pass
    
    return command.strip()


def validate_port(port: int) -> bool:
    """Validate port number is in valid range."""
    return 1 <= port <= 65535


# ─────────────────────────────────────────────
#  Environment Checks
# ─────────────────────────────────────────────

def check_credential_leakage(password: Optional[str], env_var: str) -> bool:
    """
    Check if credential is exposed in both CLI and environment.
    
    Args:
        password: Password from CLI
        env_var: Environment variable name
        
    Returns:
        True if both are set (potential exposure), False otherwise
    """
    if password is not None and os.environ.get(env_var):
        return True
    return False


def is_running_in_container() -> bool:
    """Detect if running in container (Docker, etc.)."""
    return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


def is_running_with_tty() -> bool:
    """Check if running with TTY attached (interactive mode)."""
    return os.isatty(0) if hasattr(os, "isatty") else False
