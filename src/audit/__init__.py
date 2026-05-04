"""
KIT-MCP Server — Audit Logging
Security event tracking, command auditing, failure recording.

Compliance:
- ISO 27001/27002: Audit logging, access control
- MITRE ATT&CK: Mitigate T1078 (Valid Accounts)
- NIST CSF: Detect (event logging and monitoring)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional

log = logging.getLogger("kit_mcp.audit")


# ─────────────────────────────────────────────
#  Event Types
# ─────────────────────────────────────────────

class AuditEventType(str, Enum):
    """Security audit event classifications."""
    CONNECT_SUCCESS = "connect_success"
    CONNECT_FAILURE = "connect_failure"
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    COMMAND_EXEC = "command_exec"
    COMMAND_SUCCESS = "command_success"
    COMMAND_FAILURE = "command_failure"
    SUDO_ATTEMPT = "sudo_attempt"
    HOST_KEY_MISMATCH = "host_key_mismatch"
    CONNECTION_RESET = "connection_reset"
    TIMEOUT = "timeout"
    SECURITY_WARNING = "security_warning"


class AuditSeverity(str, Enum):
    """Event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ─────────────────────────────────────────────
#  Audit Event
# ─────────────────────────────────────────────

@dataclass
class AuditEvent:
    """Security audit event record."""
    
    timestamp: str  # ISO 8601
    event_type: str
    severity: str
    host: str
    port: int
    user: str
    transport: str
    
    # Event-specific fields
    detail: str = ""
    command: Optional[str] = None  # First 200 chars if logged
    exit_code: Optional[int] = None
    error_code: Optional[str] = None
    error_category: Optional[str] = None
    
    # Request context
    duration_ms: Optional[int] = None
    remote_ip: Optional[str] = None
    auth_method: Optional[str] = None
    
    # Security context
    sudo_attempted: bool = False
    privilege_elevation_failed: bool = False
    
    # Metadata
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    def to_json(self) -> str:
        """Serialize audit event to JSON for logging/storage."""
        return json.dumps(asdict(self), default=str)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize audit event to dict."""
        return asdict(self)


# ─────────────────────────────────────────────
#  Audit Logger
# ─────────────────────────────────────────────

class AuditLogger:
    """Centralized audit event recorder."""
    
    def __init__(self, name: str = "kit_mcp.audit"):
        self.logger = logging.getLogger(name)
        self.events: list[AuditEvent] = []
    
    def _record(self, event: AuditEvent) -> None:
        """Internal: record an audit event."""
        self.events.append(event)
        
        # Log to system logger
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
        """Log a connection attempt."""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=(AuditEventType.CONNECT_SUCCESS.value if success
                       else AuditEventType.CONNECT_FAILURE.value),
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
        """Log an authentication attempt."""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=(AuditEventType.AUTH_SUCCESS.value if success
                       else AuditEventType.AUTH_FAILURE.value),
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
        """Log a command execution."""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=(AuditEventType.COMMAND_SUCCESS.value if success
                       else AuditEventType.COMMAND_FAILURE.value),
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
        """Log a security-relevant event."""
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
    
    def get_events_since(self, timestamp_iso: str) -> list[AuditEvent]:
        """Retrieve events recorded since a given ISO 8601 timestamp."""
        since = datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00"))
        return [
            e for e in self.events
            if datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")) >= since
        ]
    
    def export_events(self, output_format: str = "json") -> str:
        """Export all events in a given format."""
        if output_format == "json":
            return json.dumps(
                [e.to_dict() for e in self.events],
                indent=2,
                default=str,
            )
        return ""


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
