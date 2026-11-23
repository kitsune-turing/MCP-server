#!/usr/bin/env python3
"""
KIT-MCP v2 — servidor MCP seguro para operar un servidor remoto por SSH.

Qué cambia respecto a la v1
---------------------------
Seguridad
  * Política de ejecución: ``readonly`` (lista blanca + análisis de la línea),
    ``restricted`` (por defecto: lista negra de comandos destructivos) o
    ``unrestricted``. ``sudo`` y escritura de archivos se habilitan aparte.
  * La contraseña de sudo ya NO se refleja en la salida (``sudo -S -p ''`` sin PTY).
  * Redacción de secretos en todo lo que vuelve a la IA y al log de auditoría
    (claves privadas, AWS keys, tokens, ``password=...``, credenciales en URLs y
    las propias contraseñas configuradas).
  * Verificación de host key: known_hosts (por defecto), ``--accept-new`` (TOFU)
    o ``--host-key-fingerprint SHA256:...`` (pinning). Algoritmos débiles
    deshabilitados salvo ``--legacy-crypto``.
  * Credenciales por archivo (0600) o variable de entorno; ``--password`` en CLI
    sigue funcionando pero avisa (queda visible en ``ps`` y en el historial).
  * Auditoría JSONL con cadena HMAC (detecta manipulación) y rotación;
    verificable con ``--verify-audit``.
  * Límite de tasa de comandos (frena bucles de la IA) y de fallos de login.
  * Acceso a archivos por SFTP con resolución de symlinks, raíces permitidas y
    rutas sensibles bloqueadas.

Rendimiento
  * Herramientas asíncronas: el SSH corre en hilos y no bloquea el event loop.
  * Una sola conexión reutilizada (un canal por comando), keepalive, compresión
    opcional, reintento seguro solo si el canal no llegó a abrirse.
  * Lectura de stdout/stderr simultánea con ``select`` (sin deadlocks ni busy
    loop), timeout real de pared y memoria acotada (cabeza + cola).
  * ``run_batch`` ejecuta varios comandos en paralelo sobre la misma conexión.
  * ``system_info`` obtiene todo el estado del host en un único viaje de red.

Procesamiento de la información
  * Salida limpia: sin códigos ANSI, ``\\r\\n`` normalizado, truncado inteligente
    con aviso de bytes omitidos, conteo de líneas.
  * Resultados estructurados (JSON) y errores con ``hint`` accionable para la IA.
  * ``system_info`` devuelve métricas ya parseadas (memoria %, disco, temperatura…).

Requisitos: Python 3.10+, ``paramiko>=3.2``, ``mcp`` (1.x con FastMCP o 2.x con MCPServer).

Ejemplos
--------
  export KIT_MCP_PASSWORD='***'
  python kit_mcp.py --host 10.0.0.1 --user admin --auth password

  python kit_mcp.py --host pi.local --user pi --auth key_file --key ~/.ssh/id_ed25519 \\
      --policy readonly --known-hosts ~/.kit-mcp/known_hosts --accept-new \\
      --audit-log ~/.kit-mcp/audit.jsonl

  KIT_MCP_AUDIT_KEY=... python kit_mcp.py --verify-audit ~/.kit-mcp/audit.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import posixpath
import re
import secrets
import select
import shlex
import socket
import stat
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator

import paramiko

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _MCPServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _MCPServer  # type: ignore[no-redef]

try:
    from mcp.types import ToolAnnotations
except ImportError:  # versiones muy antiguas
    ToolAnnotations = None  # type: ignore[assignment,misc]

__version__ = "2.0.0"

log = logging.getLogger("kit_mcp")

# ═════════════════════════════════════════════════════════════════════════════
#  ENUMS
# ═════════════════════════════════════════════════════════════════════════════


class AuthType(str, Enum):
    PASSWORD = "password"
    KEY_FILE = "key_file"
    KEY_AGENT = "key_agent"
    NONE = "none"


class ExecPolicy(str, Enum):
    READONLY = "readonly"          # solo comandos de consulta conocidos
    RESTRICTED = "restricted"      # todo excepto patrones destructivos
    UNRESTRICTED = "unrestricted"  # sin filtro (solo bloqueos de secretos)


class ServerOS(str, Enum):
    LINUX = "linux"
    BSD = "bsd"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class ServerRole(str, Enum):
    GENERIC = "generic"
    RASPBERRY_PI = "raspberry_pi"
    ROUTER = "router"
    DATABASE = "database"
    WEB = "web"
    EMBEDDED = "embedded"


class ErrorCode(str, Enum):
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_MISSING_CREDENTIAL = "CONFIG_MISSING_CREDENTIAL"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    CONNECTION_DNS_FAILURE = "CONNECTION_DNS_FAILURE"
    CONNECTION_UNREACHABLE = "CONNECTION_UNREACHABLE"
    AUTH_FAILED = "AUTH_FAILED"
    AUTH_LOCKED_OUT = "AUTH_LOCKED_OUT"
    AUTH_BAD_KEY = "AUTH_BAD_KEY"
    AUTH_KEY_PASSPHRASE = "AUTH_KEY_PASSPHRASE"
    HOST_KEY_UNKNOWN = "HOST_KEY_UNKNOWN"
    HOST_KEY_MISMATCH = "HOST_KEY_MISMATCH"
    TRANSPORT_NEGOTIATION = "TRANSPORT_NEGOTIATION"
    TRANSPORT_LOST = "TRANSPORT_LOST"
    TIMEOUT_COMMAND = "TIMEOUT_COMMAND"
    POLICY_DENIED = "POLICY_DENIED"
    INTERACTIVE_COMMAND = "INTERACTIVE_COMMAND"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_INPUT = "INVALID_INPUT"
    PATH_DENIED = "PATH_DENIED"
    FILE_ERROR = "FILE_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


_HINTS: dict[ErrorCode, str] = {
    ErrorCode.HOST_KEY_UNKNOWN: "Host desconocido. Verifique la huella y arranque con "
    "--host-key-fingerprint <huella> o --known-hosts <archivo> --accept-new.",
    ErrorCode.HOST_KEY_MISMATCH: "La huella del servidor cambió. Posible MITM o reinstalación: "
    "NO continúe sin verificarlo fuera de banda.",
    ErrorCode.AUTH_LOCKED_OUT: "Demasiados fallos de autenticación; espere antes de reintentar.",
    ErrorCode.POLICY_DENIED: "El comando fue bloqueado por la política de ejecución. "
    "Use una alternativa de solo lectura o pida al operador que cambie --policy.",
    ErrorCode.INTERACTIVE_COMMAND: "Los comandos interactivos no están soportados. Use la "
    "variante no interactiva (p. ej. 'top -bn1', read_file en vez de 'less').",
    ErrorCode.RATE_LIMITED: "Límite de comandos por minuto alcanzado; agrupe con run_batch o espere.",
    ErrorCode.TIMEOUT_COMMAND: "El comando superó el timeout. Aumente timeout_s o acote la consulta.",
    ErrorCode.TRANSPORT_LOST: "Se perdió la conexión; la siguiente llamada reconectará. "
    "El comando pudo haberse ejecutado parcialmente.",
    ErrorCode.PATH_DENIED: "Ruta fuera de las raíces permitidas o marcada como sensible.",
}


# ═════════════════════════════════════════════════════════════════════════════
#  ERRORES
# ═════════════════════════════════════════════════════════════════════════════


class KitError(Exception):
    """Error único con código; evita sombrear builtins como ConnectionError/TimeoutError."""

    def __init__(self, code: ErrorCode, detail: str, **context: Any) -> None:
        self.code = code
        self.detail = detail
        self.context = context
        super().__init__(f"[{code.value}] {detail}")

    @property
    def category(self) -> str:
        return self.code.value.split("_", 1)[0].lower()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ok": False,
            "error": self.code.value,
            "category": self.category,
            "detail": self.detail,
        }
        if self.context:
            out["context"] = self.context
        if self.code in _HINTS:
            out["hint"] = _HINTS[self.code]
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  REDACCIÓN DE SECRETOS Y LIMPIEZA DE SALIDA
# ═════════════════════════════════════════════════════════════════════════════

_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED JWT]"),
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b([a-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)[a-z0-9_]*)"
                r"(\s*[=:]\s*)(?!\[REDACTED)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s/]+@"), r"\1[REDACTED]@"),
]

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")


class Redactor:
    """Elimina secretos conocidos (literales configurados) y con forma de secreto."""

    def __init__(self, literals: list[str | None] | None = None) -> None:
        self._literals = sorted({s for s in (literals or []) if s and len(s) >= 4}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        if not text:
            return text
        for lit in self._literals:
            text = text.replace(lit, "[REDACTED]")
        for pattern, repl in _REDACT_PATTERNS:
            text = pattern.sub(repl, text)
        return text


class BoundedCapture:
    """Guarda cabeza y cola de un flujo con memoria acotada (O(limit))."""

    def __init__(self, limit: int) -> None:
        self._head_max = max(limit // 2, 1)
        self._tail_max = max(limit - self._head_max, 1)
        self._head = bytearray()
        self._tail = bytearray()
        self.total = 0

    def add(self, data: bytes) -> None:
        if not data:
            return
        self.total += len(data)
        room = self._head_max - len(self._head)
        if room > 0:
            self._head += data[:room]
            data = data[room:]
        if data:
            self._tail += data
            excess = len(self._tail) - self._tail_max
            if excess > 0:
                del self._tail[:excess]

    @property
    def truncated(self) -> bool:
        return self.total > len(self._head) + len(self._tail)

    def render(self, redact: Callable[[str], str]) -> str:
        head = _clean(self._head.decode("utf-8", errors="replace"))
        if not self.truncated:
            return redact(head + _clean(self._tail.decode("utf-8", errors="replace"))).rstrip()
        omitted = self.total - len(self._head) - len(self._tail)
        tail = _clean(self._tail.decode("utf-8", errors="replace"))
        return redact(f"{head}\n… [{omitted} bytes omitidos] …\n{tail}").rstrip()


def _clean(text: str) -> str:
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(ch for ch in text if ch in "\n\t" or ch >= " ")


# ═════════════════════════════════════════════════════════════════════════════
#  POLÍTICA DE EJECUCIÓN
# ═════════════════════════════════════════════════════════════════════════════

_READONLY_COMMANDS = frozenset({
    "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "find", "stat", "file", "wc",
    "sort", "uniq", "cut", "tr", "column", "df", "du", "free", "uptime", "uname", "hostname",
    "hostnamectl", "whoami", "id", "groups", "who", "w", "last", "ps", "pgrep", "date", "pwd", "cd",
    "echo", "printf", "which", "whereis", "type", "md5sum", "sha1sum", "sha256sum", "lsblk",
    "lscpu", "lsusb", "lspci", "lsmod", "lsof", "ss", "netstat", "ip", "ping", "dig", "nslookup",
    "host", "journalctl", "systemctl", "dmesg", "vcgencmd", "sensors", "nproc", "getconf",
    "docker", "git", "readlink", "realpath", "basename", "dirname", "test", "true", "false",
    "timeout", "nice", "tree", "jq", "awk", "diff", "cmp", "zcat", "findmnt",
    "iostat", "vmstat", "mpstat", "top", "crontab", "apt", "dpkg", "rpm",
})

_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "systemctl": frozenset({"status", "is-active", "is-enabled", "is-failed", "list-units",
                            "list-unit-files", "list-timers", "show", "cat", "--failed"}),
    "docker": frozenset({"ps", "logs", "inspect", "images", "stats", "version", "info", "top", "port"}),
    "git": frozenset({"status", "log", "diff", "show", "branch", "rev-parse", "remote", "describe", "tag"}),
    "apt": frozenset({"list", "show", "policy", "search"}),
    "dpkg": frozenset({"-l", "-L", "-s", "--list", "--status", "--listfiles"}),
    "rpm": frozenset({"-qa", "-q", "-qi", "-ql"}),
    "crontab": frozenset({"-l"}),
}

_FORBIDDEN_ARGS: dict[str, tuple[str, ...]] = {
    "find": ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"),
    "sort": ("-o", "--output"),
    "journalctl": ("--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush"),
    "dmesg": ("-c", "-C", "--clear", "--read-clear"),
    "ip": ("add", "del", "delete", "set", "flush", "change", "replace", "append"),
    "awk": ("system", "|", ">", "print >", "getline"),
    "top": (),
    "git": ("--output", "-o"),
    "date": ("-s", "--set"),
    "hostname": ("-F", "--file"),
    "timeout": (),
}

_INTERACTIVE = frozenset({"vi", "vim", "nvim", "nano", "emacs", "less", "more", "htop", "btop",
                          "watch", "mc", "tmux", "screen", "ssh", "telnet", "ftp", "sftp", "passwd"})

_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [(re.compile(p), why) for p, why in [
    (r"\brm\s+(?:-[A-Za-z]*\s+|--[a-z-]+\s+)*(?:/|/\*|~|~/|\*|\.|\.\.|/(?:bin|boot|etc|home|lib|lib64|opt|root|sbin|srv|usr|var)/?)(?:\s|$)",
     "borrado recursivo de rutas del sistema"),
    (r"\brm\s+.*--no-preserve-root", "rm --no-preserve-root"),
    (r"\bmkfs(?:\.\w+)?\b|\bwipefs\b|\bshred\b|\bfdisk\b|\bparted\b|\bsgdisk\b", "formateo/borrado de discos"),
    (r"\bdd\b[^|;&]*\bof=/dev/", "escritura directa a dispositivo"),
    (r">\s*/dev/(?:sd|nvme|mmcblk|hd|vd|xvd)", "escritura directa a dispositivo"),
    (r"(?:^|[;&|]\s*|sudo\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b|\bsystemctl\s+(?:poweroff|reboot|halt|kexec)\b",
     "apagado/reinicio"),
    (r":\s*\(\s*\)\s*\{.*:\s*\|\s*:.*&.*\}", "fork bomb"),
    (r"\bchmod\s+(?:-[A-Za-z]+\s+)*[0-7]*777\s+/(?:\s|$)|\bchmod\s+-R\b[^;&|]*\s/(?:\s|$)", "chmod recursivo sobre /"),
    (r"\bchown\s+-R\b[^;&|]*\s/(?:\s|$)", "chown recursivo sobre /"),
    (r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b", "descarga y ejecución remota"),
    (r"/dev/tcp/|/dev/udp/|\bnc\b[^|;&]*\s-[A-Za-z]*e\b|\bsocat\b[^|;&]*exec:", "shell reversa"),
    (r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*~?/?\S*\.bash_history", "borrado de historial"),
    (r"\b(?:userdel|usermod|useradd|visudo|chpasswd)\b|(?:^|[;&|]\s*|sudo\s+)passwd\b", "gestión de usuarios/credenciales"),
    (r"\biptables\s+(?:-F|--flush|-P\s+\w+\s+DROP)\b|\bnft\s+flush\b|\bufw\s+(?:reset|disable)\b", "vaciado del firewall"),
    (r"\bcrontab\s+-r\b", "borrado de crontab"),
    (r">\s*/etc/(?:passwd|shadow|group|sudoers|fstab|hosts)\b", "sobrescritura de archivos críticos"),
    (r"\bkill(?:all)?\s+(?:-9\s+|-KILL\s+)?-?1\b|\bpkill\s+-9\s+-?1\b", "kill masivo"),
    (r"\bmv\s+/(?:bin|boot|etc|lib|sbin|usr)\b", "mover directorios del sistema"),
]]

# Bloqueados en TODAS las políticas: exfiltrar secretos hacia la IA.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/etc/(?:shadow|gshadow)\b"),
    re.compile(r"\.ssh/id_[A-Za-z0-9_-]+(?!\.pub)(?:\s|$|['\"])"),
    re.compile(r"\.aws/credentials\b"),
    re.compile(r"\bprintenv\b|(?:^|[;&|]\s*)env\s*(?:$|[;&|])|\bcat\s+/proc/\d+/environ\b"),
]

_SUBSTITUTION_RE = re.compile(r"`|\$\(|\$\{|<\(|>\(")
_SUDO_RE = re.compile(r"(?:^|[;&|(]\s*|\s)sudo\b")


def _tokenize_segments(command: str) -> list[tuple[str, str]]:
    """Divide en segmentos por operadores fuera de comillas. Devuelve (operador_previo, texto)."""
    segments: list[tuple[str, str]] = []
    buf: list[str] = []
    prev_op = ""
    quote: str | None = None
    i = 0
    while i < len(command):
        c = command[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(command):
                buf.append(command[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c == "\\" and i + 1 < len(command):
            buf.append(c + command[i + 1])
            i += 1
        elif c in ";&|<>()\n":
            two = command[i:i + 2]
            if two in ("&&", "||", ">>", "<<", "|&", "&>", ">&"):
                op, i = two, i + 1
            else:
                op = c
            segments.append((prev_op, "".join(buf).strip()))
            buf, prev_op = [], op
        else:
            buf.append(c)
        i += 1
    if quote:
        raise KitError(ErrorCode.INVALID_INPUT, "Comillas sin cerrar en el comando.")
    segments.append((prev_op, "".join(buf).strip()))
    return segments


@dataclass(frozen=True)
class PolicyDecision:
    command: str        # comando final a ejecutar (posiblemente reescrito)
    uses_sudo: bool


class CommandPolicy:
    def __init__(self, mode: ExecPolicy, allow_sudo: bool, sudo_password: str | None,
                 max_length: int = 8192) -> None:
        self.mode = mode
        self.allow_sudo = allow_sudo
        self._has_sudo_password = bool(sudo_password)
        self.max_length = max_length

    def check(self, command: str) -> PolicyDecision:
        if not isinstance(command, str) or not command.strip():
            raise KitError(ErrorCode.INVALID_INPUT, "Comando vacío.")
        if len(command) > self.max_length:
            raise KitError(ErrorCode.INVALID_INPUT, f"Comando demasiado largo (máx {self.max_length}).")
        if "\x00" in command:
            raise KitError(ErrorCode.INVALID_INPUT, "El comando contiene bytes nulos.")
        command = command.strip()

        for pat in _SECRET_PATTERNS:
            if pat.search(command):
                raise KitError(ErrorCode.POLICY_DENIED, "El comando intenta leer material secreto "
                               "(claves privadas, shadow, credenciales o variables de entorno).")

        uses_sudo = bool(_SUDO_RE.search(command))
        if uses_sudo and not self.allow_sudo:
            raise KitError(ErrorCode.POLICY_DENIED, "sudo no está habilitado (--allow-sudo).")

        segments = _tokenize_segments(command)
        for _, seg in segments:
            argv = self._argv(seg)
            if argv:
                name = self._command_name(argv)
                if name in _INTERACTIVE or (name == "top" and "-b" not in "".join(argv[1:])):
                    raise KitError(ErrorCode.INTERACTIVE_COMMAND, f"'{name}' es interactivo.")

        if self.mode is ExecPolicy.READONLY:
            self._check_readonly(command, segments)
        elif self.mode is ExecPolicy.RESTRICTED:
            normalized = re.sub(r"\s+", " ", command)
            for pat, why in _DANGEROUS_PATTERNS:
                if pat.search(normalized):
                    raise KitError(ErrorCode.POLICY_DENIED, f"Bloqueado: {why}.")

        return PolicyDecision(command=self._rewrite_sudo(command) if uses_sudo else command,
                              uses_sudo=uses_sudo)

    @staticmethod
    def _argv(segment: str) -> list[str]:
        if not segment:
            return []
        try:
            return shlex.split(segment)
        except ValueError as e:
            raise KitError(ErrorCode.INVALID_INPUT, f"No se pudo analizar el comando: {e}") from e

    _WRAPPERS: dict[str, frozenset[str]] = {
        "sudo": frozenset({"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t"}),
        "nice": frozenset({"-n"}), "timeout": frozenset({"-s", "-k"}),
        "stdbuf": frozenset({"-i", "-o", "-e"}), "time": frozenset(),
    }

    @classmethod
    def _command_index(cls, argv: list[str]) -> int:
        """Índice del comando real, saltando envoltorios (sudo -u x, nice -n 5, timeout 10…)."""
        idx = 0
        while idx < len(argv) and posixpath.basename(argv[idx]) in cls._WRAPPERS:
            value_opts = cls._WRAPPERS[posixpath.basename(argv[idx])]
            wrapper = posixpath.basename(argv[idx])
            idx += 1
            while idx < len(argv) and (argv[idx].startswith("-") or
                                       (wrapper == "timeout" and argv[idx][:1].isdigit())):
                idx += 2 if argv[idx] in value_opts else 1
        return idx

    @classmethod
    def _command_name(cls, argv: list[str]) -> str:
        idx = cls._command_index(argv)
        return posixpath.basename(argv[idx]) if idx < len(argv) else ""

    def _check_readonly(self, command: str, segments: list[tuple[str, str]]) -> None:
        if _SUBSTITUTION_RE.search(command):
            raise KitError(ErrorCode.POLICY_DENIED, "Sustitución de comandos/variables no permitida en modo readonly.")
        for op, seg in segments:
            if op and op not in ("|", "&&", "||", ";"):
                raise KitError(ErrorCode.POLICY_DENIED,
                               f"Operador '{op}' no permitido en modo readonly (redirecciones, subshells, background).")
            argv = self._argv(seg)
            if not argv:
                if op:
                    raise KitError(ErrorCode.INVALID_INPUT, "Segmento vacío entre operadores.")
                continue
            if "=" in argv[0] and not argv[0].startswith("="):
                raise KitError(ErrorCode.POLICY_DENIED, "Asignación de variables no permitida en modo readonly.")
            idx = self._command_index(argv)
            name = posixpath.basename(argv[idx]) if idx < len(argv) else ""
            rest = argv[idx + 1:]
            if name not in _READONLY_COMMANDS:
                raise KitError(ErrorCode.POLICY_DENIED, f"'{name}' no está en la lista de comandos de solo lectura.")
            allowed_sub = _SUBCOMMANDS.get(name)
            if allowed_sub is not None:
                sub = next((a for a in rest if not a.startswith("-") or a in allowed_sub), None)
                if sub not in allowed_sub:
                    raise KitError(ErrorCode.POLICY_DENIED,
                                   f"'{name} {sub or ''}' no permitido en readonly; permitidos: {', '.join(sorted(allowed_sub))}.")
            for bad in _FORBIDDEN_ARGS.get(name, ()):
                if any(a == bad or a.startswith(bad + "=") or (name == "awk" and bad in a) for a in rest):
                    raise KitError(ErrorCode.POLICY_DENIED, f"Argumento '{bad}' de '{name}' no permitido en readonly.")

    def _rewrite_sudo(self, command: str) -> str:
        """sudo leído desde stdin, sin prompt y sin PTY → la contraseña nunca aparece en la salida."""
        if not command.startswith("sudo "):
            # sudo no inicial: forzar no interactivo para que falle rápido en vez de colgarse
            return re.sub(r"\bsudo\s+", "sudo -n ", command)
        flag = "-S -p ''" if self._has_sudo_password else "-n"
        return f"sudo {flag} " + command[len("sudo "):]


# ═════════════════════════════════════════════════════════════════════════════
#  LÍMITES DE TASA
# ═════════════════════════════════════════════════════════════════════════════


class TokenBucket:
    def __init__(self, per_minute: int) -> None:
        self.capacity = float(max(per_minute, 1))
        self.rate = self.capacity / 60.0
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, n: int = 1) -> None:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens < n:
                wait = (n - self.tokens) / self.rate
                raise KitError(ErrorCode.RATE_LIMITED, "Límite de comandos alcanzado.",
                               retry_after_s=round(wait, 1))
            self.tokens -= n


class AuthFailureLimiter:
    def __init__(self, threshold: int = 5, window_s: int = 300) -> None:
        self.threshold, self.window = threshold, window_s
        self._fails: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        with self._lock:
            q = self._fails.setdefault(key, deque())
            now = time.monotonic()
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.threshold:
                raise KitError(ErrorCode.AUTH_LOCKED_OUT, "Bloqueado temporalmente por fallos de login.",
                               retry_after_s=int(self.window - (now - q[0])))

    def fail(self, key: str) -> None:
        with self._lock:
            self._fails.setdefault(key, deque()).append(time.monotonic())

    def success(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


# ═════════════════════════════════════════════════════════════════════════════
#  AUDITORÍA (JSONL + cadena HMAC)
# ═════════════════════════════════════════════════════════════════════════════


class AuditLog:
    """Eventos JSONL encadenados con HMAC-SHA256: borrar o editar una línea rompe la cadena."""

    GENESIS = "0" * 64

    def __init__(self, path: Path | None, key: bytes | None, redact: Redactor, recent: int = 500) -> None:
        self.session_id = secrets.token_hex(8)
        self._key = key or secrets.token_bytes(32)
        self._ephemeral_key = key is None
        self._redact = redact
        self._recent: deque[dict[str, Any]] = deque(maxlen=recent)
        self._lock = threading.Lock()
        self._prev = self.GENESIS
        self._file: logging.Logger | None = None
        if path:
            path = path.expanduser()
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.touch(mode=0o600, exist_ok=True)
            os.chmod(path, 0o600)
            self._prev = self._last_mac(path)
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=10 * 1024 * 1024,
                                                           backupCount=10, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._file = logging.getLogger(f"kit_mcp.audit.{self.session_id}")
            self._file.propagate = False
            self._file.setLevel(logging.INFO)
            self._file.addHandler(handler)
            if self._ephemeral_key:
                log.warning("KIT_MCP_AUDIT_KEY no definida: la cadena HMAC solo será verificable en esta sesión.")

    @staticmethod
    def _last_mac(path: Path) -> str:
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(f.tell() - 65536, 0))
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            return json.loads(lines[-1]).get("mac", AuditLog.GENESIS) if lines else AuditLog.GENESIS
        except (OSError, ValueError):
            return AuditLog.GENESIS

    @staticmethod
    def compute_mac(key: bytes, record: dict[str, Any]) -> str:
        body = json.dumps({k: v for k, v in record.items() if k != "mac"}, sort_keys=True,
                          separators=(",", ":"), default=str)
        return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()

    def emit(self, event: str, severity: str = "low", **fields: Any) -> None:
        rec: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "session": self.session_id,
            "event": event,
            "severity": severity,
        }
        for k, v in fields.items():
            if v is not None:
                rec[k] = self._redact(v) if isinstance(v, str) else v
        with self._lock:
            rec["prev"] = self._prev
            rec["mac"] = self.compute_mac(self._key, rec)
            self._prev = rec["mac"]
            self._recent.append(rec)
            if self._file:
                self._file.info(json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str))
        level = {"low": logging.INFO, "medium": logging.WARNING, "high": logging.ERROR,
                 "critical": logging.CRITICAL}.get(severity, logging.INFO)
        log.log(level, "audit %s %s", event, {k: rec[k] for k in ("command", "exit_code", "detail") if k in rec})

    def tail(self, n: int) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._recent)[-n:]
        return [{k: v for k, v in r.items() if k not in ("mac", "prev")} for r in items]


def verify_audit_file(path: Path, key: bytes) -> tuple[bool, int, str]:
    prev: str | None = None
    count = 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            if prev is not None and rec.get("prev") != prev:
                return False, count, f"línea {lineno}: cadena rota (falta o se reordenó un registro)"
            if not hmac.compare_digest(AuditLog.compute_mac(key, rec), rec.get("mac", "")):
                return False, count, f"línea {lineno}: MAC inválido (registro alterado o clave distinta)"
            prev = rec["mac"]
            count += 1
    return True, count, "ok"


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ═════════════════════════════════════════════════════════════════════════════

_SENSITIVE_PATH_PATTERNS = [
    re.compile(r"^/etc/(?:shadow|gshadow|sudoers)(?:$|/|\.)"),
    re.compile(r"/\.ssh/id_[^/]*$(?<!\.pub)"),
    re.compile(r"/\.ssh/authorized_keys$"),
    re.compile(r"/\.aws/credentials$"),
    re.compile(r"/\.kube/config$"),
    re.compile(r"/\.docker/config\.json$"),
    re.compile(r"/\.(?:bash|zsh)_history$"),
    re.compile(r"^/proc/(?:kcore|\d+/(?:environ|mem))$"),
    re.compile(r"^/dev/"),
]


@dataclass
class ServerConfig:
    host: str
    user: str
    port: int = 22
    name: str = ""
    auth: AuthType = AuthType.KEY_AGENT
    password: str | None = field(default=None, repr=False)
    sudo_password: str | None = field(default=None, repr=False)
    key_path: Path | None = None
    key_passphrase: str | None = field(default=None, repr=False)
    known_hosts: Path | None = None
    accept_new: bool = False
    host_key_fingerprint: str | None = None
    no_host_check: bool = False
    legacy_crypto: bool = False
    compress: bool = False
    connect_timeout: int = 15
    command_timeout: int = 120
    keepalive: int = 15
    max_output: int = 64 * 1024
    policy: ExecPolicy = ExecPolicy.RESTRICTED
    allow_sudo: bool = False
    allow_write: bool = False
    allowed_paths: list[str] = field(default_factory=list)
    rate_per_minute: int = 60
    audit_log: Path | None = None
    server_os: ServerOS = ServerOS.UNKNOWN
    server_role: ServerRole = ServerRole.GENERIC
    verbose: bool = False

    def __post_init__(self) -> None:
        if not validate_hostname(self.host):
            raise KitError(ErrorCode.CONFIG_INVALID, f"Host inválido: {self.host!r}")
        if not validate_username(self.user):
            raise KitError(ErrorCode.CONFIG_INVALID, f"Usuario inválido: {self.user!r}")
        if not 1 <= self.port <= 65535:
            raise KitError(ErrorCode.CONFIG_INVALID, f"Puerto fuera de rango: {self.port}")
        for label, val, lo, hi in (("connect_timeout", self.connect_timeout, 1, 300),
                                   ("command_timeout", self.command_timeout, 1, 86400),
                                   ("keepalive", self.keepalive, 0, 3600),
                                   ("max_output", self.max_output, 1024, 16 * 1024 * 1024),
                                   ("rate_per_minute", self.rate_per_minute, 1, 10000)):
            if not lo <= val <= hi:
                raise KitError(ErrorCode.CONFIG_INVALID, f"{label}={val} fuera de rango [{lo}, {hi}].")
        if self.auth is AuthType.PASSWORD and not self.password:
            raise KitError(ErrorCode.CONFIG_MISSING_CREDENTIAL,
                           "auth=password requiere KIT_MCP_PASSWORD, --password-file o --password.")
        if self.auth is AuthType.KEY_FILE:
            if not self.key_path:
                raise KitError(ErrorCode.CONFIG_MISSING_CREDENTIAL, "auth=key_file requiere --key.")
            self.key_path = self.key_path.expanduser()
            if not self.key_path.is_file():
                raise KitError(ErrorCode.CONFIG_MISSING_CREDENTIAL, f"No existe la llave {self.key_path}.")
            _warn_if_loose_perms(self.key_path, "llave privada")
        if self.host_key_fingerprint:
            fp = self.host_key_fingerprint.strip()
            if not fp.startswith("SHA256:"):
                fp = "SHA256:" + fp
            self.host_key_fingerprint = fp.rstrip("=")
        if self.known_hosts:
            self.known_hosts = self.known_hosts.expanduser()
        if self.accept_new and not self.known_hosts:
            raise KitError(ErrorCode.CONFIG_INVALID, "--accept-new requiere --known-hosts <archivo>.")
        cleaned: list[str] = []
        for p in self.allowed_paths:
            if not p.startswith("/"):
                raise KitError(ErrorCode.CONFIG_INVALID, f"--allowed-path debe ser absoluta: {p}")
            cleaned.append(posixpath.normpath(p))
        self.allowed_paths = cleaned
        self.name = self.name or f"{self.user}@{self.host}"

    def redacted(self) -> dict[str, Any]:
        return {
            "name": self.name, "host": self.host, "port": self.port, "user": self.user,
            "auth": self.auth.value, "policy": self.policy.value, "allow_sudo": self.allow_sudo,
            "allow_write": self.allow_write, "allowed_paths": self.allowed_paths,
            "host_key_mode": self.host_key_mode, "compress": self.compress,
            "connect_timeout": self.connect_timeout, "command_timeout": self.command_timeout,
            "max_output": self.max_output, "rate_per_minute": self.rate_per_minute,
            "server_os": self.server_os.value, "server_role": self.server_role.value,
            "sudo_password": "<set>" if self.sudo_password else None,
        }

    @property
    def host_key_mode(self) -> str:
        if self.host_key_fingerprint:
            return "pinned"
        if self.no_host_check:
            return "DISABLED"
        return "accept-new" if self.accept_new else "strict"


def validate_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    labels = hostname.rstrip(".").split(".")
    return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", lbl) for lbl in labels)


def validate_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?", username or ""))


def _warn_if_loose_perms(path: Path, label: str) -> None:
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            log.warning("%s %s es legible por otros usuarios (chmod 600 recomendado).", label, path)
    except OSError:
        pass


def _read_secret(cli_value: str | None, file_value: str | None, env_name: str, label: str) -> str | None:
    """Prioridad: archivo > variable de entorno > CLI. La variable se elimina del entorno tras leerla."""
    if file_value:
        p = Path(file_value).expanduser()
        _warn_if_loose_perms(p, label)
        try:
            return p.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as e:
            raise KitError(ErrorCode.CONFIG_MISSING_CREDENTIAL, f"No se pudo leer {label}: {e}") from e
    env_val = os.environ.pop(env_name, None)
    if env_val:
        if cli_value:
            log.warning("%s definido en CLI y en %s; se usa la variable de entorno.", label, env_name)
        return env_val
    if cli_value:
        log.warning("%s pasado por línea de comandos: es visible en 'ps' y en el historial. "
                    "Prefiera %s o el archivo correspondiente.", label, env_name)
    return cli_value


def parse_args(argv: list[str] | None = None) -> ServerConfig | tuple[str, Path]:
    p = argparse.ArgumentParser(prog="kit-mcp", description=f"KIT-MCP {__version__} — MCP seguro sobre SSH.")
    net = p.add_argument_group("Red")
    net.add_argument("--host")
    net.add_argument("--port", type=int, default=22)
    net.add_argument("--transport", default="ssh", choices=["ssh"], help="Solo SSH está implementado.")
    net.add_argument("--compress", action="store_true", help="Compresión SSH (útil en enlaces lentos).")

    idn = p.add_argument_group("Identidad y autenticación")
    idn.add_argument("--user")
    idn.add_argument("--name", default="")
    idn.add_argument("--auth", default=AuthType.KEY_AGENT.value, choices=[a.value for a in AuthType])
    idn.add_argument("--password", help="(Desaconsejado) use KIT_MCP_PASSWORD o --password-file.")
    idn.add_argument("--password-file")
    idn.add_argument("--sudo-password", dest="sudo_password", help="(Desaconsejado) use KIT_MCP_SUDO_PASSWORD.")
    idn.add_argument("--sudo-password-file", dest="sudo_password_file")
    idn.add_argument("--key", help="Llave privada (tipo detectado automáticamente).")
    idn.add_argument("--key-algo", dest="key_algo", help="Obsoleto: se ignora, el tipo se detecta solo.")

    hk = p.add_argument_group("Verificación del host")
    hk.add_argument("--known-hosts", dest="known_hosts", help="Archivo known_hosts propio.")
    hk.add_argument("--accept-new", dest="accept_new", action="store_true",
                    help="TOFU: acepta y guarda hosts nuevos, rechaza cambios.")
    hk.add_argument("--host-key-fingerprint", dest="host_key_fingerprint", help="Pin: SHA256:base64…")
    hk.add_argument("--no-host-check", dest="no_host_check", action="store_true", help="INSEGURO (solo laboratorio).")
    hk.add_argument("--legacy-crypto", dest="legacy_crypto", action="store_true",
                    help="Permite algoritmos SHA1/CBC para equipos antiguos.")

    pol = p.add_argument_group("Política")
    pol.add_argument("--policy", default=ExecPolicy.RESTRICTED.value, choices=[e.value for e in ExecPolicy])
    pol.add_argument("--allow-sudo", dest="allow_sudo", action="store_true")
    pol.add_argument("--allow-write", dest="allow_write", action="store_true", help="Habilita write_file.")
    pol.add_argument("--allowed-path", dest="allowed_paths", action="append", default=[],
                     help="Raíz permitida para herramientas de archivos (repetible).")
    pol.add_argument("--rate-limit", dest="rate_per_minute", type=int, default=60, help="Comandos por minuto.")

    tm = p.add_argument_group("Tiempos y salida")
    tm.add_argument("--timeout", type=int, default=15, help="Timeout de conexión (s).")
    tm.add_argument("--cmd-timeout", dest="cmd_timeout", type=int, default=120, help="Timeout por comando (s).")
    tm.add_argument("--keepalive", type=int, default=15)
    tm.add_argument("--max-output", dest="max_output", type=int, default=64 * 1024, help="Bytes por flujo.")

    misc = p.add_argument_group("Varios")
    misc.add_argument("--audit-log", dest="audit_log", help="Archivo JSONL de auditoría.")
    misc.add_argument("--verify-audit", dest="verify_audit", help="Verifica la cadena HMAC de un log y sale.")
    misc.add_argument("--os", default=ServerOS.UNKNOWN.value, choices=[o.value for o in ServerOS])
    misc.add_argument("--role", default=ServerRole.GENERIC.value, choices=[r.value for r in ServerRole])
    misc.add_argument("--verbose", "-v", action="store_true")
    misc.add_argument("--version", action="version", version=__version__)

    ns = p.parse_args(argv)
    if ns.verify_audit:
        return ("verify", Path(ns.verify_audit).expanduser())
    if not ns.host or not ns.user:
        p.error("--host y --user son obligatorios")
    if ns.key_algo:
        log.info("--key-algo ya no es necesario; el tipo de llave se detecta automáticamente.")
    if ns.no_host_check:
        log.warning("Verificación de host key DESACTIVADA: vulnerable a MITM. No usar en producción.")

    return ServerConfig(
        host=ns.host, port=ns.port, user=ns.user, name=ns.name, auth=AuthType(ns.auth),
        password=_read_secret(ns.password, ns.password_file, "KIT_MCP_PASSWORD", "Contraseña"),
        sudo_password=_read_secret(ns.sudo_password, ns.sudo_password_file, "KIT_MCP_SUDO_PASSWORD",
                                   "Contraseña de sudo"),
        key_path=Path(ns.key) if ns.key else None,
        key_passphrase=os.environ.pop("KIT_MCP_KEY_PASSPHRASE", None),
        known_hosts=Path(ns.known_hosts) if ns.known_hosts else None,
        accept_new=ns.accept_new, host_key_fingerprint=ns.host_key_fingerprint,
        no_host_check=ns.no_host_check, legacy_crypto=ns.legacy_crypto, compress=ns.compress,
        connect_timeout=ns.timeout, command_timeout=ns.cmd_timeout, keepalive=ns.keepalive,
        max_output=ns.max_output, policy=ExecPolicy(ns.policy), allow_sudo=ns.allow_sudo,
        allow_write=ns.allow_write, allowed_paths=ns.allowed_paths, rate_per_minute=ns.rate_per_minute,
        audit_log=Path(ns.audit_log) if ns.audit_log else None,
        server_os=ServerOS(ns.os), server_role=ServerRole(ns.role), verbose=ns.verbose,
    )


# ═════════════════════════════════════════════════════════════════════════════
#  TRANSPORTE SSH
# ═════════════════════════════════════════════════════════════════════════════

_WEAK_ALGORITHMS = {
    "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1"],
    "ciphers": ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "arcfour"],
    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1-96"],
    "keys": ["ssh-dss"],
    "pubkeys": ["ssh-dss"],
}


def key_fingerprint(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class _StrictPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        raise KitError(ErrorCode.HOST_KEY_UNKNOWN, f"{hostname} no está en known_hosts.",
                       fingerprint=key_fingerprint(key), key_type=key.get_name())


class _PinnedPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str) -> None:
        self.expected = expected

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        got = key_fingerprint(key)
        if not hmac.compare_digest(got, self.expected):
            raise KitError(ErrorCode.HOST_KEY_MISMATCH, "La huella no coincide con la fijada.",
                           expected=self.expected, received=got)


class _AcceptNewPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, path: Path, audit: AuditLog) -> None:
        self.path, self.audit = path, audit

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(str(self.path))
        os.chmod(self.path, 0o600)
        self.audit.emit("host_key_accepted", "medium", host=hostname, fingerprint=key_fingerprint(key))


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    stdout_bytes: int
    stderr_bytes: int
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.exit_code == 0,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "stdout_lines": self.stdout.count("\n") + 1 if self.stdout else 0,
            "bytes": {"stdout": self.stdout_bytes, "stderr": self.stderr_bytes},
            "truncated": self.truncated,
        }


class SSHSession:
    """Conexión SSH persistente y thread-safe. Cada comando abre su propio canal."""

    def __init__(self, cfg: ServerConfig, audit: AuditLog, redact: Redactor,
                 auth_limiter: AuthFailureLimiter | None = None) -> None:
        self.cfg = cfg
        self.audit = audit
        self.redact = redact
        self._auth_limiter = auth_limiter or AuthFailureLimiter()
        self._client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None
        self._lock = threading.RLock()
        self._sftp_lock = threading.Lock()
        self.connected_at: float | None = None

    # ── conexión ──────────────────────────────────────────────────────────────
    def _alive(self) -> bool:
        t = self._client.get_transport() if self._client else None
        return bool(t and t.is_active() and t.is_authenticated())

    def client(self) -> paramiko.SSHClient:
        with self._lock:
            if not self._alive():
                self._close_locked()
                self._connect_locked()
            assert self._client is not None
            return self._client

    def _load_key(self) -> paramiko.PKey:
        path = str(self.cfg.key_path)
        try:
            if hasattr(paramiko.PKey, "from_path"):
                return paramiko.PKey.from_path(path, passphrase=self.cfg.key_passphrase)
            last: Exception | None = None
            for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                try:
                    return cls.from_private_key_file(path, password=self.cfg.key_passphrase)
                except paramiko.PasswordRequiredException:
                    raise
                except paramiko.SSHException as e:
                    last = e
            raise paramiko.SSHException(str(last))
        except paramiko.PasswordRequiredException as e:
            raise KitError(ErrorCode.AUTH_KEY_PASSPHRASE,
                           "La llave requiere passphrase (defina KIT_MCP_KEY_PASSPHRASE).") from e
        except (paramiko.SSHException, ValueError, OSError) as e:
            raise KitError(ErrorCode.AUTH_BAD_KEY, f"No se pudo cargar la llave: {type(e).__name__}") from e

    def _connect_locked(self) -> None:
        cfg = self.cfg
        limiter_key = f"{cfg.host}:{cfg.port}:{cfg.user}"
        self._auth_limiter.check(limiter_key)

        client = paramiko.SSHClient()
        if cfg.host_key_fingerprint:
            client.set_missing_host_key_policy(_PinnedPolicy(cfg.host_key_fingerprint))
        elif cfg.no_host_check:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            try:
                client.load_system_host_keys()
            except OSError:
                pass
            if cfg.known_hosts:
                cfg.known_hosts.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                cfg.known_hosts.touch(mode=0o600, exist_ok=True)
                client.load_host_keys(str(cfg.known_hosts))
            client.set_missing_host_key_policy(
                _AcceptNewPolicy(cfg.known_hosts, self.audit) if cfg.accept_new and cfg.known_hosts
                else _StrictPolicy())

        kwargs: dict[str, Any] = dict(
            hostname=cfg.host, port=cfg.port, username=cfg.user,
            timeout=cfg.connect_timeout, banner_timeout=cfg.connect_timeout,
            auth_timeout=cfg.connect_timeout, channel_timeout=cfg.connect_timeout,
            allow_agent=cfg.auth is AuthType.KEY_AGENT, look_for_keys=False,
            compress=cfg.compress,
        )
        if not cfg.legacy_crypto:
            kwargs["disabled_algorithms"] = _WEAK_ALGORITHMS
        if cfg.auth is AuthType.PASSWORD:
            kwargs["password"] = cfg.password
        elif cfg.auth is AuthType.KEY_FILE:
            kwargs["pkey"] = self._load_key()

        t0 = time.monotonic()
        try:
            client.connect(**kwargs)
        except KitError as e:
            client.close()
            sev = "critical" if e.code is ErrorCode.HOST_KEY_MISMATCH else "high"
            self.audit.emit("host_key_rejected", sev, host=cfg.host, detail=e.detail, **e.context)
            raise
        except paramiko.BadHostKeyException as e:
            client.close()
            got = key_fingerprint(e.key)
            self.audit.emit("host_key_mismatch", "critical", host=cfg.host, received=got)
            raise KitError(ErrorCode.HOST_KEY_MISMATCH, "La huella del servidor no coincide con known_hosts.",
                           received=got, expected=key_fingerprint(e.expected_key)) from e
        except paramiko.AuthenticationException as e:
            client.close()
            self._auth_limiter.fail(limiter_key)
            self.audit.emit("auth_failure", "medium", host=cfg.host, user=cfg.user, auth=cfg.auth.value)
            raise KitError(ErrorCode.AUTH_FAILED, "Autenticación rechazada por el servidor.",
                           auth=cfg.auth.value) from e
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            client.close()
            raise KitError(ErrorCode.CONNECTION_REFUSED, f"{cfg.host}:{cfg.port} rechazó la conexión.") from e
        except socket.gaierror as e:
            client.close()
            raise KitError(ErrorCode.CONNECTION_DNS_FAILURE, f"No se pudo resolver {cfg.host!r}.") from e
        except (socket.timeout, TimeoutError) as e:
            client.close()
            raise KitError(ErrorCode.CONNECTION_TIMEOUT,
                           f"Sin respuesta de {cfg.host}:{cfg.port} en {cfg.connect_timeout}s.") from e
        except paramiko.SSHException as e:
            client.close()
            msg = str(e).lower()
            if any(w in msg for w in ("negotiat", "incompatible", "no matching", "kex", "cipher")):
                raise KitError(ErrorCode.TRANSPORT_NEGOTIATION, "No hay algoritmos comunes con el servidor "
                               "(¿equipo antiguo? pruebe --legacy-crypto).", detail=str(e)) from e
            if "banner" in msg or "timeout" in msg:
                raise KitError(ErrorCode.CONNECTION_TIMEOUT, "Timeout esperando el banner SSH.") from e
            raise KitError(ErrorCode.TRANSPORT_LOST, f"Error SSH: {self.redact(str(e))}") from e
        except OSError as e:
            client.close()
            raise KitError(ErrorCode.CONNECTION_UNREACHABLE, f"Host inalcanzable: {e.strerror or e}") from e

        self._auth_limiter.success(limiter_key)
        transport = client.get_transport()
        if transport and cfg.keepalive > 0:
            transport.set_keepalive(cfg.keepalive)
        self._client = client
        self.connected_at = time.time()
        self.audit.emit("connect", host=cfg.host, port=cfg.port, user=cfg.user, auth=cfg.auth.value,
                        host_key_mode=cfg.host_key_mode, duration_ms=int((time.monotonic() - t0) * 1000),
                        cipher=getattr(transport, "remote_cipher", None))

    def _close_locked(self) -> None:
        # No se toma _sftp_lock aquí: el orden de locks es siempre _lock → _sftp_lock.
        # Cerrar el cliente SSH cierra también el canal SFTP.
        sftp, self._sftp = self._sftp, None
        if sftp:
            try:
                sftp.close()
            except Exception:  # noqa: BLE001 — cierre best-effort
                pass
        if self._client:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None
            self.connected_at = None

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def info(self) -> dict[str, Any]:
        with self._lock:
            t = self._client.get_transport() if self._client else None
            if not t or not t.is_active():
                return {"connected": False}
            return {
                "connected": True,
                "server_version": t.remote_version,
                "cipher": t.remote_cipher,
                "mac": t.remote_mac,
                "compression": t.remote_compression,
                "connected_for_s": int(time.time() - (self.connected_at or time.time())),
            }

    # ── ejecución ─────────────────────────────────────────────────────────────
    def _open_channel(self) -> paramiko.Channel:
        """Abre un canal; si la conexión cayó, reconecta UNA vez (seguro: aún no se ejecutó nada)."""
        for attempt in (1, 2):
            try:
                transport = self.client().get_transport()
                if transport is None:
                    raise paramiko.SSHException("sin transporte")
                return transport.open_session(timeout=self.cfg.connect_timeout)
            except KitError:
                raise
            except (paramiko.SSHException, EOFError, OSError) as e:
                self.close()
                if attempt == 2:
                    raise KitError(ErrorCode.TRANSPORT_LOST, "No se pudo abrir un canal SSH.") from e
        raise AssertionError("inalcanzable")

    def exec(self, command: str, timeout_s: float, max_output: int,
             stdin_data: bytes | None = None) -> CommandResult:
        start = time.monotonic()
        deadline = start + timeout_s
        out, err = BoundedCapture(max_output), BoundedCapture(max_output)
        chan = self._open_channel()
        try:
            chan.exec_command(command)
            if stdin_data:
                chan.sendall(stdin_data)
            chan.shutdown_write()

            def drain() -> None:
                while chan.recv_ready():
                    out.add(chan.recv(65536))
                while chan.recv_stderr_ready():
                    err.add(chan.recv_stderr(65536))

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise KitError(ErrorCode.TIMEOUT_COMMAND, f"Timeout tras {timeout_s:.0f}s.",
                                   partial_stdout=out.render(self.redact)[-2000:])
                select.select([chan], [], [], min(remaining, 1.0))
                drain()
                if (chan.eof_received or chan.closed) and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
            if not chan.status_event.wait(max(deadline - time.monotonic(), 0.05)):
                raise KitError(ErrorCode.TIMEOUT_COMMAND, "El proceso no informó su código de salida a tiempo.")
            drain()
            exit_code = chan.recv_exit_status()
            if exit_code == -1:
                t = chan.get_transport()
                if t is None or not t.is_active():
                    # sin código de salida y sin transporte: no es un fallo del comando, es una caída
                    self.close()
                    raise KitError(ErrorCode.TRANSPORT_LOST, "La conexión se cerró antes de recibir el código de salida.",
                                   partial_stdout=out.render(self.redact)[-2000:])
        except KitError:
            raise
        except (paramiko.SSHException, EOFError, OSError) as e:
            self.close()
            raise KitError(ErrorCode.TRANSPORT_LOST, "Se perdió la conexión durante el comando.") from e
        finally:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass

        return CommandResult(
            exit_code=exit_code,
            stdout=out.render(self.redact),
            stderr=err.render(self.redact),
            duration_ms=int((time.monotonic() - start) * 1000),
            stdout_bytes=out.total,
            stderr_bytes=err.total,
            truncated=out.truncated or err.truncated,
        )

    @contextmanager
    def sftp(self) -> Iterator[paramiko.SFTPClient]:
        """SFTPClient reutilizado y serializado (no es seguro compartirlo entre hilos)."""
        # Orden de locks: _sftp_lock → _lock (client()). Nadie toma _sftp_lock teniendo _lock.
        with self._sftp_lock:
            sftp = self._sftp
            if sftp is None or sftp.sock.closed:
                for attempt in (1, 2):
                    try:
                        sftp = self.client().open_sftp()
                        sftp.get_channel().settimeout(self.cfg.command_timeout)
                        break
                    except (paramiko.SSHException, EOFError, OSError, AttributeError) as e:
                        self.close()   # la conexión cayó entre medias: reconectar una vez
                        if attempt == 2:
                            raise KitError(ErrorCode.TRANSPORT_LOST, "No se pudo abrir SFTP.") from e
                self._sftp = sftp
            try:
                yield sftp
            except (paramiko.SSHException, EOFError, socket.timeout) as e:
                self._sftp = None
                raise KitError(ErrorCode.TRANSPORT_LOST, f"Fallo SFTP: {type(e).__name__}") from e
            except OSError as e:
                if sftp.sock.closed:          # el canal murió a mitad de la operación
                    self._sftp = None
                    raise KitError(ErrorCode.TRANSPORT_LOST, "Canal SFTP cerrado durante la operación.") from e
                raise


# ═════════════════════════════════════════════════════════════════════════════
#  SERVICIO (lógica de negocio independiente del framework MCP)
# ═════════════════════════════════════════════════════════════════════════════

_SYSINFO_SCRIPT = r"""
s(){ printf '\n@@%s\n' "$1"; }
s hostname; hostname 2>/dev/null
s kernel; uname -srm 2>/dev/null
s os; ( . /etc/os-release 2>/dev/null && printf '%s\n' "$PRETTY_NAME" ) || sw_vers -productVersion 2>/dev/null
s model; tr -d '\0' < /proc/device-tree/model 2>/dev/null
s uptime; cat /proc/uptime 2>/dev/null
s load; cat /proc/loadavg 2>/dev/null
s cpus; nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null
s mem; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null
s disk; df -P -k 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|overlay|udev|none|shm)$/ && $6 !~ /^\/(proc|sys|dev|run)/'
s temp; cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
s failed; systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | head -20
s end
"""


def parse_sysinfo(raw: str) -> dict[str, Any]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in raw.splitlines():
        if line.startswith("@@"):
            current = line[2:].strip()
            sections[current] = []
        elif current and line.strip():
            sections[current].append(line.strip())

    def first(k: str) -> str | None:
        return sections.get(k, [None])[0] if sections.get(k) else None

    info: dict[str, Any] = {
        "hostname": first("hostname"), "kernel": first("kernel"), "os": first("os"), "model": first("model"),
    }
    if up := first("uptime"):
        secs = int(float(up.split()[0]))
        info["uptime"] = {"seconds": secs, "human": f"{secs // 86400}d {secs % 86400 // 3600}h {secs % 3600 // 60}m"}
    if ld := first("load"):
        parts = ld.split()
        info["load_avg"] = {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    if cpus := first("cpus"):
        info["cpus"] = int(cpus) if cpus.isdigit() else cpus
        if "load_avg" in info and isinstance(info["cpus"], int) and info["cpus"]:
            info["load_per_cpu_1m"] = round(info["load_avg"]["1m"] / info["cpus"], 2)
    mem = {ln.split(":")[0]: int(ln.split()[1]) for ln in sections.get("mem", []) if len(ln.split()) >= 2}
    if "MemTotal" in mem:
        total, avail = mem["MemTotal"], mem.get("MemAvailable", 0)
        info["memory"] = {"total_mb": total // 1024, "available_mb": avail // 1024,
                          "used_pct": round(100 * (total - avail) / total, 1) if total else None}
        if mem.get("SwapTotal"):
            info["swap"] = {"total_mb": mem["SwapTotal"] // 1024,
                            "used_pct": round(100 * (mem["SwapTotal"] - mem.get("SwapFree", 0)) / mem["SwapTotal"], 1)}
    disks = []
    for ln in sections.get("disk", []):
        f = ln.split()
        if len(f) >= 6 and f[1].isdigit():
            disks.append({"mount": f[5], "device": f[0], "size_gb": round(int(f[1]) / 1048576, 1),
                          "avail_gb": round(int(f[3]) / 1048576, 1), "used_pct": int(f[4].rstrip("%") or 0)})
    if disks:
        info["disks"] = disks
    if (t := first("temp")) and t.lstrip("-").isdigit():
        info["cpu_temp_c"] = round(int(t) / 1000, 1)
    if sections.get("failed"):
        info["failed_units"] = sections["failed"]

    alerts = []
    if info.get("memory", {}).get("used_pct") and info["memory"]["used_pct"] >= 90:
        alerts.append(f"memoria al {info['memory']['used_pct']}%")
    alerts += [f"disco {d['mount']} al {d['used_pct']}%" for d in disks if d["used_pct"] >= 90]
    if info.get("cpu_temp_c", 0) >= 75:
        alerts.append(f"temperatura CPU {info['cpu_temp_c']} °C")
    if info.get("load_per_cpu_1m", 0) >= 1.5:
        alerts.append(f"carga alta ({info['load_per_cpu_1m']} por CPU)")
    if info.get("failed_units"):
        alerts.append(f"{len(info['failed_units'])} servicio(s) systemd fallidos")
    info["alerts"] = alerts
    return {k: v for k, v in info.items() if v not in (None, [], {})} | {"alerts": alerts}


class KitService:
    MAX_BATCH = 20
    MAX_READ = 1024 * 1024
    MAX_WRITE = 1024 * 1024
    MAX_LIST = 1000

    def __init__(self, cfg: ServerConfig, session: SSHSession | None = None) -> None:
        self.cfg = cfg
        self.redact = Redactor([cfg.password, cfg.sudo_password, cfg.key_passphrase])
        key = os.environ.pop("KIT_MCP_AUDIT_KEY", None)
        self.audit = AuditLog(cfg.audit_log, key.encode() if key else None, self.redact)
        self.session = session or SSHSession(cfg, self.audit, self.redact)
        self.policy = CommandPolicy(cfg.policy, cfg.allow_sudo, cfg.sudo_password)
        self.rate = TokenBucket(cfg.rate_per_minute)
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="kit-batch")

    # ── comandos ──────────────────────────────────────────────────────────────
    def run(self, command: str, timeout_s: int | None = None, cwd: str | None = None,
            max_output: int | None = None, _internal: bool = False) -> dict[str, Any]:
        cmd_hash = hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:16] if isinstance(command, str) else None
        try:
            self.rate.acquire()
            if _internal:
                decision = PolicyDecision(command=command, uses_sudo=False)
            else:
                decision = self.policy.check(command)
            final = decision.command
            if cwd:
                if "\x00" in cwd or len(cwd) > 4096:
                    raise KitError(ErrorCode.INVALID_INPUT, "cwd inválido.")
                final = f"cd -- {shlex.quote(cwd)} && {final}"
            timeout = float(min(max(timeout_s or self.cfg.command_timeout, 1), self.cfg.command_timeout * 10))
            limit = min(max(max_output or self.cfg.max_output, 1024), self.cfg.max_output * 4)
            stdin = (self.cfg.sudo_password + "\n").encode() if "sudo -S -p ''" in final else None

            result = self.session.exec(final, timeout, limit, stdin)
            if decision.uses_sudo and stdin:
                result.stderr = re.sub(r"^\[sudo\][^\n]*\n?", "", result.stderr)
            self.audit.emit("command", "low" if result.exit_code == 0 else "medium",
                            command=command[:500], cmd_sha256=cmd_hash, cwd=cwd, exit_code=result.exit_code,
                            duration_ms=result.duration_ms, sudo=decision.uses_sudo, internal=_internal or None,
                            out_bytes=result.stdout_bytes)
            return result.to_dict()
        except KitError as e:
            sev = "high" if e.code in (ErrorCode.POLICY_DENIED, ErrorCode.HOST_KEY_MISMATCH) else "medium"
            self.audit.emit("command_rejected" if e.code in (ErrorCode.POLICY_DENIED, ErrorCode.INTERACTIVE_COMMAND,
                                                             ErrorCode.INVALID_INPUT, ErrorCode.RATE_LIMITED)
                            else "command_error", sev, command=command[:500] if isinstance(command, str) else None,
                            cmd_sha256=cmd_hash, error=e.code.value, detail=e.detail)
            return e.to_dict()

    def run_batch(self, commands: list[str], parallel: bool = True, stop_on_error: bool = False,
                  timeout_s: int | None = None) -> dict[str, Any]:
        if not isinstance(commands, list) or not commands:
            return KitError(ErrorCode.INVALID_INPUT, "Se requiere una lista de comandos.").to_dict()
        if len(commands) > self.MAX_BATCH:
            return KitError(ErrorCode.INVALID_INPUT, f"Máximo {self.MAX_BATCH} comandos por lote.").to_dict()
        t0 = time.monotonic()
        per_out = max(self.cfg.max_output // max(len(commands), 1), 4096)
        if parallel and not stop_on_error:
            futures = [self._pool.submit(self.run, c, timeout_s, None, per_out) for c in commands]
            results = [f.result() for f in futures]
        else:
            results = []
            for c in commands:
                r = self.run(c, timeout_s, None, per_out)
                results.append(r)
                if stop_on_error and not r.get("ok"):
                    break
        items = [{"command": c, **r} for c, r in zip(commands, results)]
        return {
            "ok": all(r.get("ok") for r in results) and len(results) == len(commands),
            "executed": len(results), "succeeded": sum(1 for r in results if r.get("ok")),
            "duration_ms": int((time.monotonic() - t0) * 1000), "results": items,
        }

    def system_info(self) -> dict[str, Any]:
        r = self.run(_SYSINFO_SCRIPT, timeout_s=30, _internal=True)
        if "error" in r:
            return r
        try:
            return {"ok": True, **parse_sysinfo(r["stdout"]), "duration_ms": r["duration_ms"]}
        except (ValueError, IndexError, KeyError) as e:
            return {"ok": False, "error": "PARSE_ERROR", "detail": str(e), "raw": r["stdout"][:4000]}

    def status(self) -> dict[str, Any]:
        t0 = time.monotonic()
        probe = self.run("echo ok", timeout_s=10, _internal=True)
        base = {
            "reachable": probe.get("ok", False) and probe.get("stdout") == "ok",
            "latency_ms": int((time.monotonic() - t0) * 1000),
            "server": self.cfg.redacted(),
            "session": self.session.info(),
            "version": __version__,
        }
        if "error" in probe:
            base.update({k: probe[k] for k in ("error", "detail", "hint", "context") if k in probe})
        return base

    # ── archivos (SFTP) ───────────────────────────────────────────────────────
    def _resolve(self, sftp: paramiko.SFTPClient, path: str, must_exist: bool = True) -> str:
        if not isinstance(path, str) or not path or "\x00" in path or len(path) > 4096:
            raise KitError(ErrorCode.INVALID_INPUT, "Ruta inválida.")
        try:
            if must_exist:
                resolved = sftp.normalize(path)          # REALPATH: resuelve '..' y symlinks en el servidor
            else:
                parent, base = posixpath.split(path.rstrip("/") or "/")
                if base in ("", ".", ".."):
                    raise KitError(ErrorCode.INVALID_INPUT, "Nombre de archivo inválido.")
                resolved = posixpath.join(sftp.normalize(parent or "."), base)
        except IOError as e:
            if sftp.sock.closed:
                raise KitError(ErrorCode.TRANSPORT_LOST, "Canal SFTP cerrado.") from e
            raise KitError(ErrorCode.FILE_ERROR, f"No existe o no es accesible: {path}",
                           errno=getattr(e, "errno", None)) from e
        for pat in _SENSITIVE_PATH_PATTERNS:
            if pat.search(resolved):
                raise KitError(ErrorCode.PATH_DENIED, f"Ruta sensible bloqueada: {resolved}")
        roots = self.cfg.allowed_paths
        if roots and not any(resolved == r or resolved.startswith(r.rstrip("/") + "/") for r in roots):
            raise KitError(ErrorCode.PATH_DENIED, f"{resolved} está fuera de las raíces permitidas.",
                           allowed=roots)
        return resolved

    def _file_op(self, op: str, fn: Callable[[paramiko.SFTPClient], dict[str, Any]], **audit: Any) -> dict[str, Any]:
        idempotent = op != "file_write"
        try:
            self.rate.acquire()
            for attempt in (1, 2):
                try:
                    with self.session.sftp() as sftp:
                        res = fn(sftp)
                    break
                except KitError as e:
                    # lecturas/listados son idempotentes: se reintentan una vez si cayó la conexión
                    if not (idempotent and attempt == 1 and e.code is ErrorCode.TRANSPORT_LOST):
                        raise
            self.audit.emit(op, "medium" if op == "file_write" else "low", **audit,
                            path=res.get("path"), bytes=res.get("bytes"))
            return res
        except KitError as e:
            self.audit.emit(f"{op}_error", "high" if e.code is ErrorCode.PATH_DENIED else "medium",
                            **audit, error=e.code.value, detail=e.detail)
            return e.to_dict()
        except (IOError, AttributeError) as e:
            err = KitError(ErrorCode.FILE_ERROR, f"{e.strerror or e}", errno=getattr(e, "errno", None))
            self.audit.emit(f"{op}_error", "medium", **audit, error=err.code.value, detail=err.detail)
            return err.to_dict()

    def read_file(self, path: str, offset: int = 0, max_bytes: int = 65536, encoding: str = "text") -> dict[str, Any]:
        max_bytes = min(max(int(max_bytes), 1), self.MAX_READ)
        offset = max(int(offset), 0)

        def op(sftp: paramiko.SFTPClient) -> dict[str, Any]:
            real = self._resolve(sftp, path)
            st = sftp.stat(real)
            if stat.S_ISDIR(st.st_mode or 0):
                raise KitError(ErrorCode.INVALID_INPUT, "Es un directorio; use list_directory.")
            size = st.st_size or 0
            with sftp.open(real, "rb") as f:
                f.seek(offset)
                want = max(min(max_bytes, size - offset), 0)
                if want:
                    f.prefetch(offset + want)
                data = f.read(want) if want else b""
            res: dict[str, Any] = {"ok": True, "path": real, "size": size, "offset": offset, "bytes": len(data),
                                   "eof": offset + len(data) >= size,
                                   "next_offset": None if offset + len(data) >= size else offset + len(data)}
            if encoding == "base64":
                res["content_base64"] = base64.b64encode(data).decode()
            elif b"\x00" in data[:8192]:
                res.update(ok=False, error="BINARY_FILE", detail="Archivo binario; use encoding='base64'.")
            else:
                text = self.redact(_clean(data.decode("utf-8", errors="replace")))
                res["content"] = text
                res["lines"] = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
            return res

        return self._file_op("file_read", op, requested=path)

    def list_directory(self, path: str = ".", show_hidden: bool = False) -> dict[str, Any]:
        def op(sftp: paramiko.SFTPClient) -> dict[str, Any]:
            real = self._resolve(sftp, path)
            entries = []
            for a in sftp.listdir_attr(real):
                if not show_hidden and a.filename.startswith("."):
                    continue
                mode = a.st_mode or 0
                kind = ("dir" if stat.S_ISDIR(mode) else "link" if stat.S_ISLNK(mode)
                        else "file" if stat.S_ISREG(mode) else "other")
                entries.append({"name": a.filename, "type": kind, "size": a.st_size,
                                "mode": stat.filemode(mode),
                                "mtime": datetime.fromtimestamp(a.st_mtime or 0, timezone.utc).isoformat(timespec="seconds")})
            entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
            truncated = len(entries) > self.MAX_LIST
            return {"ok": True, "path": real, "count": len(entries), "truncated": truncated,
                    "entries": entries[: self.MAX_LIST]}

        return self._file_op("file_list", op, requested=path)

    def write_file(self, path: str, content: str, mode: str = "overwrite", create_dirs: bool = False) -> dict[str, Any]:
        if not self.cfg.allow_write or self.cfg.policy is ExecPolicy.READONLY:
            return KitError(ErrorCode.POLICY_DENIED, "Escritura deshabilitada (--allow-write y política ≠ readonly).").to_dict()
        if mode not in ("overwrite", "append"):
            return KitError(ErrorCode.INVALID_INPUT, "mode debe ser 'overwrite' o 'append'.").to_dict()
        data = content.encode("utf-8")
        if len(data) > self.MAX_WRITE:
            return KitError(ErrorCode.INVALID_INPUT, f"Contenido > {self.MAX_WRITE} bytes.").to_dict()

        def op(sftp: paramiko.SFTPClient) -> dict[str, Any]:
            if create_dirs:
                self._mkdirs(sftp, posixpath.dirname(path))
            real = self._resolve(sftp, path, must_exist=False)
            if mode == "overwrite":
                tmp = f"{real}.kit-{secrets.token_hex(4)}.tmp"   # escritura atómica: tmp + rename
                with sftp.open(tmp, "wb") as f:
                    f.set_pipelined(True)
                    f.write(data)
                try:
                    old_mode = sftp.stat(real).st_mode
                    sftp.chmod(tmp, stat.S_IMODE(old_mode or 0o644))
                except IOError:
                    pass
                try:
                    sftp.posix_rename(tmp, real)
                except IOError:
                    sftp.remove(tmp)
                    raise
            else:
                with sftp.open(real, "ab") as f:
                    f.write(data)
            return {"ok": True, "path": real, "bytes": len(data), "mode": mode,
                    "sha256": hashlib.sha256(data).hexdigest()}

        return self._file_op("file_write", op, requested=path)

    def _mkdirs(self, sftp: paramiko.SFTPClient, directory: str) -> None:
        if not directory:
            return
        parts, cur = [], directory
        while cur and cur not in ("/", "."):
            try:
                sftp.stat(cur)
                break
            except IOError:
                parts.append(cur)
                cur = posixpath.dirname(cur)
        for d in reversed(parts):
            self._resolve(sftp, d, must_exist=False)
            sftp.mkdir(d, mode=0o755)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        self.session.close()


# ═════════════════════════════════════════════════════════════════════════════
#  SERVIDOR MCP
# ═════════════════════════════════════════════════════════════════════════════


def _annotations(**kw: Any) -> dict[str, Any]:
    return {"annotations": ToolAnnotations(**kw)} if ToolAnnotations is not None else {}


def _instructions(cfg: ServerConfig) -> str:
    caps = [f"política '{cfg.policy.value}'"]
    caps.append("sudo habilitado" if cfg.allow_sudo else "sin sudo")
    caps.append("escritura de archivos habilitada" if cfg.allow_write and cfg.policy is not ExecPolicy.READONLY
                else "sin escritura de archivos")
    if cfg.allowed_paths:
        caps.append("archivos limitados a " + ", ".join(cfg.allowed_paths))
    return (
        f"Acceso remoto a '{cfg.name}' ({cfg.host}), SO {cfg.server_os.value}, rol {cfg.server_role.value}; "
        f"{'; '.join(caps)}.\n"
        "Guía: empiece con system_info para conocer el estado del host. Prefiera read_file/list_directory "
        "sobre cat/ls para archivos. Agrupe consultas independientes con run_batch (se ejecutan en paralelo). "
        "Use solo comandos no interactivos (p. ej. 'top -bn1', 'journalctl -n 100 --no-pager', "
        "'systemctl status X --no-pager'). Acote la salida (head, tail, grep, -n) para no truncar. "
        "Si recibe POLICY_DENIED no intente evadirlo: informe al usuario. Los secretos se muestran como [REDACTED]."
    )


def build_server(svc: KitService) -> Any:
    cfg = svc.cfg
    server = _MCPServer("kit-mcp", instructions=_instructions(cfg))
    readonly = cfg.policy is ExecPolicy.READONLY

    def call(fn: Callable[..., dict[str, Any]], *args: Any) -> Any:
        async def runner() -> dict[str, Any]:
            try:
                return await asyncio.to_thread(fn, *args)
            except KitError as e:
                return e.to_dict()
            except Exception as e:  # noqa: BLE001 — nunca filtrar trazas a la IA
                log.exception("Error inesperado en herramienta")
                return {"ok": False, "error": ErrorCode.UNKNOWN_ERROR.value, "detail": svc.redact(type(e).__name__)}
        return runner()

    @server.tool(**_annotations(title="Ejecutar comando", readOnlyHint=readonly, destructiveHint=not readonly,
                                openWorldHint=True))
    async def run_command(command: str, timeout_s: int | None = None, cwd: str | None = None) -> dict[str, Any]:
        """Ejecuta un comando de shell no interactivo en el servidor remoto.

        Devuelve exit_code, stdout, stderr (limpios, sin ANSI, secretos redactados), duración y si hubo truncado.
        timeout_s: límite en segundos (por defecto el del servidor). cwd: directorio de trabajo.
        """
        return await call(svc.run, command, timeout_s, cwd)

    @server.tool(**_annotations(title="Ejecutar lote", readOnlyHint=readonly, destructiveHint=not readonly,
                                openWorldHint=True))
    async def run_batch(commands: list[str], parallel: bool = True, stop_on_error: bool = False,
                        timeout_s: int | None = None) -> dict[str, Any]:
        """Ejecuta hasta 20 comandos en una sola llamada. parallel=True los corre a la vez sobre la misma
        conexión (más rápido); stop_on_error=True los corre en orden y se detiene en el primer fallo."""
        return await call(svc.run_batch, commands, parallel, stop_on_error, timeout_s)

    @server.tool(**_annotations(title="Estado del sistema", readOnlyHint=True, idempotentHint=True))
    async def system_info() -> dict[str, Any]:
        """Resumen estructurado del host en un solo viaje: SO, kernel, uptime, carga, CPU, memoria, discos,
        temperatura, servicios fallidos y alertas (memoria/disco ≥90 %, temperatura ≥75 °C, carga alta)."""
        return await call(svc.system_info)

    @server.tool(**_annotations(title="Estado de la conexión", readOnlyHint=True, idempotentHint=True))
    async def server_status() -> dict[str, Any]:
        """Comprueba alcance y latencia, y devuelve la configuración (sin credenciales) y datos de la sesión SSH."""
        return await call(svc.status)

    @server.tool(**_annotations(title="Leer archivo", readOnlyHint=True, idempotentHint=True))
    async def read_file(path: str, offset: int = 0, max_bytes: int = 65536, encoding: str = "text") -> dict[str, Any]:
        """Lee un archivo remoto por SFTP (más rápido y seguro que cat). Paginable con offset/next_offset.
        encoding: 'text' (por defecto) o 'base64' para binarios. Máximo 1 MiB por llamada."""
        return await call(svc.read_file, path, offset, max_bytes, encoding)

    @server.tool(**_annotations(title="Listar directorio", readOnlyHint=True, idempotentHint=True))
    async def list_directory(path: str = ".", show_hidden: bool = False) -> dict[str, Any]:
        """Lista un directorio remoto con tipo, tamaño, permisos y fecha (directorios primero)."""
        return await call(svc.list_directory, path, show_hidden)

    if cfg.allow_write and not readonly:
        @server.tool(**_annotations(title="Escribir archivo", readOnlyHint=False, destructiveHint=True))
        async def write_file(path: str, content: str, mode: str = "overwrite",
                             create_dirs: bool = False) -> dict[str, Any]:
            """Escribe texto en un archivo remoto. mode='overwrite' es atómico (tmp + rename, conserva permisos);
            mode='append' agrega al final. Máximo 1 MiB."""
            return await call(svc.write_file, path, content, mode, create_dirs)

    @server.tool(**_annotations(title="Auditoría reciente", readOnlyHint=True))
    async def audit_tail(limit: int = 20) -> dict[str, Any]:
        """Últimos eventos de auditoría de esta sesión (comandos, rechazos, conexiones)."""
        return {"ok": True, "session": svc.audit.session_id,
                "events": svc.audit.tail(min(max(int(limit), 1), 200))}

    return server


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════


def main(argv: list[str] | None = None) -> int:
    # stdout es el canal MCP (stdio): todo log va a stderr.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        parsed = parse_args(argv)
    except KitError as e:
        log.error("%s", e)
        return 2

    if isinstance(parsed, tuple):
        key = os.environ.get("KIT_MCP_AUDIT_KEY")
        if not key:
            log.error("Defina KIT_MCP_AUDIT_KEY para verificar el log.")
            return 2
        ok, n, msg = verify_audit_file(parsed[1], key.encode())
        print(json.dumps({"valid": ok, "records": n, "detail": msg}))
        return 0 if ok else 1

    cfg = parsed
    logging.getLogger().setLevel(logging.DEBUG if cfg.verbose else logging.INFO)
    logging.getLogger("paramiko").setLevel(logging.INFO if cfg.verbose else logging.WARNING)
    svc = KitService(cfg)
    log.info("KIT-MCP %s iniciado: %s", __version__, cfg.redacted())
    svc.audit.emit("server_start", config=cfg.redacted())
    try:
        build_server(svc).run()
    finally:
        svc.audit.emit("server_stop")
        svc.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
