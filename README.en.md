# KIT-MCP

🌐 [Español](README.md) · **English**

An [MCP](https://modelcontextprotocol.io) server that lets an AI assistant (Claude Desktop, Claude Code or any other MCP client) operate a remote server over **SSH** in a controlled way: run commands, inspect system state, and read or write files, with security policies, secret redaction and auditing.

The whole server is a single file: `kit_mcp.py`.

> **Language note:** tool output messages (`detail`, `hint`, the instructions sent to the AI) are in Spanish. Error codes such as `POLICY_DENIED` are language-neutral.

---

## Contents

- [Features](#features)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [Connecting to an MCP client](#connecting-to-an-mcp-client)
- [Credentials](#credentials)
- [Server verification (host key)](#server-verification-host-key)
- [Execution policies](#execution-policies)
- [Available tools](#available-tools)
- [Auditing](#auditing)
- [Options reference](#options-reference)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)
- [Recommendations and limitations](#recommendations-and-limitations)

---

## Features

**Security**
- Three execution policies: `readonly`, `restricted` (default) and `unrestricted`.
- `sudo` and file writes are disabled unless explicitly enabled.
- The sudo password never appears in the output (sent with `sudo -S -p ''`, no PTY).
- Automatic redaction of secrets in everything the AI receives and in the audit log: private keys, AWS keys, GitHub/Slack tokens, JWTs, `password=…`, credentials embedded in URLs, and the configured passwords themselves.
- Under every policy, commands that read `/etc/shadow`, SSH private keys, AWS credentials or environment variables are blocked.
- Server verification via `known_hosts`, trust on first use (TOFU) or a pinned fingerprint. Weak algorithms are disabled by default.
- Per-minute command limit and temporary lockout after authentication failures.
- JSONL audit log with an HMAC chain that detects edited or deleted records.

**Performance**
- Asynchronous tools: SSH work runs in threads and never blocks the MCP server.
- A single persistent connection (one channel per command), keepalive and optional compression.
- stdout and stderr are read concurrently, with a real wall-clock timeout and bounded memory.
- `run_batch` runs up to 20 commands in parallel over the same connection.
- `system_info` collects the whole host state in a single network round trip.

**More useful output for the AI**
- Clean output (no ANSI codes) and truncation that keeps both the beginning and the end.
- Structured JSON results and errors with an actionable `hint`.
- Pre-computed metrics with alerts (memory/disk ≥ 90 %, temperature ≥ 75 °C, high load, failed services).

---

## Requirements and installation

- Python **3.10** or later
- `paramiko` **3.2** or later
- `mcp` (works with both 1.x and 2.x)

```bash
git clone https://github.com/kitsune-turing/MCP-server.git
cd MCP-server
python3 -m venv .venv && source .venv/bin/activate
pip install "paramiko>=3.2" "mcp[cli]"
```

Check the installation:

```bash
python kit_mcp.py --version
python kit_mcp.py --help
```

---

## Quick start

With an SSH key (recommended):

```bash
python kit_mcp.py \
  --host 10.0.0.5 --user pi \
  --auth key_file --key ~/.ssh/id_ed25519 \
  --known-hosts ~/.kit-mcp/known_hosts --accept-new
```

With a password, passed through an environment variable:

```bash
export KIT_MCP_PASSWORD='my-password'
python kit_mcp.py --host 10.0.0.5 --user admin --auth password \
  --known-hosts ~/.kit-mcp/known_hosts --accept-new
```

The server speaks MCP over **stdio**, so you normally don't run it by hand: your MCP client launches it (see the next section). Logs go to stderr.

---

## Connecting to an MCP client

### Claude Desktop

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "raspberry": {
      "command": "/path/MCP-server/.venv/bin/python",
      "args": [
        "/path/MCP-server/kit_mcp.py",
        "--host", "10.0.0.5",
        "--user", "pi",
        "--auth", "key_file",
        "--key", "~/.ssh/id_ed25519",
        "--known-hosts", "~/.kit-mcp/known_hosts",
        "--accept-new",
        "--policy", "restricted",
        "--audit-log", "~/.kit-mcp/audit.jsonl",
        "--os", "linux",
        "--role", "raspberry_pi"
      ],
      "env": {
        "KIT_MCP_AUDIT_KEY": "<long-random-string>"
      }
    }
  }
}
```

Restart Claude Desktop. For several servers, add one entry per server (`"router": {...}`, `"web": {...}`).

### Claude Code

```bash
claude mcp add raspberry -- /path/.venv/bin/python /path/kit_mcp.py \
  --host 10.0.0.5 --user pi --auth key_file --key ~/.ssh/id_ed25519 \
  --known-hosts ~/.kit-mcp/known_hosts --accept-new
```

### Testing without a client

```bash
npx @modelcontextprotocol/inspector python kit_mcp.py --host 10.0.0.5 --user pi --auth key_agent
```

---

## Credentials

| Method | `--auth` | How to provide it |
|---|---|---|
| Private key | `key_file` | `--key PATH`. If it has a passphrase: `KIT_MCP_KEY_PASSPHRASE`. The key type (Ed25519, ECDSA, RSA) is detected automatically. |
| SSH agent | `key_agent` (default) | Uses the keys loaded in `ssh-agent`. |
| Password | `password` | `--password-file PATH`, the `KIT_MCP_PASSWORD` variable, or `--password`. |
| None | `none` | Only for devices without authentication. |

Sudo password (requires `--allow-sudo`): `--sudo-password-file`, `KIT_MCP_SUDO_PASSWORD` or `--sudo-password`.

**Precedence:** file → environment variable → command line. Once read, the variable is removed from the process environment.

> ⚠️ `--password` and `--sudo-password` work, but they are visible in `ps` and in shell history. The program warns about it at startup. Use files with `600` permissions or environment variables instead.

```bash
printf '%s' 'my-password' > ~/.kit-mcp/pass && chmod 600 ~/.kit-mcp/pass
python kit_mcp.py --host 10.0.0.5 --user admin --auth password --password-file ~/.kit-mcp/pass ...
```

---

## Server verification (host key)

Verifying the server's fingerprint prevents man-in-the-middle (MITM) attacks. There are four modes:

| Mode | Options | Behavior |
|---|---|---|
| Strict (default) | — or `--known-hosts FILE` | Only accepts hosts already listed in `~/.ssh/known_hosts` or in the given file. |
| TOFU | `--known-hosts FILE --accept-new` | Accepts and saves a new host the first time; rejects it if the fingerprint later changes. |
| Pinned | `--host-key-fingerprint SHA256:…` | Only accepts that exact fingerprint. The most secure mode. |
| Disabled | `--no-host-check` | **Insecure.** Lab use only; warns on every start. |

When the host is unknown, the `HOST_KEY_UNKNOWN` error includes the server's fingerprint. To check it, run this on the server itself:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

If it matches, you can pin it with `--host-key-fingerprint`.

For older devices (routers, embedded systems) that only support SHA1 or CBC, add `--legacy-crypto`.

---

## Execution policies

Selected with `--policy`:

### `readonly`: inspection only
Only accepts commands from an allowlist (`ls`, `cat`, `grep`, `df`, `free`, `ps`, `journalctl`, `ip`, `ss`, `docker ps/logs`, `git status/log`, `systemctl status`…) and parses the command line with quote awareness:
- Allows `|`, `&&`, `||` and `;` between allowed commands.
- Blocks redirections (`>`, `<`), background `&`, `$(…)`, backticks, variable assignments and dangerous arguments (`find -delete/-exec`, `ip … add/del`, `awk system()`…).
- `write_file` stays disabled even if `--allow-write` is passed.

### `restricted`: default
Allows any command except destructive ones: recursive deletion of system paths, `mkfs`, `dd` to block devices, shutdown or reboot, fork bombs, `curl | sh`, reverse shells, history wiping, user management, flushing the firewall, overwriting `/etc/passwd`, `chmod -R 777 /`, and so on.

### `unrestricted`
No command filter. Secret-reading blocks, redaction, auditing and rate limiting still apply.

### Applies to every policy
- `sudo` only with `--allow-sudo`. Without a sudo password, `sudo -n` is used so it fails fast instead of hanging.
- Interactive commands (`vim`, `nano`, `less`, `htop`, `top` without `-b`, `ssh`…) are rejected and a non-interactive alternative is suggested.
- The `--rate-limit` commands per minute limit applies (60 by default).

> The `restricted` denylist reduces risk but is not foolproof. In production, combine `readonly` with a low-privilege SSH user.

---

## Available tools

Every tool returns JSON with `ok`. Errors include `error`, `category`, `detail` and, where relevant, `hint`.

| Tool | Description |
|---|---|
| `run_command(command, timeout_s?, cwd?)` | Runs a non-interactive command. Returns `exit_code`, `stdout`, `stderr`, `duration_ms`, `stdout_lines`, `bytes` and `truncated`. |
| `run_batch(commands, parallel=true, stop_on_error=false, timeout_s?)` | Up to 20 commands. Parallel by default; with `stop_on_error` they run in order and stop at the first failure. |
| `system_info()` | Hostname, OS, kernel, model, uptime, load, CPUs, memory, swap, disks, temperature, failed systemd services and `alerts`. |
| `server_status()` | Reachability, latency, configuration (without credentials) and SSH session data (version, cipher, time connected). |
| `read_file(path, offset=0, max_bytes=65536, encoding="text")` | Reads over SFTP. Pageable through `next_offset`. For binary files use `encoding="base64"`. Up to 1 MiB per call. |
| `list_directory(path=".", show_hidden=false)` | Lists entries with type, size, permissions and date; directories first. |
| `write_file(path, content, mode="overwrite", create_dirs=false)` | **Only available with `--allow-write`** and a policy other than `readonly`. `overwrite` is atomic (temp file + rename) and keeps permissions; `append` adds to the end. Up to 1 MiB. |
| `audit_tail(limit=20)` | Latest audit events of the session. |

**File confinement:** with `--allowed-path /path` (repeatable), file tools only operate inside those roots. Paths and symlinks are resolved on the server, so `../` or a link pointing outside is rejected. `/etc/shadow`, `/etc/sudoers`, `~/.ssh/id_*`, `authorized_keys`, `~/.aws/credentials`, `~/.kube/config`, shell histories and `/dev/*` are always blocked.

### Response examples

`run_command("df -h /")`:

```json
{
  "ok": true,
  "exit_code": 0,
  "stdout": "Filesystem  Size  Used Avail Use% Mounted on\n/dev/root    29G  8.1G   20G  30% /",
  "stderr": "",
  "duration_ms": 42,
  "stdout_lines": 2,
  "bytes": {"stdout": 98, "stderr": 0},
  "truncated": false
}
```

Blocked command (messages are in Spanish):

```json
{
  "ok": false,
  "error": "POLICY_DENIED",
  "category": "policy",
  "detail": "Bloqueado: borrado recursivo de rutas del sistema.",
  "hint": "El comando fue bloqueado por la política de ejecución. Use una alternativa de solo lectura o pida al operador que cambie --policy."
}
```

`system_info()` (abridged):

```json
{
  "ok": true,
  "hostname": "raspberrypi",
  "os": "Debian GNU/Linux 12 (bookworm)",
  "model": "Raspberry Pi 4 Model B Rev 1.4",
  "uptime": {"seconds": 864000, "human": "10d 0h 0m"},
  "load_avg": {"1m": 0.42, "5m": 0.38, "15m": 0.35},
  "memory": {"total_mb": 3794, "available_mb": 2810, "used_pct": 25.9},
  "disks": [{"mount": "/", "size_gb": 29.0, "avail_gb": 20.1, "used_pct": 30}],
  "cpu_temp_c": 48.7,
  "alerts": []
}
```

---

## Auditing

Every connection, command, rejection and file operation produces an event. Without `--audit-log`, events are kept in memory only (the last 500, available through `audit_tail`) and written to stderr. With `--audit-log FILE`:

- JSONL is written with `600` permissions and rotated every 10 MB (10 backup files).
- Commands are logged redacted, together with the SHA-256 hash of the original command.
- Each record carries `prev` and `mac` (HMAC-SHA256 of the previous and current record), so editing, deleting or reordering lines breaks the chain.

Set a fixed key so you can verify the log later:

```bash
export KIT_MCP_AUDIT_KEY="$(openssl rand -hex 32)"   # store it in a secrets manager
```

Verify a log:

```bash
KIT_MCP_AUDIT_KEY=... python kit_mcp.py --verify-audit ~/.kit-mcp/audit.jsonl
# {"valid": true, "records": 128, "detail": "ok"}
```

If `KIT_MCP_AUDIT_KEY` is not set, a random key is generated per session, and the log can only be verified while that session is still running.

---

## Options reference

| Option | Default | Description |
|---|---|---|
| `--host` | — | Hostname, IPv4 or IPv6. **Required.** |
| `--user` | — | SSH user. **Required.** |
| `--port` | `22` | SSH port. |
| `--name` | `user@host` | Friendly name shown to the AI. |
| `--auth` | `key_agent` | `password`, `key_file`, `key_agent` or `none`. |
| `--key` | — | Path to the private key. |
| `--password-file` / `--password` | — | Password (or the `KIT_MCP_PASSWORD` variable). |
| `--sudo-password-file` / `--sudo-password` | — | Sudo password (or the `KIT_MCP_SUDO_PASSWORD` variable). |
| `--known-hosts` | — | Custom `known_hosts` file. |
| `--accept-new` | off | TOFU mode (requires `--known-hosts`). |
| `--host-key-fingerprint` | — | Pinned fingerprint `SHA256:…`. |
| `--no-host-check` | off | Disables verification (insecure). |
| `--legacy-crypto` | off | Allows SHA1/CBC algorithms. |
| `--compress` | off | SSH compression, useful on slow links. |
| `--policy` | `restricted` | `readonly`, `restricted` or `unrestricted`. |
| `--allow-sudo` | off | Allows `sudo`. |
| `--allow-write` | off | Enables `write_file`. |
| `--allowed-path` | — | Allowed root for file tools (repeatable, absolute path). |
| `--rate-limit` | `60` | Commands per minute. |
| `--timeout` | `15` | Connection timeout (s). |
| `--cmd-timeout` | `120` | Per-command timeout (s). The AI may request up to 10× this value. |
| `--keepalive` | `15` | Keepalive interval (s); `0` disables it. |
| `--max-output` | `65536` | Bytes kept per stream (stdout/stderr). |
| `--audit-log` | — | JSONL audit file. |
| `--verify-audit` | — | Verifies a log and exits. |
| `--os` | `unknown` | Hint for the AI: `linux`, `bsd`, `macos`, `windows`, `unknown`. |
| `--role` | `generic` | Hint for the AI: `generic`, `raspberry_pi`, `router`, `database`, `web`, `embedded`. |
| `--verbose`, `-v` | off | Debug logging. |

| Environment variable | Purpose |
|---|---|
| `KIT_MCP_PASSWORD` | SSH password. |
| `KIT_MCP_SUDO_PASSWORD` | Sudo password. |
| `KIT_MCP_KEY_PASSPHRASE` | Private key passphrase. |
| `KIT_MCP_AUDIT_KEY` | HMAC key for the audit log. |

Compatibility with v1: `--transport ssh` and `--key-algo` are still accepted (the latter is no longer needed and is ignored).

---

## Tests

`test_kit_mcp.py` starts a real in-process SSH/SFTP server (built with paramiko) and tests the MCP end to end: execution, large output without deadlocks, timeouts, redaction, sudo, policies, parallel batches, limits, host keys, login-failure lockout, SFTP with confinement, auditing with tamper detection, MCP tool registration and concurrency with reconnections.

```bash
pip install pytest pytest-timeout
pytest -q --timeout 60 test_kit_mcp.py
```

Requires Linux or macOS with `bash`; no `sshd` needed.

---

## Troubleshooting

| Error | Cause and fix |
|---|---|
| `HOST_KEY_UNKNOWN` | The host is not in `known_hosts`. Check the fingerprint in `context` and use `--accept-new` or `--host-key-fingerprint`. |
| `HOST_KEY_MISMATCH` | The fingerprint changed. It may be a server reinstall or a MITM attack: verify it out of band before continuing. |
| `AUTH_FAILED` | Wrong user or credential, or the server does not accept that method. |
| `AUTH_LOCKED_OUT` | 5 failures within 5 minutes; wait `retry_after_s`. |
| `AUTH_KEY_PASSPHRASE` | The key is encrypted: set `KIT_MCP_KEY_PASSPHRASE`. |
| `TRANSPORT_NEGOTIATION` | Old device without modern algorithms: try `--legacy-crypto`. |
| `CONNECTION_REFUSED` / `CONNECTION_TIMEOUT` | Closed port, firewall or wrong IP. |
| `POLICY_DENIED` | Blocked by the active policy; adjust `--policy`, `--allow-sudo` or `--allow-write` if appropriate. |
| `INTERACTIVE_COMMAND` | Use the non-interactive variant (`top -bn1`, `journalctl --no-pager`, `read_file`). |
| `TIMEOUT_COMMAND` | Increase `timeout_s` or narrow the query. The error includes `partial_stdout`. |
| `RATE_LIMITED` | Group commands with `run_batch` or raise `--rate-limit`. |
| `TRANSPORT_LOST` | The connection dropped; the next call reconnects. The command may have run partially. |
| `mcp.server.fastmcp` not found | You are running old code with `mcp` 2.x. `kit_mcp.py` already supports both versions. |

For connection details, add `-v`.

---

## Recommendations and limitations

- Create a dedicated SSH user with minimal privileges and, where possible, key-based authentication.
- Pin the server fingerprint (`--host-key-fingerprint`) in production.
- Enable `--allow-sudo` and `--allow-write` only when needed, and restrict file access with `--allowed-path`.
- Set `KIT_MCP_AUDIT_KEY` and `--audit-log` for verifiable traceability.
- When a command exceeds its timeout its channel is closed, but without a PTY the remote process may keep running. For long tasks, use `timeout N command` inside the command itself.
- With a sudo password, only the leading `sudo` of a command receives it; `sudo` calls later in the command run with `-n`.
- Each server instance manages a single host. For several hosts, register several entries in the MCP client.
- Only SSH is implemented. Telnet, serial, TCP and UDP are not supported.
