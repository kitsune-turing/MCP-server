# KIT-MCP Server

**Generic MCP server for remote shell access over SSH, Telnet, TCP, and Serial.**

> Originally designed for Raspberry Pi connections — now connects to _any_ server.

---

## Standalone Version

This project also includes a **single-file Python version** (`kit_mcp_standalone.py`) with all components consolidated:
- Enums, errors, and security utilities
- Audit logging with JSON serialization
- Configuration parsing and validation
- Transport abstraction (SSH) with rate limiting
- MCP server endpoint

**Usage**:
```bash
python kit_mcp_standalone.py --host 10.0.0.1 --user admin --auth password --password secret
```

This is useful for:
- Minimal deployments (single file to deploy)
- Embedded environments
- CI/CD pipelines where modularity is less important
- Learning the full architecture in one file

---

## Quick Start

```bash
# SSH with key file
kit-mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_ed25519

# SSH with password (prefer key auth in production)
kit-mcp --host 10.0.0.5 --user admin --auth password --password s3cr3t --port 2222

# SSH with sudo password (for commands requiring elevated privileges)
kit-mcp --host 192.168.1.10 --user kitsune --auth key_file --key ~/.ssh/id_ed25519 --sudo-password MyS3cr3t

# Telnet (no auth)
kit-mcp --host 172.16.0.1 --user admin --transport telnet --auth none

# Via Docker
docker run --rm -i \
  -v ~/.ssh:/home/mcp/.ssh:ro \
  ghcr.io/your-org/kit-mcp-server \
  --host 192.168.1.10 --user pi --auth key_file --key /home/mcp/.ssh/id_ed25519
```

---

## CLI Flags Reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--host` | ✅ | — | Hostname or IP address |
| `--user` | ✅ | — | Remote username |
| `--auth` | ✅ | — | `password` · `key_file` · `key_agent` · `certificate` · `none` |
| `--port` | | transport default | Port (22=SSH, 23=Telnet) |
| `--transport` | | `ssh` | `ssh` · `telnet` · `tcp` · `udp` · `serial` |
| `--password` | if `--auth password` | `$KIT_MCP_PASSWORD` | Auth password |
| `--sudo-password` | optional | `$KIT_MCP_SUDO_PASSWORD` | Password for sudo commands (separate from login password) |
| `--key` | if `--auth key_file` | — | Path to private key |
| `--key-algo` | | auto-detect | `ed25519` · `rsa` · `ecdsa` |
| `--timeout` | | `15` | Connection timeout (seconds) |
| `--cmd-timeout` | | `120` | Per-command timeout (seconds) |
| `--keepalive` | | `15` | SSH keepalive interval (0 = off) |
| `--os` | | `unknown` | Hint: `linux` · `bsd` · `macos` · `windows` |
| `--role` | | `generic` | Hint: `raspberry_pi` · `router` · `database` · `web` · `embedded` |
| `--name` | | `user@host` | Human-readable label (appears in logs) |
| `--no-host-check` | | false | Skip SSH host-key verification ⚠️ dev only |
| `-v / --verbose` | | false | Debug logging |

> **Password security**: use the `KIT_MCP_PASSWORD` environment variable instead  
> of `--password` to avoid credentials appearing in shell history.  
> Similarly, use `KIT_MCP_SUDO_PASSWORD` for sudo password.

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `run_command(command)` | Execute a shell command remotely |
| `connect_server(prompt)` | Alias for `run_command` (backward compat) |
| `server_status()` | Check reachability + return connection metadata |

All tools return a typed dict:

```json
// Success
{ "ok": true, "exit_code": 0, "stdout": "...", "stderr": "", "duration_ms": 42 }

// Error
{ "ok": false, "error": "AUTH_BAD_KEY", "category": "auth", "detail": "...", "context": {} }
```

---

## Error Codes

Errors are fully typed with `ErrorCode` (string enum) and `ErrorCategory`:

| Category | Codes (examples) |
|----------|-----------------|
| `connection` | `CONNECTION_REFUSED` · `CONNECTION_TIMEOUT` · `CONNECTION_HOST_UNREACHABLE` · `CONNECTION_DNS_FAILURE` |
| `auth` | `AUTH_BAD_PASSWORD` · `AUTH_BAD_KEY` · `AUTH_KEY_NOT_FOUND` · `AUTH_KEY_PASSPHRASE` · `AUTH_HOST_KEY_MISMATCH` |
| `timeout` | `TIMEOUT_CONNECT` · `TIMEOUT_COMMAND` · `TIMEOUT_BANNER` · `TIMEOUT_AUTH` |
| `command` | `COMMAND_NON_ZERO_EXIT` · `COMMAND_SIGNAL_KILLED` |
| `config` | `CONFIG_MISSING_HOST` · `CONFIG_INVALID_PORT` · `CONFIG_MISSING_CREDENTIAL` |
| `transport` | `TRANSPORT_NEGOTIATION` · `TRANSPORT_KEEPALIVE_LOST` |

---

## Docker

```bash
# Build
docker build -t kit-mcp-server .

# Run (SSH with key)
docker run --rm -i \
  -v ~/.ssh:/home/mcp/.ssh:ro \
  kit-mcp-server \
  --host 192.168.1.10 --user pi --auth key_file --key /home/mcp/.ssh/id_ed25519

# Docker Compose — override via .env
echo "KIT_MCP_HOST=192.168.1.10" >> .env
echo "KIT_MCP_USER=pi" >> .env
echo "KIT_MCP_AUTH=key_file" >> .env
docker compose up server
```

---

## Sudo Support

The server supports automatic password injection for `sudo` commands. This is **optional** and separate from the login password.

**Key points:**
- The `--sudo-password` is **stored at startup** but only used when needed
- It is **NOT used** for regular (non-sudo) commands
- It is **ONLY used** when a command explicitly starts with `sudo`
- You can provide it and never use it - it will simply remain unused

**How it works:**
- When a command starts with `sudo`, the server automatically:
  1. Allocates a PTY (pseudo-terminal) for interactive mode
  2. Injects the sudo password when prompted
  3. Completes the command and returns results
- When a command does NOT start with `sudo`:
  1. The sudo password is completely ignored
  2. Command executes normally without PTY overhead

**Usage:**

```bash
# Initialize the server with sudo password (available but optional to use)
kit-mcp --host 192.168.1.10 --user kitsune --auth key_file --key ~/.ssh/id_ed25519 --sudo-password MySecretSudoPass
```

Then execute commands:

```bash
# These commands DO NOT use the sudo password (no sudo prefix):
run_command("ls -la")                           # ✗ no sudo password needed
run_command("cat /etc/hostname")                # ✗ no sudo password needed
run_command("whoami")                           # ✗ no sudo password needed

# These commands DO use the sudo password (starts with sudo):
run_command("sudo systemctl restart nginx")     # ✓ uses sudo password automatically
run_command("sudo cat /etc/shadow")             # ✓ uses sudo password automatically
run_command("sudo apt update")                  # ✓ uses sudo password automatically
run_command("sudo reboot")                      # ✓ uses sudo password automatically
```

**Security notes:**
- The sudo password is **separate** from login credentials
- Use the `KIT_MCP_SUDO_PASSWORD` environment variable to avoid shell history
- You can provide `--sudo-password` even if you never use `sudo` commands
- Non-sudo commands work normally without any PTY overhead
- The password is **only consumed** when actually needed

---

## Getting Started as an MCP Server

Follow these step-by-step instructions to run KIT-MCP as an MCP server.

**Step 1: Install dependencies**

```bash
# Clone the repository
git clone https://github.com/your-org/kit-mcp-server.git
cd kit-mcp-server

# Install the package in development mode
pip install -e .
```

**Step 2: Verify installation**

```bash
# Check if the command is available
kit-mcp --help
```

You should see the CLI help output with all available flags.

**Step 3: Start the MCP server**

Choose one of the following based on your connection type:

```bash
# SSH with key file (recommended)
kit-mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_ed25519

# SSH with password
kit-mcp --host 192.168.1.10 --user admin --auth password --password MyPassword

# SSH with sudo support
kit-mcp --host 192.168.1.10 --user kitsune --auth key_file --key ~/.ssh/id_ed25519 --sudo-password SudoPassword

# Telnet (no authentication)
kit-mcp --host 172.16.0.1 --user admin --transport telnet --auth none
```

The server starts and waits for MCP client connections. You should see:
```
INFO: KIT-MCP Server initialized
INFO: Connected to 192.168.1.10:22
INFO: Waiting for MCP client connections...
```

**Step 4: Connect from your MCP client**

In your MCP-compatible client (Claude Desktop, etc.), configure it to connect to this server.

Example Claude Desktop config (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "kit-mcp": {
      "command": "kit-mcp",
      "args": [
        "--host", "192.168.1.10",
        "--user", "pi",
        "--auth", "key_file",
        "--key", "/home/user/.ssh/id_ed25519"
      ]
    }
  }
}
```

**Step 5: Start using MCP tools**

Once connected, you can now use the MCP tools:

```python
# Execute a simple command
result = mcp.call_tool("run_command", {"command": "ls -la /home"})

# Execute with sudo (if configured)
result = mcp.call_tool("run_command", {"command": "sudo systemctl restart nginx"})

# Check server status
status = mcp.call_tool("server_status", {})
```

---

## Architecture

```
src/
├── enums/          TransportType, AuthType, ErrorCode, ErrorCategory, …
├── errors/         Typed exception hierarchy (KitMCPError → ConnectionError → …)
├── config/         ServerConfig dataclass + CLI parser
├── transport/      BaseTransport (ABC) → SSHTransport → [TelnetTransport, …]
└── core/
    └── server.py   MCP tools + singleton transport manager
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch strategy and team roles.

```
main (protected) → develop → feature/00N-*
```

Never push to `main` directly.

---

## License

MIT
