# CONTRIBUTING — KIT-MCP Server

## Branch Strategy

```
main          (protected — no direct pushes, no force-push)
 └─ develop   (integration branch)
      ├─ feature/001-ssh-transport
      ├─ feature/002-telnet-transport
      ├─ feature/003-serial-transport
      └─ feature/004-...
```

### Rules

| Branch prefix | Who creates it | Merges into | Notes |
|---|---|---|---|
| `feature/00N-<slug>` | Any engineer | `develop` | All new work lands here |
| `fix/00N-<slug>` | Any engineer | `develop` | Bug fixes |
| `develop` | Team | `main` (via PR) | Integration; must pass CI |
| `main` | CI only | — | **Never push here directly** |

### Opening a PR

1. Branch off `develop`:
   ```bash
   git checkout develop && git pull
   git checkout -b feature/005-tcp-transport
   ```
2. Make commits.  
3. Push and open a PR **from `feature/005-tcp-transport` → `develop`**.
4. At least one review required (BackEnd or QA).
5. CI must pass (lint + unit + integration + docker build).
6. Squash-merge — keep history clean.

---

## Team Roles

| Role | Responsibilities |
|---|---|
| **BackEnd** | Core transport implementations (`src/transport/`), new protocol support |
| **QA** | Test coverage (`tests/`), integration test scenarios, error-path verification |
| **Server Admin** | Dockerfile, `docker-compose.yml`, CI pipelines, deployment guides |
| **All** | Enum definitions, error hierarchy, config parsing — shared ownership |

---

## Development Setup

```bash
# Clone
git clone https://github.com/your-org/KIT-mcp-server.git
cd KIT-mcp-server
git checkout develop

# Python env
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src && mypy src

# Docker (build + test)
docker compose run tests
docker compose run lint
```

---

## Adding a New Transport

1. Create `src/transport/<name>.py` implementing `BaseTransport`.  
2. Register it in `create_transport()` inside `src/transport/__init__.py`.  
3. Add the transport value to `TransportType` enum.  
4. Add integration tests in `tests/integration/test_<name>_transport.py`.  
5. Open PR `feature/00N-<name>-transport`.
