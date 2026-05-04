# KIT-MCP Server

**Servidor MCP genérico para acceso remoto a shells sobre SSH, Telnet, TCP y Serial.**

> Originalmente diseñado para conexiones a Raspberry Pi — ahora se conecta a _cualquier_ servidor.

---

## Versión Standalone

Este proyecto también incluye una **versión de un único archivo Python** (`kit_mcp_standalone.py`) con todos los componentes consolidados:
- Enums, errores y utilidades de seguridad
- Registro de auditoría con serialización JSON
- Análisis y validación de configuración
- Abstracción de transporte (SSH) con limitación de velocidad
- Endpoint del servidor MCP

**Uso**:
```bash
python kit_mcp_standalone.py --host 10.0.0.1 --user admin --auth password --password secret
```

Esto es útil para:
- Despliegues mínimos (archivo único para desplegar)
- Ambientes incrustados
- Tuberías de CI/CD donde la modularidad es menos importante
- Aprender la arquitectura completa en un archivo

---

## Inicio Rápido

```bash
# SSH con archivo de clave
kit-mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_ed25519

# SSH con contraseña (preferir autenticación por clave en producción)
kit-mcp --host 10.0.0.5 --user admin --auth password --password s3cr3t --port 2222

# SSH con contraseña de sudo (para comandos que requieren privilegios elevados)
kit-mcp --host 192.168.1.10 --user kitsune --auth key_file --key ~/.ssh/id_ed25519 --sudo-password MiS3cr3t

# Telnet (sin autenticación)
kit-mcp --host 172.16.0.1 --user admin --transport telnet --auth none

# Mediante Docker
docker run --rm -i \
  -v ~/.ssh:/home/mcp/.ssh:ro \
  ghcr.io/your-org/kit-mcp-server \
  --host 192.168.1.10 --user pi --auth key_file --key /home/mcp/.ssh/id_ed25519
```

---

## Referencia de Banderas CLI

| Bandera | Requerida | Por defecto | Descripción |
|------|----------|---------|-------------|
| `--host` | ✅ | — | Nombre de host o dirección IP |
| `--user` | ✅ | — | Nombre de usuario remoto |
| `--auth` | ✅ | — | `password` · `key_file` · `key_agent` · `certificate` · `none` |
| `--port` | | por defecto de transporte | Puerto (22=SSH, 23=Telnet) |
| `--transport` | | `ssh` | `ssh` · `telnet` · `tcp` · `udp` · `serial` |
| `--password` | si `--auth password` | `$KIT_MCP_PASSWORD` | Contraseña de autenticación |
| `--sudo-password` | opcional | `$KIT_MCP_SUDO_PASSWORD` | Contraseña para comandos sudo (separada de la contraseña de acceso) |
| `--key` | si `--auth key_file` | — | Ruta a la clave privada |
| `--key-algo` | | auto-detección | `ed25519` · `rsa` · `ecdsa` · `dsa` |
| `--timeout` | | `15` | Tiempo de espera de conexión (segundos) |
| `--cmd-timeout` | | `120` | Tiempo de espera por comando (segundos) |
| `--keepalive` | | `15` | Intervalo de keepalive SSH (0 = desactivado) |
| `--os` | | `unknown` | Pista: `linux` · `bsd` · `macos` · `windows` |
| `--role` | | `generic` | Pista: `raspberry_pi` · `router` · `database` · `web` · `embedded` |
| `--name` | | `user@host` | Etiqueta legible por humanos (aparece en logs) |
| `--no-host-check` | | false | Omitir verificación de clave de host SSH ⚠️ solo dev |
| `-v / --verbose` | | false | Registro de depuración |

> **Seguridad de contraseña**: usa la variable de entorno `KIT_MCP_PASSWORD` en lugar  
> de `--password` para evitar que las credenciales aparezcan en el historial de shell.  
> De manera similar, usa `KIT_MCP_SUDO_PASSWORD` para la contraseña de sudo.

---

## Herramientas MCP

| Herramienta | Descripción |
|------|-------------|
| `run_command(command)` | Ejecuta un comando de shell remotamente |
| `connect_server(prompt)` | Alias para `run_command` (compatibilidad hacia atrás) |
| `server_status()` | Verifica la accesibilidad y retorna metadatos de conexión |

Todas las herramientas devuelven un diccionario tipado:

```json
// Éxito
{ "ok": true, "exit_code": 0, "stdout": "...", "stderr": "", "duration_ms": 42 }

// Error
{ "ok": false, "error": "AUTH_BAD_KEY", "category": "auth", "detail": "...", "context": {} }
```

---

## Códigos de Error

Los errores están completamente tipados con `ErrorCode` (enumeración de cadena) y `ErrorCategory`:

| Categoría | Códigos (ejemplos) |
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
# Construir
docker build -t kit-mcp-server .

# Ejecutar (SSH con clave)
docker run --rm -i \
  -v ~/.ssh:/home/mcp/.ssh:ro \
  kit-mcp-server \
  --host 192.168.1.10 --user pi --auth key_file --key /home/mcp/.ssh/id_ed25519

# Docker Compose — anular mediante .env
echo "KIT_MCP_HOST=192.168.1.10" >> .env
echo "KIT_MCP_USER=pi" >> .env
echo "KIT_MCP_AUTH=key_file" >> .env
docker compose up server
```

---

## Soporte de sudo

El servidor soporta inyección automática de contraseña para comandos `sudo`. Esto es **opcional** y separado de la contraseña de inicio de sesión.

**Puntos clave:**
- La contraseña `--sudo-password` se **almacena al iniciar** pero solo se usa cuando es necesaria
- **NO se usa** para comandos regulares (sin sudo)
- **SOLO se usa** cuando un comando explícitamente comienza con `sudo`
- Puedes proporcionarla y nunca usarla - simplemente permanecerá sin usar

**Cómo funciona:**
- Cuando un comando comienza con `sudo`, el servidor automáticamente:
  1. Asigna un PTY (pseudo-terminal) para modo interactivo
  2. Inyecta la contraseña de sudo cuando se solicita
  3. Completa el comando y devuelve los resultados
- Cuando un comando NO comienza con `sudo`:
  1. La contraseña de sudo se ignora completamente
  2. El comando se ejecuta normalmente sin sobrecarga de PTY

**Uso:**

```bash
# Inicializar el servidor con contraseña de sudo (disponible pero opcional para usar)
kit-mcp --host 192.168.1.10 --user kitsune --auth key_file --key ~/.ssh/id_ed25519 --sudo-password MiContraseñaSudo
```

Luego ejecutar comandos:

```bash
# Estos comandos NO usan la contraseña de sudo (sin prefijo sudo):
run_command("ls -la")                           # ✗ sin necesidad de contraseña sudo
run_command("cat /etc/hostname")                # ✗ sin necesidad de contraseña sudo
run_command("whoami")                           # ✗ sin necesidad de contraseña sudo

# Estos comandos SÍ usan la contraseña de sudo (comienzan con sudo):
run_command("sudo systemctl restart nginx")     # ✓ usa contraseña sudo automáticamente
run_command("sudo cat /etc/shadow")             # ✓ usa contraseña sudo automáticamente
run_command("sudo apt update")                  # ✓ usa contraseña sudo automáticamente
run_command("sudo reboot")                      # ✓ usa contraseña sudo automáticamente
```

**Notas de seguridad:**
- La contraseña de sudo es **independiente** de las credenciales de acceso
- Usar la variable de entorno `KIT_MCP_SUDO_PASSWORD` para evitar historial de shell
- Puedes proporcionar `--sudo-password` incluso si nunca usas comandos `sudo`
- Los comandos sin sudo funcionan normalmente sin sobrecarga de PTY
- La contraseña **solo se consume** cuando realmente se necesita

---

## Comenzando como Servidor MCP

Sigue estas instrucciones paso a paso para ejecutar KIT-MCP como un servidor MCP.

**Paso 1: Instalar dependencias**

```bash
# Clonar el repositorio
git clone https://github.com/your-org/kit-mcp-server.git
cd kit-mcp-server

# Instalar el paquete en modo desarrollo
pip install -e .
```

**Paso 2: Verificar la instalación**

```bash
# Verificar que el comando esté disponible
kit-mcp --help
```

Deberías ver la salida de ayuda del CLI con todas las banderas disponibles.

**Paso 3: Iniciar el servidor MCP**

Elige una de las siguientes opciones según tu tipo de conexión:

```bash
# SSH con archivo de clave (recomendado)
kit-mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_ed25519

# SSH con contraseña
kit-mcp --host 192.168.1.10 --user admin --auth password --password MiContraseña

# SSH con soporte de sudo
kit-mcp --host 192.168.1.10 --user kitsune --auth key_file --key ~/.ssh/id_ed25519 --sudo-password ContraseñaSudo

# Telnet (sin autenticación)
kit-mcp --host 172.16.0.1 --user admin --transport telnet --auth none
```

El servidor inicia y espera conexiones de clientes MCP. Deberías ver:
```
INFO: KIT-MCP Server initialized
INFO: Connected to 192.168.1.10:22
INFO: Waiting for MCP client connections...
```

**Paso 4: Conectarse desde tu cliente MCP**

En tu cliente compatible con MCP (Claude Desktop, etc.), configúralo para conectarse a este servidor.

Ejemplo de configuración de Claude Desktop (`claude_desktop_config.json`):
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

**Paso 5: Comenzar a usar herramientas MCP**

Una vez conectado, puedes usar las herramientas MCP:

```python
# Ejecutar un comando simple
result = mcp.call_tool("run_command", {"command": "ls -la /home"})

# Ejecutar con sudo (si está configurado)
result = mcp.call_tool("run_command", {"command": "sudo systemctl restart nginx"})

# Verificar el estado del servidor
status = mcp.call_tool("server_status", {})
```

---

## Arquitectura

```
src/
├── enums/          TransportType, AuthType, ErrorCode, ErrorCategory, …
├── errors/         Jerarquía de excepciones tipada (KitMCPError → ConnectionError → …)
├── config/         Dataclass ServerConfig + parser CLI
├── transport/      BaseTransport (ABC) → SSHTransport → [TelnetTransport, …]
└── core/
    └── server.py   Herramientas MCP + gestor de transporte singleton
```

---

## Contribuyendo

Ver [CONTRIBUTING.md](CONTRIBUTING.md) para estrategia de ramas y roles del equipo.

```
main (protegida) → develop → feature/00N-*
```

Nunca hagas push directamente a `main`.

---

## Licencia

MIT
