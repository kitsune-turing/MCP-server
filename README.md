# KIT-MCP

Servidor [MCP](https://modelcontextprotocol.io) que permite a un asistente de IA (Claude Desktop, Claude Code u otro cliente MCP) operar un servidor remoto por **SSH** de forma controlada: ejecutar comandos, consultar el estado del sistema y leer o escribir archivos, con políticas de seguridad, redacción de secretos y auditoría.

Todo el servidor está en un único archivo: `kit_mcp.py`.

---

## Contenido

- [Características](#características)
- [Requisitos e instalación](#requisitos-e-instalación)
- [Inicio rápido](#inicio-rápido)
- [Conectarlo a un cliente MCP](#conectarlo-a-un-cliente-mcp)
- [Credenciales](#credenciales)
- [Verificación del servidor (host key)](#verificación-del-servidor-host-key)
- [Políticas de ejecución](#políticas-de-ejecución)
- [Herramientas disponibles](#herramientas-disponibles)
- [Auditoría](#auditoría)
- [Referencia de opciones](#referencia-de-opciones)
- [Pruebas](#pruebas)
- [Solución de problemas](#solución-de-problemas)
- [Recomendaciones y limitaciones](#recomendaciones-y-limitaciones)

---

## Características

**Seguridad**
- Tres políticas de ejecución: `readonly`, `restricted` (por defecto) y `unrestricted`.
- `sudo` y escritura de archivos deshabilitados salvo que se activen de forma explícita.
- La contraseña de sudo nunca aparece en la salida (se envía con `sudo -S -p ''`, sin PTY).
- Redacción automática de secretos en todo lo que recibe la IA y en la auditoría: claves privadas, AWS keys, tokens de GitHub/Slack, JWT, `password=…`, credenciales en URLs y las contraseñas configuradas.
- Bloqueo en todas las políticas de comandos que leen `/etc/shadow`, claves privadas SSH, credenciales de AWS o variables de entorno.
- Verificación del servidor por `known_hosts`, aceptación la primera vez (TOFU) o huella fijada. Algoritmos débiles deshabilitados por defecto.
- Límite de comandos por minuto y bloqueo temporal tras fallos de autenticación.
- Auditoría JSONL con cadena HMAC que detecta registros editados o borrados.

**Rendimiento**
- Herramientas asíncronas: el SSH corre en hilos y no bloquea el servidor MCP.
- Una sola conexión persistente (un canal por comando), keepalive y compresión opcional.
- Lectura simultánea de stdout y stderr, timeout real y memoria acotada.
- `run_batch` ejecuta hasta 20 comandos en paralelo sobre la misma conexión.
- `system_info` obtiene todo el estado del host en un único viaje de red.

**Información más útil para la IA**
- Salida limpia (sin códigos ANSI) y truncado que conserva el inicio y el final.
- Resultados JSON estructurados y errores con un `hint` accionable.
- Métricas ya calculadas con alertas (memoria/disco ≥ 90 %, temperatura ≥ 75 °C, carga alta, servicios caídos).

---

## Requisitos e instalación

- Python **3.10** o superior
- `paramiko` **3.2** o superior
- `mcp` (compatible con 1.x y 2.x)

```bash
git clone https://github.com/kitsune-turing/MCP-server.git
cd MCP-server
python3 -m venv .venv && source .venv/bin/activate
pip install "paramiko>=3.2" "mcp[cli]"
```

Comprobar la instalación:

```bash
python kit_mcp.py --version
python kit_mcp.py --help
```

---

## Inicio rápido

Con llave SSH (recomendado):

```bash
python kit_mcp.py \
  --host 10.0.0.5 --user pi \
  --auth key_file --key ~/.ssh/id_ed25519 \
  --known-hosts ~/.kit-mcp/known_hosts --accept-new
```

Con contraseña, pasada por variable de entorno:

```bash
export KIT_MCP_PASSWORD='mi-contraseña'
python kit_mcp.py --host 10.0.0.5 --user admin --auth password \
  --known-hosts ~/.kit-mcp/known_hosts --accept-new
```

El servidor habla MCP por **stdio**, así que normalmente no lo ejecutas a mano: lo lanza tu cliente MCP (siguiente sección). Los logs salen por stderr.

---

## Conectarlo a un cliente MCP

### Claude Desktop

Edita `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "raspberry": {
      "command": "/ruta/MCP-server/.venv/bin/python",
      "args": [
        "/ruta/MCP-server/kit_mcp.py",
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
        "KIT_MCP_AUDIT_KEY": "<cadena-larga-y-aleatoria>"
      }
    }
  }
}
```

Reinicia Claude Desktop. Para varios servidores, agrega una entrada por cada uno (`"router": {...}`, `"web": {...}`).

### Claude Code

```bash
claude mcp add raspberry -- /ruta/.venv/bin/python /ruta/kit_mcp.py \
  --host 10.0.0.5 --user pi --auth key_file --key ~/.ssh/id_ed25519 \
  --known-hosts ~/.kit-mcp/known_hosts --accept-new
```

### Probar sin cliente

```bash
npx @modelcontextprotocol/inspector python kit_mcp.py --host 10.0.0.5 --user pi --auth key_agent
```

---

## Credenciales

| Método | `--auth` | Cómo se proporciona |
|---|---|---|
| Llave privada | `key_file` | `--key RUTA`. Si tiene passphrase: `KIT_MCP_KEY_PASSPHRASE`. El tipo (Ed25519, ECDSA, RSA) se detecta solo. |
| Agente SSH | `key_agent` (por defecto) | Usa las llaves cargadas en `ssh-agent`. |
| Contraseña | `password` | `--password-file RUTA`, variable `KIT_MCP_PASSWORD` o `--password`. |
| Ninguna | `none` | Solo para equipos sin autenticación. |

Contraseña de sudo (requiere `--allow-sudo`): `--sudo-password-file`, `KIT_MCP_SUDO_PASSWORD` o `--sudo-password`.

**Prioridad:** archivo → variable de entorno → línea de comandos. Tras leerla, la variable se elimina del entorno del proceso.

> ⚠️ `--password` y `--sudo-password` funcionan, pero quedan visibles en `ps` y en el historial de la shell. El programa lo advierte al arrancar. Usa archivos con permisos `600` o variables de entorno.

```bash
printf '%s' 'mi-contraseña' > ~/.kit-mcp/pass && chmod 600 ~/.kit-mcp/pass
python kit_mcp.py --host 10.0.0.5 --user admin --auth password --password-file ~/.kit-mcp/pass ...
```

---

## Verificación del servidor (host key)

Verificar la huella del servidor evita ataques de intermediario (MITM). Hay cuatro modos:

| Modo | Opciones | Comportamiento |
|---|---|---|
| Estricto (por defecto) | — o `--known-hosts ARCHIVO` | Solo acepta hosts que ya estén en `~/.ssh/known_hosts` o en el archivo indicado. |
| TOFU | `--known-hosts ARCHIVO --accept-new` | Acepta y guarda un host nuevo la primera vez; si después cambia la huella, lo rechaza. |
| Fijada | `--host-key-fingerprint SHA256:…` | Solo acepta esa huella exacta. Es el modo más seguro. |
| Desactivado | `--no-host-check` | **Inseguro.** Solo para laboratorio; avisa en cada arranque. |

Si el host es desconocido, el error `HOST_KEY_UNKNOWN` incluye la huella del servidor. Para comprobarla, ejecuta en el propio servidor:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Si es la misma, puedes fijarla con `--host-key-fingerprint`.

Para equipos antiguos (routers, embebidos) que solo soportan SHA1 o CBC, agrega `--legacy-crypto`.

---

## Políticas de ejecución

Se elige con `--policy`:

### `readonly`: solo consulta
Acepta únicamente comandos de una lista blanca (`ls`, `cat`, `grep`, `df`, `free`, `ps`, `journalctl`, `ip`, `ss`, `docker ps/logs`, `git status/log`, `systemctl status`…) y analiza la línea respetando comillas:
- Permite `|`, `&&`, `||` y `;` entre comandos permitidos.
- Bloquea redirecciones (`>`, `<`), `&` en segundo plano, `$(…)`, comillas invertidas, asignaciones de variables y argumentos peligrosos (`find -delete/-exec`, `ip … add/del`, `awk system()`…).
- `write_file` queda deshabilitado aunque se pase `--allow-write`.

### `restricted`: por defecto
Permite cualquier comando excepto los destructivos: borrado recursivo de rutas del sistema, `mkfs`, `dd` hacia dispositivos, apagado o reinicio, fork bombs, `curl | sh`, shells reversas, borrado de historial, gestión de usuarios, vaciado del firewall, sobrescritura de `/etc/passwd`, `chmod -R 777 /`, etc.

### `unrestricted`
Sin filtro de comandos. Se mantienen el bloqueo de lectura de secretos, la redacción, la auditoría y el límite de tasa.

### Aplica a todas las políticas
- `sudo` solo con `--allow-sudo`. Si no hay contraseña de sudo, se usa `sudo -n` para que falle rápido en lugar de quedarse esperando.
- Se rechazan los comandos interactivos (`vim`, `nano`, `less`, `htop`, `top` sin `-b`, `ssh`…) y se sugiere la alternativa no interactiva.
- Se aplica el límite de `--rate-limit` comandos por minuto (60 por defecto).

> La lista negra de `restricted` reduce el riesgo, pero no es infalible. En producción, combina `readonly` con un usuario SSH de pocos privilegios.

---

## Herramientas disponibles

Todas devuelven JSON con `ok`. Los errores incluyen `error`, `category`, `detail` y, cuando aplica, `hint`.

| Herramienta | Descripción |
|---|---|
| `run_command(command, timeout_s?, cwd?)` | Ejecuta un comando no interactivo. Devuelve `exit_code`, `stdout`, `stderr`, `duration_ms`, `stdout_lines`, `bytes` y `truncated`. |
| `run_batch(commands, parallel=true, stop_on_error=false, timeout_s?)` | Hasta 20 comandos. En paralelo por defecto; con `stop_on_error` los ejecuta en orden y se detiene en el primer fallo. |
| `system_info()` | Hostname, SO, kernel, modelo, uptime, carga, CPUs, memoria, swap, discos, temperatura, servicios systemd fallidos y `alerts`. |
| `server_status()` | Alcance, latencia, configuración (sin credenciales) y datos de la sesión SSH (versión, cifrado, tiempo conectado). |
| `read_file(path, offset=0, max_bytes=65536, encoding="text")` | Lee por SFTP. Paginable con `next_offset`. Para binarios usa `encoding="base64"`. Máximo 1 MiB por llamada. |
| `list_directory(path=".", show_hidden=false)` | Lista con tipo, tamaño, permisos y fecha; los directorios primero. |
| `write_file(path, content, mode="overwrite", create_dirs=false)` | **Solo aparece con `--allow-write`** y una política distinta de `readonly`. `overwrite` es atómico (temporal + rename) y conserva los permisos; `append` agrega al final. Máximo 1 MiB. |
| `audit_tail(limit=20)` | Últimos eventos de auditoría de la sesión. |

**Confinamiento de archivos:** con `--allowed-path /ruta` (repetible), las herramientas de archivos solo operan dentro de esas raíces. Las rutas y los symlinks se resuelven en el servidor, así que `../` o un enlace hacia fuera se rechazan. Siempre se bloquean `/etc/shadow`, `/etc/sudoers`, `~/.ssh/id_*`, `authorized_keys`, `~/.aws/credentials`, `~/.kube/config`, historiales de shell y `/dev/*`.

### Ejemplos de respuesta

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

Comando bloqueado:

```json
{
  "ok": false,
  "error": "POLICY_DENIED",
  "category": "policy",
  "detail": "Bloqueado: borrado recursivo de rutas del sistema.",
  "hint": "El comando fue bloqueado por la política de ejecución. Use una alternativa de solo lectura o pida al operador que cambie --policy."
}
```

`system_info()` (resumido):

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

## Auditoría

Cada conexión, comando, rechazo y operación de archivos genera un evento. Sin `--audit-log`, los eventos se guardan solo en memoria (los últimos 500, consultables con `audit_tail`) y salen por stderr. Con `--audit-log ARCHIVO`:

- Se escribe JSONL con permisos `600` y rotación cada 10 MB (10 archivos de respaldo).
- Los comandos se registran redactados, junto con el hash SHA-256 del comando original.
- Cada registro lleva `prev` y `mac` (HMAC-SHA256 del registro anterior y del actual), así que editar, borrar o reordenar líneas rompe la cadena.

Define una clave fija para poder verificar el log más adelante:

```bash
export KIT_MCP_AUDIT_KEY="$(openssl rand -hex 32)"   # guárdala en un gestor de secretos
```

Verificar un log:

```bash
KIT_MCP_AUDIT_KEY=... python kit_mcp.py --verify-audit ~/.kit-mcp/audit.jsonl
# {"valid": true, "records": 128, "detail": "ok"}
```

Si no defines `KIT_MCP_AUDIT_KEY`, se genera una clave aleatoria por sesión y el log solo se puede verificar mientras esa sesión siga activa.

---

## Referencia de opciones

| Opción | Por defecto | Descripción |
|---|---|---|
| `--host` | — | Hostname, IPv4 o IPv6. **Obligatorio.** |
| `--user` | — | Usuario SSH. **Obligatorio.** |
| `--port` | `22` | Puerto SSH. |
| `--name` | `user@host` | Nombre descriptivo que se muestra a la IA. |
| `--auth` | `key_agent` | `password`, `key_file`, `key_agent` o `none`. |
| `--key` | — | Ruta de la llave privada. |
| `--password-file` / `--password` | — | Contraseña (o variable `KIT_MCP_PASSWORD`). |
| `--sudo-password-file` / `--sudo-password` | — | Contraseña de sudo (o variable `KIT_MCP_SUDO_PASSWORD`). |
| `--known-hosts` | — | Archivo `known_hosts` propio. |
| `--accept-new` | no | Modo TOFU (requiere `--known-hosts`). |
| `--host-key-fingerprint` | — | Huella fijada `SHA256:…`. |
| `--no-host-check` | no | Desactiva la verificación (inseguro). |
| `--legacy-crypto` | no | Permite algoritmos SHA1/CBC. |
| `--compress` | no | Compresión SSH, útil en enlaces lentos. |
| `--policy` | `restricted` | `readonly`, `restricted` o `unrestricted`. |
| `--allow-sudo` | no | Permite `sudo`. |
| `--allow-write` | no | Habilita `write_file`. |
| `--allowed-path` | — | Raíz permitida para archivos (repetible, ruta absoluta). |
| `--rate-limit` | `60` | Comandos por minuto. |
| `--timeout` | `15` | Timeout de conexión (s). |
| `--cmd-timeout` | `120` | Timeout por comando (s). La IA puede pedir hasta 10× este valor. |
| `--keepalive` | `15` | Intervalo de keepalive (s); `0` lo desactiva. |
| `--max-output` | `65536` | Bytes conservados por flujo (stdout/stderr). |
| `--audit-log` | — | Archivo JSONL de auditoría. |
| `--verify-audit` | — | Verifica un log y termina. |
| `--os` | `unknown` | Pista para la IA: `linux`, `bsd`, `macos`, `windows`, `unknown`. |
| `--role` | `generic` | Pista para la IA: `generic`, `raspberry_pi`, `router`, `database`, `web`, `embedded`. |
| `--verbose`, `-v` | no | Logs de depuración. |

| Variable de entorno | Uso |
|---|---|
| `KIT_MCP_PASSWORD` | Contraseña SSH. |
| `KIT_MCP_SUDO_PASSWORD` | Contraseña de sudo. |
| `KIT_MCP_KEY_PASSPHRASE` | Passphrase de la llave privada. |
| `KIT_MCP_AUDIT_KEY` | Clave HMAC de la auditoría. |

Compatibilidad con la v1: se mantienen `--transport ssh` y `--key-algo` (este último ya no hace falta y se ignora).

---

## Pruebas

`test_kit_mcp.py` levanta un servidor SSH/SFTP real en proceso (con paramiko) y prueba el MCP de punta a punta: ejecución, salida grande sin bloqueos, timeout, redacción, sudo, políticas, lotes paralelos, límites, host keys, bloqueo por fallos de login, SFTP con confinamiento, auditoría con detección de manipulación, registro de herramientas MCP y concurrencia con reconexiones.

```bash
pip install pytest pytest-timeout
pytest -q --timeout 60 test_kit_mcp.py
```

Requiere Linux o macOS con `bash`; no necesita `sshd`.

---

## Solución de problemas

| Error | Causa y solución |
|---|---|
| `HOST_KEY_UNKNOWN` | El host no está en `known_hosts`. Verifica la huella del `context` y usa `--accept-new` o `--host-key-fingerprint`. |
| `HOST_KEY_MISMATCH` | La huella cambió. Puede ser una reinstalación del servidor o un ataque MITM: verifícalo fuera de banda antes de continuar. |
| `AUTH_FAILED` | Usuario o credencial incorrectos, o el servidor no acepta ese método. |
| `AUTH_LOCKED_OUT` | 5 fallos en 5 minutos; espera `retry_after_s`. |
| `AUTH_KEY_PASSPHRASE` | La llave está cifrada: define `KIT_MCP_KEY_PASSPHRASE`. |
| `TRANSPORT_NEGOTIATION` | Equipo antiguo sin algoritmos modernos: prueba `--legacy-crypto`. |
| `CONNECTION_REFUSED` / `CONNECTION_TIMEOUT` | El puerto está cerrado, hay un firewall o la IP es incorrecta. |
| `POLICY_DENIED` | Lo bloqueó la política activa; ajusta `--policy`, `--allow-sudo` o `--allow-write` si corresponde. |
| `INTERACTIVE_COMMAND` | Usa la variante no interactiva (`top -bn1`, `journalctl --no-pager`, `read_file`). |
| `TIMEOUT_COMMAND` | Aumenta `timeout_s` o acota la consulta. El error trae `partial_stdout`. |
| `RATE_LIMITED` | Agrupa con `run_batch` o sube `--rate-limit`. |
| `TRANSPORT_LOST` | Se cayó la conexión; la siguiente llamada reconecta. El comando pudo haberse ejecutado parcialmente. |
| `mcp.server.fastmcp` no existe | Estás usando `mcp` 2.x con código antiguo. `kit_mcp.py` ya soporta las dos versiones. |

Para ver los detalles de conexión, agrega `-v`.

---

## Recomendaciones y limitaciones

- Crea un usuario SSH dedicado con los mínimos privilegios y, si es posible, autenticación por llave.
- Fija la huella del servidor (`--host-key-fingerprint`) en entornos de producción.
- Habilita `--allow-sudo` y `--allow-write` solo cuando sea necesario, y limita los archivos con `--allowed-path`.
- Define `KIT_MCP_AUDIT_KEY` y `--audit-log` para tener trazabilidad verificable.
- Cuando un comando supera el timeout se cierra su canal, pero sin PTY el proceso remoto puede seguir vivo. Para tareas largas, usa `timeout N comando` en el propio comando.
- Con contraseña de sudo, solo el `sudo` inicial del comando la recibe; los `sudo` intermedios se ejecutan con `-n`.
- Cada instancia del servidor gestiona un solo host. Para varios hosts, registra varias entradas en el cliente MCP.
- Solo se implementa SSH. Telnet, serial, TCP y UDP no están soportados.
