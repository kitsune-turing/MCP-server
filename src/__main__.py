"""
KIT-MCP Server — CLI entry point.

Run as:
  python -m kit_mcp --host 192.168.1.10 --user pi --auth key_file --key ~/.ssh/id_ed25519
  kit-mcp --host 10.0.0.5 --user admin --auth password --password s3cr3t
"""
from __future__ import annotations

import sys

from kit_mcp.config import parse_args
from kit_mcp.errors import ConfigError, KitMCPError
from kit_mcp.core.server import init_server, mcp


def main(argv: list[str] | None = None) -> None:
    try:
        config = parse_args(argv)
    except ConfigError as e:
        print(f"\n[CONFIG ERROR] {e}\n", file=sys.stderr)
        sys.exit(2)
    except SystemExit:
        raise  # argparse --help / error exit
    except Exception as e:
        print(f"\n[FATAL] {e}\n", file=sys.stderr)
        sys.exit(1)

    init_server(config)

    try:
        mcp.run(transport="stdio")
    except KitMCPError as e:
        print(f"\n[{e.category.value.upper()}] {e}\n", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
