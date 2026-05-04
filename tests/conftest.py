"""Shared pytest fixtures for KIT-MCP tests."""
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))
