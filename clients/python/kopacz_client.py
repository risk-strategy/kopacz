#!/usr/bin/env python3
"""
Standalone Python CLI entrypoint for Kopacz v3.
Can be run directly (`python3 clients/python/kopacz_client.py ...`) or
packaged into a single executable `.pyz` archive via `clients/python/build_pyz.sh`.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (REPO_ROOT / "kopacz").is_dir() and str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from kopacz.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
