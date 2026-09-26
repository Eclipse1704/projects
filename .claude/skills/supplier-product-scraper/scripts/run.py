#!/usr/bin/env python3
"""Supplier product scraper -> Hebrew HTML catalogue.  See ../SKILL.md."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
