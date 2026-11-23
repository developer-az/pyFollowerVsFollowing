"""Allow ``python -m osint_kit``."""

from __future__ import annotations

import sys

from osint_kit.cli import main

if __name__ == "__main__":
    sys.exit(main())
