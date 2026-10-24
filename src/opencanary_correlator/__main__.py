"""Entry point for ``python -m opencanary_correlator``."""

from __future__ import annotations

import sys

from opencanary_correlator.cli import main

if __name__ == "__main__":
    sys.exit(main())
