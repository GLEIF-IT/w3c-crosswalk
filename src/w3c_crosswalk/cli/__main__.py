"""Support `python -m w3c_crosswalk.cli`."""

from __future__ import annotations

import sys

from .main import main


if __name__ == "__main__":
    sys.exit(main())
