"""Repo-root import shim so `from src.ingest import ...` works.

Pytest already puts this directory on sys.path and imports the modules directly.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
