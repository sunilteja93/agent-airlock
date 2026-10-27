"""Connectivity check for Meta Model API."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from airlock.meta_client import ping


if __name__ == "__main__":
    print(ping())
