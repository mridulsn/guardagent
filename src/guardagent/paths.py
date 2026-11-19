"""Repository paths. Everything is relative to the repo root, never absolute."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
DOCS_DIR = DATA_DIR / "docs"
DB_PATH = DATA_DIR / "shop.db"
WEB_DATA = ROOT / "web" / "data"
CACHE_DIR = ROOT / ".cache"
RUNS_DIR = ROOT / "runs"
