"""Local DB management — download from GitHub Releases for offline scanning.

The DB is built by vuln-intel-db GitHub Actions every 6 hours and published
as a GitHub Release artifact. Users download once and scan offline.

DB location: ~/.dscanner/db/vuln-db.json.gz (~15-30MB)
"""

import gzip
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

import httpx

_log = logging.getLogger(__name__)

DB_DIR = Path.home() / ".dscanner" / "db"
DB_FILE = DB_DIR / "vuln-db.json.gz"
DB_META = DB_DIR / "meta.json"

# Default: download from GitHub Releases
GITHUB_DB_URL = "https://github.com/yourorg/vuln-intel-db/releases/download/db-latest/vuln-db.json.gz"
GITHUB_META_URL = "https://github.com/yourorg/vuln-intel-db/releases/download/db-latest/db-meta.json"


def update_db(api_url: str | None = None) -> dict:
    """Download latest vulnerability DB.

    Sources (in priority order):
      1. VulnIntel API export endpoint (if api_url provided)
      2. GitHub Releases (default, free)
    """
    DB_DIR.mkdir(parents=True, exist_ok=True)

    if api_url:
        return _download_from_api(api_url)
    return _download_from_github()


def _download_from_github() -> dict:
    """Download pre-built DB from GitHub Releases."""
    _log.info("Downloading DB from GitHub Releases...")

    with httpx.Client(timeout=120, follow_redirects=True) as client:
        # Download meta first (small)
        try:
            resp = client.get(GITHUB_META_URL)
            resp.raise_for_status()
            meta = resp.json()
            with open(DB_META, "w") as f:
                json.dump(meta, f)
        except Exception:
            meta = {}

        # Download DB file
        resp = client.get(GITHUB_DB_URL)
        resp.raise_for_status()
        with open(DB_FILE, "wb") as f:
            f.write(resp.content)

    size_mb = DB_FILE.stat().st_size / 1024 / 1024
    _log.info("Downloaded %.1f MB", size_mb)

    return {
        "total": meta.get("total_advisories", 0),
        "sources": list(meta.get("by_source", {}).keys()),
        "updated_at": meta.get("built_at"),
        "size_mb": round(size_mb, 1),
    }


def _download_from_api(api_url: str) -> dict:
    """Download DB by exporting from VulnIntel API."""
    _log.info("Downloading DB from API: %s", api_url)

    ecosystems = [
        "debian-trixie", "debian-bookworm", "debian-bullseye",
        "alpine-3.19", "alpine-3.20", "alpine-3.21",
        "pypi", "npm", "go", "maven", "cargo", "rubygems",
    ]

    all_advisories = []
    with httpx.Client(timeout=60) as client:
        for eco in ecosystems:
            try:
                resp = client.get(f"{api_url}/api/v1/export/{eco}")
                resp.raise_for_status()
                data = resp.json()
                all_advisories.extend(data.get("advisories", []))
            except Exception as exc:
                _log.warning("Failed to export %s: %s", eco, exc)

    db = {
        "version": 1,
        "built_at": datetime.utcnow().isoformat(),
        "total_advisories": len(all_advisories),
        "advisories": all_advisories,
        "kev": [],
        "kev_cves": [],
        "epss": {},
    }

    with gzip.open(DB_FILE, "wt", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"))

    meta = {
        "total_advisories": len(all_advisories),
        "updated_at": db["built_at"],
    }
    with open(DB_META, "w") as f:
        json.dump(meta, f)

    return {"total": len(all_advisories), "sources": ecosystems, "updated_at": db["built_at"]}


def get_db_stats() -> dict:
    """Get local DB stats."""
    if not DB_META.exists():
        return {"total": 0, "sources": [], "updated_at": None, "available": False}
    with open(DB_META) as f:
        data = json.load(f)
    data["available"] = DB_FILE.exists()
    return data


def load_db() -> dict | None:
    """Load the local DB into memory. Returns None if not available."""
    if not DB_FILE.exists():
        return None
    try:
        with gzip.open(DB_FILE, "rt", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def query_local_db(package: str, ecosystem: str) -> list[dict]:
    """Query the local DB for advisories. Used in offline mode."""
    db = load_db()
    if not db:
        return []

    results = []
    for adv in db.get("advisories", []):
        if adv.get("pkg") == package and adv.get("eco") == ecosystem:
            results.append(adv)

    return results
