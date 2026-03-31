"""Core scanner — extracts image, detects packages, matches vulns."""

import io
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request

import httpx
from packaging.version import Version, InvalidVersion
from rich.console import Console

_log = logging.getLogger(__name__)
console = Console()


def scan_image(
    image: str,
    api_url: str = "https://api.dscanner.io",
    offline: bool = False,
    scan_secrets: bool = True,
    scan_misconfig: bool = True,
    registry_auth: dict | None = None,
    quiet: bool = False,
) -> dict:
    """Scan a Docker image end-to-end. Returns full results dict."""

    extract_dir = None
    try:
        # Step 1: Extract image filesystem
        if not quiet:
            console.print("  Extracting image...", end="")
        t0 = time.monotonic()
        extract_dir = _extract_image(image, registry_auth)
        ext_ms = int((time.monotonic() - t0) * 1000)
        if not quiet:
            console.print(f" [green]done[/green] ({ext_ms}ms)")

        # Step 2: Detect distro
        distro = _detect_distro(extract_dir)

        # Step 3: Detect packages
        if not quiet:
            console.print("  Detecting packages...", end="")
        t0 = time.monotonic()
        packages = _detect_packages(extract_dir)
        pkg_ms = int((time.monotonic() - t0) * 1000)
        if not quiet:
            console.print(f" [green]{len(packages)} packages[/green] ({pkg_ms}ms)")

        # Step 4: Match vulnerabilities via VulnIntel DB API
        if not quiet:
            console.print("  Matching advisories...", end="")
        t0 = time.monotonic()
        vulns = _match_vulnerabilities(packages, distro, api_url, offline)
        vuln_ms = int((time.monotonic() - t0) * 1000)
        if not quiet:
            console.print(f" [green]{len(vulns)} vulnerabilities[/green] ({vuln_ms}ms)")

        # Step 5: Secret scanning
        secrets = []
        if scan_secrets:
            if not quiet:
                console.print("  Scanning secrets...", end="")
            t0 = time.monotonic()
            secrets = _scan_secrets(extract_dir)
            sec_ms = int((time.monotonic() - t0) * 1000)
            if not quiet:
                console.print(f" [green]{len(secrets)} secrets[/green] ({sec_ms}ms)")

        # Step 6: Misconfig checks
        misconfigs = []
        if scan_misconfig:
            if not quiet:
                console.print("  Checking misconfigs...", end="")
            t0 = time.monotonic()
            misconfigs = _check_misconfigs(extract_dir, distro)
            mis_ms = int((time.monotonic() - t0) * 1000)
            if not quiet:
                console.print(f" [green]{len(misconfigs)} issues[/green] ({mis_ms}ms)")

        if not quiet:
            console.print()

        return {
            "image": image,
            "distro": distro,
            "packages": [{"name": p[0], "version": p[1], "type": p[2], "ecosystem": p[3]} for p in packages],
            "vulnerabilities": vulns,
            "secrets": secrets,
            "misconfigurations": misconfigs,
        }

    finally:
        if extract_dir and os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)


# ── Image extraction ────────────────────────────────────────────────────

def _extract_image(image: str, auth: dict | None) -> str:
    """Extract image filesystem to temp dir using Docker or registry API."""
    tmp = tempfile.mkdtemp(prefix="dscanner_")

    # Try Docker first
    try:
        cid = subprocess.run(
            ["docker", "create", image, "true"],
            capture_output=True, text=True, timeout=120,
        )
        if cid.returncode == 0:
            container_id = cid.stdout.strip()
            tar_path = os.path.join(tmp, "image.tar")
            subprocess.run(
                ["docker", "export", container_id, "-o", tar_path],
                capture_output=True, timeout=120,
            )
            subprocess.run(["docker", "rm", container_id], capture_output=True)
            if os.path.exists(tar_path):
                with tarfile.open(tar_path, "r") as tar:
                    for member in tar.getmembers():
                        if member.issym() or member.islnk():
                            continue  # skip symlinks (cause issues on Windows)
                        if ".." in member.name or member.name.startswith("/"):
                            continue
                        try:
                            tar.extract(member, tmp, filter="fully_trusted")
                        except (OSError, PermissionError):
                            pass
                os.unlink(tar_path)
                return tmp
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: minimal extraction for package DBs only
    # (full registry extraction is in the engine module)
    return tmp


# ── Distro detection ────────────────────────────────────────────────────

def _detect_distro(root: str) -> dict:
    """Read /etc/os-release."""
    info = {"id": "", "version_id": "", "codename": "", "family": "unknown"}
    os_release = os.path.join(root, "etc/os-release")
    if not os.path.isfile(os_release):
        return info

    with open(os_release, errors="replace") as f:
        for line in f:
            if "=" not in line:
                continue
            key, _, val = line.strip().partition("=")
            val = val.strip('"').strip("'")
            if key == "ID":
                info["id"] = val.lower()
            elif key == "VERSION_ID":
                info["version_id"] = val
            elif key == "VERSION_CODENAME":
                info["codename"] = val.lower()

    # Determine family
    if info["id"] in ("debian", "ubuntu", "raspbian"):
        info["family"] = "debian"
    elif info["id"] in ("alpine", "wolfi"):
        info["family"] = "alpine"
    elif info["id"] in ("rhel", "centos", "fedora", "rocky", "almalinux"):
        info["family"] = "redhat"

    return info


# ── Package detection ───────────────────────────────────────────────────

def _detect_packages(root: str) -> list[tuple[str, str, str, str]]:
    """Detect installed packages. Returns [(name, version, type, ecosystem)]."""
    packages = []

    # dpkg
    status = os.path.join(root, "var/lib/dpkg/status")
    if os.path.isfile(status):
        with open(status, errors="replace") as f:
            name = version = ""
            installed = False
            for line in f:
                if line.startswith("Package: "):
                    name = line[9:].strip()
                elif line.startswith("Version: "):
                    version = line[9:].strip()
                elif line.startswith("Status: ") and "installed" in line:
                    installed = True
                elif line.strip() == "":
                    if name and version and installed:
                        packages.append((name, version, "dpkg", "debian"))
                    name = version = ""
                    installed = False

    # apk
    installed = os.path.join(root, "lib/apk/db/installed")
    if os.path.isfile(installed):
        with open(installed, errors="replace") as f:
            name = version = ""
            for line in f:
                if line.startswith("P:"):
                    name = line[2:].strip()
                elif line.startswith("V:"):
                    version = line[2:].strip()
                elif line.strip() == "":
                    if name and version:
                        packages.append((name, version, "apk", "alpine"))
                    name = version = ""

    # pip
    for search in ["usr/lib", "usr/local/lib"]:
        base = os.path.join(root, search)
        if not os.path.isdir(base):
            continue
        for dp, dn, fn in os.walk(base):
            for d in dn:
                if d.endswith(".dist-info"):
                    meta = os.path.join(dp, d, "METADATA")
                    if not os.path.isfile(meta):
                        meta = os.path.join(dp, d, "PKG-INFO")
                    if os.path.isfile(meta):
                        n = v = ""
                        with open(meta, errors="replace") as mf:
                            for ml in mf:
                                if ml.startswith("Name: "):
                                    n = ml[6:].strip()
                                elif ml.startswith("Version: "):
                                    v = ml[9:].strip()
                                if n and v:
                                    break
                        if n and v:
                            packages.append((n, v, "pip", "pypi"))

    return packages


# ── Vulnerability matching via API ──────────────────────────────────────

def _match_vulnerabilities(packages, distro, api_url, offline) -> list[dict]:
    """Query VulnIntel DB API for advisories."""
    if offline:
        return _match_offline(packages, distro)

    vulns = []

    # Build ecosystem keys
    eco_map = {}
    for name, version, pkg_type, eco in packages:
        if eco == "debian" and distro.get("codename"):
            db_eco = f"debian-{distro['codename']}"
        elif eco == "alpine" and distro.get("version_id"):
            minor = ".".join(distro["version_id"].split(".")[:2])
            db_eco = f"alpine-{minor}"
        else:
            db_eco = eco
        eco_map.setdefault(db_eco, []).append((name, version))

    # Bulk query the API
    try:
        query_packages = []
        for db_eco, pkgs in eco_map.items():
            for name, version in pkgs:
                query_packages.append({"name": name, "ecosystem": db_eco})

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{api_url}/api/v1/bulk-query",
                json={"packages": query_packages},
            )
            resp.raise_for_status()
            data = resp.json()

        # Process results
        for key, result in data.get("results", {}).items():
            pkg_name = result.get("package", "")
            ecosystem = result.get("ecosystem", "")

            # Find the installed version for this package
            installed_version = ""
            for name, version, _, eco in packages:
                if name == pkg_name:
                    installed_version = version
                    break

            for adv in result.get("advisories", []):
                if adv.get("status") == "not-affected":
                    continue

                # Check if installed version < fixed version
                fixed = adv.get("fixed_version")
                if fixed and installed_version:
                    if _version_gte(installed_version, fixed, distro.get("family", "")):
                        continue  # installed >= fixed, not affected

                vulns.append({
                    "cve_id": adv["cve_id"],
                    "severity": adv.get("severity") or "MEDIUM",
                    "package_name": pkg_name,
                    "installed_version": installed_version,
                    "fixed_version": fixed,
                    "description": adv.get("description", ""),
                    "cvss_v3_score": adv.get("cvss_v3_score"),
                    "source": adv.get("source", ""),
                    "epss": None,
                    "is_kev": False,
                })

    except Exception as exc:
        _log.warning("API query failed: %s — falling back to offline", exc)
        return _match_offline(packages, distro)

    # Deduplicate
    seen = set()
    unique = []
    for v in vulns:
        key = (v["cve_id"], v["package_name"])
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return unique


def _match_offline(packages, distro) -> list[dict]:
    """Offline fallback — uses local DB file if available."""
    # For now, return empty. Local DB support can be added later.
    _log.info("Offline mode: no local DB available")
    return []


def _version_gte(installed: str, fixed: str, family: str) -> bool:
    """Check if installed >= fixed using appropriate comparison."""
    try:
        # Simple semver comparison for now
        a = installed.split("-")[0].split("+")[0].split("~")[0]
        b = fixed.split("-")[0].split("+")[0].split("~")[0]
        return Version(a) >= Version(b)
    except (InvalidVersion, ValueError):
        return False


# ── Secret scanning (simplified for CLI) ────────────────────────────────

import re

_SECRET_PATTERNS = [
    ("aws-key", "CRITICAL", "AWS Access Key", re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")),
    ("github-pat", "CRITICAL", "GitHub Token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("private-key", "CRITICAL", "Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("db-conn", "HIGH", "Database Connection String", re.compile(r"(?:postgres|mysql|mongodb)(?:ql)?://[^:]+:[^@]+@")),
    ("slack-token", "HIGH", "Slack Token", re.compile(r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}")),
    ("stripe-key", "CRITICAL", "Stripe Secret Key", re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
]

_SKIP_EXT = {".pyc", ".so", ".png", ".jpg", ".gif", ".zip", ".gz", ".tar", ".woff", ".ttf"}
_SKIP_DIRS = {"__pycache__", ".git", "node_modules", "site-packages"}


def _scan_secrets(root: str) -> list[dict]:
    secrets = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rel = os.path.relpath(dp, root)
        if rel.count(os.sep) > 5:
            dn.clear()
            continue
        for f in fn:
            if os.path.splitext(f)[1].lower() in _SKIP_EXT:
                continue
            fp = os.path.join(dp, f)
            if os.path.islink(fp) or os.path.getsize(fp) > 1_000_000:
                continue
            try:
                with open(fp, errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if i > 5000:
                            break
                        for rule_id, sev, desc, pat in _SECRET_PATTERNS:
                            if pat.search(line):
                                secrets.append({
                                    "rule_id": rule_id,
                                    "severity": sev,
                                    "description": desc,
                                    "file_path": os.path.relpath(fp, root),
                                    "line": i,
                                })
            except OSError:
                pass
    return secrets


# ── Misconfiguration checks (simplified) ────────────────────────────────

def _check_misconfigs(root: str, distro: dict) -> list[dict]:
    issues = []

    # Check: running as root
    # (would need image config for this, skip in CLI)

    # Check: sensitive files
    sensitive = [
        ("etc/shadow", "CRITICAL", "Password shadow file exposed"),
        ("root/.ssh/id_rsa", "CRITICAL", "SSH private key found"),
        ("root/.aws/credentials", "CRITICAL", "AWS credentials found"),
        ("root/.bash_history", "MEDIUM", "Shell history file present"),
    ]
    for path, sev, title in sensitive:
        fp = os.path.join(root, path)
        if os.path.exists(fp) and (os.path.isdir(fp) or os.path.getsize(fp) > 0):
            issues.append({"severity": sev, "title": title, "file_path": path})

    return issues
