# dscanner

Fast Docker image vulnerability scanner. Finds CVEs, secrets, and misconfigurations.

```
pip install dscanner
dscanner scan nginx:latest
```

## What It Does

```
$ dscanner scan python:3.12-slim

  dscanner v1.0.0 — scanning python:3.12-slim

  Detecting packages...     88 packages found (320ms)
  Matching advisories...    12 vulnerabilities (45ms)
  Scanning secrets...       0 secrets (180ms)
  Checking misconfigs...    3 issues (25ms)

  ┌─────────────────────────────────────────────────────────────┐
  │  RESULTS: python:3.12-slim                                  │
  ├────────┬────────┬────────┬────────┬────────┬───────────────┤
  │  CRIT  │  HIGH  │  MED   │  LOW   │ TOTAL  │ Secrets/Misc  │
  │   0    │   6    │   8    │   74   │  88    │   0 / 3       │
  └────────┴────────┴────────┴────────┴────────┴───────────────┘

  CVE-2026-2673    HIGH    openssl     3.5.5-1~deb13u1    unfixed
  CVE-2026-29111   HIGH    libudev1    257.9-1~deb13u1    unfixed
  CVE-2025-69720   HIGH    ncurses     6.5+20250216-2     unfixed
  ...

  Full report: dscanner scan python:3.12-slim --format json
```

## Features

- **Fast** — Rust-powered package detection, parallel scanning
- **Accurate** — Uses distro-specific advisories (like Trivy), not raw NVD
- **More than CVEs** — Also finds hardcoded secrets and misconfigurations
- **No daemon needed** — Works without Docker daemon (pulls via registry API)
- **Offline mode** — Download DB once, scan without internet
- **CI/CD ready** — Exit code 1 on critical/high findings, JSON/SARIF output

## Install

```bash
pip install dscanner

# Or with Docker
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock dscanner/dscanner scan nginx:latest
```

## Usage

```bash
# Scan an image
dscanner scan nginx:latest
dscanner scan python:3.12-slim --severity HIGH,CRITICAL
dscanner scan myregistry.io/app:v1 --username user --password pass

# Output formats
dscanner scan nginx:latest --format table    # default
dscanner scan nginx:latest --format json     # machine-readable
dscanner scan nginx:latest --format sarif    # GitHub/GitLab integration
dscanner scan nginx:latest --format csv

# CI/CD mode (exit 1 if critical/high found)
dscanner scan nginx:latest --exit-code 1 --severity CRITICAL,HIGH

# Offline mode
dscanner db update                           # download DB
dscanner scan nginx:latest --offline         # scan without internet

# Secret scanning
dscanner scan nginx:latest --secrets         # include secret detection
dscanner scan nginx:latest --misconfig       # include misconfiguration checks
dscanner scan nginx:latest --all             # everything

# SBOM generation
dscanner sbom nginx:latest --format cyclonedx
dscanner sbom nginx:latest --format spdx
```

## GitHub Actions

```yaml
- uses: yourorg/dscanner-action@v1
  with:
    image: myapp:${{ github.sha }}
    severity: CRITICAL,HIGH
    exit-code: 1
```

## How It Works

1. Pulls image layers from registry (no Docker daemon needed)
2. Detects OS + language packages from filesystem
3. Queries **VulnIntel DB** for distro-specific advisories
4. Optionally scans for secrets and misconfigurations
5. Reports findings with fix recommendations

## Advisory Database

Powered by [vuln-intel-db](https://github.com/yourorg/vuln-intel-db) — an open-source vulnerability intelligence database that aggregates:

- Debian Security Tracker
- Alpine SecDB
- Red Hat OVAL
- GitHub Advisory (GHSA)
- OSV.dev
- CISA KEV (Known Exploited)
- EPSS scores
- NVD

## License

Apache 2.0
