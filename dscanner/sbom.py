"""SBOM generation — CycloneDX and SPDX output."""

from datetime import datetime, timezone
from dscanner import __version__
from dscanner.scanner import _extract_image, _detect_packages, _detect_distro
import shutil


def generate_sbom(image: str, fmt: str = "cyclonedx") -> dict:
    """Generate SBOM for a Docker image."""
    extract_dir = _extract_image(image, None)
    try:
        packages = _detect_packages(extract_dir)
        distro = _detect_distro(extract_dir)

        if fmt == "spdx":
            return _spdx(image, packages, distro)
        return _cyclonedx(image, packages, distro)
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


def _cyclonedx(image, packages, distro):
    components = []
    for name, version, pkg_type, ecosystem in packages:
        purl_type = {"dpkg": "deb", "apk": "apk", "pip": "pypi", "npm": "npm"}.get(pkg_type, pkg_type)
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:{purl_type}/{name}@{version}",
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "dscanner", "name": "dscanner", "version": __version__}],
            "component": {"type": "container", "name": image},
        },
        "components": components,
    }


def _spdx(image, packages, distro):
    spdx_packages = []
    for name, version, pkg_type, ecosystem in packages:
        purl_type = {"dpkg": "deb", "apk": "apk", "pip": "pypi", "npm": "npm"}.get(pkg_type, pkg_type)
        spdx_packages.append({
            "SPDXID": f"SPDXRef-{name}-{version}".replace("/", "-"),
            "name": name,
            "versionInfo": version,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{purl_type}/{name}@{version}",
            }],
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": image,
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [f"Tool: dscanner-{__version__}"],
        },
        "packages": spdx_packages,
    }
