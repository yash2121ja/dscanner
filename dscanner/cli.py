"""CLI entry point — `dscanner scan nginx:latest`"""

import json
import sys
import time

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from dscanner import __version__
from dscanner.scanner import scan_image
from dscanner.db import update_db, get_db_stats
from dscanner.sbom import generate_sbom

console = Console()

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "UNKNOWN": "dim",
}


@click.group()
@click.version_option(__version__, prog_name="dscanner")
def main():
    """dscanner — Fast Docker image vulnerability scanner."""
    pass


@main.command()
@click.argument("image")
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "csv", "sarif"]))
@click.option("--severity", "-s", default="", help="Filter: CRITICAL,HIGH,MEDIUM,LOW")
@click.option("--exit-code", "-e", default=0, type=int, help="Exit code when vulns found (for CI/CD)")
@click.option("--secrets/--no-secrets", default=True, help="Scan for secrets")
@click.option("--misconfig/--no-misconfig", default=True, help="Check misconfigurations")
@click.option("--all", "scan_all", is_flag=True, help="Enable all checks")
@click.option("--offline", is_flag=True, help="Use local DB only, no API calls")
@click.option("--api-url", default="https://api.dscanner.io", envvar="DSCANNER_API_URL", help="VulnIntel DB API URL")
@click.option("--username", "-u", default="", help="Registry username")
@click.option("--password", "-p", default="", help="Registry password")
@click.option("--quiet", "-q", is_flag=True, help="Only output results, no progress")
def scan(image, fmt, severity, exit_code, secrets, misconfig, scan_all, offline, api_url, username, password, quiet):
    """Scan a Docker image for vulnerabilities."""
    if scan_all:
        secrets = misconfig = True

    sev_filter = set(severity.upper().split(",")) if severity else set()

    if not quiet:
        console.print(f"\n  [bold]dscanner[/bold] v{__version__} — scanning [cyan]{image}[/cyan]\n")

    auth = {"username": username, "password": password} if username else None

    t0 = time.monotonic()
    result = scan_image(
        image,
        api_url=api_url,
        offline=offline,
        scan_secrets=secrets,
        scan_misconfig=misconfig,
        registry_auth=auth,
        quiet=quiet,
    )
    elapsed = int((time.monotonic() - t0) * 1000)

    vulns = result["vulnerabilities"]
    sec = result.get("secrets", [])
    mis = result.get("misconfigurations", [])
    pkgs = result.get("packages", [])

    # Filter by severity
    if sev_filter:
        vulns = [v for v in vulns if v["severity"] in sev_filter]

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, default=str))
    elif fmt == "csv":
        _output_csv(vulns)
    elif fmt == "sarif":
        click.echo(json.dumps(_to_sarif(image, vulns), indent=2))
    else:
        _output_table(image, vulns, sec, mis, pkgs, elapsed, quiet)

    # Exit code for CI/CD
    if exit_code and vulns:
        has_critical = any(v["severity"] in ("CRITICAL", "HIGH") for v in vulns)
        if has_critical:
            sys.exit(exit_code)


@main.command()
def db():
    """Update the local vulnerability database."""
    console.print("\n  Updating vulnerability database...\n")
    stats = update_db()
    console.print(f"  Advisories: [green]{stats['total']:,}[/green]")
    console.print(f"  Sources:    {', '.join(stats.get('sources', []))}")
    console.print(f"  Updated:    [green]OK[/green]\n")


@main.command()
@click.argument("image")
@click.option("--format", "-f", "fmt", default="cyclonedx", type=click.Choice(["cyclonedx", "spdx"]))
def sbom(image, fmt):
    """Generate SBOM for a Docker image."""
    result = generate_sbom(image, fmt)
    click.echo(json.dumps(result, indent=2, default=str))


# ── Output formatters ───────────────────────────────────────────────────

def _output_table(image, vulns, secrets, misconfigs, pkgs, elapsed_ms, quiet):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        counts[v.get("severity", "LOW")] = counts.get(v.get("severity", "LOW"), 0) + 1

    # Summary panel
    summary = Table(box=box.SIMPLE_HEAD, show_header=True, pad_edge=False)
    summary.add_column("CRIT", style="bold red", justify="center", width=6)
    summary.add_column("HIGH", style="bold yellow", justify="center", width=6)
    summary.add_column("MED", style="yellow", justify="center", width=6)
    summary.add_column("LOW", style="blue", justify="center", width=6)
    summary.add_column("Total", justify="center", width=6)
    summary.add_column("Secrets", justify="center", width=8)
    summary.add_column("Misconfig", justify="center", width=9)
    summary.add_row(
        str(counts["CRITICAL"]), str(counts["HIGH"]),
        str(counts["MEDIUM"]), str(counts["LOW"]),
        str(len(vulns)), str(len(secrets)), str(len(misconfigs)),
    )

    console.print(Panel(summary, title=f"[bold]{image}[/bold]  ({elapsed_ms}ms, {len(pkgs)} packages)", border_style="cyan"))

    if not vulns and not secrets and not misconfigs:
        console.print("  [green]No vulnerabilities found![/green]\n")
        return

    # Vulnerability table
    if vulns:
        table = Table(box=box.ROUNDED, show_lines=False, pad_edge=False)
        table.add_column("CVE", style="cyan", width=22)
        table.add_column("Severity", width=10)
        table.add_column("Package", width=20)
        table.add_column("Installed", width=18)
        table.add_column("Fixed In", style="green", width=15)
        table.add_column("EPSS", width=6)

        for v in sorted(vulns, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4)):
            sev_style = SEV_COLORS.get(v["severity"], "")
            epss = f"{v['epss']:.0%}" if v.get("epss") else "-"
            kev = " [red]KEV[/red]" if v.get("is_kev") else ""
            table.add_row(
                v["cve_id"] + kev,
                f"[{sev_style}]{v['severity']}[/{sev_style}]",
                v["package_name"],
                v["installed_version"],
                v.get("fixed_version") or "-",
                epss,
            )

        console.print(table)

    # Secrets
    if secrets:
        console.print(f"\n  [bold red]Secrets ({len(secrets)}):[/bold red]")
        for s in secrets[:10]:
            console.print(f"    [{SEV_COLORS.get(s['severity'], '')}]{s['severity']}[/] {s['description']}  [dim]{s['file_path']}[/dim]")

    # Misconfigs
    if misconfigs:
        console.print(f"\n  [bold yellow]Misconfigurations ({len(misconfigs)}):[/bold yellow]")
        for m in misconfigs[:10]:
            console.print(f"    [{SEV_COLORS.get(m['severity'], '')}]{m['severity']}[/] {m['title']}")

    console.print()


def _output_csv(vulns):
    import csv, io
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["CVE", "Severity", "Package", "Installed", "Fixed", "CVSS", "EPSS", "KEV"])
    for v in vulns:
        w.writerow([
            v["cve_id"], v["severity"], v["package_name"],
            v["installed_version"], v.get("fixed_version", ""),
            v.get("cvss_v3_score", ""), v.get("epss", ""), v.get("is_kev", False),
        ])
    click.echo(out.getvalue())


def _to_sarif(image, vulns):
    """Convert to SARIF format for GitHub/GitLab integration."""
    rules = []
    results = []
    for v in vulns:
        rule_id = v["cve_id"]
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": f"{v['severity']}: {v['cve_id']} in {v['package_name']}"},
            "fullDescription": {"text": v.get("description", "")[:1000]},
            "defaultConfiguration": {
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(v["severity"], "note")
            },
        })
        results.append({
            "ruleId": rule_id,
            "message": {"text": f"{v['cve_id']} ({v['severity']}) in {v['package_name']} {v['installed_version']}. Fix: {v.get('fixed_version', 'none')}"},
            "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(v["severity"], "note"),
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "dscanner",
                    "version": __version__,
                    "informationUri": "https://github.com/yourorg/dscanner",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


if __name__ == "__main__":
    main()
