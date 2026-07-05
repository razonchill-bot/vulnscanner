#!/usr/bin/env python3
"""
CLI entry point.

Usage:
    python cli.py --url https://example.com --output report.html
    python cli.py --url https://example.com --allow-private   (for local CTF boxes)
"""
import argparse
import sys
from pathlib import Path

from core.engine import run_scan
from risk.scoring import calculate_risk
from risk.owasp_mapping import map_owasp
from report.html_report import render_html_report
from report.history import save_scan
from core.target import InvalidTargetError


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", help="Target URL to scan (prompts interactively if omitted)")
    parser.add_argument("--output", default="report.html", help="Path to write the HTML report")
    parser.add_argument("--allow-private", action="store_true",
                         help="Allow scanning private/loopback IP ranges (e.g. local CTF VM)")
    parser.add_argument("--max-requests", type=int, default=500,
                         help="Safety cap on total requests per scan")
    args = parser.parse_args()

    url = args.url or input("Enter the website URL to scan: ").strip()

    print(f"[*] Starting scan of {url}")
    print("[*] This runs read-only checks and non-destructive detection probes only.")

    try:
        scan_report = run_scan(url, allow_private_ips=args.allow_private, max_requests=args.max_requests)
    except InvalidTargetError as e:
        print(f"[!] Invalid target: {e}", file=sys.stderr)
        sys.exit(1)

    for name, result in scan_report.module_results.items():
        if result.error:
            print(f"[!] {name}: FAILED ({result.error})")
        else:
            print(f"[+] {name}: {len(result.findings)} finding(s)")

    risk_summary = calculate_risk(scan_report.module_results)
    owasp_map = map_owasp(risk_summary)

    save_scan(scan_report.target.url, risk_summary)

    html_report = render_html_report(scan_report, risk_summary, owasp_map)
    output_path = Path(args.output)
    output_path.write_text(html_report, encoding="utf-8")

    print(f"\n[*] Overall risk: {risk_summary.overall_rating}")
    print(f"[*] Report saved to {output_path.resolve()}")


if __name__ == "__main__":
    main()
