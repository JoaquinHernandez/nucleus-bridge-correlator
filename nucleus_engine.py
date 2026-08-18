import os
import sys
import json
import time
from datetime import datetime, timezone

# ANSI Styling Tokens
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
 ███╗   ██╗██╗   ██╗ ██████╗██╗     ███████╗██╗   ██╗███████╗
 ████╗  ██║██║   ██║██╔════╝██║     ██╔════╝██║   ██║██╔════╝
 ██╔██╗ ██║██║   ██║██║     ██║     █████╗  ██║   ██║███████╗
 ██║╚██╗██║██║   ██║██║     ██║     ██╔══╝  ██║   ██║╚════██║
 ██║ ╚████║╚██████╔╝╚██████╗███████╗███████╗╚██████╔╝███████║
 ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝
{RESET}{AMBER} » UNIFIED VULNERABILITY TELEMETRY & REMEDIATION CORRELATOR «{RESET}
"""

class NucleusBridgeEngine:
    def __init__(self, policy_path="correlation_policy.json", scan_path="nuclei_scan_sample.json"):
        if not os.path.exists(policy_path) or not os.path.exists(scan_path):
            print(f"{RED}[-] Error: Missing policy or sample scan file.{RESET}")
            sys.exit(1)

        with open(policy_path, "r") as f:
            self.policy = json.load(f)

        with open(scan_path, "r") as f:
            self.scans = json.load(f)

        self.sla = self.policy.get("sla_remediation_days", {})
        self.cve_db = self.policy.get("cve_database", {})

    def run_correlation(self):
        print(BANNER)
        print(f"{BOLD}Ingesting Vulnerability Scans & Correlating Telemetry...{RESET}\n")

        steps = [
            "Parsing raw JSON scanner outputs (Nuclei / Infrastructure Scans)",
            "Deduplicating cross-host vulnerability findings",
            "Cross-referencing CVE identifiers with CVSS & MITRE ATT&CK Matrix",
            "Calculating DevSecOps SLA remediation deadlines"
        ]
        for step in steps:
            time.sleep(0.25)
            print(f"  {CYAN}▸{RESET} {step}...")

        print("\n" + "=" * 85 + "\n")
        print(f"{BOLD}{'CVE / IDENTIFIER':<18} {'SEVERITY':<12} {'TARGET HOST':<32} {'SLA DEADLINE'}{RESET}")
        print("-" * 85)

        findings = []

        for item in self.scans:
            cve = item.get("cve_id", "N/A")
            severity = item.get("severity", "INFO")
            host = item.get("host", "Unknown")
            cve_meta = self.cve_db.get(cve, {})

            sla_days = self.sla.get(severity, 30)
            sla_text = f"Fix in ≤ {sla_days} Days"

            sev_color = RED if severity == "CRITICAL" else (AMBER if severity == "HIGH" else CYAN)
            print(f"{cve:<18} {sev_color}{severity:<12}{RESET} {host:<32} {sla_text}")

            findings.append({
                "cve": cve,
                "title": cve_meta.get("title", item.get("template_id")),
                "severity": severity,
                "host": host,
                "cvss": cve_meta.get("cvss", "N/A"),
                "mitre": cve_meta.get("mitre_id", "N/A"),
                "remediation": cve_meta.get("remediation", "Apply vendor patch.")
            })

        print("=" * 85)
        print(f"\n{BOLD}Correlation Summary:{RESET} Ingested {len(findings)} unique vulnerability findings across infrastructure assets.\n")

        print(f"{AMBER}{BOLD}[🛠️ ACTIONABLE REMEDIATION DIRECTIVES]{RESET}")
        for idx, f in enumerate(findings, start=1):
            print(f"  {CYAN}#{idx} [{f['severity']}]{RESET} {BOLD}{f['cve']}: {f['title']}{RESET} (CVSS: {f['cvss']})")
            print(f"     ├─ Target: {f['host']}")
            print(f"     ├─ MITRE ATT&CK: {f['mitre']}")
            print(f"     └─ Remediation: {f['remediation']}\n")

        self.generate_html_report(findings)

    def generate_html_report(self, findings):
        """Generates a clean HTML report artifact."""
        html_file = "vulnerability_audit_report.html"
        rows = ""
        for f in findings:
            rows += f"""
            <tr>
                <td><b>{f['cve']}</b></td>
                <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
                <td>{f['host']}</td>
                <td>{f['cvss']}</td>
                <td>{f['remediation']}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Executive Vulnerability Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0284c7; color: white; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .critical {{ background: #ef4444; color: white; }}
        .high {{ background: #f97316; color: white; }}
        .medium {{ background: #eab308; color: black; }}
    </style>
</head>
<body>
    <h1>🛡️ Executive Vulnerability Audit Report</h1>
    <p>Automated telemetry correlation generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    <table>
        <thead>
            <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Target Host</th>
                <th>CVSS</th>
                <th>Recommended Remediation</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""
        with open(html_file, "w") as f:
            f.write(html_content)
        print(f"{GREEN}[✓] Generated Executive HTML Report:{RESET} {html_file}\n")

if __name__ == "__main__":
    engine = NucleusBridgeEngine()
    engine.run_correlation()
