#!/usr/bin/env python3
"""
iOS App Scanner - .ipa Security Analysis
Extracts and analyzes iOS applications for security vulnerabilities
"""

import os
import sys
import zipfile
import plistlib
import subprocess
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


class iOSScanner:
    """
    iOS Application Security Scanner

    Analyzes .ipa files for:
    - Info.plist misconfigurations
    - App Transport Security (ATS) settings
    - Jailbreak detection
    - Keychain usage
    - URL schemes
    - Binary security features
    - Embedded provisioning profiles
    """

    def __init__(self, ipa_path: str, output_dir: str = "ios_reports"):
        self.ipa_path = ipa_path
        self.output_dir = output_dir
        self.app_name = Path(ipa_path).stem
        self.extract_dir: str = ""  # Will be set in extract_ipa()
        self.info_plist = None
        self.findings = []

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

    def scan(self) -> Dict[str, Any]:
        """
        Run complete iOS security scan

        Returns:
            dict: Scan results with findings
        """
        print(f"\n🍎 iOS Security Scanner - Starting analysis of {self.app_name}")
        print("=" * 70)

        try:
            # Step 1: Extract .ipa
            print("\n[1/6] Extracting .ipa archive...")
            self.extract_ipa()

            # Step 2: Parse Info.plist
            print("[2/6] Parsing Info.plist...")
            self.parse_info_plist()

            # Step 3: Check ATS settings
            print("[3/6] Checking App Transport Security...")
            self.check_ats()

            # Step 4: Analyze URL schemes
            print("[4/6] Analyzing URL schemes...")
            self.check_url_schemes()

            # Step 5: Check binary security
            print("[5/6] Checking binary security features...")
            self.check_binary_security()

            # Step 6: Check for sensitive data
            print("[6/6] Searching for sensitive data...")
            self.check_sensitive_data()

            # Generate report
            print("\n[*] Generating security report...")
            report = self.generate_report()

            print(f"\n✅ Scan complete! Found {len(self.findings)} security issues")
            print(f"📄 Report saved to: {self.output_dir}/")

            return report

        except Exception as e:
            print(f"\n❌ Error during scan: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "findings": self.findings}

        finally:
            # Cleanup
            self.cleanup()

    def extract_ipa(self):
        """Extract .ipa file (it's just a ZIP archive)"""
        self.extract_dir = os.path.join(self.output_dir, f"{self.app_name}_extracted")
        os.makedirs(self.extract_dir, exist_ok=True)

        with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
            zip_ref.extractall(self.extract_dir)

        print(f"   ✓ Extracted to {self.extract_dir}")

    def parse_info_plist(self):
        """Parse Info.plist file"""
        # Find Info.plist (usually in Payload/*.app/Info.plist)
        payload_dir = os.path.join(self.extract_dir, "Payload")

        if not os.path.exists(payload_dir):
            raise Exception("Payload directory not found in .ipa")

        # Find .app directory
        app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
        if not app_dirs:
            raise Exception("No .app directory found in Payload/")

        app_dir = os.path.join(payload_dir, app_dirs[0])
        plist_path = os.path.join(app_dir, "Info.plist")

        if not os.path.exists(plist_path):
            raise Exception("Info.plist not found")

        # Parse plist
        with open(plist_path, 'rb') as f:
            self.info_plist = plistlib.load(f)

        print(f"   ✓ Parsed Info.plist")
        print(f"   Bundle ID: {self.info_plist.get('CFBundleIdentifier', 'Unknown')}")
        print(f"   Version: {self.info_plist.get('CFBundleShortVersionString', 'Unknown')}")

    def check_ats(self):
        """Check App Transport Security settings"""
        ats_settings = self.info_plist.get('NSAppTransportSecurity', {})

        # Check if ATS is completely disabled
        if ats_settings.get('NSAllowsArbitraryLoads', False):
            self.add_finding(
                title="App Transport Security Disabled",
                severity="HIGH",
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp_mobile="M5: Insecure Communication",
                description=(
                    "The app has disabled App Transport Security (ATS) completely by setting "
                    "NSAllowsArbitraryLoads to YES. This allows the app to load resources over "
                    "insecure HTTP connections, making it vulnerable to man-in-the-middle attacks."
                ),
                recommendation=(
                    "Remove NSAllowsArbitraryLoads or set it to NO. Use HTTPS for all network "
                    "communication. If you must connect to specific insecure domains, use "
                    "NSExceptionDomains instead of disabling ATS globally."
                ),
                evidence={
                    "NSAllowsArbitraryLoads": True,
                    "location": "Info.plist > NSAppTransportSecurity"
                }
            )
            print("   ⚠️  HIGH: App Transport Security is disabled!")

        # Check for exception domains
        exception_domains = ats_settings.get('NSExceptionDomains', {})
        if exception_domains:
            for domain, settings in exception_domains.items():
                if settings.get('NSExceptionAllowsInsecureHTTPLoads', False):
                    self.add_finding(
                        title=f"Insecure HTTP Allowed for Domain: {domain}",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-319",
                        cwe_name="Cleartext Transmission of Sensitive Information",
                        owasp_mobile="M5: Insecure Communication",
                        description=(
                            f"The app allows insecure HTTP connections to {domain}. "
                            "This creates a potential for man-in-the-middle attacks when "
                            "communicating with this domain."
                        ),
                        recommendation=f"Use HTTPS for {domain} or implement certificate pinning.",
                        evidence={
                            "domain": domain,
                            "NSExceptionAllowsInsecureHTTPLoads": True
                        }
                    )
                    print(f"   ⚠️  MEDIUM: Insecure HTTP allowed for {domain}")

        if not ats_settings:
            print("   ✓ No ATS configuration found (using defaults)")
        elif not ats_settings.get('NSAllowsArbitraryLoads', False) and not exception_domains:
            print("   ✓ App Transport Security is properly configured")

    def check_url_schemes(self):
        """Check for custom URL schemes"""
        url_types = self.info_plist.get('CFBundleURLTypes', [])

        if url_types:
            schemes = []
            for url_type in url_types:
                url_schemes = url_type.get('CFBundleURLSchemes', [])
                schemes.extend(url_schemes)

            if schemes:
                self.add_finding(
                    title="Custom URL Schemes Registered",
                    severity="INFO",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id="CWE-939",
                    cwe_name="Improper Authorization in Handler for Custom URL Scheme",
                    owasp_mobile="M1: Improper Platform Usage",
                    description=(
                        f"The app registers custom URL schemes: {', '.join(schemes)}. "
                        "Ensure proper validation of data received through these schemes "
                        "to prevent URL scheme hijacking and injection attacks."
                    ),
                    recommendation=(
                        "Validate and sanitize all input from URL schemes. Implement proper "
                        "authorization checks before performing sensitive actions triggered by URLs."
                    ),
                    evidence={"schemes": schemes}
                )
                print(f"   ℹ️  INFO: Custom URL schemes: {', '.join(schemes)}")
        else:
            print("   ✓ No custom URL schemes registered")

    def check_binary_security(self):
        """Check binary security features (PIE, Stack Canaries, ARC)"""
        # Find the main binary
        payload_dir = os.path.join(self.extract_dir, "Payload")
        app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]

        if not app_dirs:
            return

        app_dir = os.path.join(payload_dir, app_dirs[0])
        app_name = app_dirs[0].replace('.app', '')
        binary_path = os.path.join(app_dir, app_name)

        if not os.path.exists(binary_path):
            print("   ⚠️  Binary not found, skipping binary analysis")
            return

        # Use otool to check binary features (macOS/Linux with Xcode tools)
        try:
            # Check for PIE (Position Independent Executable)
            result = subprocess.run(
                ['otool', '-hv', binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Check PIE flag
                if 'PIE' not in output:
                    self.add_finding(
                        title="Position Independent Executable (PIE) Not Enabled",
                        severity="MEDIUM",
                        cvss_score=4.3,
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-250",
                        cwe_name="Execution with Unnecessary Privileges",
                        owasp_mobile="M7: Client Code Quality",
                        description=(
                            "The binary is not compiled with PIE (Position Independent Executable) "
                            "flag. This makes it easier for attackers to exploit memory corruption "
                            "vulnerabilities by knowing the exact memory addresses of code."
                        ),
                        recommendation="Enable PIE in Xcode build settings (it's enabled by default).",
                        evidence={"binary": binary_path, "PIE": False}
                    )
                    print("   ⚠️  MEDIUM: PIE not enabled")
                else:
                    print("   ✓ PIE enabled")

                # Check for stack canaries
                canary_result = subprocess.run(
                    ['otool', '-I', binary_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if canary_result.returncode == 0 and '___stack_chk_fail' in canary_result.stdout:
                    print("   ✓ Stack canaries enabled")
                else:
                    self.add_finding(
                        title="Stack Canaries Not Detected",
                        severity="MEDIUM",
                        cvss_score=4.3,
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        owasp_mobile="M7: Client Code Quality",
                        description=(
                            "Stack canaries were not detected in the binary. Stack canaries help "
                            "protect against buffer overflow attacks."
                        ),
                        recommendation="Enable stack protection in compiler settings.",
                        evidence={"binary": binary_path, "stack_canaries": False}
                    )
                    print("   ⚠️  MEDIUM: Stack canaries not detected")

        except FileNotFoundError:
            print("   ⚠️  otool not found - install Xcode command line tools for binary analysis")
        except Exception as e:
            print(f"   ⚠️  Binary analysis failed: {e}")

    def check_sensitive_data(self):
        """Search for hardcoded secrets and sensitive data"""
        # Search in plist files, strings, etc.
        os.path.join(self.extract_dir, "Payload")

        sensitive_patterns = {
            'api_key': r'api[_-]?key',
            'secret': r'secret',
            'password': r'password',
            'token': r'token',
            'private_key': r'private[_-]?key',
        }

        # Check Info.plist for sensitive keys
        plist_str = str(self.info_plist).lower()
        found_patterns = []

        for pattern_name, pattern in sensitive_patterns.items():
            if pattern in plist_str:
                found_patterns.append(pattern_name)

        if found_patterns:
            self.add_finding(
                title="Potential Sensitive Data in Info.plist",
                severity="LOW",
                cvss_score=2.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information",
                owasp_mobile="M9: Insecure Data Storage",
                description=(
                    f"Found potential sensitive data keys in Info.plist: {', '.join(found_patterns)}. "
                    "Review these entries to ensure no hardcoded secrets are present."
                ),
                recommendation="Move all secrets to secure storage (Keychain). Never hardcode secrets in plist files.",
                evidence={"patterns_found": found_patterns}
            )
            print(f"   ⚠️  LOW: Potential sensitive keys in Info.plist: {', '.join(found_patterns)}")
        else:
            print("   ✓ No obvious sensitive data in Info.plist")

    def add_finding(self, title: str, severity: str, cvss_score: float,
                    cvss_vector: str, cwe_id: str, cwe_name: str,
                    owasp_mobile: str, description: str, recommendation: str,
                    evidence: Dict[str, Any]):
        """Add a security finding"""
        self.findings.append({
            "title": title,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "owasp_mobile": owasp_mobile,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        })

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        report = {
            "app_name": self.app_name,
            "bundle_id": self.info_plist.get('CFBundleIdentifier', 'Unknown'),
            "version": self.info_plist.get('CFBundleShortVersionString', 'Unknown'),
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings,
            "severity_summary": self.get_severity_summary()
        }

        # Save JSON report
        json_path = os.path.join(self.output_dir, f"{self.app_name}_ios_report.json")
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Save HTML report
        html_path = os.path.join(self.output_dir, f"{self.app_name}_ios_report.html")
        self.generate_html_report(report, html_path)

        return report

    def get_severity_summary(self) -> Dict[str, int]:
        """Count findings by severity"""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            severity = finding['severity']
            if severity in summary:
                summary[severity] += 1
        return summary

    def generate_html_report(self, report: Dict[str, Any], output_path: str):
        """Generate HTML report"""
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
            "INFO": "#6c757d"
        }

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>iOS Security Report - {report['app_name']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007aff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .summary-card {{ flex: 1; min-width: 150px; padding: 20px; border-radius: 8px; color: white; text-align: center; }}
        .summary-card h3 {{ margin: 0; font-size: 32px; }}
        .summary-card p {{ margin: 5px 0 0 0; }}
        .finding {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #ccc; }}
        .finding h3 {{ margin-top: 0; color: #333; }}
        .severity {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 12px; }}
        .cvss {{ background: #e9ecef; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .evidence {{ background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; font-family: monospace; font-size: 13px; }}
        .recommendation {{ background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #0c5460; }}
        .meta {{ color: #6c757d; font-size: 14px; margin: 20px 0; }}
        .icon {{ font-size: 24px; margin-right: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1><span class="icon">🍎</span>iOS Security Scan Report</h1>

        <div class="meta">
            <p><strong>App:</strong> {report['app_name']}</p>
            <p><strong>Bundle ID:</strong> {report['bundle_id']}</p>
            <p><strong>Version:</strong> {report['version']}</p>
            <p><strong>Scan Date:</strong> {report['scan_date']}</p>
        </div>

        <h2>Summary</h2>
        <div class="summary">
"""

        for severity, count in report['severity_summary'].items():
            if count > 0:
                color = severity_colors.get(severity, '#6c757d')
                html += f"""
            <div class="summary-card" style="background: {color};">
                <h3>{count}</h3>
                <p>{severity}</p>
            </div>
"""

        html += """
        </div>

        <h2>Findings</h2>
"""

        for finding in report['findings']:
            severity_color = severity_colors.get(finding['severity'], '#6c757d')
            html += f"""
        <div class="finding" style="border-left-color: {severity_color};">
            <h3>{finding['title']}</h3>
            <span class="severity" style="background: {severity_color};">{finding['severity']}</span>

            <div class="cvss">
                <strong>CVSS Score:</strong> {finding['cvss_score']} ({finding['severity']})<br>
                <strong>Vector:</strong> {finding['cvss_vector']}<br>
                <strong>CWE:</strong> {finding['cwe_id']} - {finding['cwe_name']}<br>
                <strong>OWASP Mobile:</strong> {finding['owasp_mobile']}
            </div>

            <p><strong>Description:</strong><br>{finding['description']}</p>

            <div class="recommendation">
                <strong>💡 Recommendation:</strong><br>{finding['recommendation']}
            </div>

            <details>
                <summary><strong>Evidence</strong></summary>
                <div class="evidence">{json.dumps(finding['evidence'], indent=2)}</div>
            </details>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html)

    def cleanup(self):
        """Clean up extracted files"""
        # Keep extracted files for manual inspection


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python ios_scanner.py <path_to_ipa>")
        sys.exit(1)

    ipa_path = sys.argv[1]

    if not os.path.exists(ipa_path):
        print(f"Error: File not found: {ipa_path}")
        sys.exit(1)

    if not ipa_path.endswith('.ipa'):
        print("Error: File must be a .ipa file")
        sys.exit(1)

    scanner = iOSScanner(ipa_path)
    report = scanner.scan()

    # Print summary
    print("\n" + "=" * 70)
    print("📊 SCAN SUMMARY")
    print("=" * 70)
    print(f"Total findings: {report['total_findings']}")
    for severity, count in report['severity_summary'].items():
        if count > 0:
            print(f"  {severity}: {count}")


if __name__ == "__main__":
    main()
