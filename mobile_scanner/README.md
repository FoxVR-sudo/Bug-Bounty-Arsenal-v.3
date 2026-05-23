# MobileBounty-Arsenal 2.0 🍎🤖

**Mobile Security Scanner for iOS & Android Bug Bounty Hunting**

## 🎯 Features

### iOS Support (.ipa) 🍎
- ✅ **Info.plist Analysis** - Configuration security audit
- ✅ **App Transport Security (ATS)** - Detect disabled/weak HTTPS enforcement
- ✅ **URL Scheme Security** - Custom URL handler analysis
- ✅ **Binary Security** - PIE, Stack Canaries, ARC checks
- ✅ **Hardcoded Secrets** - API keys, tokens detection
- ✅ **CVSS v3.1 Scoring** - Industry-standard severity ratings
- ✅ **CWE/OWASP Mapping** - Complete vulnerability classification

### Android Support (.apk) 🤖
- ✅ **18 Security Detectors** - Comprehensive vulnerability coverage
- ✅ **Certificate Pinning** - MitM protection verification
- ✅ **Root Detection** - Device integrity checks
- ✅ **Backup Security** - ADB backup configuration
- ✅ **Exported Components** - Attack surface analysis
- ✅ **Weak Cryptography** - Insecure algorithm detection
- ✅ **WebView Security** - JavaScript/file access risks

### Professional Reporting 📊
- **HTML Reports** - Interactive, color-coded findings
- **JSON Export** - Programmatic integration
- **CVSS v3.1** - Official vulnerability scoring
- **CWE IDs** - MITRE classification
- **OWASP Mobile Top 10** - Industry framework alignment
- **HackerOne Ready** - Professional bug bounty submissions

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/FoxVR-sudo/MobileBounty-Arsenal.git
cd MobileBounty-Arsenal
pip install -r requirements.txt
```

### iOS Scanning

```bash
# Basic iOS scan
python mobile_scanner/ios/ios_scanner.py app.ipa

# Output: ios_reports/app_ios_report.html
```

### Android Scanning

```bash
# Basic Android scan
python mobile_scanner.py --apk app.apk

# Verbose output
python mobile_scanner.py --apk app.apk --verbose

# Output: mobile_reports/app_report.html
```

## 📱 iOS Detectors

### 1. App Transport Security (ATS) ⚠️ HIGH
**Detects:**
- `NSAllowsArbitraryLoads = YES` (ATS completely disabled)
- Insecure HTTP exception domains
- Weak TLS configuration

**CVSS:** 7.4 (HIGH)  
**CWE:** CWE-319 (Cleartext Transmission)  
**Impact:** Man-in-the-middle attacks, credential theft

### 2. URL Scheme Vulnerabilities ℹ️ INFO
**Detects:**
- Custom URL schemes (deeplinks)
- Potential URL scheme hijacking

**CWE:** CWE-939 (Improper Authorization)  
**Recommendation:** Validate all URL scheme inputs

### 3. Binary Security 🔒 MEDIUM
**Checks:**
- PIE (Position Independent Executable)
- Stack canaries
- ARC (Automatic Reference Counting)

**Tools:** `otool` binary analysis

### 4. Hardcoded Secrets 🔑 LOW-HIGH
**Searches for:**
- API keys in Info.plist
- Embedded secrets
- Tokens and passwords

**CWE:** CWE-798 (Hardcoded Credentials)

## 🤖 Android Detectors (18 total)

1. **Certificate Pinning** - MitM protection
2. **Root Detection** - Device integrity
3. **Backup Enabled** - Data extraction risk
4. **Exported Components** - Attack surface
5. **Hardcoded Secrets** - API keys, tokens
6. **Weak Cryptography** - DES, MD5, SHA1
7. **WebView Security** - XSS, file access
8. **Debuggable Apps** - Production debugging
9. **Insecure Storage** - World-readable files
10. **SQL Injection** - Database vulnerabilities
11. **XSS Patterns** - Cross-site scripting
12. **SSRF** - Server-side request forgery
13. **LFI** - Local file inclusion
14. **Open Redirect** - URL redirection
15. **CSRF** - Cross-site request forgery
16. **Security Headers** - HTTP header misconfig
17. **Insecure Random** - Weak RNG
18. **Jailbreak Detection** - iOS integrity checks

## 📊 Report Formats

### HTML Report (Interactive)
```html
✅ Color-coded severity badges
✅ CVSS score breakdowns
✅ CWE links to MITRE database
✅ Expandable evidence sections
✅ Remediation recommendations
```

### JSON Report (Programmatic)
```json
{
  "app_name": "Example App",
  "total_findings": 5,
  "findings": [
    {
      "title": "App Transport Security Disabled",
      "severity": "HIGH",
      "cvss_score": 7.4,
      "cwe_id": "CWE-319",
      "evidence": {...}
    }
  ]
}
```

## 🎯 Bug Bounty Workflow

### 1. Scan Target App
```bash
# iOS
python mobile_scanner/ios/ios_scanner.py target.ipa

# Android
python mobile_scanner.py --apk target.apk
```

### 2. Review Findings
```bash
# Open HTML report
open ios_reports/target_ios_report.html
open mobile_reports/target_report.html
```

### 3. Submit to HackerOne/Bugcrowd
- Copy finding details
- Include CVSS scores
- Attach HTML report as evidence
- Reference CWE/OWASP classifications

## 🔧 Advanced Usage

### iOS Binary Analysis (macOS/Linux with Xcode)
```bash
# Requires Xcode command line tools
xcode-select --install

# Scanner will automatically use otool for binary analysis
python mobile_scanner/ios/ios_scanner.py app.ipa
```

### Custom Output Directory
```bash
# iOS
python mobile_scanner/ios/ios_scanner.py app.ipa --output custom_dir

# Android
python mobile_scanner.py --apk app.apk --output custom_dir
```

## 📚 Documentation

- **CVSS Calculator:** Automatic CVSS v3.1 scoring
- **CWE Database:** 20+ vulnerability classifications
- **OWASP Mobile:** Top 10 (2024 edition)
- **Bug Bounty Guide:** Submission best practices

## 🏆 Success Stories

### Syfe Bug Bounty Campaign
```
✅ Android Certificate Pinning: $2,000-$8,000 (potential)
✅ Backup Enabled: $500-$2,000 (potential)
✅ Weak Root Detection: $500-$1,500 (potential)
```

## 🛠️ Requirements

```txt
Python 3.8+
plistlib (iOS)
zipfile (iOS)
androguard (Android)
requests
beautifulsoup4
```

## 🔮 Roadmap

### v2.1 - Dynamic Testing (Coming Soon)
- [ ] Frida integration
- [ ] SSL pinning bypass automation
- [ ] Runtime memory analysis
- [ ] Automated exploitation
- [ ] Screenshot evidence generation

### v3.0 - Advanced Features
- [ ] Flutter/React Native support
- [ ] Dynamic analysis server
- [ ] CI/CD integration
- [ ] API fuzzing
- [ ] Automated HackerOne submission

## 📄 License

MIT License - See LICENSE file

## 👤 Author

**FoxVR**
- GitHub: [@FoxVR-sudo](https://github.com/FoxVR-sudo)
- Bug Bounty: Security researcher specializing in mobile applications

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Add tests for new detectors
4. Submit pull request

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Always:
- Get permission before testing
- Follow responsible disclosure
- Respect bug bounty program rules
- Never test on production without authorization

## 📞 Support

Found a bug? Have a suggestion?
- Open an issue on GitHub
- Submit a pull request
- Contact via bug bounty platforms

---

**MobileBounty-Arsenal v2.0** - Professional Mobile Security Testing for Bug Bounty Hunters 🎯
