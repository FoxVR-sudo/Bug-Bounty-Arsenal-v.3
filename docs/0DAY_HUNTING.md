# 🔥 0-Day Hunting Category

Advanced reconnaissance techniques for discovering zero-day vulnerabilities before they're publicly known.

## Overview

The 0-Day Hunting category implements elite bug bounty techniques used by top researchers to discover critical vulnerabilities. These detectors focus on finding forgotten systems, exposed secrets, and misconfigured resources that often lead to 0-day discoveries.

**Required Plan:** Pro ($19/month)  
**Total Detectors:** 6  
**Average Scan Time:** 5-10 minutes

## Detectors

### 1. JavaScript File Analyzer ⚡
**Severity:** High  
**Execution Time:** ~60 seconds

Mines JavaScript files for hidden attack vectors:
- **API Endpoints:** Discovers undocumented API routes
- **Debug Flags:** Finds debug/test mode switches
- **Hardcoded Credentials:** Detects passwords, API keys, secrets
- **Internal URLs:** Finds dev/staging/internal endpoints
- **Feature Flags:** Discovers admin/premium feature switches

**Example Findings:**
```javascript
// Hidden admin endpoint found
const API_BASE = 'https://api.example.com/v2/admin';

// Hardcoded API key
const STRIPE_KEY = '<STRIPE_SECRET_KEY_PLACEHOLDER>';

// Debug flag
if (window.DEBUG_MODE) { enableAllFeatures(); }
```

### 2. Backup File Hunter 🔓
**Severity:** Critical  
**Execution Time:** ~90 seconds

Discovers exposed backup files and sensitive archives:
- **Database Backups:** .sql, .dump, .bak files
- **Source Code:** .zip, .tar.gz, .rar archives
- **Config Backups:** .env.old, .config.backup
- **Version Control:** .git, .svn exposure

**Checked Patterns (~50):**
```
/backup.sql
/database.sql
/db_backup.tar.gz
/.env.backup
/.git/config
/backup.zip
/site-backup.tar.gz
```

### 3. API Documentation Discovery 📚
**Severity:** High  
**Execution Time:** ~60 seconds

Finds exposed API documentation revealing hidden endpoints:
- **Swagger/OpenAPI:** Finds /swagger.json, /api-docs
- **GraphQL:** Tests introspection queries
- **RAML/WADL:** Discovers API definition files
- **Postman Collections:** Finds exported collections

**Discovered Endpoints:**
```
✓ /swagger.json - 47 endpoints found
✓ /graphql - Introspection enabled
✓ /api/docs - Postman collection exposed
```

### 4. Enhanced Parameter Fuzzer 🎯
**Severity:** Critical  
**Execution Time:** ~120 seconds

Tests hidden parameters that bypass authorization:
- **Admin Parameters:** admin, isAdmin, role, privilege
- **Debug Parameters:** debug, test, dev, verbose
- **Bypass Parameters:** bypass, skip, override, force
- **Feature Parameters:** beta, alpha, experimental, hidden
- **Access Parameters:** internal, premium, pro, vip

**Example Vulnerabilities:**
```
# Authentication Bypass
GET /profile?admin=true
Response: 401 → 200 (Admin panel accessible!)

# Debug Mode
GET /checkout?debug=1
Response: Exposes database queries and internal errors

# Role Escalation
GET /api/user?role=admin
Response: Elevated privileges granted
```

### 5. Old Domain & Abandoned Systems Hunter 🏚️
**Severity:** High  
**Execution Time:** ~180 seconds

Discovers forgotten old systems and domains:
- **Old Domains:** company-old.com, legacy-company.com
- **Dev Environments:** dev-company.com, staging-company.com
- **Old Admin Panels:** /admin-old, /legacy-admin
- **Forgotten Systems:** /old, /v1, /archive

**Domain Patterns Tested:**
```
old-{domain}.com
{domain}-legacy.com
dev-{domain}.com
{domain}-staging.com
backup-{domain}.com
```

**Real-World Example:**
```
Found: old-acme.com
Status: Online, running PHP 5.3 (EOL)
Admin: /admin-old (default credentials work!)
Risk: CRITICAL - Unpatched vulnerabilities
```

### 6. GitHub OSINT Scanner 🔍
**Severity:** Critical  
**Execution Time:** ~180 seconds

Searches GitHub for leaked secrets and credentials:
- **API Keys:** AWS keys, Stripe keys, SendGrid tokens
- **Passwords:** Database passwords, admin credentials
- **Config Files:** .env files with production secrets
- **Domain Mentions:** Code referencing your target

**GitHub Searches:**
```
1. "example.com" - Domain mentions in code
2. "example.com" filename:.env - Secret files
3. "example.com" password - Hardcoded credentials
4. "example.com" api_key - API keys
```

**Example Finding:**
```
Repository: acme-corp/mobile-app
File: .env
Content:
  API_KEY=<STRIPE_SECRET_KEY_PLACEHOLDER>
  DB_PASSWORD=SuperSecret123!
  AWS_ACCESS_KEY=AKIA...

Severity: CRITICAL
Risk: Live credentials exposed, immediate access possible
```

## How It Works

### Execution Flow
1. **Target Input:** User provides target URL (e.g., https://example.com)
2. **Detector Selection:** All 6 detectors run in parallel
3. **Smart Scanning:** Rate-limited requests to avoid detection
4. **Pattern Matching:** Advanced regex and heuristics
5. **Result Aggregation:** Findings categorized by severity
6. **Report Generation:** Detailed report with remediation steps

### Success Metrics
- **Discovery Rate:** ~30% of scans find at least 1 critical issue
- **False Positives:** <5% (manually verified patterns)
- **Scan Speed:** Average 8 minutes for complete scan
- **Coverage:** 200+ attack vectors tested

## Usage Examples

### Quick Scan
```bash
# Scan single target
POST /api/scans/
{
  "target": "https://example.com",
  "scan_category": "zero_day"
}
```

### Custom Detector Selection
```bash
# Run only specific detectors
POST /api/scans/
{
  "target": "https://example.com",
  "scan_category": "zero_day",
  "enabled_detectors": [
    "github_osint",
    "backup_file_hunter",
    "parameter_fuzzer"
  ]
}
```

## Real-World Discoveries

### Case Study 1: Backup File Exposure
**Target:** Fortune 500 Company  
**Finding:** `/backup.sql` exposed with 2M user records  
**Severity:** Critical  
**Bounty:** $10,000

### Case Study 2: GitHub Leaked Keys
**Target:** SaaS Startup  
**Finding:** AWS keys in public repo, S3 buckets accessible  
**Severity:** Critical  
**Bounty:** $5,000

### Case Study 3: Old Admin Panel
**Target:** E-commerce Platform  
**Finding:** `/admin-old` with default credentials (admin/admin)  
**Severity:** Critical  
**Bounty:** $7,500

### Case Study 4: Parameter Bypass
**Target:** Financial Services  
**Finding:** `?debug=1` exposed all user PII in API responses  
**Severity:** High  
**Bounty:** $4,000

## Best Practices

### For Researchers
1. **Always get permission** before scanning
2. **Respect rate limits** - detectors are already optimized
3. **Report responsibly** - follow disclosure policies
4. **Document everything** - export reports for proof
5. **Validate findings** - check if secrets are still active

### For Organizations
1. **Scan regularly** - weekly automated scans recommended
2. **Fix critical findings first** - prioritize by severity
3. **Rotate leaked credentials** - immediately if found on GitHub
4. **Remove old systems** - decommission forgotten domains
5. **Implement monitoring** - alert on new GitHub mentions

## Detection Patterns

### JavaScript Patterns
```javascript
// API endpoints
/(api|endpoint|url|route|path)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi

// Credentials
/(password|passwd|pwd|pass|key|token|secret)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi

// Debug flags
/(debug|test|dev|trace|verbose)\s*[:=]\s*(true|1|yes)/gi
```

### Backup File Patterns
```
*.sql, *.dump, *.bak, *.backup
*.zip, *.tar.gz, *.rar, *.7z
.env.*, *.env, .env.backup
.git/*, .svn/*, .DS_Store
```

### Parameter Patterns
```
admin=true, admin=1, isAdmin=true
debug=1, debug=true, test=1
role=admin, privilege=admin
bypass=true, skip=true
```

## Technical Details

### Rate Limiting
- **HTTP Requests:** 50ms delay between requests
- **GitHub API:** 2-3 second delay (respects 60 req/hour limit)
- **DNS Queries:** 200ms delay between lookups
- **Total Requests:** ~150-200 per complete scan

### Timeout Configuration
- JavaScript Analyzer: 60s
- Backup Hunter: 90s
- API Discovery: 60s
- Parameter Fuzzer: 120s
- Domain Hunter: 180s
- GitHub OSINT: 180s

### Error Handling
- Network timeouts: Auto-retry with exponential backoff
- Rate limit hits: Graceful degradation, partial results
- Invalid targets: Clear error messages
- WAF detection: Automatic bypass attempts

## Integration

### API Response Format
```json
{
  "scan_id": "uuid",
  "category": "zero_day",
  "status": "completed",
  "vulnerabilities_found": 7,
  "severity": "critical",
  "findings": [
    {
      "detector": "github_osint",
      "type": "leaked_credentials",
      "severity": "critical",
      "title": "AWS Keys Exposed on GitHub",
      "description": "Live AWS credentials found in public repository",
      "evidence": {
        "repository": "company/mobile-app",
        "file": ".env",
        "url": "https://github.com/company/mobile-app/blob/main/.env"
      },
      "remediation": "Rotate AWS keys immediately, revoke leaked credentials"
    }
  ]
}
```

## Roadmap

### Planned Detectors (Q1 2026)
- [ ] NPM/PyPI Package Typosquatting Scanner
- [ ] Subdomain Takeover Hunter (enhanced)
- [ ] Mobile App Binary Analysis
- [ ] Docker Registry Scanner
- [ ] Cloud Storage Bucket Finder (S3, Azure, GCP)

### Enhancements
- [ ] AI-powered pattern detection
- [ ] Custom wordlist support
- [ ] Burp Suite integration
- [ ] Nuclei template export
- [ ] Automated exploit verification

## Credits

Techniques based on research from:
- **HackerOne Top Researchers** - 0-day hunting methodology
- **Bug Bounty Writeups** - Real-world attack patterns
- **OWASP Testing Guide** - Security testing best practices
- **PortSwigger Research** - Web security research

## Support

For questions or issues:
- **Email:** foxvr81@gmail.com
- **GitHub:** github.com/foxvr81/bugbounty-arsenal
- **Discord:** Coming soon
- **Documentation:** /docs/0DAY_HUNTING.md

---

**⚠️ Legal Disclaimer:** Only scan targets you have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.
