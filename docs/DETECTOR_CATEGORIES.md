# Detector Categories & Plan Access

## Overview

All security detectors are organized into **8 categories** based on their purpose and complexity. Access to categories is controlled by your subscription plan.

## Categories

### 🌐 Web Security (Free)
**Basic web vulnerability scanning**

Available to all plans. Includes fundamental web security tests:
- XSS Pattern Detector
- SQL Pattern Detector  
- Local File Inclusion (LFI) Detector
- Open Redirect Detector
- XXE Detector
- SSTI Detector
- CSRF Detector
- CORS Detector
- Security Headers Detector
- Directory Listing Detector
- Reflection Detector

**Total: 11 detectors**

---

### 💉 Injection Attacks (Pro)
**Advanced injection testing**

Available on **Pro** and **Enterprise** plans:
- Command Injection Detector
- NoSQL Injection Detector
- GraphQL Injection Detector
- Header Injection Detector
- Prototype Pollution Detector

**Total: 5 detectors**

---

### 🔌 API Security (Pro)
**REST, GraphQL, and API documentation discovery**

Available on **Pro** and **Enterprise** plans:
- API Security Detector
- GraphQL Detector
- API Docs Discovery
- JWT Detector
- JWT Vulnerability Scanner
- OAuth Detector

**Total: 6 detectors**

---

### 🔗 SSRF & OOB (Enterprise)
**Server-Side Request Forgery & Out-of-Band attacks**

**Enterprise only** - Advanced out-of-band testing:
- SSRF Detector
- Advanced SSRF Detector
- SSRF OOB Detector
- SSRF OOB Advanced Detector

**Total: 4 detectors**

---

### 🔐 Authentication (Pro)
**Authentication bypass, brute force, session attacks**

Available on **Pro** and **Enterprise** plans:
- Auth Bypass Detector
- Brute Force Detector
- Rate Limit Bypass Detector
- Race Condition Detector

**Total: 4 detectors**

---

### 💼 Business Logic (Enterprise)
**Business logic flaws, IDOR, access control**

**Enterprise only** - Complex logic flaw testing:
- IDOR Detector
- Business Logic Detector
- Cache Poisoning Detector

**Total: 3 detectors**

---

### 🔍 Reconnaissance (Free)
**Subdomain discovery, secret detection, file hunting**

Available to all plans. Information gathering tools:
- Subdomain Takeover Detector
- Secret Detector
- JS File Analyzer
- Backup File Hunter
- Simple File List Detector
- Old Domain Hunter
- GitHub OSINT

**Total: 7 detectors**

---

### ⚡ Fuzzing (Pro)
**Parameter fuzzing, file upload, CVE scanning**

Available on **Pro** and **Enterprise** plans:
- Basic Param Fuzzer
- Parameter Fuzzer
- Fuzz Detector
- File Upload Detector
- CVE Database Detector

**Total: 5 detectors**

---

## Plan Comparison

| Plan | Categories | Total Detectors |
|------|-----------|----------------|
| **Free** | Web, Recon | 18 detectors |
| **Pro** | Web, Recon, Injection, API, Auth, Fuzzing | 39 detectors |
| **Enterprise** | All categories | 45 detectors |

## API Endpoints

### Get All Categories
```bash
GET /api/detector-categories/
```

Returns all categories with `is_allowed` flag based on your plan.

**Response:**
```json
{
  "current_plan": "free",
  "categories": [
    {
      "key": "web",
      "name": "Web Security",
      "icon": "🌐",
      "description": "Basic web vulnerability scanning",
      "required_plan": "free",
      "is_allowed": true,
      "detectors": [...],
      "detector_count": 11
    },
    ...
  ],
  "total_categories": 8,
  "unlocked_categories": 2
}
```

### Get Allowed Detectors
```bash
GET /api/detector-categories/allowed/
```

Returns only the detectors you can use with your current plan.

**Response:**
```json
{
  "plan": "free",
  "allowed_categories": ["web", "recon"],
  "allowed_detectors": [
    "xss_pattern_detector",
    "sql_pattern_detector",
    ...
  ],
  "detector_count": 18
}
```

### Validate Detectors
```bash
POST /api/detector-categories/validate/
Content-Type: application/json

{
  "detectors": ["xss_pattern_detector", "command_injection_detector"]
}
```

Checks if all detectors are allowed for your plan.

**Response:**
```json
{
  "plan": "free",
  "all_allowed": false,
  "results": [
    {
      "detector": "xss_pattern_detector",
      "is_allowed": true
    },
    {
      "detector": "command_injection_detector",
      "is_allowed": false
    }
  ]
}
```

## Scan Creation Validation

When creating a scan, the system automatically validates:

1. **Subscription exists** - You must have an active subscription
2. **Daily limit** - Check if you haven't exceeded daily scan limit
3. **Monthly limit** - Check if you haven't exceeded monthly scan limit
4. **Detector permissions** - All selected detectors must be allowed for your plan

**Example Error:**
```json
{
  "detail": "Your free plan does not allow these detectors: command_injection_detector. Upgrade your plan to access them."
}
```

## Usage in Frontend

```javascript
// Get all categories with access info
const response = await fetch('/api/detector-categories/', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
const data = await response.json();

// Filter unlocked categories
const unlocked = data.categories.filter(c => c.is_allowed);

// Show upgrade prompt for locked categories
const locked = data.categories.filter(c => !c.is_allowed);
```

## Notes

- **Free users** get 18 detectors across Web and Recon categories
- **Pro users** unlock 21 additional detectors (39 total)
- **Enterprise users** get all 45 detectors including SSRF and Business Logic
- Plan validation happens on the backend - frontend should only show allowed detectors
- Attempting to use unauthorized detectors will return a 403 Permission Denied error
