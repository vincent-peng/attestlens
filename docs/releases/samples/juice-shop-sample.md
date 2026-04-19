# Privacy Act Compliance Report — OWASP Juice Shop

**Report ID:** 7e41b920-bdd3-48c7-bf3c-2996601f791d
**Date:** 19/04/2026
**Framework:** APP / NDB (Privacy Act 1988)
**Target URL:** https://demo.owasp-juice.shop/

## Executive Summary

- **Overall Grade:** A (92/100)
- **Risk Level:** MEDIUM
- **Total Findings:** 11

### APP Control Status

| Principle | Obligation | Status | Score |
|---|---|---|---|
| APP_1 | Open & Transparent | UNKNOWN | 100/100 |
| APP_2 | Anonymity | UNKNOWN | 100/100 |
| APP_3 | Collection | UNKNOWN | 100/100 |
| APP_4 | Unsolicited Info | UNKNOWN | 100/100 |
| APP_5 | Notification | UNKNOWN | 100/100 |
| APP_6 | Use & Disclosure | UNKNOWN | 100/100 |
| APP_7 | Direct Marketing | UNKNOWN | 100/100 |
| APP_8 | Cross-Border | UNKNOWN | 100/100 |
| APP_9 | Gov Identifiers | UNKNOWN | 100/100 |
| APP_10 | Data Quality | UNKNOWN | 100/100 |
| APP_11 | Security | FAIL | 49/100 |
| APP_12 | Access | UNKNOWN | 100/100 |
| APP_13 | Correction | UNKNOWN | 100/100 |
| NDB | Data Breach Notification | UNKNOWN | 100/100 |

## Findings

### [HIGH] Missing Content-Security-Policy Header
- **ID:** fe25fe7f836c67ab
- **Rule:** AL-URL-001
- **Category:** Security Headers
- **File:** N/A

Content-Security-Policy prevents XSS, clickjacking, and other code injection attacks by specifying approved sources of content.

**Suggested Fix:** Add a Content-Security-Policy header to your server configuration:

### [HIGH] Missing Strict-Transport-Security Header
- **ID:** accda2c93269c694
- **Rule:** AL-URL-002
- **Category:** Security Headers
- **File:** N/A

HSTS forces browsers to always use HTTPS, preventing protocol downgrade attacks and cookie hijacking.

**Suggested Fix:** Add a Strict-Transport-Security header to your server configuration:

### [MEDIUM] Missing Referrer-Policy Header
- **ID:** 85c39219d2705fc5
- **Rule:** AL-URL-005
- **Category:** Security Headers
- **File:** N/A

Referrer-Policy controls how much referrer information is shared with other sites. Without it, browsers may send full URLs including sensitive path/query parameters.

**Suggested Fix:** Add a Referrer-Policy header:

### [LOW] Missing Permissions-Policy Header
- **ID:** cfd111829c8cc401
- **Rule:** AL-URL-006
- **Category:** Security Headers
- **File:** N/A

Permissions-Policy controls which browser features and APIs the page can use (camera, microphone, geolocation, etc.).

**Suggested Fix:** Add a Permissions-Policy header:

### [INFO] Missing X-XSS-Protection Header (Legacy)
- **ID:** 6c42e9faf7357fb3
- **Rule:** AL-URL-007
- **Category:** Security Headers
- **File:** N/A

X-XSS-Protection is a legacy header for older browsers. Modern browsers rely on Content-Security-Policy instead. Only needed if supporting IE or old browsers.

**Suggested Fix:** X-XSS-Protection is a legacy header. Modern browsers use Content-Security-Policy instead.

### [MEDIUM] Missing Cross-Origin-Opener-Policy Header
- **ID:** f71ffb2cb9eec67c
- **Rule:** AL-URL-008
- **Category:** Security Headers
- **File:** N/A

COOP isolates your document from cross-origin documents opened via window.open or links, preventing side-channel attacks like Spectre.

**Suggested Fix:** Add a Cross-Origin-Opener-Policy header:

### [MEDIUM] Missing Cross-Origin-Resource-Policy Header
- **ID:** 953649ebf553c5ac
- **Rule:** AL-URL-009
- **Category:** Security Headers
- **File:** N/A

CORP prevents cross-origin resources from being loaded by other sites, mitigating speculative side-channel attacks.

**Suggested Fix:** Add a Cross-Origin-Resource-Policy header:

### [LOW] Missing Cross-Origin-Embedder-Policy Header
- **ID:** 3117cca359e1d166
- **Rule:** AL-URL-010
- **Category:** Security Headers
- **File:** N/A

COEP requires all loaded resources to opt-in to being loaded, enabling use of SharedArrayBuffer and preventing data leaks.

**Suggested Fix:** Add a Cross-Origin-Embedder-Policy header:

### [MEDIUM] Wildcard CORS Configuration
- **ID:** 015423d4a29fb795
- **Rule:** AL-URL-013
- **Category:** CORS
- **File:** N/A

Access-Control-Allow-Origin is set to "*", allowing any origin to make cross-origin requests. This can expose user data to malicious websites.

**Suggested Fix:** Restrict CORS to specific trusted origins:

### [MEDIUM] innerHTML Assignment Detected
- **ID:** a9b9649d5fa44caa
- **Rule:** AL-JS-004
- **Category:** JS Security
- **File:** N/A

Direct innerHTML assignment was found. If the assigned content includes untrusted data, this creates an XSS vulnerability. React's JSX and other frameworks auto-escape content by default.

**Suggested Fix:** Replace innerHTML with safer DOM manipulation:

### [INFO] Console Logging in Production Code
- **ID:** 8d51e61990f867be
- **Rule:** AL-JS-008
- **Category:** JS Security
- **File:** N/A

Console logging statements were found in client-side code. While not a direct security vulnerability, verbose logging can leak sensitive data (tokens, user info, API responses) to browser developer tools.

**Suggested Fix:** Remove or guard console logging in production:

## Remediation

### Fix: Missing Content-Security-Policy Header [MEDIUM_EFFORT]
- **Estimated Time:** 1-2 hours
- **Impact:** Compliance risk if not addressed
- **APP References:** APP_11

Content-Security-Policy prevents XSS, clickjacking, and other code injection attacks by specifying approved sources of content.

**Fix:** Add a Content-Security-Policy header to your server configuration:

### Fix: Missing Strict-Transport-Security Header [MEDIUM_EFFORT]
- **Estimated Time:** 1-2 hours
- **Impact:** Compliance risk if not addressed
- **APP References:** APP_11

HSTS forces browsers to always use HTTPS, preventing protocol downgrade attacks and cookie hijacking.

**Fix:** Add a Strict-Transport-Security header to your server configuration:

### Review Security Headers practices [STRUCTURAL]
- **Estimated Time:** 1+ days
- **Impact:** Ongoing compliance improvement
- **APP References:** APP_11

3 medium-severity findings in Security Headers. Requires systematic review.

### Review CORS practices [STRUCTURAL]
- **Estimated Time:** 1+ days
- **Impact:** Ongoing compliance improvement
- **APP References:** APP_11

1 medium-severity findings in CORS. Requires systematic review.

### Review JS Security practices [STRUCTURAL]
- **Estimated Time:** 1+ days
- **Impact:** Ongoing compliance improvement
- **APP References:** APP_11

1 medium-severity findings in JS Security. Requires systematic review.

---
*This report is generated by AttestLens and does not constitute legal advice. Consult a qualified privacy professional for formal compliance assessment.*
*Generated by AttestLens v0.2.0 — 19/04/2026, 6:20:05 pm*