# Project Report

## ZERO TRUST – Website Security Assessment and Continuous Monitoring System
*MCA Mini Project – Cybersecurity*

---

## Abstract
Websites are frequently deployed with weak security configuration: missing HTTP security headers, no redirect from HTTP to HTTPS, insecure cookies, certificates close to expiry, or servers that reveal their software versions. These weaknesses are easy to detect but are rarely checked continuously. This project implements a web-based system that performs **passive, non-intrusive** security assessments of websites that an administrator is **authorized** to assess, converts the observations into findings with evidence and recommendations, computes a transparent **risk score (0–100)**, **monitors** websites on a schedule to detect configuration changes, keeps an **audit trail**, and produces **PDF reports**. The application itself follows the **Zero Trust** model—*never trust, always verify*—through strong authentication, least-privilege authorization, per-request session re-verification and strict protection against Server-Side Request Forgery (SSRF). It is built with Java, Spring Boot, Spring Security, Spring Data JPA, MySQL and a vanilla JavaScript frontend.

---

## 1. Introduction
### 1.1 Background
- **HTTPS and TLS** protect data in transit. A website without HTTPS, or with an invalid or expired certificate, exposes users to eavesdropping and man-in-the-middle attacks.
- **HTTP security headers** instruct browsers to enable protections: HSTS (always use HTTPS), CSP (limit script sources, mitigating XSS), X-Frame-Options (prevent clickjacking), X-Content-Type-Options (prevent MIME sniffing), Referrer-Policy (limit URL leakage) and Permissions-Policy (restrict powerful browser features).
- **Cookie attributes** `Secure`, `HttpOnly` and `SameSite` protect session cookies from network capture, script access and cross-site request forgery.
- **Zero Trust Architecture** (NIST SP 800-207) removes implicit trust: every request is authenticated and authorized, access is least-privilege, and activity is continuously monitored.

### 1.2 Problem statement
Organisations need a simple, safe and auditable way to check the security configuration of their websites regularly, to understand the risk in plain terms, and to be alerted when the configuration changes—while ensuring that only authorized people can run assessments and only against authorized websites.

### 1.3 Objectives
1. Register and manage authorized website targets.
2. Assess HTTPS availability and redirection, TLS certificate validity, security headers, cookie security, response metadata and information disclosure—passively.
3. Calculate a transparent risk score and classification from actual findings.
4. Present findings with severity, evidence and recommendations; allow filtering.
5. Monitor websites on a schedule and detect changes.
6. Maintain scan history and an audit log; generate PDF reports.
7. Enforce authentication, role-based access and per-website authorization.

### 1.4 Scope
In scope: passive configuration assessment of HTTP(S) websites reachable on the public internet. Out of scope (by design): vulnerability exploitation, payload injection, brute force, port scanning, load testing, and scanning of internal networks.

---

## 2. Requirements
### 2.1 Functional requirements
| ID | Requirement |
|---|---|
| FR1 | Users sign in with username and password; administrators manage users (ADMIN / ANALYST roles) |
| FR2 | Optional self-registration, with administrator approval |
| FR3 | Administrators register, edit and delete websites after confirming authorization, and assign analysts |
| FR4 | Authorized users run passive scans of registered websites |
| FR5 | The system assesses HTTPS, TLS certificate, six security headers, cookies, response metadata and technology disclosure |
| FR6 | The system computes a 0–100 score and risk classification and lists weaknesses and recommendations |
| FR7 | Users browse and filter findings by website, severity, category and date |
| FR8 | Administrators configure scheduled monitoring; the system records history and detected changes |
| FR9 | Users browse scan history and open full results of any scan |
| FR10 | Administrators view the audit log |
| FR11 | Users download a PDF report of any completed scan |
| FR12 | The dashboard shows live statistics from the database |

### 2.2 Non-functional requirements
| Category | Requirement |
|---|---|
| Security | BCrypt passwords, CSRF protection, secure session cookies, strict CSP, SSRF protection, audit logging, no secrets in source code |
| Safety | Only passive requests; rate limits and timeouts; only authorized targets |
| Privacy | No cookie values or page content stored |
| Usability | Responsive dark dashboard for desktop, tablet and mobile; loading, empty and error states |
| Reliability | Persistent MongoDB storage; interrupted scans marked failed on restart |
| Maintainability | Layered architecture, DTOs, 127 automated tests |

### 2.3 Hardware and software requirements
- Any PC with 4 GB RAM or more; Windows 10/11 (also runs on Linux/macOS).
- JDK 21+, Maven 3.9+, MongoDB 6+, a modern web browser.
- Internet access for scanning real websites (not needed for tests).

---

## 3. System design
### 3.1 Architecture
Three-tier, layered architecture:

```
Presentation   : HTML/CSS/JavaScript single-page dashboard (Fetch API)
Security layer : Spring Security filter chain (authentication, CSRF, roles, session re-verification)
Application    : REST controllers → services (business logic, scanner, risk engine, monitoring, reports)
Data           : Spring Data MongoDB repositories → MongoDB
External       : target websites (reached only through the SSRF-protected scanner client)
```

### 3.2 Use cases
| Actor | Use cases |
|---|---|
| Administrator | Log in/out, manage users, approve registrations, register/edit/delete websites, assign analysts, run scans, view results/findings/risk, configure monitoring, view audit logs, download reports, change settings |
| Analyst | Log in/out, view assigned websites, run scans on them, view results/findings/risk/monitoring history, download reports, change own password |
| Scheduler (system) | Run due monitoring checks, compare with previous scan, record events and alerts |

### 3.3 Data flow of a scan
```
User ──POST /api/scans {websiteId}──► ScanController
   ► ScanService: access check (ADMIN or assigned analyst), cooldown, one-scan-per-site lock
   ► save ScanRecord(RUNNING), audit SCAN_STARTED
   ► WebsiteScannerService.assess(url)
        TargetUrlValidator: scheme, port, hostname, DNS, IP ranges
        SocketHttpFetcher: connect to validated IP, TLS with hostname verification, read headers only
        follow redirects manually (re-validate each hop)
        Analyzers → findings
   ► RiskScoringService → score + classification
   ► save ScanRecord(COMPLETED/FAILED) + Findings, update website summary, audit SCAN_COMPLETED
   ◄ ScanResponse (JSON) ──► dashboard renders score gauge, charts and findings
```

### 3.4 Database design
Nine tables: `app_users`, `website_targets`, `target_analyst_access`, `scan_records`, `findings`, `monitoring_configs`, `monitoring_events`, `audit_logs`, `app_settings`. See [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) for columns, constraints, indexes and the ER diagram.

### 3.5 Module design
| Module | Main classes |
|---|---|
| Authentication & authorization | `SecurityConfig`, `AuthService`, `AppUserDetailsService`, `UserPrincipal`, `SessionRevalidationFilter`, `CurrentUserService` |
| Dashboard | `DashboardController`, `DashboardService` |
| Website management | `WebsiteController`, `WebsiteService`, `TargetUrlValidator` |
| Scanner | `ScanController`, `ScanService`, `WebsiteScannerService`, `SocketHttpFetcher`, `HttpsAnalyzer`, `TlsAnalyzer`, `SecurityHeaderAnalyzer`, `CookieAnalyzer`, `ResponseAnalyzer`, `DisclosureAnalyzer` |
| Risk assessment | `RiskScoringService` |
| Findings | `FindingController`, `FindingService` |
| Monitoring | `MonitoringController`, `MonitoringService`, `MonitoringComparator`, `MonitoringScheduler` |
| Audit | `AuditController`, `AuditService` |
| Reports | `ReportController`, `ReportService` (OpenPDF) |
| Users & settings | `UserController`, `UserService`, `SettingsController`, `SettingsService` |

---

## 4. Implementation highlights
1. **Hardened HTTP client.** Java's built-in `HttpClient` resolves DNS itself, which would allow a DNS-rebinding attack between validation and connection. `SocketHttpFetcher` connects to the exact validated IP, re-checks it immediately before connecting, performs TLS with SNI and hostname verification, sends a minimal `GET`, reads at most 64 KB of headers within strict time limits and never reads the body.
2. **Certificate reporting without disabling verification.** A wrapper delegates every trust decision to the JVM's trust manager and only records the presented certificate, so expired or untrusted certificates can be described in reports while the connection still fails as it would in a browser.
3. **Transparent scoring.** Severity weights, category caps and a critical ceiling make the score explainable; the Risk Assessment page and PDF show the exact deductions.
4. **Change detection.** Each check result has a stable `checkKey`, allowing monitoring to report regressions, new issues, resolved issues and header changes between scans.
5. **Continuous verification.** A security filter re-reads the user on every request, so access is revoked the moment an account is disabled.
6. **Strict Content-Security-Policy for the app itself.** The UI uses no inline scripts or styles, and charts are drawn with DOM/SVG, so `script-src 'self'; style-src 'self'` works without exceptions.

---

## 5. Testing
### 5.1 Strategy
- **Unit tests** for the analyzers, risk engine and SSRF validator using mock HTTP responses and a fake DNS resolver.
- **Socket-level tests** of the HTTP client against a local test server.
- **Integration tests** (full Spring context, MockMvc, separate local MongoDB test database, mocked fetcher) for authentication, authorization, persistence, reports and monitoring.
- **Manual end-to-end verification** against real public websites and in a real browser.

Automated tests need no internet access (only a local MongoDB). Result: **127 tests, 0 failures** (`mvn test`).

### 5.2 Selected test cases
| # | Test case | Expected result | Status |
|---|---|---|---|
| 1 | Access `/api/websites` without login | 401 JSON; pages redirect to `/login.html` | Pass |
| 2 | Login without CSRF token | 403 | Pass |
| 3 | Wrong password / unknown user | 401 "Invalid username or password." | Pass |
| 4 | 5 wrong passwords then correct password | Account locked | Pass |
| 5 | Disabled (pending) account login | 401, awaiting approval | Pass |
| 6 | Analyst calls `/api/users`, `/api/audit-logs`, `POST /api/websites` | 403 + `ACCESS_DENIED` audit | Pass |
| 7 | Analyst opens a website not assigned to them | 403 | Pass |
| 8 | Admin disables a logged-in analyst | Analyst's next request 401, `SESSION_REVOKED` | Pass |
| 9 | Register `http://localhost`, `127.0.0.1`, `169.254.169.254`, `10.x`, `[::1]`, `ftp://`, port 22, `user:pw@host` | 400 with reason | Pass |
| 10 | Hostname resolving to a private IP, or to public + loopback | Rejected | Pass |
| 11 | Website redirects to an internal or metadata address | Redirect not followed; MEDIUM finding | Pass |
| 12 | Redirect loop | Stops after 5 redirects; finding | Pass |
| 13 | Site with all headers and secure cookies | Score 100 | Pass |
| 14 | HTTP-only site | CRITICAL "HTTPS is not available", score ≤ 49 | Pass |
| 15 | Expired / untrusted certificate | CRITICAL findings with certificate details | Pass |
| 16 | Certificate expiring in 7 / 25 days | HIGH / MEDIUM | Pass |
| 17 | Cookie value in `Set-Cookie` | Value never appears in any stored field | Pass |
| 18 | Weak CSP (`*`, `unsafe-inline`, `unsafe-eval`) / report-only CSP | Flagged | Pass |
| 19 | Response headers > 64 KB / slow server / non-HTTP server | Rejected / timeout / error | Pass |
| 20 | Scan persisted | ScanRecord COMPLETED, findings stored, website summary updated, audit entry | Pass |
| 21 | Unreachable website | Scan FAILED with reason, no score | Pass |
| 22 | PDF report | `application/pdf`, starts with `%PDF-`, audited | Pass |
| 23 | Monitoring: baseline, then headers added | `BASELINE`, then `CHANGES_DETECTED` with positive score change and "Resolved" entries | Pass |
| 24 | Monitoring interval 1 minute | 400 (allowed 5–1440) | Pass |
| 25 | Delete website | Scans and findings removed (cascade), audit entry kept | Pass |
| 26 | Admin tries to delete/disable/demote self | 400 | Pass |
| 27 | Weak password on user creation | 400 with policy message | Pass |
| 28 | Application response headers | CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy present | Pass |

### 5.3 Manual verification results (30 Oct 2026)
| Website | Score | Classification | Main findings |
|---|---|---|---|
| https://example.com | 57 | Moderate | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy missing; HTTP not redirected to HTTPS |
| https://github.com | 94 | Excellent | Permissions-Policy missing; one cookie without HttpOnly |

All 12 dashboard pages were loaded in a headless browser with no JavaScript errors and no Content-Security-Policy violations, at desktop and mobile widths.

---

## 6. Results and discussion
The system meets all functional requirements. Real-world scans produce plausible, explainable scores: a well-hardened site (GitHub) scores Excellent, while a minimal demo site (example.com) scores Moderate due to missing headers. Monitoring correctly identifies improvements and regressions between scans. Zero Trust controls were verified both automatically and manually: analysts are confined to assigned websites, every denial is audited, and disabling an account terminates its active session immediately.

## 7. Limitations
Passive checks see only what headers and the TLS handshake reveal; only the registered page is assessed; TLS cipher/protocol enumeration is not performed; trust decisions use the JVM trust store; HTTP/2-only servers are not supported; monitoring runs only while the application is running. See README §15.

## 8. Conclusion
The project demonstrates how Zero Trust principles—continuous verification, least privilege and full visibility—can be applied both to the *design of a security tool* and to the *assessment of websites*. It combines practical web-security knowledge (HTTPS, TLS, headers, cookies) with secure software engineering (authentication, authorization, CSRF, CSP, SSRF prevention, audit logging) in a complete, tested, database-backed application.

## 9. Future enhancements
Email/webhook alerts, multi-factor authentication, DNS-based domain ownership verification, additional passive checks (SPF/DMARC/CAA, security.txt, CORS), TLS configuration enumeration, trend reports and CSV export, Docker deployment with HTTPS.

---

## Appendix A – Viva preparation (questions and short answers)
**What is Zero Trust?** A security model that assumes no implicit trust based on network location; every request must be authenticated, authorized and continuously validated, with least-privilege access and monitoring.

**Where is Zero Trust applied in this project?** Every API/page requires authentication; roles plus per-website assignments (least privilege); the user is re-verified on every request; only explicitly authorized websites can be scanned; every destination is re-validated before connecting; all actions are audited.

**Why BCrypt and not SHA-256?** BCrypt is deliberately slow and salted, making brute-force and rainbow-table attacks impractical; SHA-256 is fast and designed for integrity, not password storage.

**What is CSRF and how is it prevented?** A malicious site making the victim's browser send authenticated requests. Every state-changing request must carry a token from the `XSRF-TOKEN` cookie in a header, which another site cannot read; the session cookie is also `SameSite=Strict`.

**What is SSRF and why does a scanner need protection?** Server-Side Request Forgery tricks a server into requesting internal resources (e.g. `http://169.254.169.254/` cloud metadata, admin panels on `localhost`). The scanner allows only http/https on approved ports, rejects internal hostnames, checks every resolved IP against blocked ranges, connects to the validated IP (defeating DNS rebinding), and re-validates every redirect.

**What is DNS rebinding?** An attacker's DNS first answers with a public IP (passing validation) and then with an internal IP when the actual connection is made. Connecting directly to the already-validated IP prevents it.

**Why is the scan "passive"?** It sends ordinary `GET` requests like a browser and only reads headers and certificate data; it never sends attack payloads.

**Why not disable certificate verification to read expired certificates?** That would make the scanner itself vulnerable to man-in-the-middle attacks and give wrong results. Verification stays on; the presented certificate is merely recorded before the trust manager rejects it.

**Explain HSTS / CSP / X-Frame-Options.** HSTS forces browsers to use HTTPS for a period (`max-age`); CSP whitelists content sources to mitigate XSS; X-Frame-Options (or CSP `frame-ancestors`) prevents the page being framed for clickjacking.

**What do Secure, HttpOnly and SameSite do?** Secure – cookie only sent over HTTPS; HttpOnly – not readable by JavaScript (limits XSS impact); SameSite – restricts sending on cross-site requests (CSRF mitigation).

**How is the score calculated and why caps and a ceiling?** 100 minus severity-weighted deductions per failed check; per-category caps prevent one area dominating; any CRITICAL finding caps the score at 49 so a site with e.g. an expired certificate never looks "Good".

**Why DTOs instead of returning entities?** To control exactly what is exposed (e.g. never password hashes), avoid lazy-loading problems and keep the API stable.

**Why is each audit entry saved immediately as its own document?** So that an audit record (e.g. a failed attempt) is kept even if the main operation fails part-way.

**How does monitoring detect changes?** Each check has a stable key; the comparator compares the new scan's checks, score, headers and certificate with the previous scan and records differences.
