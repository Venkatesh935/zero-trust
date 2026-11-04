# ZERO TRUST – Website Security Assessment and Continuous Monitoring System

An MCA cybersecurity mini project. A Spring Boot web application that lets authenticated users register websites they are **authorized** to assess, run **passive** security assessments (HTTPS, TLS certificate, HTTP security headers, cookie attributes, response metadata, technology disclosure), calculate a transparent **0–100 risk score**, **monitor** websites on a schedule with change detection, keep a full **audit trail**, and download **PDF reports**.

The whole system is built around the Zero Trust principle: **Never trust, always verify.**

---

## Contents
1. [Problem statement](#1-problem-statement)
2. [Objectives](#2-objectives)
3. [Proposed solution](#3-proposed-solution)
4. [Technology stack](#4-technology-stack)
5. [System architecture](#5-system-architecture)
6. [Modules](#6-modules)
7. [Database design](#7-database-design)
8. [API overview](#8-api-overview)
9. [Security methodology](#9-security-methodology)
10. [Risk scoring methodology](#10-risk-scoring-methodology)
11. [Installation and MongoDB setup](#11-installation-and-mongodb-setup)
12. [Running the project](#12-running-the-project)
13. [Demonstration script / how to test each module](#13-demonstration-script--how-to-test-each-module)
14. [Automated tests](#14-automated-tests)
15. [Limitations](#15-limitations)
16. [Future enhancements](#16-future-enhancements)

Detailed documents: [docs/PROJECT_REPORT.md](docs/PROJECT_REPORT.md) · [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) · [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) · [docs/SECURITY_METHODOLOGY.md](docs/SECURITY_METHODOLOGY.md)

---

## 1. Problem statement
Many websites are deployed with weak security configuration: no HTTPS redirect, missing security headers, cookies without `Secure`/`HttpOnly`/`SameSite`, certificates that silently expire, or servers that advertise their software versions. These problems are easy to detect but often go unnoticed because nobody checks them regularly. Organisations also need to control **who** may run such assessments and keep a record of what was done.

## 2. Objectives
- Assess the security configuration of authorized websites using safe, passive checks.
- Present results as understandable findings with evidence and recommendations.
- Quantify risk with a transparent, reproducible score.
- Monitor websites continuously and detect configuration changes and certificate expiry.
- Enforce authentication, role-based authorization and per-website access (Zero Trust).
- Record all security-relevant actions in an audit log and produce PDF reports.

## 3. Proposed solution
A layered Spring Boot application with a vanilla JavaScript single-page dashboard. Administrators register websites (confirming authorization), assign analysts to specific websites, and run or schedule scans. A custom, hardened HTTP client collects only status lines and headers. Analyzer classes convert observations into findings; the risk engine scores them; results are stored in MongoDB and visualised in the dashboard and PDF reports.

## 4. Technology stack
| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, vanilla JavaScript (Fetch API), hand-built SVG charts – no frameworks |
| Backend | Java 21, Spring Boot 4.1, Spring Web MVC, Spring Security 7, Spring Data MongoDB, Bean Validation, Jackson, Spring Scheduling |
| Database | MongoDB 6+ (Spring Data MongoDB) |
| Reports | OpenPDF 2.0 |
| Testing | JUnit, Spring Boot Test, MockMvc, Mockito, separate local MongoDB test database |
| Build | Maven |

## 5. System architecture
```
 Browser (HTML/CSS/JS SPA)
      │  HTTPS-ready, session cookie + CSRF token
      ▼
 Spring Security filter chain ── authentication, CSRF, role rules,
      │                          session re-verification on every request
      ▼
 Controllers (/api/**)  ──►  DTOs (no entities exposed)
      │
      ▼
 Services ───────────────────────────────────────────────────────────┐
  AuthService · UserService · WebsiteService · ScanService            │
  WebsiteScannerService ─► TargetUrlValidator (SSRF) ─► SocketHttpFetcher ─► Internet
     analyzers: HTTPS · TLS · Security headers · Cookies · Response · Disclosure
  RiskScoringService · FindingService · DashboardService               │
  MonitoringService + MonitoringComparator ◄── MonitoringScheduler     │
  ReportService (PDF) · AuditService · SettingsService                 │
      │                                                                │
      ▼                                                                │
 Repositories (Spring Data MongoDB) ──► MongoDB zero_trust_db ◄──────────────┘
```

Package layout (`src/main/java/com/zerotrust`):

| Package | Responsibility |
|---|---|
| `config` | Security configuration, typed properties, first-start admin setup |
| `controller` | REST endpoints |
| `dto` | Request/response objects (`ApiResponse` envelope) |
| `entity` | MongoDB documents and enums |
| `repository` | Spring Data repositories |
| `service` | Business logic; `service.scanner` holds the scanner engine and analyzers |
| `security` | Principal, SSRF URL validator, session re-verification filter, access control |
| `exception` | `ApiException`, `UnsafeTargetException`, global exception handler |
| `scheduler` | Monitoring scheduler |
| `util` | IP range rules, password policy |

## 6. Modules
| # | Module | Summary |
|---|---|---|
| 1 | Authentication & authorization | Login/logout, BCrypt (cost 12), roles ADMIN / ANALYST, CSRF, session fixation protection, account lockout after 5 failures, optional self-registration (accounts start disabled until approved), per-request session re-verification |
| 2 | Dashboard | 10 live statistics, average score gauge, risk distribution, severity chart, recent scans, monitoring status, quick actions |
| 3 | Website targets | Register/edit/delete websites; URL validated incl. DNS + IP checks; explicit authorization confirmation; analyst assignment |
| 4 | Security scanner | Passive HTTPS, TLS, header, cookie, response and disclosure checks with strict SSRF protection |
| 5 | Risk assessment | Transparent score, category breakdown, severity distribution, main weaknesses, recommendations |
| 6 | Security findings | Filter by website, severity, category, date; evidence + recommendation per finding |
| 7 | Continuous monitoring | Scheduled scans (5–1440 min), change detection (score, headers, checks, certificate), history + trend chart, run-now |
| 8 | Scan history | Paged list of all scans, full stored results per scan |
| 9 | Audit logs | Logins, failures, lockouts, denials, CRUD, scans, monitoring alerts, reports, session revocations (ADMIN only) |
| 10 | Reports | Downloadable PDF built from stored scan data |
| 11 | User management | Create, edit, enable/approve, unlock, reset password, delete (with last-admin safeguards) |
| 12 | Settings | Change own password, toggle self-registration, view security and scanner policy |

## 7. Database design
Database `zero_trust_db` (created automatically). Collections: `app_users`, `website_targets`, `scan_records`, `findings`, `monitoring_configs`, `monitoring_events`, `audit_logs`, `app_settings`, `counters`. Collections and indexes are created automatically. Document fields, references and indexes: [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md).

Key relationships: one user → many scans and audit entries; one website → many scans; one scan → many findings; one website → one monitoring configuration → many monitoring events; websites ↔ analysts (many-to-many access grants). Deleting a website cascades to its scans, findings and monitoring data (done explicitly by the application, since MongoDB has no foreign keys).

## 8. API overview
All endpoints return `{ "success", "message", "data", "errors", "timestamp" }` (except the PDF download).

| Area | Endpoints |
|---|---|
| Auth | `GET /api/auth/csrf` · `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/me` · `POST /api/auth/register` · `GET /api/auth/registration-status` · `PUT /api/auth/password` |
| Dashboard | `GET /api/dashboard/summary` · `/recent-scans` · `/risk-distribution` |
| Websites | `GET/POST /api/websites` · `GET/PUT/DELETE /api/websites/{id}` |
| Scans | `POST /api/scans` · `GET /api/scans` · `GET /api/scans/{id}` · `GET /api/scans/{id}/findings` |
| Findings | `GET /api/findings` · `GET /api/findings/{id}` |
| Monitoring | `GET/POST /api/monitoring` · `PUT/DELETE /api/monitoring/{id}` · `GET /api/monitoring/{id}/history` · `POST /api/monitoring/{id}/run` |
| Audit | `GET /api/audit-logs` (ADMIN) |
| Reports | `GET /api/reports/{scanId}/pdf` |
| Users | `GET/POST /api/users` · `PUT/DELETE /api/users/{id}` (ADMIN) |
| Settings | `GET /api/settings` · `PUT /api/settings` (ADMIN) |

Full reference with request/response examples: [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md).

## 9. Security methodology
Summary (details in [docs/SECURITY_METHODOLOGY.md](docs/SECURITY_METHODOLOGY.md)):
- **Zero Trust access control** – every page and API requires an authenticated session (except login/registration); admin operations are checked by URL rules *and* method-level `@PreAuthorize`; analysts only access websites explicitly assigned to them; the user's account is re-verified against the database on **every request**, so disabling, deleting or changing a user's role revokes their session immediately.
- **Credential protection** – BCrypt hashing, password policy, account lockout, generic login error messages, no hard-coded passwords (initial admin from `ZT_ADMIN_PASSWORD` or a one-time random password).
- **Web protections** – CSRF tokens (double-submit cookie), `HttpOnly` + `SameSite=Strict` session cookie, session ID change on login, strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy, Permissions-Policy; output escaping in the UI.
- **SSRF protection** for the scanner – http/https only; ports 80/443/8080/8443 only; no credentials in URLs; internal hostnames rejected; DNS resolved and **every** address checked against loopback, private, link-local, CGNAT, multicast, reserved, documentation, IPv6 ULA/link-local/transition ranges and cloud metadata endpoints; the socket connects to the **validated IP** (defeats DNS rebinding) and re-checks it immediately before connecting; redirects are followed manually with every hop re-validated; connect/read/total timeouts; 64 KB header limit; response bodies are never read.
- **Privacy** – cookie values are discarded during parsing; no page content is stored; audit logs never contain passwords, tokens or cookie values.
- **Passive only** – one `GET` request per URL variant; no payloads, brute force, port scanning or exploitation.

## 10. Risk scoring methodology
```
score = 100 − Σ min(category deductions, category cap)
        failed check deduction: CRITICAL 25 · HIGH 15 · MEDIUM 8 · LOW 3 · INFORMATIONAL 0
        category caps: HTTPS 35 · TLS 30 · Security headers 35 · Cookies 15 · HTTP response 10 · Disclosure 6
if any CRITICAL finding exists → score = min(score, 49)
```
| Score | Classification |
|---|---|
| 90–100 | Excellent |
| 75–89 | Good |
| 50–74 | Moderate |
| 25–49 | High Risk |
| 0–24 | Critical Risk |

Example: a site with valid HTTPS but no security headers and no HTTP→HTTPS redirect loses 35 (headers, capped from 40) + 8 (redirect) = **57, Moderate**.

> The score measures **configuration hygiene observed by passive checks**. It is not a penetration test and is not proof that a website is secure or vulnerable.

## 11. Installation and MongoDB setup
### Prerequisites
- JDK 21 or newer (`java -version`)
- Maven 3.9+ (`mvn -v`) – or use the included `mvnw.cmd`
- MongoDB 6+ running on `localhost:27017` (Windows service `MongoDB`), or a MongoDB Atlas connection string

### MongoDB
Nothing needs to be created by hand: the database `zero_trust_db`, its collections and indexes are created automatically on first start. Numeric IDs are generated from a `counters` collection. The default connection (`mongodb://localhost:27017/zero_trust_db`) needs no credentials; for a secured server or Atlas, set `MONGODB_URI`.

### Environment variables
No credentials are stored in source code or `application.properties`.

| Variable | Required | Purpose |
|---|---|---|
| `MONGODB_URI` | no (default `mongodb://localhost:27017/zero_trust_db`) | Full MongoDB connection string, e.g. `mongodb+srv://user:pass@cluster.mongodb.net/zero_trust_db` |
| `MONGODB_DATABASE` | no (default `zero_trust_db`) | Database name |
| `ZT_ADMIN_USERNAME` | no (default `admin`) | Initial administrator name (first start only) |
| `ZT_ADMIN_PASSWORD` | recommended | Initial administrator password (first start only). Must satisfy the password policy; otherwise a random password is generated and printed once in the console |

Password policy: 8–128 characters with upper-case, lower-case, digit and special character, not containing the username.

## 12. Running the project
### Windows PowerShell
```powershell
cd C:\Users\subra\zero-trust

# Settings for this PowerShell window only (MONGODB_URI is optional for a local MongoDB)
# $env:MONGODB_URI = "mongodb://localhost:27017/zero_trust_db"
$env:ZT_ADMIN_PASSWORD = "ZeroTrust@2026!"    # used only when the first admin is created

# Run tests (needs the local MongoDB, no internet) and start the application
mvn clean test
mvn spring-boot:run
```
Or use the helper script, which asks for the connection string and admin password without echoing the latter:
```powershell
cd C:\Users\subra\zero-trust
powershell -ExecutionPolicy Bypass -File .\run-local.ps1
```
Open **http://localhost:8080** and sign in as `admin` with the `ZT_ADMIN_PASSWORD` you set (or the generated password printed in the console on first start). Change it under **Settings**.

To build a runnable JAR:
```powershell
mvn clean package
java -jar target\zero-trust-0.0.1-SNAPSHOT.jar
```

To make the variables permanent for your Windows user (optional):
```powershell
[Environment]::SetEnvironmentVariable("MONGODB_URI", "mongodb://localhost:27017/zero_trust_db", "User")
```

### Internet connectivity
| Feature | Needs internet? |
|---|---|
| Login, dashboard, users, audit, reports of stored scans, history | No |
| Registering a website (DNS resolution for SSRF validation) | Yes (DNS) |
| Running scans / monitoring checks | Yes – the target website must be reachable |
| Automated tests (`mvn test`) | No – they use mock HTTP responses and fake DNS, plus the separate `zero_trust_test` database on local MongoDB |

## 13. Demonstration script / how to test each module
1. **Start MongoDB** (Windows service `MongoDB`) and run the application.
2. **Login**: open http://localhost:8080 → redirected to the login page. Try a wrong password (generic error, logged as `LOGIN_FAILURE`), then sign in as `admin`.
3. **Dashboard**: statistics are empty at first (no fake data).
4. **Website Targets → Register website**: e.g. a site you own, or the public demo domain `https://example.com`. Tick the authorization confirmation. Try `http://localhost`, `http://192.168.1.1` or `http://169.254.169.254` – they are rejected by SSRF protection.
5. **Security Scanner**: choose the website → **Run scan**. View the score, findings, and the Security Headers / TLS / Cookies / HTTPS & Response / Disclosure tabs.
6. **Risk Assessment**: see how each category contributed to the score.
7. **Security Findings**: filter by severity, category, website and date.
8. **Continuous Monitoring → Enable monitoring** (e.g. 5 minutes), then **Run now** twice and open **History** to see the trend chart and detected changes. The scheduler also runs due checks automatically every minute.
9. **Scan History**: open any previous scan.
10. **Reports**: download the PDF report.
11. **User Management**: create an ANALYST, then edit a website and assign it to the analyst. Sign in as the analyst in a private window: only the assigned website is visible, admin pages are hidden, and direct API calls return 403 (logged as `ACCESS_DENIED`). Disable the analyst as admin – the analyst's open session is revoked on the next click (`SESSION_REVOKED`).
12. **Audit Logs**: review every action above.
13. **Sign up**: on the login page click **Create an account** (or open `/register.html`), then approve the new account in User Management. Self-registration can be switched off under **Settings**.

## 14. Automated tests
`mvn test` runs **127 tests** without internet access. The integration tests use the separate database `zero_trust_test` on the local MongoDB (start `mongod` first; the database is emptied at the start of each run and never touches `zero_trust_db`). HTTP responses and DNS are mocked:

| Test class | Covers |
|---|---|
| `TargetUrlValidatorTest` | URL validation and SSRF protection (schemes, ports, credentials, internal hosts, 25 blocked IP forms, DNS answers mixing public/private IPs) |
| `SocketHttpFetcherTest` | Real socket client against a local server: header parsing, header size limit, timeouts, non-HTTP responses, refusal to connect to loopback |
| `SecurityHeaderAnalyzerTest` | Security header detection and configuration checks |
| `CookieAnalyzerTest` | Cookie attribute detection; cookie values never appear in findings |
| `TlsAndHttpsAnalyzerTest` | HTTPS availability/redirect/downgrade; certificate trust, expiry thresholds, protocol |
| `WebsiteScannerServiceTest` | Complete scans with mock responses: redirects, blocked redirects to internal/metadata IPs, redirect loops, HTTP-only sites, TLS failures, unreachable sites |
| `RiskScoringServiceTest` | Weights, category caps, critical ceiling, classification boundaries |
| `AuthenticationIntegrationTest` | Login/logout, CSRF, lockout, disabled accounts, registration approval, password change, password policy, security headers |
| `AuthorizationIntegrationTest` | Role rules, per-website analyst access, session revocation, last-admin safeguards, URL validation via API |
| `ScanWorkflowIntegrationTest` | Scan persistence, findings API, dashboard, PDF report, failed scans, monitoring change detection, cascade delete, audit entries |

## 15. Limitations
- Checks are passive and limited to what HTTP headers and the TLS handshake reveal; application-level vulnerabilities (XSS, SQL injection, logic flaws) are not tested – by design.
- Only the registered page (plus redirects) is assessed, not the whole site.
- TLS assessment reports the negotiated protocol only; it does not enumerate all supported protocol versions or cipher suites (that would require many extra connections).
- Certificate trust uses the JVM trust store, which can differ slightly from browser trust stores.
- The scanner speaks HTTP/1.1 only; HTTP/2-only servers (rare) cannot be assessed.
- Monitoring runs inside the application – checks only happen while the application is running; in-memory scan rate-limits reset on restart.
- Self-signed internal sites cannot be scanned, because private networks are blocked by SSRF protection.

## 16. Future enhancements
- Email / webhook notifications for monitoring alerts.
- Multi-factor authentication (TOTP) for administrators.
- Domain ownership verification (DNS TXT record) before allowing scans.
- Additional passive checks: DNS (SPF/DMARC/CAA), `security.txt`, CORS and cache headers, mixed content.
- Full TLS configuration testing (supported versions and ciphers).
- Trend comparison reports across many scans and CSV export.
- Containerised deployment (Docker Compose with MongoDB) and HTTPS for the dashboard itself.
- to run this project run this cammand in the treminal ".\mvnw.cmd spring-boot:run"