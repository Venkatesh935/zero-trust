# Security Methodology

This document explains how the application applies Zero Trust to its own design, how the passive scanner works, how it is protected against misuse (SSRF), and how risk is scored.

## 1. Zero Trust principles applied

| Principle | Implementation |
|---|---|
| **Never trust, always verify** | Every page and API request requires an authenticated session; on *every* request `SessionRevalidationFilter` reloads the user from the database and revokes the session immediately if the account was deleted, disabled or its role changed. |
| **Least privilege** | Two roles. ANALYST can only see, scan and report on websites an administrator explicitly assigned; all user, audit, website-management, monitoring-management and settings operations require ADMIN. |
| **Defence in depth** | Role rules are enforced twice: URL rules in `SecurityConfig` and `@PreAuthorize` on controllers; per-website rules in `CurrentUserService.checkTargetAccess` inside services. |
| **Explicit authorization of targets** | A website can only be registered after the administrator confirms ownership/permission; scans accept only registered website IDs, never free-form URLs; scheduled jobs only use stored target URLs. |
| **Assume breach / visibility** | Security-relevant events, including denied access and session revocations, are recorded in an audit log that only administrators can read. |
| **Verify explicitly at the network level** | Every scan destination (and every redirect) is re-validated, and the address is checked again immediately before a socket is opened. |

## 2. Authentication and session security
- **Password storage:** BCrypt with cost factor 12 (`BCryptPasswordEncoder(12)`); plain-text passwords are never stored or logged.
- **Password policy:** 8–128 characters, upper- and lower-case, digit, special character, must not contain the username.
- **Initial administrator:** created only when the user table is empty, from `ZT_ADMIN_USERNAME` / `ZT_ADMIN_PASSWORD`. If the password is missing or weak, a random 16-character password is generated and printed once to the console. No password appears in source code.
- **Brute-force protection:** 5 consecutive failures lock the account for 15 minutes (`ACCOUNT_LOCKED` audited). Unknown users and wrong passwords receive the same message; Spring Security also performs a dummy hash for unknown users to avoid timing differences.
- **Session:** server-side session, cookie `ZTSESSION` with `HttpOnly` and `SameSite=Strict`, cookie-only tracking (no URL session IDs), 30-minute idle timeout. The session ID is changed at login (session-fixation protection) and the session is invalidated at logout. The principal's password hash is erased after authentication, so it is not stored in the session.
- **Self-registration:** on by default (administrators can switch it off in Settings); new accounts are ANALYST and **disabled** until an administrator approves them.

## 3. Web application protections
- **CSRF:** all state-changing requests require the `X-XSRF-TOKEN` header matching the `XSRF-TOKEN` cookie (Spring Security SPA CSRF configuration), including the login form (prevents login CSRF).
- **Security headers sent by the application itself:**
  `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`, `Cache-Control: no-store` on dynamic content. The frontend contains no inline scripts or styles, so the strict CSP needs no exceptions.
- **XSS:** all dynamic values are HTML-escaped in the frontend (`ZT.esc`); the CSP blocks injected scripts as a second layer.
- **Input validation:** Bean Validation on all request DTOs; enum and number parameters are type-checked; page sizes are clamped.
- **Error handling:** a global handler returns consistent JSON with safe messages; stack traces and internal messages are never sent to clients (`server.error.include-message=never`).
- **Log injection:** audit descriptions are stripped of control characters and length-limited.
- **Secrets:** database credentials come from environment variables only.

## 4. Passive scanning methodology
For a registered URL the scanner makes at most a handful of ordinary `GET` requests:

1. **HTTPS probe:** `https://host/path`, following redirects (max 5).
2. **HTTP probe:** `http://host/path`, stopping at the redirect to HTTPS when HTTPS works.

Only the **status line and headers** are read; the response body is never read or stored. From these observations six analyzers produce findings:

| Check | What is evaluated | Typical findings |
|---|---|---|
| **HTTPS** | HTTPS reachable with a trusted certificate; HTTP→HTTPS redirect; HTTPS→HTTP downgrade in the redirect chain | HTTPS not available (CRITICAL), no redirect (MEDIUM), downgrade (HIGH) |
| **TLS certificate** | Chain trust and hostname match (JVM trust store, verification never disabled); expiry date and days remaining; negotiated protocol | Validation failed (CRITICAL), expired (CRITICAL), ≤ 14 days (HIGH), ≤ 30 days (MEDIUM), TLS 1.0/1.1 (HIGH) |
| **Security headers** | HSTS (presence, max-age ≥ 180 days), CSP (presence, enforced vs report-only, wildcards, `unsafe-inline`/`unsafe-eval`), X-Frame-Options or CSP `frame-ancestors`, X-Content-Type-Options `nosniff`, Referrer-Policy (unsafe values), Permissions-Policy | Missing HSTS (HIGH), missing CSP / clickjacking protection (MEDIUM), others (LOW) |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie` in the chain; `SameSite=None` without `Secure` | Missing Secure on HTTPS (MEDIUM), missing HttpOnly/SameSite (LOW) |
| **HTTP response** | Final status code, response time, content type, redirect count, blocked redirects | 5xx (MEDIUM), redirect loop (MEDIUM), redirect to disallowed destination (MEDIUM), slow (> 3 s, LOW) |
| **Information disclosure** | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator` | Version disclosed (LOW), product named (INFORMATIONAL) |

Information disclosure findings explicitly state that revealing a technology is **not** proof of a vulnerability.

**When a certificate is invalid**, the handshake still fails exactly as in a browser. A wrapper around the default trust manager only *records* the certificate the server presented before delegating every decision to the JVM's trust manager, so details such as the expiry date can be reported without weakening verification.

**Privacy:** cookie values are discarded at parse time (only names and attributes are kept); no page content, full header dumps or session secrets are stored.

**What is never done:** no attack payloads, no SQL injection or XSS probes, no brute force, no directory enumeration, no port scanning, no denial-of-service testing.

## 5. SSRF protection
A scanner that fetches URLs could be abused to reach internal systems (Server-Side Request Forgery). The defences, implemented in `TargetUrlValidator`, `IpAddressRules` and `SocketHttpFetcher`:

1. **Scheme allow-list:** only `http` and `https`.
2. **Port allow-list:** 80, 443, 8080, 8443 (configurable via `zerotrust.scanner.allowed-ports`).
3. **No embedded credentials** (`user:pass@host`), no whitespace/control characters, max 500 characters.
4. **Hostname rules:** `localhost`, `*.localhost`, `*.local`, `*.localdomain`, `*.internal`, `*.intranet`, `*.corp`, `*.home`, `*.lan`, `*.home.arpa`, reverse-DNS zones, and single-label names (e.g. `http://intranet/`) are rejected; hostnames must be syntactically valid.
5. **IP literals are parsed directly**, never sent to DNS, so the literal itself is checked.
6. **DNS resolution and full address check:** all addresses a name resolves to are checked; if *any* is forbidden the target is rejected. Blocked ranges:
   - IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT, incl. Alibaba metadata `100.100.100.200`), `127.0.0.0/8`, `169.254.0.0/16` (incl. `169.254.169.254` cloud metadata), `172.16.0.0/12`, `192.0.0.0/24` (incl. Oracle metadata), `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` (multicast), `240.0.0.0/4` (reserved), `255.255.255.255`, and `168.63.129.16` (Azure platform endpoint).
   - IPv6: `::`, `::1`, IPv4-mapped/compatible addresses (checked against the IPv4 rules), `64:ff9b::/96` and `64:ff9b:1::/48` (NAT64), `100::/64`, `2001::/32` (Teredo), `2001:db8::/32`, `2002::/16` (6to4), `fc00::/7` (ULA, incl. AWS `fd00:ec2::254`), `fe80::/10`, `fec0::/10`, `ff00::/8`.
7. **DNS-rebinding protection:** Java's `HttpClient` resolves hostnames itself, so the IP it connects to could differ from the one that was validated. The scanner therefore uses its own minimal HTTP/1.1 client that opens the TCP socket **to the exact validated IP address** (TLS still uses the hostname for SNI and certificate verification) and calls `assertAddressAllowed` again immediately before connecting.
8. **Manual redirect handling:** redirects are never followed automatically. Each `Location` is resolved, re-validated with steps 1–6, and only then requested. Disallowed redirect targets are reported as a finding and not contacted. At most 5 redirects.
9. **Resource limits:** 5 s connect timeout, 8 s read timeout, overall deadline per request, 64 KB maximum header size, body never read, at most two resolved addresses tried.
10. **Abuse limits:** one concurrent scan per website, 30 s cooldown between manual scans of the same website, monitoring interval 5–1440 minutes, at most 3 scheduled checks per minute.

These rules are covered by `TargetUrlValidatorTest`, `SocketHttpFetcherTest` and `WebsiteScannerServiceTest`.

## 6. Risk scoring methodology
Implemented in `RiskScoringService`; the same calculation is used for stored scores, the Risk Assessment page and the PDF report.

1. Start at **100**.
2. Each **failed** check deducts points by severity:

   | Severity | Deduction | Meaning |
   |---|---|---|
   | CRITICAL | 25 | Directly undermines transport security (no HTTPS, invalid/expired certificate) |
   | HIGH | 15 | Serious weakness (no HSTS, HTTPS→HTTP downgrade, certificate expiring within 14 days, obsolete TLS) |
   | MEDIUM | 8 | Important hardening missing (CSP, clickjacking protection, HTTP→HTTPS redirect, insecure cookies) |
   | LOW | 3 | Best-practice gaps (nosniff, Referrer-Policy, Permissions-Policy, version disclosure) |
   | INFORMATIONAL | 0 | Context only |

3. **Category caps** keep any single area from dominating: HTTPS 35, TLS 30, Security headers 35, Cookies 15, HTTP response 10, Information disclosure 6.
4. **Critical ceiling:** if at least one CRITICAL finding exists, the score is limited to **49** (High Risk), so a site with an expired certificate can never look "Good" just because its headers are fine.
5. **Classification:** 90–100 Excellent · 75–89 Good · 50–74 Moderate · 25–49 High Risk · 0–24 Critical Risk.

**Worked example (example.com, observed on 30 Oct 2026):** HTTPS OK, certificate valid (56 days), HTTP does not redirect (MEDIUM −8), HSTS missing (HIGH 15), CSP missing (8), X-Frame-Options missing (8), X-Content-Type-Options, Referrer-Policy and Permissions-Policy missing (3 each). Headers raw deduction 40 → capped at 35. Score = 100 − 8 − 35 = **57 → Moderate**.

The score is a **configuration assessment**, not a penetration test result: a high score does not prove a website is secure, and a low score does not prove it is exploitable.

## 7. Continuous monitoring and change detection
`MonitoringScheduler` runs every minute and executes due checks (bounded per cycle). Each check runs a normal passive scan of the stored URL and `MonitoringComparator` compares it with the previous scan of the same website:
- availability changes (became unavailable / available again),
- score changes with the delta,
- per-check regressions, new issues, resolved issues,
- security-header value changes (CSP nonces are normalized to avoid false alarms),
- certificate replacement, certificate expiring within 30 days, untrusted certificates.

The result state (`BASELINE`, `STABLE`, `CHANGES_DETECTED`, `DEGRADED`, `UNAVAILABLE`) is stored with the change list; `DEGRADED` and `UNAVAILABLE` also create a `MONITORING_ALERT` audit entry.

## 8. Audit logging
Recorded actions: logins (success/failure), lockouts, logouts, session revocations, access denials, registrations, user create/update/delete, password changes, website create/update/delete, scan start/completion/failure, monitoring changes and alerts, report generation, settings changes. Each entry stores user ID, username, action, description, related website ID, client IP address and timestamp. Entries are saved immediately as separate documents so they persist even when the surrounding operation fails. The client IP is taken from the TCP connection (`X-Forwarded-For` is ignored because clients can forge it).
