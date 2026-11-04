# API Documentation

Base URL: `http://localhost:8080`

## Conventions

**Response envelope** (all JSON endpoints):
```json
{ "success": true, "message": "Website registered.", "data": { ... }, "timestamp": "2026-10-30T06:37:05Z" }
```
Errors:
```json
{ "success": false, "message": "Website URL is required.", "errors": { "url": "Website URL is required." }, "timestamp": "..." }
```
Fields with no value are omitted. Timestamps are ISO-8601 UTC.

**Authentication:** session cookie `ZTSESSION` (HttpOnly, SameSite=Strict) created by `POST /api/auth/login`.

**CSRF:** every `POST`, `PUT` and `DELETE` must send header `X-XSRF-TOKEN` equal to the `XSRF-TOKEN` cookie. Call `GET /api/auth/csrf` once to obtain the cookie.

**Paged responses:** `{ "content": [...], "page": 0, "size": 20, "totalElements": 42, "totalPages": 3 }`

**Status codes:** 200 OK · 201 Created · 400 validation error / unsafe URL · 401 not authenticated / session revoked · 403 forbidden (role, website not assigned, CSRF) · 404 not found · 409 conflict (duplicate, scan already running) · 429 scan cooldown · 500 unexpected error (no details exposed)

**Roles:** `ANY` = any authenticated user, `ADMIN` = administrators only. "Assigned" means analysts only see websites (and their scans, findings, reports, monitoring) explicitly assigned to them; admins see everything.

---

## Authentication — `/api/auth`

| Method | Path | Access | Description |
|---|---|---|---|
| GET | `/api/auth/csrf` | public | Issues the CSRF token cookie; returns `{headerName, token}` |
| POST | `/api/auth/login` | public + CSRF | Sign in |
| POST | `/api/auth/logout` | ANY | Sign out and invalidate the session |
| GET | `/api/auth/me` | ANY | Current user |
| GET | `/api/auth/registration-status` | public | `{ "enabled": true }` |
| POST | `/api/auth/register` | public + CSRF | Self-registration (only when enabled; creates a disabled ANALYST) |
| PUT | `/api/auth/password` | ANY | Change own password |

**POST /api/auth/login**
```json
{ "username": "admin", "password": "ZeroTrust@2026!" }
```
200 → `data: { "id": 1, "username": "admin", "fullName": "System Administrator", "role": "ADMIN", "lastLoginAt": "..." }`
401 → `"Invalid username or password."` (same message for unknown users), `"Account is temporarily locked..."`, or `"Account is disabled or awaiting administrator approval."`

**POST /api/auth/register**
```json
{ "username": "student1", "fullName": "Student One", "email": "s1@example.com", "password": "Strong#Pass1" }
```
201 when registration is enabled; 403 when disabled; 409 if the username exists.

**PUT /api/auth/password**
```json
{ "currentPassword": "Old#Pass1", "newPassword": "New#Pass2" }
```

---

## Dashboard — `/api/dashboard` (ANY, scoped to assigned websites)

| Method | Path | Description |
|---|---|---|
| GET | `/summary` | Counts and monitoring list |
| GET | `/recent-scans?limit=8` | Latest scans (1–50) |
| GET | `/risk-distribution` | Websites per risk level, failed checks per severity |

`GET /api/dashboard/summary` → 
```json
{ "totalWebsites": 2, "totalScans": 4, "secureWebsites": 1, "attentionWebsites": 1, "highRiskWebsites": 0,
  "unscannedWebsites": 0, "criticalFindings": 0, "highFindings": 1, "mediumFindings": 3, "lowFindings": 5,
  "infoFindings": 2, "averageScore": 76, "monitoredWebsites": 1, "monitoring": [ { ...MonitoringDto } ] }
```
Website posture counts use each website's latest completed scan (secure ≥ 75, attention 50–74, high-risk < 50). Finding counts are the failed checks in those latest scans.

---

## Websites — `/api/websites`

| Method | Path | Access | Description |
|---|---|---|---|
| GET | `/api/websites` | ANY (assigned) | List websites |
| GET | `/api/websites/{id}` | ANY (assigned) | One website |
| POST | `/api/websites` | ADMIN | Register |
| PUT | `/api/websites/{id}` | ADMIN | Update |
| DELETE | `/api/websites/{id}` | ADMIN | Delete website with its scans, findings and monitoring |

**Request body (POST/PUT)**
```json
{
  "name": "Company website",
  "url": "https://www.example.com",
  "description": "Public marketing site",
  "authorizationConfirmed": true,
  "authorizationNote": "Owned by our organization",
  "analystIds": [2]
}
```
Validation: name ≤ 100, url ≤ 500, description ≤ 1000, `authorizationConfirmed` must be `true`. The URL passes the full SSRF validation (scheme, port, hostname, DNS, IP ranges) and is normalized. `analystIds` must reference ANALYST users. Duplicate URLs → 409.

**Response `WebsiteDto`**
```json
{ "id": 1, "name": "Company website", "url": "https://www.example.com/", "hostname": "www.example.com",
  "description": "...", "authorizationConfirmed": true, "authorizationNote": "...",
  "createdBy": { "id": 1, "username": "admin" }, "analysts": [ { "id": 2, "username": "analyst1" } ],
  "lastScanId": 7, "lastScore": 57, "lastRiskLevel": "MODERATE", "lastRiskLabel": "Moderate",
  "lastScanStatus": "COMPLETED", "lastScanAt": "...", "monitoringEnabled": true, "createdAt": "...", "updatedAt": "..." }
```

Unsafe URL example → 400 `"Destination resolves to a private, internal or reserved address, which is not allowed."`

---

## Scans — `/api/scans`

| Method | Path | Access | Description |
|---|---|---|---|
| POST | `/api/scans` | ANY (assigned) | Run a passive scan synchronously and return the full result |
| GET | `/api/scans?websiteId=&status=&from=&to=&page=0&size=20` | ANY (assigned) | Scan history (newest first) |
| GET | `/api/scans/{id}` | ANY (assigned) | Full scan result |
| GET | `/api/scans/{id}/findings` | ANY (assigned) | All check results of a scan |

**POST /api/scans** — only a registered website ID is accepted (never a URL):
```json
{ "websiteId": 1 }
```
201 → `ScanResponse`. 409 if a scan of this website is already running; 429 if the same website was scanned manually within the cooldown (30 s).

**`ScanResponse`** (abridged)
```json
{
  "summary": { "id": 7, "websiteId": 1, "websiteName": "Example Domain", "websiteUrl": "https://example.com/",
               "status": "COMPLETED", "trigger": "MANUAL", "startedAt": "...", "completedAt": "...",
               "score": 57, "riskLevel": "MODERATE", "riskLabel": "Moderate", "totalFindings": 8,
               "criticalCount": 0, "highCount": 1, "mediumCount": 3, "lowCount": 3, "infoCount": 1, "initiatedBy": "admin" },
  "scannedUrl": "https://example.com/",
  "https": { "httpsAvailable": true, "httpAvailable": true, "httpRedirectsToHttps": false },
  "response": { "statusCode": 200, "responseTimeMs": 391, "finalUrl": "https://example.com/",
                "contentType": "text/html; charset=utf-8", "redirectCount": 0, "redirectChain": ["200 https://example.com/"] },
  "tls": { "protocol": "TLSv1.3", "cipherSuite": "TLS_AES_256_GCM_SHA384", "subject": "CN=example.com",
           "issuer": "CN=...", "validFrom": "...", "validTo": "...", "daysRemaining": 56, "trusted": true, "error": null },
  "risk": { "score": 57, "riskLevel": "MODERATE", "riskLabel": "Moderate", "riskDescription": "...",
            "totalFindings": 8, "critical": 0, "high": 1, "medium": 3, "low": 3, "informational": 1,
            "criticalCeilingApplied": false,
            "categories": [ { "category": "SECURITY_HEADERS", "label": "Security Headers", "failedChecks": 6,
                              "rawDeduction": 40, "maxDeduction": 35, "appliedDeduction": 35 } ],
            "mainWeaknesses": [ { ...FindingDto } ], "recommendations": [ "[HIGH] Add Strict-Transport-Security ..." ],
            "disclaimer": "This score reflects ..." },
  "findings": [ { ...FindingDto } ]
}
```
For a failed scan, `summary.status` is `FAILED`, `errorMessage` explains why, and `risk` is absent.

---

## Findings — `/api/findings` (ANY, assigned)

| Method | Path | Description |
|---|---|---|
| GET | `/api/findings` | Search findings |
| GET | `/api/findings/{id}` | One finding |

Query parameters: `websiteId`, `severity` (`CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL`), `category` (`HTTPS|TLS|SECURITY_HEADERS|COOKIES|HTTP_RESPONSE|INFORMATION_DISCLOSURE`), `from`, `to` (ISO date-time, scan date), `latestOnly` (default `true` = latest completed scan of each website), `includePassed` (default `false`), `page`, `size` (≤ 100).

**`FindingDto`**
```json
{ "id": 41, "scanId": 7, "websiteId": 1, "websiteName": "Example Domain", "category": "SECURITY_HEADERS",
  "categoryLabel": "Security Headers", "checkKey": "HEADER_HSTS", "title": "Strict-Transport-Security header missing",
  "description": "Without HSTS ...", "severity": "HIGH", "passed": false, "evidence": "Not present",
  "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains ...", "scanDate": "..." }
```

---

## Monitoring — `/api/monitoring`

| Method | Path | Access | Description |
|---|---|---|---|
| GET | `/api/monitoring` | ANY (assigned) | List configurations |
| POST | `/api/monitoring` | ADMIN | Create `{ "websiteId": 1, "intervalMinutes": 60, "enabled": true }` |
| PUT | `/api/monitoring/{id}` | ADMIN | Update `{ "intervalMinutes": 30, "enabled": false }` (both optional) |
| DELETE | `/api/monitoring/{id}` | ADMIN | Remove configuration and its history |
| GET | `/api/monitoring/{id}/history?page=0&size=20` | ANY (assigned) | Monitoring events, newest first |
| POST | `/api/monitoring/{id}/run` | ADMIN | Run a check now |

Interval must be 5–1440 minutes; one configuration per website (409 otherwise).

**`MonitoringEventDto`**
```json
{ "id": 2, "checkedAt": "...", "scanId": 9, "available": true, "score": 73, "previousScore": 57, "scoreChange": 16,
  "tlsDaysRemaining": 56, "state": "CHANGES_DETECTED",
  "changes": [ "Security score changed from 57 to 73 (+16).", "Resolved: Strict-Transport-Security header missing" ] }
```
States: `BASELINE` (first check), `STABLE`, `CHANGES_DETECTED`, `DEGRADED` (score dropped, new HIGH/CRITICAL issue, certificate untrusted or expiring within 14 days), `UNAVAILABLE`.

---

## Audit logs — `/api/audit-logs` (ADMIN)

`GET /api/audit-logs?action=LOGIN_FAILURE&username=adm&from=...&to=...&page=0&size=25`

```json
{ "id": 120, "username": "analyst1", "action": "ACCESS_DENIED",
  "description": "Attempted access to website target 1 without assignment", "targetId": 1,
  "ipAddress": "127.0.0.1", "timestamp": "..." }
```
Actions: `LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, ACCOUNT_LOCKED, USER_REGISTERED, USER_CREATED, USER_UPDATED, USER_DELETED, PASSWORD_CHANGED, WEBSITE_CREATED, WEBSITE_UPDATED, WEBSITE_DELETED, SCAN_STARTED, SCAN_COMPLETED, SCAN_FAILED, MONITORING_CREATED, MONITORING_UPDATED, MONITORING_DELETED, MONITORING_ALERT, REPORT_GENERATED, SETTINGS_UPDATED, ACCESS_DENIED, SESSION_REVOKED`.

---

## Reports — `/api/reports`

`GET /api/reports/{scanId}/pdf` (ANY, assigned) → `application/pdf` with `Content-Disposition: attachment; filename="ZeroTrust_Report_<site>_scan<id>.pdf"`. 409 while the scan is still running. Every download is audited (`REPORT_GENERATED`).

---

## Users — `/api/users` (ADMIN)

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List users |
| POST | `/api/users` | `{ "username", "fullName", "email", "password", "role": "ANALYST", "enabled": true }` |
| PUT | `/api/users/{id}` | `{ "fullName", "email", "role", "enabled", "password", "unlock": true }` (all optional) |
| DELETE | `/api/users/{id}` | Delete user |

Safeguards (400): cannot delete, disable or change the role of your own account; at least one enabled ADMIN must remain. Passwords must satisfy the password policy.

---

## Settings — `/api/settings`

| Method | Path | Access | Description |
|---|---|---|---|
| GET | `/api/settings` | ANY | Registration flag, scanner limits, monitoring limits, lockout policy |
| PUT | `/api/settings` | ADMIN | `{ "registrationEnabled": true }` |

## Health
`GET /api/health` (public) → `{ "status": "UP", "application": "Zero Trust API" }`

## Example: PowerShell session
```powershell
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod http://localhost:8080/api/auth/csrf -WebSession $s | Out-Null
$xsrf = ($s.Cookies.GetCookies("http://localhost:8080") | Where-Object Name -eq "XSRF-TOKEN").Value
$h = @{ "X-XSRF-TOKEN" = $xsrf }
Invoke-RestMethod http://localhost:8080/api/auth/login -Method Post -WebSession $s -Headers $h `
  -ContentType "application/json" -Body '{"username":"admin","password":"ZeroTrust@2026!"}'
Invoke-RestMethod http://localhost:8080/api/dashboard/summary -WebSession $s
```
