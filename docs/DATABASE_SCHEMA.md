# Database Schema – `zero_trust_db` (MongoDB)

MongoDB 6+ via Spring Data MongoDB. Collections and indexes are created automatically on first start (`spring.data.mongodb.auto-index-creation=true`). All timestamps are stored in UTC. Documents keep numeric `_id` values, generated atomically from the `counters` collection (one counter per collection), so API identifiers are short numbers.

## Collections and relationships

```
 app_users ──< scan_records >── website_targets ──< (assignedAnalysts: [app_users])
    │  (initiatedBy)      (target)       │
    │                                    ├── monitoring_configs (target, unique) ──< monitoring_events (config, scan)
    └──< website_targets.createdBy       │
    └──< audit_logs.user (logical)       └──< findings (scan → scan_records; targetId, scanStartedAt denormalized)

 app_settings   (key/value, no relations)
 counters       (_id = collection name, seq = last issued ID)
```

References between documents are stored as the referenced `_id` (`@DocumentReference`). MongoDB has no foreign keys, so the application enforces what the relational schema did with `ON DELETE`:

| Event | Behaviour |
|---|---|
| Website deleted | `WebsiteService.delete` removes its monitoring events, monitoring config, findings and scans |
| User deleted | `UserService.delete` removes the user from every website's `assignedAnalysts`; references in `createdBy`, `initiatedBy` and `audit_logs.user` simply resolve to `null` (audit entries keep their `username` snapshot) |
| Monitoring config deleted | Its monitoring events are removed |

## Collections

### `app_users`
`username` (unique index), `fullName`, `email`, `passwordHash` (BCrypt), `role` (`ADMIN`/`ANALYST`, indexed), `enabled`, `failedLoginAttempts`, `lockedUntil`, `lastLoginAt`, `createdAt`, `updatedAt`.

### `website_targets`
`name`, `url` (unique index), `hostname` (indexed), `description`, `authorizationConfirmed`, `authorizationNote`, `createdBy` (→ app_users), `assignedAnalysts` (array of → app_users), `lastScanId`, `lastScore`, `lastRiskLevel`, `lastScanStatus`, `lastScanAt`, `createdAt`, `updatedAt`.

### `scan_records`
`target` (→ website_targets), `initiatedBy` (→ app_users, null for scheduled scans), `trigger` (`MANUAL`/`SCHEDULED`), `status` (indexed), `startedAt` (indexed), `completedAt`, `scannedUrl`, HTTP metadata (`finalUrl`, `httpStatusCode`, `responseTimeMs`, `contentType`, `redirectChain`, `redirectCount`), HTTPS flags (`httpsAvailable`, `httpAvailable`, `httpRedirectsToHttps`), TLS details (`tlsProtocol`, `tlsCipherSuite`, `tlsSubject`, `tlsIssuer`, `tlsValidFrom`, `tlsValidTo`, `tlsDaysRemaining`, `tlsTrusted`, `tlsError`), risk result (`score`, `riskLevel`, `totalFindings`, `criticalCount`, `highCount`, `mediumCount`, `lowCount`, `infoCount`), `errorMessage`.
Compound index: `{target: 1, startedAt: -1}`.

### `findings`
`scan` (→ scan_records, indexed), `targetId` and `scanStartedAt` (copied from the scan so findings can be filtered and sorted without joins; `targetId` indexed), `category`, `checkKey`, `title`, `description`, `severity`, `passed`, `evidence`, `recommendation`. Passed checks are stored too (`passed = true`).

### `monitoring_configs`
`target` (→ website_targets, unique index), `enabled`, `intervalMinutes`, `lastRunAt`, `nextRunAt`, `lastState`, `consecutiveFailures`, `createdBy` (→ app_users), `createdAt`, `updatedAt`.

### `monitoring_events`
`config` (→ monitoring_configs), `scan` (→ scan_records), `checkedAt`, `available`, `score`, `previousScore`, `tlsDaysRemaining`, `state`, `changes` (one change per line).
Compound index: `{config: 1, checkedAt: -1}`.

### `audit_logs`
`user` (→ app_users, logical only), `username` (snapshot), `action` (indexed), `description`, `targetId` (logical only), `ipAddress`, `createdAt` (indexed). Entries are written immediately as separate documents, so they are kept even when the surrounding operation fails, and they survive deletion of the user or website they refer to.

### `app_settings`
`_id` = setting key (e.g. `registration.enabled`), `value`, `updatedAt`.

### `counters`
`_id` = collection name, `seq` = last numeric ID issued.

## Notes
- Transactions are not used (they require a replica set). Each operation writes whole documents; scan results are saved in order scan → findings → website summary, and scans still `RUNNING` after a crash are marked `FAILED` at start-up.
- Website and username uniqueness is enforced by unique indexes plus a case-insensitive check in the service layer.
