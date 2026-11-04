/* Renders a complete scan result (used by the Security Scanner and Scan History pages). */
"use strict";

(function () {
    const esc = ZT.esc;

    ZT.findingCard = function (f, options) {
        const opts = options || {};
        const sevClass = f.passed ? "PASS" : f.severity;
        return `
          <details class="finding b-${esc(sevClass)}" ${opts.open ? "open" : ""}>
            <summary>
              <div class="finding-head">
                ${f.passed ? '<span class="badge st-PASS">PASS</span>' : ZT.sevBadge(f.severity)}
                <h4>${esc(f.title)}</h4>
                <span class="badge plain risk-NONE">${esc(f.categoryLabel)}</span>
              </div>
              <div class="finding-meta">
                ${opts.showWebsite ? `<a href="#/scans/${esc(f.scanId)}">${esc(f.websiteName)}</a> &middot; ` : ""}
                Scan #${esc(f.scanId)} &middot; ${esc(ZT.fmtDate(f.scanDate))} &middot; check <code>${esc(f.checkKey)}</code>
              </div>
            </summary>
            <div class="finding-body">
              <p>${esc(f.description || "")}</p>
              ${f.evidence ? `<div class="evidence"><span class="muted">Evidence:</span> ${esc(f.evidence)}</div>` : ""}
              ${f.recommendation && !f.passed ? `<div class="fix"><b>Recommendation:</b> ${esc(f.recommendation)}</div>` : ""}
            </div>
          </details>`;
    };

    function checkRow(f) {
        const cls = f.passed ? "pass" : f.severity === "INFORMATIONAL" ? "info" : "fail";
        const mark = f.passed ? "&#10003;" : f.severity === "INFORMATIONAL" ? "i" : "!";
        return `
          <div class="check-row">
            <span class="check-icon ${cls}" aria-hidden="true">${mark}</span>
            <div>
              <div class="title">${esc(f.title)}</div>
              ${f.evidence ? `<div class="val">${esc(f.evidence)}</div>` : ""}
              ${!f.passed && f.recommendation ? `<div class="small mt text-2"><b>Fix:</b> ${esc(f.recommendation)}</div>` : ""}
            </div>
            <div>${f.passed ? '<span class="badge st-PASS">PASS</span>' : ZT.sevBadge(f.severity)}</div>
          </div>`;
    }

    function checks(findings, category, emptyText) {
        const list = findings.filter((f) => f.category === category);
        if (list.length === 0) return `<p class="muted">${esc(emptyText || "Not assessed for this scan.")}</p>`;
        return list.map(checkRow).join("");
    }

    function kv(rows) {
        return `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
    }

    ZT.renderScan = function (container, scan, options) {
        const opts = options || {};
        const s = scan.summary;
        const risk = scan.risk;
        const findings = scan.findings || [];
        const failed = findings.filter((f) => !f.passed);
        const passed = findings.filter((f) => f.passed);
        const tls = scan.tls || {};
        const resp = scan.response || {};
        const https = scan.https || {};

        container.innerHTML = `
          <div class="card">
            <div class="card-head">
              <div>
                <h2>${esc(s.websiteName)} ${ZT.statusBadge(s.status)}</h2>
                <div class="muted small break">${esc(scan.scannedUrl)} &middot; Scan #${esc(s.id)} &middot; ${esc(s.trigger)} &middot; ${esc(ZT.fmtDate(s.startedAt))} &middot; by ${esc(s.initiatedBy)}</div>
              </div>
              <div class="btn-group">
                ${opts.rescan ? `<button class="btn" data-act="rescan">${ZT.icon("refresh")}Scan again</button>` : ""}
                ${risk ? `<a class="btn" href="#/risk?scan=${esc(s.id)}">${ZT.icon("gauge")}Risk assessment</a>` : ""}
                <button class="btn btn-primary" data-act="pdf">${ZT.icon("download")}PDF report</button>
              </div>
            </div>
            ${s.status === "FAILED" ? `<div class="alert alert-error">${ZT.icon("alert")}<div><b>The website could not be assessed.</b><br>${esc(scan.errorMessage)}</div></div>` : ""}
            ${risk ? `
            <div class="grid grid-3">
              <div class="center">
                <div data-gauge></div>
                <div class="mt">${ZT.riskBadge(risk.riskLevel, risk.riskLabel)}</div>
                <p class="small muted mt">${esc(risk.riskDescription)}</p>
              </div>
              <div>
                <h3 class="small muted mb">FINDINGS BY SEVERITY (${esc(risk.totalFindings)})</h3>
                <div data-sev></div>
              </div>
              <div>
                <h3 class="small muted mb">KEY FACTS</h3>
                ${kv([
                    ["HTTPS", ZT.yesNo(https.httpsAvailable)],
                    ["HTTP → HTTPS", ZT.yesNo(https.httpRedirectsToHttps)],
                    ["Certificate", tls.trusted === null || tls.trusted === undefined ? '<span class="muted">-</span>'
                        : tls.trusted ? `<span class="badge st-PASS">Trusted</span> <span class="small muted">${esc(tls.daysRemaining)} days left</span>` : '<span class="badge st-FAILED">Invalid</span>'],
                    ["HTTP status", esc(resp.statusCode ?? "-")],
                    ["Response time", resp.responseTimeMs != null ? esc(resp.responseTimeMs) + " ms" : "-"],
                ])}
              </div>
            </div>` : ""}
          </div>

          ${findings.length ? `
          <div class="card">
            <div class="tabs" role="tablist">
              <button class="active" data-tab="findings" role="tab">Findings (${failed.length})</button>
              <button data-tab="headers" role="tab">Security Headers</button>
              <button data-tab="tls" role="tab">TLS Certificate</button>
              <button data-tab="cookies" role="tab">Cookies</button>
              <button data-tab="https" role="tab">HTTPS &amp; Response</button>
              <button data-tab="disclosure" role="tab">Information Disclosure</button>
            </div>
            <div data-pane="findings">
              ${failed.length ? failed.map((f) => ZT.findingCard(f)).join("") : ZT.empty("No findings", "All passive checks passed.")}
              ${passed.length ? `<h3 class="small muted mt mb">PASSED CHECKS (${passed.length})</h3>${passed.map((f) => ZT.findingCard(f)).join("")}` : ""}
            </div>
            <div data-pane="headers" hidden>
              <p class="small muted mb">Presence and basic configuration of HTTP security headers on the final response.</p>
              ${checks(findings, "SECURITY_HEADERS")}
            </div>
            <div data-pane="tls" hidden>
              ${kv([
                  ["Trusted", ZT.yesNo(tls.trusted)],
                  ["Subject", esc(tls.subject || "-")],
                  ["Issuer", esc(tls.issuer || "-")],
                  ["Valid from", esc(ZT.fmtDate(tls.validFrom))],
                  ["Valid until", esc(ZT.fmtDate(tls.validTo))],
                  ["Days remaining", esc(tls.daysRemaining ?? "-")],
                  ["Protocol / cipher", esc((tls.protocol || "-") + " / " + (tls.cipherSuite || "-"))],
                  ["Validation error", esc(tls.error || "None")],
              ])}
              <div class="mt">${checks(findings, "TLS")}</div>
            </div>
            <div data-pane="cookies" hidden>
              <div class="alert alert-info mb">${ZT.icon("lock")}<div>Only cookie names and their Secure / HttpOnly / SameSite attributes are inspected. Cookie values are discarded and never stored.</div></div>
              ${checks(findings, "COOKIES")}
            </div>
            <div data-pane="https" hidden>
              ${kv([
                  ["HTTPS available", ZT.yesNo(https.httpsAvailable)],
                  ["Plain HTTP reachable", ZT.yesNo(https.httpAvailable)],
                  ["HTTP redirects to HTTPS", ZT.yesNo(https.httpRedirectsToHttps)],
                  ["Final URL", esc(resp.finalUrl || "-")],
                  ["Status code", esc(resp.statusCode ?? "-")],
                  ["Response time", resp.responseTimeMs != null ? esc(resp.responseTimeMs) + " ms" : "-"],
                  ["Content type", esc(resp.contentType || "-")],
                  ["Redirects followed", esc(resp.redirectCount ?? "-")],
              ])}
              ${resp.redirectChain && resp.redirectChain.length ? `<h3 class="small muted mt mb">REQUEST CHAIN</h3><div class="chain">${esc(resp.redirectChain.join("\n"))}</div>` : ""}
              <div class="mt">${checks(findings, "HTTPS")}${checks(findings, "HTTP_RESPONSE", "")}</div>
            </div>
            <div data-pane="disclosure" hidden>
              <p class="small muted mb">Revealing technology headers is not a vulnerability by itself, but it helps attackers fingerprint the server.</p>
              ${checks(findings, "INFORMATION_DISCLOSURE")}
            </div>
          </div>` : ""}`;

        if (risk) {
            ZT.charts.gauge(container.querySelector("[data-gauge]"), risk.score);
            ZT.charts.bars(container.querySelector("[data-sev]"), [
                { label: "Critical", value: risk.critical, cls: "CRITICAL" },
                { label: "High", value: risk.high, cls: "HIGH" },
                { label: "Medium", value: risk.medium, cls: "MEDIUM" },
                { label: "Low", value: risk.low, cls: "LOW" },
                { label: "Info", value: risk.informational, cls: "INFORMATIONAL" },
            ]);
        }
        container.querySelectorAll("[data-tab]").forEach((tab) => tab.addEventListener("click", () => {
            container.querySelectorAll("[data-tab]").forEach((t) => t.classList.toggle("active", t === tab));
            container.querySelectorAll("[data-pane]").forEach((p) => { p.hidden = p.dataset.pane !== tab.dataset.tab; });
        }));
        container.querySelector('[data-act="pdf"]').addEventListener("click", (e) => ZT.downloadReport(s.id, e.currentTarget));
        const rescan = container.querySelector('[data-act="rescan"]');
        if (rescan && opts.rescan) rescan.addEventListener("click", () => opts.rescan(s.websiteId));
    };
})();
