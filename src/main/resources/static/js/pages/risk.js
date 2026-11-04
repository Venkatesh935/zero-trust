/* Risk assessment: transparent score breakdown for a scan. */
"use strict";

ZT.pages.risk = {
    title: "Risk Assessment",
    subtitle: "How the 0-100 security score is calculated from actual findings",
    async render(view, ctx) {
        const esc = ZT.esc;
        const websites = (await ZT.api("/api/websites")).filter((w) => w.lastScanId);
        if (!ctx.isCurrent()) return;
        let scanId = ctx.params.get("scan") || (websites[0] && websites[0].lastScanId);

        view.innerHTML = `
          <div class="card">
            <div class="row">
              <div class="field spacer"><label for="r-site">Website (latest completed scan)</label>
                <select id="r-site"><option value="">Select a website...</option>
                  ${websites.map((w) => `<option value="${esc(w.lastScanId)}" ${String(w.lastScanId) === String(scanId) ? "selected" : ""}>${esc(w.name)} - score ${esc(w.lastScore)}</option>`).join("")}
                </select></div>
            </div>
          </div>
          <div data-body class="mt"></div>
          <div class="card mt">
            <div class="card-head"><h3>Scoring methodology</h3></div>
            <div class="grid grid-2">
              <div>
                <p class="small text-2 mb">The score starts at <b>100</b>. Each failed check deducts points according to its severity.
                Deductions are capped per category so that many small issues in one area cannot outweigh everything else.
                If any <b>CRITICAL</b> finding exists the score is limited to <b>49</b>.</p>
                <table><thead><tr><th>Severity</th><th class="num">Deduction</th></tr></thead><tbody>
                  <tr><td>${ZT.sevBadge("CRITICAL")}</td><td class="num">-25</td></tr>
                  <tr><td>${ZT.sevBadge("HIGH")}</td><td class="num">-15</td></tr>
                  <tr><td>${ZT.sevBadge("MEDIUM")}</td><td class="num">-8</td></tr>
                  <tr><td>${ZT.sevBadge("LOW")}</td><td class="num">-3</td></tr>
                  <tr><td>${ZT.sevBadge("INFORMATIONAL")}</td><td class="num">0</td></tr>
                </tbody></table>
              </div>
              <div>
                <table><thead><tr><th>Score</th><th>Classification</th></tr></thead><tbody>
                  <tr><td>90 - 100</td><td>${ZT.riskBadge("EXCELLENT", "Excellent")}</td></tr>
                  <tr><td>75 - 89</td><td>${ZT.riskBadge("GOOD", "Good")}</td></tr>
                  <tr><td>50 - 74</td><td>${ZT.riskBadge("MODERATE", "Moderate")}</td></tr>
                  <tr><td>25 - 49</td><td>${ZT.riskBadge("HIGH_RISK", "High Risk")}</td></tr>
                  <tr><td>0 - 24</td><td>${ZT.riskBadge("CRITICAL_RISK", "Critical Risk")}</td></tr>
                </tbody></table>
                <p class="small muted mt">Category caps: HTTPS 35, TLS 30, Security headers 35, Cookies 15, HTTP response 10, Information disclosure 6.</p>
              </div>
            </div>
          </div>`;

        const body = view.querySelector("[data-body]");
        view.querySelector("#r-site").addEventListener("change", (e) => {
            scanId = e.target.value;
            if (scanId) history.replaceState(null, "", "#/risk?scan=" + scanId);
            load();
        });

        async function load() {
            if (!scanId) {
                body.innerHTML = `<div class="card">${ZT.empty("No completed scans", "Run a scan to see its risk assessment.", '<a class="btn btn-primary" href="#/scanner">Open scanner</a>')}</div>`;
                return;
            }
            body.innerHTML = `<div class="card">${ZT.loading()}</div>`;
            const scan = await ZT.api("/api/scans/" + encodeURIComponent(scanId));
            if (!ctx.isCurrent()) return;
            const r = scan.risk;
            if (!r) {
                body.innerHTML = `<div class="card"><div class="alert alert-warn">${ZT.icon("alert")}<div>Scan #${esc(scanId)} did not complete, so no risk score was calculated. ${esc(scan.errorMessage || "")}</div></div></div>`;
                return;
            }
            body.innerHTML = `
              <div class="grid grid-3">
                <div class="card center">
                  <div class="card-head"><h3>Overall security score</h3></div>
                  <div data-gauge></div>
                  <div class="mt">${ZT.riskBadge(r.riskLevel, r.riskLabel)}</div>
                  <p class="small text-2 mt">${esc(r.riskDescription)}</p>
                  ${r.criticalCeilingApplied ? `<p class="small mt"><span class="badge sev-CRITICAL">Capped at 49</span> a critical finding exists</p>` : ""}
                  <p class="small muted mt">${esc(scan.summary.websiteName)} &middot; scan #${esc(scan.summary.id)} &middot; ${esc(ZT.fmtDate(scan.summary.startedAt))}</p>
                </div>
                <div class="card">
                  <div class="card-head"><h3>Severity distribution</h3><span class="hint">${esc(r.totalFindings)} findings</span></div>
                  <div data-sev></div>
                </div>
                <div class="card">
                  <div class="card-head"><h3>Points deducted by category</h3></div>
                  <div data-cat></div>
                  <p class="small muted mt">Bar = applied deduction (after category cap).</p>
                </div>
              </div>
              <div class="card flush mt">
                <div class="card-head"><h3>Score breakdown</h3></div>
                <div class="table-wrap mt"><table>
                  <thead><tr><th>Category</th><th class="num">Failed checks</th><th class="num">Raw deduction</th><th class="num">Cap</th><th class="num">Applied</th></tr></thead>
                  <tbody>${r.categories.map((c) => `<tr><td>${esc(c.label)}</td><td class="num">${esc(c.failedChecks)}</td>
                    <td class="num">${esc(c.rawDeduction)}</td><td class="num">${esc(c.maxDeduction)}</td><td class="num"><b>${c.appliedDeduction ? "-" + esc(c.appliedDeduction) : "0"}</b></td></tr>`).join("")}
                    <tr><td><b>Final score</b></td><td></td><td></td><td></td><td class="num"><b>${esc(r.score)}</b></td></tr>
                  </tbody></table></div>
              </div>
              <div class="grid grid-2 mt">
                <div class="card">
                  <div class="card-head"><h3>Main security weaknesses</h3></div>
                  ${r.mainWeaknesses.length ? r.mainWeaknesses.map((f) => ZT.findingCard(f)).join("") : '<p class="muted">No significant weaknesses identified.</p>'}
                </div>
                <div class="card">
                  <div class="card-head"><h3>Recommended improvements</h3></div>
                  ${r.recommendations.length ? `<ol class="small text-2">${r.recommendations.map((x) => `<li class="mb">${esc(x)}</li>`).join("")}</ol>` : '<p class="muted">No changes required.</p>'}
                </div>
              </div>
              <div class="alert alert-info mt">${ZT.icon("info")}<div>${esc(r.disclaimer)}</div></div>`;
            ZT.charts.gauge(body.querySelector("[data-gauge]"), r.score);
            ZT.charts.bars(body.querySelector("[data-sev]"), [
                { label: "Critical", value: r.critical, cls: "CRITICAL" }, { label: "High", value: r.high, cls: "HIGH" },
                { label: "Medium", value: r.medium, cls: "MEDIUM" }, { label: "Low", value: r.low, cls: "LOW" },
                { label: "Info", value: r.informational, cls: "INFORMATIONAL" }]);
            ZT.charts.bars(body.querySelector("[data-cat]"), r.categories.map((c) => ({
                label: c.label, value: c.appliedDeduction, cls: "ACCENT", hint: "points (cap " + c.maxDeduction + ")" })), { max: 35 });
        }
        load().catch((e) => { body.innerHTML = `<div class="card">${ZT.errorBox(e.message)}</div>`; });
    },
};
