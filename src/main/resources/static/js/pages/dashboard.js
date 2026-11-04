/* Dashboard: live statistics from /api/dashboard/*. */
"use strict";

ZT.pages.dashboard = {
    title: "Dashboard",
    subtitle: "Security posture of your authorized websites",
    async render(view, ctx) {
        const esc = ZT.esc;
        const [summary, recent, dist] = await Promise.all([
            ZT.api("/api/dashboard/summary"),
            ZT.api("/api/dashboard/recent-scans?limit=8"),
            ZT.api("/api/dashboard/risk-distribution"),
        ]);
        if (!ctx.isCurrent()) return;
        const admin = ZT.isAdmin();

        const stat = (cls, label, value, sub) => `
          <div class="stat ${cls}"><div class="label">${esc(label)}</div>
          <div class="value">${esc(value)}</div><div class="sub">${esc(sub || "")}</div></div>`;

        view.innerHTML = `
          ${summary.totalWebsites === 0 ? `
            <div class="alert alert-info mb">${ZT.icon("info")}<div><b>Welcome to Zero Trust.</b>
            ${admin ? "Start by registering a website you own or are authorized to assess, then run a security scan."
                    : "No websites have been assigned to you yet. Ask an administrator to grant you access to a website."}</div></div>` : ""}
          <div class="stats">
            ${stat("c-accent", "Registered websites", summary.totalWebsites, summary.unscannedWebsites + " not yet scanned")}
            ${stat("c-blue", "Total scans", summary.totalScans, "manual + scheduled")}
            ${stat("c-ok", "Secure websites", summary.secureWebsites, "score 75 or higher")}
            ${stat("c-medium", "Need attention", summary.attentionWebsites, "score 50 - 74")}
            ${stat("c-high", "High-risk websites", summary.highRiskWebsites, "score below 50")}
            ${stat("c-critical", "Critical findings", summary.criticalFindings, "in latest scans")}
            ${stat("c-high", "High findings", summary.highFindings, "in latest scans")}
            ${stat("c-medium", "Medium findings", summary.mediumFindings, "in latest scans")}
            ${stat("c-low", "Low findings", summary.lowFindings, "in latest scans")}
            ${stat("c-accent", "Monitored websites", summary.monitoredWebsites, "continuous monitoring on")}
          </div>

          <div class="grid grid-main">
            <div class="stack">
              <div class="grid grid-2">
                <div class="card">
                  <div class="card-head"><h3>Security score summary</h3><span class="hint">average of latest scans</span></div>
                  <div data-avg></div>
                  <p class="center small muted mt">${summary.averageScore === null ? "No completed scans yet." : "Across " + (summary.totalWebsites - summary.unscannedWebsites) + " scanned website(s)"}</p>
                </div>
                <div class="card">
                  <div class="card-head"><h3>Risk distribution</h3><span class="hint">websites by risk level</span></div>
                  <div data-risk></div>
                </div>
              </div>
              <div class="card flush">
                <div class="card-head"><h3>Recent security scans</h3><a href="#/history" class="small">View all</a></div>
                <div data-recent class="mt"></div>
              </div>
            </div>
            <div class="stack">
              <div class="card">
                <div class="card-head"><h3>Quick actions</h3></div>
                <div class="quick-actions">
                  ${admin ? `<a class="btn" href="#/targets?new=1">${ZT.icon("plus")}Register website</a>` : ""}
                  <a class="btn" href="#/scanner">${ZT.icon("play")}Run a scan</a>
                  <a class="btn" href="#/findings">${ZT.icon("bug")}View findings</a>
                  <a class="btn" href="#/reports">${ZT.icon("download")}Get a report</a>
                  <a class="btn" href="#/monitoring">${ZT.icon("activity")}Monitoring</a>
                  ${admin ? `<a class="btn" href="#/audit">${ZT.icon("list")}Audit logs</a>` : ""}
                </div>
              </div>
              <div class="card">
                <div class="card-head"><h3>Findings by severity</h3><span class="hint">latest scans</span></div>
                <div data-sev></div>
              </div>
              <div class="card">
                <div class="card-head"><h3>Monitoring status</h3><a href="#/monitoring" class="small">Manage</a></div>
                <div class="monitor-list" data-monitor></div>
              </div>
            </div>
          </div>`;

        ZT.charts.gauge(view.querySelector("[data-avg]"), summary.averageScore, { caption: "average score" });

        const levelCls = { "Excellent": "EXCELLENT", "Good": "GOOD", "Moderate": "MODERATE", "High Risk": "HIGH_RISK", "Critical Risk": "CRITICAL_RISK", "Not scanned": "NONE" };
        ZT.charts.bars(view.querySelector("[data-risk]"), Object.entries(dist.websitesByRiskLevel)
            .map(([label, value]) => ({ label, value, cls: levelCls[label], hint: "website(s)" })));

        const sevLabels = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFORMATIONAL: "Info" };
        ZT.charts.bars(view.querySelector("[data-sev]"), Object.entries(dist.findingsBySeverity)
            .map(([key, value]) => ({ label: sevLabels[key] || key, value, cls: key, hint: "finding(s)" })));

        const recentEl = view.querySelector("[data-recent]");
        recentEl.innerHTML = recent.length === 0
            ? ZT.empty("No scans yet", "Run your first passive security assessment.", '<a class="btn btn-primary" href="#/scanner">Open scanner</a>')
            : `<div class="table-wrap"><table>
                 <thead><tr><th>Website</th><th>Date</th><th class="num">Score</th><th>Risk</th><th class="num hide-sm">Findings</th><th>Status</th></tr></thead>
                 <tbody>${recent.map((s) => `
                   <tr class="clickable" data-href="#/scans/${esc(s.id)}">
                     <td><div class="primary">${esc(s.websiteName)}</div><div class="secondary">${esc(s.trigger)} &middot; #${esc(s.id)}</div></td>
                     <td class="nowrap">${esc(ZT.relTime(s.startedAt))}</td>
                     <td class="num">${ZT.scorePill(s.score)}</td>
                     <td>${s.riskLevel ? ZT.riskBadge(s.riskLevel, s.riskLabel) : '<span class="muted">-</span>'}</td>
                     <td class="num hide-sm">${esc(s.totalFindings)}</td>
                     <td>${ZT.statusBadge(s.status)}</td>
                   </tr>`).join("")}</tbody></table></div>`;
        recentEl.querySelectorAll("tr[data-href]").forEach((tr) => tr.addEventListener("click", () => { location.hash = tr.dataset.href; }));

        const mon = view.querySelector("[data-monitor]");
        mon.innerHTML = summary.monitoring.length === 0
            ? `<p class="muted small">No websites are being monitored.${admin ? ' <a href="#/monitoring">Enable monitoring</a>' : ""}</p>`
            : summary.monitoring.map((m) => `
                <div class="m-row">
                  <div class="m-name"><div class="primary">${esc(m.websiteName)}</div>
                    <div class="small muted">${m.enabled ? "every " + esc(m.intervalMinutes) + " min &middot; last " + esc(ZT.relTime(m.lastRunAt)) : "paused"}</div></div>
                  ${ZT.scorePill(m.lastScore)}
                  ${ZT.statusBadge(m.enabled ? m.lastState : "DISABLED")}
                </div>`).join("");
    },
};
