/* Scan history list and individual scan detail (#/scans/{id}). */
"use strict";

ZT.pages.history = {
    title: "Scan History",
    subtitle: "Every manual and scheduled assessment, stored in the database",
    async render(view, ctx) {
        const esc = ZT.esc;
        const websites = await ZT.api("/api/websites");
        if (!ctx.isCurrent()) return;
        const state = { websiteId: ctx.params.get("website") || "", status: "", page: 0 };

        view.innerHTML = `
          <div class="card">
            <div class="filters">
              <div class="field"><label for="h-site">Website</label><select id="h-site" data-k="websiteId"><option value="">All websites</option>
                ${websites.map((w) => `<option value="${esc(w.id)}" ${String(w.id) === state.websiteId ? "selected" : ""}>${esc(w.name)}</option>`).join("")}</select></div>
              <div class="field"><label for="h-status">Status</label><select id="h-status" data-k="status"><option value="">Any status</option>
                <option>COMPLETED</option><option>FAILED</option><option>RUNNING</option></select></div>
            </div>
          </div>
          <div class="card flush" data-list></div>`;
        const list = view.querySelector("[data-list]");
        view.querySelectorAll("[data-k]").forEach((el) => el.addEventListener("change", () => {
            state[el.dataset.k] = el.value;
            state.page = 0;
            load();
        }));

        async function load() {
            list.innerHTML = ZT.loading();
            try {
                const page = await ZT.api("/api/scans" + ZT.qs({ websiteId: state.websiteId, status: state.status, page: state.page, size: 15 }));
                if (!ctx.isCurrent()) return;
                if (page.totalElements === 0) {
                    list.innerHTML = ZT.empty("No scans found", "Scans appear here after you run an assessment.", '<a class="btn btn-primary" href="#/scanner">Open scanner</a>');
                    return;
                }
                list.innerHTML = `<div class="table-wrap"><table>
                  <thead><tr><th>Scan ID</th><th>Website</th><th>Date &amp; time</th><th class="num">Score</th><th>Risk</th><th class="num">Findings</th><th>Status</th><th class="hide-sm">Trigger</th><th></th></tr></thead>
                  <tbody>${page.content.map((s) => `
                    <tr class="clickable" data-href="#/scans/${esc(s.id)}">
                      <td class="mono">#${esc(s.id)}</td>
                      <td><div class="primary">${esc(s.websiteName)}</div><div class="secondary">${esc(s.websiteUrl)}</div></td>
                      <td class="nowrap">${esc(ZT.fmtDate(s.startedAt))}</td>
                      <td class="num">${ZT.scorePill(s.score)}</td>
                      <td>${s.riskLevel ? ZT.riskBadge(s.riskLevel, s.riskLabel) : '<span class="muted">-</span>'}</td>
                      <td class="num">${esc(s.totalFindings)}${s.criticalCount + s.highCount ? `<div class="small score-bad">${esc(s.criticalCount)}C / ${esc(s.highCount)}H</div>` : ""}</td>
                      <td>${ZT.statusBadge(s.status)}</td>
                      <td class="hide-sm small text-2">${esc(s.trigger)}<div class="muted">${esc(s.initiatedBy)}</div></td>
                      <td class="actions">${s.status !== "RUNNING" ? `<button class="btn btn-sm" data-pdf="${esc(s.id)}" title="Download PDF">${ZT.icon("download")}</button>` : ""}</td>
                    </tr>`).join("")}</tbody></table></div>${ZT.pager(page)}`;
                list.querySelectorAll("tr[data-href]").forEach((tr) => tr.addEventListener("click", (e) => {
                    if (!e.target.closest("button")) location.hash = tr.dataset.href;
                }));
                list.querySelectorAll("[data-pdf]").forEach((b) => b.addEventListener("click", () => ZT.downloadReport(b.dataset.pdf, b)));
                ZT.bindPager(list, (p) => { state.page = p; load(); });
            } catch (e) {
                list.innerHTML = ZT.errorBox(e.message);
            }
        }
        load();
    },
};

ZT.pages.scans = {
    title: "Scan Result",
    subtitle: "Complete results of a stored assessment",
    async render(view, ctx) {
        const id = ctx.args[0];
        if (!id) { location.hash = "#/history"; return; }
        const scan = await ZT.api("/api/scans/" + encodeURIComponent(id));
        if (!ctx.isCurrent()) return;
        view.innerHTML = `<p class="mb"><a href="#/history">&larr; Back to scan history</a></p><div data-scan></div>`;
        ZT.renderScan(view.querySelector("[data-scan]"), scan, {
            rescan: (websiteId) => { location.hash = "#/scanner?website=" + websiteId + "&run=1"; },
        });
    },
};
