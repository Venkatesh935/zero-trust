/* PDF report generation. */
"use strict";

ZT.pages.reports = {
    title: "Reports",
    subtitle: "Download PDF security assessment reports generated from stored scan results",
    async render(view, ctx) {
        const esc = ZT.esc;
        const websites = await ZT.api("/api/websites");
        if (!ctx.isCurrent()) return;
        const latest = websites.filter((w) => w.lastScanId);

        view.innerHTML = `
          <div class="grid grid-main">
            <div class="card flush">
              <div class="card-head"><h2>Latest assessment per website</h2></div>
              <div class="mt">${latest.length === 0 ? ZT.empty("No completed scans", "Run a scan to generate a report.", '<a class="btn btn-primary" href="#/scanner">Open scanner</a>') : `
                <div class="table-wrap"><table>
                  <thead><tr><th>Website</th><th>Assessed</th><th class="num">Score</th><th>Risk</th><th></th></tr></thead>
                  <tbody>${latest.map((w) => `
                    <tr>
                      <td><div class="primary">${esc(w.name)}</div><div class="secondary">${esc(w.url)}</div></td>
                      <td class="nowrap">${esc(ZT.fmtDate(w.lastScanAt))}</td>
                      <td class="num">${ZT.scorePill(w.lastScore)}</td>
                      <td>${ZT.riskBadge(w.lastRiskLevel, w.lastRiskLabel)}</td>
                      <td class="actions"><a class="btn btn-sm" href="#/scans/${esc(w.lastScanId)}">${ZT.icon("eye")}</a>
                        <button class="btn btn-sm btn-primary" data-pdf="${esc(w.lastScanId)}">${ZT.icon("download")}PDF</button></td>
                    </tr>`).join("")}</tbody></table></div>`}</div>
            </div>
            <div class="card">
              <div class="card-head"><h3>Report contents</h3></div>
              <ol class="small text-2">
                <li>Project name, website name and URL</li><li>Assessment date</li><li>Overall security score and risk classification</li>
                <li>HTTPS status</li><li>TLS certificate information</li><li>Security header assessment</li>
                <li>Cookie security assessment</li><li>Security findings with evidence</li><li>Recommended improvements</li>
                <li>Final assessment summary</li>
              </ol>
              <p class="small muted mt">Reports for older scans can be downloaded from <a href="#/history">Scan History</a>. Every report download is recorded in the audit log.</p>
            </div>
          </div>`;
        view.querySelectorAll("[data-pdf]").forEach((b) => b.addEventListener("click", () => ZT.downloadReport(b.dataset.pdf, b)));
    },
};
