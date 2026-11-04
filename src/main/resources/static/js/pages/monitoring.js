/* Continuous monitoring configuration and history. */
"use strict";

ZT.pages.monitoring = {
    title: "Continuous Monitoring",
    subtitle: "Scheduled passive assessments with change detection",
    async render(view, ctx) {
        const esc = ZT.esc;
        const admin = ZT.isAdmin();
        const [configs, websites, settings] = await Promise.all([
            ZT.api("/api/monitoring"), ZT.api("/api/websites"), ZT.api("/api/settings")]);
        if (!ctx.isCurrent()) return;
        const unmonitored = websites.filter((w) => !configs.some((c) => c.websiteId === w.id));
        const selected = ctx.args[0] || (configs[0] && String(configs[0].id));

        view.innerHTML = `
          <div class="card flush">
            <div class="card-head">
              <div><h2>Monitored websites</h2><div class="hint">The scheduler checks for due websites every minute and runs at most a few checks per cycle.</div></div>
              ${admin ? `<button class="btn btn-primary" data-add ${unmonitored.length ? "" : "disabled"}>${ZT.icon("plus")}Enable monitoring</button>` : ""}
            </div>
            <div class="mt">${configs.length === 0 ? ZT.empty("No monitoring configured", admin ? "Enable monitoring for a registered website." : "An administrator has not enabled monitoring for your websites.") : `
              <div class="table-wrap"><table>
                <thead><tr><th>Website</th><th>Status</th><th class="num">Interval</th><th class="hide-sm">Last check</th><th class="hide-sm">Next check</th><th class="num">Score</th><th></th></tr></thead>
                <tbody>${configs.map((c) => `
                  <tr>
                    <td><div class="primary">${esc(c.websiteName)}</div><div class="secondary">${esc(c.websiteUrl)}</div></td>
                    <td>${ZT.statusBadge(c.enabled ? c.lastState : "DISABLED")}${c.consecutiveFailures ? `<div class="small muted">${esc(c.consecutiveFailures)} failed in a row</div>` : ""}</td>
                    <td class="num">${esc(c.intervalMinutes)} min</td>
                    <td class="hide-sm nowrap">${esc(ZT.relTime(c.lastRunAt))}</td>
                    <td class="hide-sm nowrap">${c.enabled ? esc(c.nextRunAt ? ZT.relTime(c.nextRunAt) : "-") : '<span class="muted">paused</span>'}</td>
                    <td class="num">${ZT.scorePill(c.lastScore)}</td>
                    <td class="actions">
                      <a class="btn btn-sm" href="#/monitoring/${esc(c.id)}">${ZT.icon("history")}History</a>
                      ${admin ? `
                      <label class="switch" title="Enable or pause"><input type="checkbox" data-toggle="${esc(c.id)}" ${c.enabled ? "checked" : ""}><span class="track"></span></label>
                      <button class="btn btn-sm" data-run="${esc(c.id)}" title="Run check now">${ZT.icon("play")}</button>
                      <button class="btn btn-sm" data-edit="${esc(c.id)}" title="Change interval">${ZT.icon("edit")}</button>
                      <button class="btn btn-sm btn-danger" data-del="${esc(c.id)}" title="Remove">${ZT.icon("trash")}</button>` : ""}
                    </td>
                  </tr>`).join("")}</tbody></table></div>`}
            </div>
          </div>
          <div data-history class="mt"></div>`;

        const byId = Object.fromEntries(configs.map((c) => [String(c.id), c]));
        const intervalField = (value) => `
          <div class="field"><label for="m-int">Check interval (minutes)</label>
            <input id="m-int" name="intervalMinutes" type="number" min="${settings.monitoringMinIntervalMinutes}" max="${settings.monitoringMaxIntervalMinutes}" value="${esc(value)}" required>
            <div class="help">Between ${settings.monitoringMinIntervalMinutes} and ${settings.monitoringMaxIntervalMinutes} minutes. Short intervals generate more requests to the website.</div></div>`;

        const add = view.querySelector("[data-add]");
        if (add) add.addEventListener("click", async () => {
            const ok = await ZT.modal({
                title: "Enable continuous monitoring", submitLabel: "Enable",
                body: `<div class="field mb"><label for="m-site">Website</label><select id="m-site" name="websiteId">
                  ${unmonitored.map((w) => `<option value="${esc(w.id)}">${esc(w.name)} - ${esc(w.url)}</option>`).join("")}</select></div>
                  ${intervalField(60)}`,
                onSubmit: (form) => ZT.api("/api/monitoring", { method: "POST",
                    body: { websiteId: Number(form.websiteId.value), intervalMinutes: Number(form.intervalMinutes.value), enabled: true } }),
            });
            if (ok) { ZT.toast("Monitoring enabled. The first check runs within about a minute.", "success"); ZT.refresh(); }
        });
        view.querySelectorAll("[data-toggle]").forEach((t) => t.addEventListener("change", async () => {
            try {
                await ZT.api("/api/monitoring/" + t.dataset.toggle, { method: "PUT", body: { enabled: t.checked } });
                ZT.toast(t.checked ? "Monitoring resumed." : "Monitoring paused.", "success");
                ZT.refresh();
            } catch (e) { t.checked = !t.checked; ZT.toast(e.message, "error"); }
        }));
        view.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", async () => {
            const c = byId[b.dataset.edit];
            const ok = await ZT.modal({ title: "Monitoring interval - " + c.websiteName, size: "small", body: intervalField(c.intervalMinutes),
                onSubmit: (form) => ZT.api("/api/monitoring/" + c.id, { method: "PUT", body: { intervalMinutes: Number(form.intervalMinutes.value) } }) });
            if (ok) { ZT.toast("Interval updated.", "success"); ZT.refresh(); }
        }));
        view.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
            const c = byId[b.dataset.del];
            if (!(await ZT.confirm("Remove monitoring", `Stop monitoring "${c.websiteName}" and delete its monitoring history? Scan records are kept.`, "Remove"))) return;
            try {
                await ZT.api("/api/monitoring/" + c.id, { method: "DELETE" });
                ZT.toast("Monitoring removed.", "success");
                location.hash = "#/monitoring";
                ZT.refresh();
            } catch (e) { ZT.toast(e.message, "error"); }
        }));
        view.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", async () => {
            b.disabled = true;
            b.innerHTML = '<span class="spinner"></span>';
            try {
                const ev = await ZT.api("/api/monitoring/" + b.dataset.run + "/run", { method: "POST" });
                ZT.toast("Check complete: " + ev.state.replace(/_/g, " ").toLowerCase() + ".", ev.available ? "success" : "warn");
                location.hash = "#/monitoring/" + b.dataset.run;
                ZT.refresh();
            } catch (e) {
                ZT.toast(e.message, "error");
                b.disabled = false;
                b.innerHTML = ZT.icon("play");
            }
        }));

        if (selected && byId[selected]) loadHistory(byId[selected]);

        async function loadHistory(config) {
            const host = view.querySelector("[data-history]");
            host.innerHTML = `<div class="card">${ZT.loading("Loading monitoring history...")}</div>`;
            try {
                const page = await ZT.api(`/api/monitoring/${config.id}/history?size=50`);
                if (!ctx.isCurrent()) return;
                const events = page.content;
                host.innerHTML = `
                  <div class="grid grid-2">
                    <div class="card"><div class="card-head"><h3>Score trend - ${esc(config.websiteName)}</h3><span class="hint">last ${events.length} checks</span></div><div data-chart></div></div>
                    <div class="card"><div class="card-head"><h3>Detected changes</h3></div>
                      ${events.length === 0 ? ZT.empty("No checks yet", "History appears after the first scheduled check.") : `
                      <div class="timeline">${events.map((e) => `
                        <div class="tl-item s-${esc(e.state)}">
                          <div class="row"><b>${esc(ZT.fmtDate(e.checkedAt))}</b> ${ZT.statusBadge(e.state)}
                            ${e.score !== null ? ZT.scorePill(e.score) : ""}
                            ${e.scoreChange ? `<span class="small ${e.scoreChange > 0 ? "score-ok" : "score-bad"}">${e.scoreChange > 0 ? "+" : ""}${esc(e.scoreChange)}</span>` : ""}
                            ${e.scanId ? `<a class="small" href="#/scans/${esc(e.scanId)}">scan #${esc(e.scanId)}</a>` : ""}</div>
                          ${e.changes.length ? `<ul>${e.changes.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>` : '<div class="small muted">No changes since the previous check.</div>'}
                        </div>`).join("")}</div>`}
                    </div>
                  </div>`;
                ZT.charts.scoreLine(host.querySelector("[data-chart]"),
                    events.slice().reverse().map((e) => ({ t: e.checkedAt, y: e.score, label: e.state.replace(/_/g, " ") })));
            } catch (e) {
                host.innerHTML = `<div class="card">${ZT.errorBox(e.message)}</div>`;
            }
        }
    },
};
