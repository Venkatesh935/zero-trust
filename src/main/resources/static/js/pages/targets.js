/* Website target registration and management. */
"use strict";

ZT.pages.targets = {
    title: "Website Targets",
    subtitle: "Websites you own or are explicitly authorized to assess",
    async render(view, ctx) {
        const esc = ZT.esc;
        const admin = ZT.isAdmin();
        const websites = await ZT.api("/api/websites");
        if (!ctx.isCurrent()) return;

        view.innerHTML = `
          <div class="card flush">
            <div class="card-head">
              <div><h2>Registered websites (${websites.length})</h2>
                <div class="hint">${admin ? "Only register websites you own or have written permission to assess." : "Websites an administrator has assigned to you."}</div></div>
              ${admin ? `<button class="btn btn-primary" data-act="add">${ZT.icon("plus")}Register website</button>` : ""}
            </div>
            <div class="mt" data-table></div>
          </div>`;

        const table = view.querySelector("[data-table]");
        if (websites.length === 0) {
            table.innerHTML = ZT.empty("No websites registered", admin ? "Register your first authorized website target." : "Ask an administrator to assign a website to you.",
                admin ? `<button class="btn btn-primary" data-act="add2">${ZT.icon("plus")}Register website</button>` : "");
        } else {
            table.innerHTML = `<div class="table-wrap"><table>
              <thead><tr><th>Website</th><th class="hide-sm">Description</th><th class="num">Score</th><th>Risk</th><th class="hide-sm">Last scan</th><th class="hide-sm">Access</th><th></th></tr></thead>
              <tbody>${websites.map((w) => `
                <tr>
                  <td><div class="primary">${esc(w.name)}</div><div class="secondary">${esc(w.url)}</div></td>
                  <td class="hide-sm"><div class="small text-2">${esc(w.description || "-")}</div></td>
                  <td class="num">${ZT.scorePill(w.lastScore)}</td>
                  <td>${ZT.riskBadge(w.lastRiskLevel, w.lastRiskLabel)}</td>
                  <td class="hide-sm nowrap">${w.lastScanAt ? esc(ZT.relTime(w.lastScanAt)) + " " + (w.lastScanStatus === "FAILED" ? ZT.statusBadge("FAILED") : "") : '<span class="muted">never</span>'}
                    ${w.monitoringEnabled ? '<div class="small muted">monitored</div>' : ""}</td>
                  <td class="hide-sm small text-2">${w.analysts.length ? w.analysts.map((a) => esc(a.username)).join(", ") : '<span class="muted">admins only</span>'}</td>
                  <td class="actions">
                    <button class="btn btn-sm btn-primary" data-scan="${esc(w.id)}" title="Run a passive scan">${ZT.icon("play")}Scan</button>
                    ${w.lastScanId ? `<a class="btn btn-sm" href="#/scans/${esc(w.lastScanId)}" title="Latest result">${ZT.icon("eye")}</a>` : ""}
                    ${admin ? `<button class="btn btn-sm" data-edit="${esc(w.id)}" title="Edit">${ZT.icon("edit")}</button>
                    <button class="btn btn-sm btn-danger" data-del="${esc(w.id)}" title="Delete">${ZT.icon("trash")}</button>` : ""}
                  </td>
                </tr>`).join("")}</tbody></table></div>`;
        }

        const byId = Object.fromEntries(websites.map((w) => [String(w.id), w]));
        view.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", () => openForm(null)));
        view.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openForm(byId[b.dataset.edit])));
        view.querySelectorAll("[data-scan]").forEach((b) => b.addEventListener("click", () => { location.hash = "#/scanner?website=" + b.dataset.scan + "&run=1"; }));
        view.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
            const w = byId[b.dataset.del];
            if (!(await ZT.confirm("Delete website", `Delete "${w.name}"? All scan history, findings and monitoring data for this website will be permanently removed.`, "Delete"))) return;
            try {
                await ZT.api("/api/websites/" + w.id, { method: "DELETE" });
                ZT.toast("Website deleted.", "success");
                ZT.refresh();
            } catch (e) { ZT.toast(e.message, "error"); }
        }));

        if (admin && ctx.params.get("new")) {
            history.replaceState(null, "", "#/targets");
            openForm(null);
        }

        async function openForm(website) {
            let analysts = [];
            try {
                analysts = (await ZT.api("/api/users")).filter((u) => u.role === "ANALYST");
            } catch (e) { /* user list optional */ }
            const assigned = new Set((website ? website.analysts : []).map((a) => a.id));
            const result = await ZT.modal({
                title: website ? "Edit website" : "Register website",
                submitLabel: website ? "Save changes" : "Register",
                body: `
                  <div class="form-grid">
                    <div class="field"><label for="w-name">Website name *</label>
                      <input id="w-name" name="name" type="text" maxlength="100" required value="${esc(website ? website.name : "")}" placeholder="Company website"></div>
                    <div class="field"><label for="w-url">Website URL *</label>
                      <input id="w-url" name="url" type="url" maxlength="500" required value="${esc(website ? website.url : "")}" placeholder="https://www.example.com">
                      <div class="help">http(s) only, public hosts, ports 80/443/8080/8443.</div></div>
                    <div class="field full"><label for="w-desc">Description</label>
                      <textarea id="w-desc" name="description" maxlength="1000" placeholder="Purpose, owner, environment...">${esc(website ? website.description || "" : "")}</textarea></div>
                    <div class="field full"><label>Analyst access</label>
                      ${analysts.length ? `<div class="checklist">${analysts.map((a) => `
                        <label class="check"><input type="checkbox" name="analyst" value="${esc(a.id)}" ${assigned.has(a.id) ? "checked" : ""}>
                        <span>${esc(a.username)}${a.fullName ? " - " + esc(a.fullName) : ""}${a.enabled ? "" : " (disabled)"}</span></label>`).join("")}</div>`
                        : '<p class="small muted">No analyst accounts exist. Administrators can access every website.</p>'}
                      <div class="help">Zero Trust: analysts can only see and scan websites explicitly assigned to them.</div></div>
                    <div class="field full"><label for="w-note">Authorization reference</label>
                      <input id="w-note" name="authorizationNote" type="text" maxlength="500" value="${esc(website ? website.authorizationNote || "" : "")}" placeholder="e.g. Owned by our organization / written approval from site owner, 2026-10-30"></div>
                    <div class="field full">
                      <label class="check"><input type="checkbox" name="authorizationConfirmed" ${website ? "checked" : ""}>
                      <span>I confirm that I own this website or have explicit permission from its owner to perform passive security assessments on it.</span></label>
                    </div>
                  </div>`,
                onSubmit: async (form) => {
                    const data = ZT.formData(form);
                    if (!data.name || !data.url) throw new Error("Website name and URL are required.");
                    if (!form.authorizationConfirmed.checked) throw new Error("You must confirm that you are authorized to assess this website.");
                    const body = {
                        name: data.name,
                        url: data.url,
                        description: data.description,
                        authorizationNote: data.authorizationNote,
                        authorizationConfirmed: true,
                        analystIds: [...form.querySelectorAll('input[name="analyst"]:checked')].map((c) => Number(c.value)),
                    };
                    return website
                        ? ZT.api("/api/websites/" + website.id, { method: "PUT", body })
                        : ZT.api("/api/websites", { method: "POST", body });
                },
            });
            if (result) {
                ZT.toast(website ? "Website updated." : "Website registered. You can now run a scan.", "success");
                ZT.refresh();
            }
        }
    },
};
