/* Audit log viewer (ADMIN only). */
"use strict";

ZT.pages.audit = {
    title: "Audit Logs",
    subtitle: "Security-relevant activity - visible to administrators only",
    admin: true,
    async render(view, ctx) {
        const esc = ZT.esc;
        const actions = ["LOGIN_SUCCESS", "LOGIN_FAILURE", "LOGOUT", "ACCOUNT_LOCKED", "SESSION_REVOKED", "ACCESS_DENIED",
            "USER_REGISTERED", "USER_CREATED", "USER_UPDATED", "USER_DELETED", "PASSWORD_CHANGED",
            "WEBSITE_CREATED", "WEBSITE_UPDATED", "WEBSITE_DELETED", "SCAN_STARTED", "SCAN_COMPLETED", "SCAN_FAILED",
            "MONITORING_CREATED", "MONITORING_UPDATED", "MONITORING_DELETED", "MONITORING_ALERT", "REPORT_GENERATED", "SETTINGS_UPDATED"];
        const state = { action: "", username: "", from: "", to: "", page: 0 };
        const tone = (a) => /FAILURE|LOCKED|DENIED|REVOKED|DELETED|FAILED|ALERT/.test(a) ? "st-FAILED"
            : /SUCCESS|COMPLETED|CREATED/.test(a) ? "st-PASS" : "st-RUNNING";

        view.innerHTML = `
          <div class="card">
            <div class="filters">
              <div class="field"><label for="a-action">Action</label><select id="a-action" data-k="action"><option value="">All actions</option>
                ${actions.map((a) => `<option value="${a}">${a.replace(/_/g, " ")}</option>`).join("")}</select></div>
              <div class="field"><label for="a-user">User</label><input id="a-user" type="text" data-k="username" placeholder="username contains..."></div>
              <div class="field"><label for="a-from">From</label><input id="a-from" type="date" data-k="from"></div>
              <div class="field"><label for="a-to">To</label><input id="a-to" type="date" data-k="to"></div>
            </div>
            <p class="small muted">Passwords, session identifiers and cookie values are never written to the audit log.</p>
          </div>
          <div class="card flush" data-list></div>`;
        const list = view.querySelector("[data-list]");
        let debounce;
        view.querySelectorAll("[data-k]").forEach((el) => el.addEventListener(el.tagName === "INPUT" && el.type === "text" ? "input" : "change", () => {
            state[el.dataset.k] = el.value;
            state.page = 0;
            clearTimeout(debounce);
            debounce = setTimeout(load, 300);
        }));

        async function load() {
            list.innerHTML = ZT.loading();
            try {
                const page = await ZT.api("/api/audit-logs" + ZT.qs({
                    action: state.action, username: state.username,
                    from: state.from ? new Date(state.from + "T00:00:00").toISOString() : "",
                    to: state.to ? new Date(new Date(state.to + "T00:00:00").getTime() + 86400000).toISOString() : "",
                    page: state.page, size: 25,
                }));
                if (!ctx.isCurrent()) return;
                if (page.totalElements === 0) {
                    list.innerHTML = ZT.empty("No audit entries", "No activity matches these filters.");
                    return;
                }
                list.innerHTML = `<div class="table-wrap"><table>
                  <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Description</th><th class="hide-sm">Target</th><th class="hide-sm">IP address</th></tr></thead>
                  <tbody>${page.content.map((a) => `
                    <tr>
                      <td class="nowrap small">${esc(ZT.fmtDate(a.timestamp))}</td>
                      <td class="primary">${esc(a.username || "-")}</td>
                      <td><span class="badge ${tone(a.action)}">${esc(a.action.replace(/_/g, " "))}</span></td>
                      <td class="small text-2">${esc(a.description || "")}</td>
                      <td class="hide-sm mono">${a.targetId ? "#" + esc(a.targetId) : "-"}</td>
                      <td class="hide-sm mono">${esc(a.ipAddress || "-")}</td>
                    </tr>`).join("")}</tbody></table></div>${ZT.pager(page)}`;
                ZT.bindPager(list, (p) => { state.page = p; load(); });
            } catch (e) {
                list.innerHTML = ZT.errorBox(e.message);
            }
        }
        load();
    },
};
