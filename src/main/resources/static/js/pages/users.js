/* User management (ADMIN only). */
"use strict";

ZT.pages.users = {
    title: "User Management",
    subtitle: "Accounts, roles and access approval",
    admin: true,
    async render(view, ctx) {
        const esc = ZT.esc;
        const users = await ZT.api("/api/users");
        if (!ctx.isCurrent()) return;
        const pending = users.filter((u) => !u.enabled);

        view.innerHTML = `
          ${pending.length ? `<div class="alert alert-warn mb">${ZT.icon("alert")}<div><b>${pending.length} account(s) disabled or awaiting approval.</b> Enable an account to allow sign-in.</div></div>` : ""}
          <div class="card flush">
            <div class="card-head"><div><h2>Users (${users.length})</h2>
              <div class="hint">ADMIN: full access. ANALYST: only websites explicitly assigned on the Website Targets page.</div></div>
              <button class="btn btn-primary" data-add>${ZT.icon("plus")}Add user</button></div>
            <div class="table-wrap mt"><table>
              <thead><tr><th>User</th><th>Role</th><th>Status</th><th class="hide-sm">Last login</th><th class="hide-sm">Created</th><th></th></tr></thead>
              <tbody>${users.map((u) => `
                <tr>
                  <td><div class="primary">${esc(u.username)}${u.id === ZT.user.id ? ' <span class="small muted">(you)</span>' : ""}</div>
                    <div class="secondary">${esc(u.fullName || "")}${u.email ? " &middot; " + esc(u.email) : ""}</div></td>
                  <td>${ZT.roleBadge(u.role)}</td>
                  <td>${u.enabled ? ZT.statusBadge("ENABLED") : ZT.statusBadge("DISABLED")}
                    ${u.locked ? '<span class="badge sev-HIGH">LOCKED</span>' : ""}</td>
                  <td class="hide-sm nowrap">${esc(ZT.relTime(u.lastLoginAt))}</td>
                  <td class="hide-sm nowrap">${esc(ZT.fmtDay(u.createdAt))}</td>
                  <td class="actions">
                    ${!u.enabled ? `<button class="btn btn-sm btn-primary" data-approve="${esc(u.id)}">${ZT.icon("check")}Enable</button>` : ""}
                    ${u.locked ? `<button class="btn btn-sm" data-unlock="${esc(u.id)}">${ZT.icon("key")}Unlock</button>` : ""}
                    <button class="btn btn-sm" data-edit="${esc(u.id)}" title="Edit">${ZT.icon("edit")}</button>
                    ${u.id !== ZT.user.id ? `<button class="btn btn-sm btn-danger" data-del="${esc(u.id)}" title="Delete">${ZT.icon("trash")}</button>` : ""}
                  </td>
                </tr>`).join("")}</tbody></table></div>
          </div>`;

        const byId = Object.fromEntries(users.map((u) => [String(u.id), u]));
        const update = async (id, body, message) => {
            try {
                await ZT.api("/api/users/" + id, { method: "PUT", body });
                ZT.toast(message, "success");
                ZT.refresh();
            } catch (e) { ZT.toast(e.message, "error"); }
        };

        view.querySelector("[data-add]").addEventListener("click", () => openForm(null));
        view.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openForm(byId[b.dataset.edit])));
        view.querySelectorAll("[data-approve]").forEach((b) => b.addEventListener("click", () => update(b.dataset.approve, { enabled: true }, "Account enabled.")));
        view.querySelectorAll("[data-unlock]").forEach((b) => b.addEventListener("click", () => update(b.dataset.unlock, { unlock: true }, "Account unlocked.")));
        view.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
            const u = byId[b.dataset.del];
            if (!(await ZT.confirm("Delete user", `Delete user "${u.username}"? Their audit history is kept, and any active session is revoked immediately.`, "Delete"))) return;
            try {
                await ZT.api("/api/users/" + u.id, { method: "DELETE" });
                ZT.toast("User deleted.", "success");
                ZT.refresh();
            } catch (e) { ZT.toast(e.message, "error"); }
        }));

        async function openForm(user) {
            const self = user && user.id === ZT.user.id;
            const ok = await ZT.modal({
                title: user ? "Edit user - " + user.username : "Add user",
                submitLabel: user ? "Save changes" : "Create user",
                body: `
                  <div class="form-grid">
                    ${user ? "" : `<div class="field"><label for="u-name">Username *</label><input id="u-name" name="username" type="text" maxlength="50" required></div>`}
                    <div class="field"><label for="u-full">Full name</label><input id="u-full" name="fullName" type="text" maxlength="100" value="${esc(user ? user.fullName || "" : "")}"></div>
                    <div class="field"><label for="u-email">Email</label><input id="u-email" name="email" type="email" maxlength="120" value="${esc(user ? user.email || "" : "")}"></div>
                    <div class="field"><label for="u-role">Role</label><select id="u-role" name="role" ${self ? "disabled" : ""}>
                      <option value="ANALYST" ${user && user.role === "ANALYST" ? "selected" : ""}>ANALYST</option>
                      <option value="ADMIN" ${user && user.role === "ADMIN" ? "selected" : ""}>ADMIN</option></select></div>
                    <div class="field full"><label for="u-pass">${user ? "Reset password (leave blank to keep)" : "Password *"}</label>
                      <input id="u-pass" name="password" type="password" autocomplete="new-password" maxlength="128" ${user ? "" : "required"}>
                      <div class="help">At least 8 characters with upper-case, lower-case, a digit and a special character.</div></div>
                    ${self ? "" : `<div class="field full"><label class="check"><input type="checkbox" name="enabled" ${!user || user.enabled ? "checked" : ""}><span>Account enabled</span></label></div>`}
                  </div>
                  ${self ? '<p class="small muted mt">You cannot change your own role or disable your own account.</p>' : ""}`,
                onSubmit: (form) => {
                    const d = ZT.formData(form);
                    const enabled = form.enabled ? form.enabled.checked : undefined;
                    if (!user) {
                        return ZT.api("/api/users", { method: "POST", body: {
                            username: d.username, fullName: d.fullName, email: d.email || null, password: form.password.value, role: d.role, enabled } });
                    }
                    const body = { fullName: d.fullName, email: d.email || null, enabled };
                    if (!self) body.role = d.role;
                    if (form.password.value) body.password = form.password.value;
                    return ZT.api("/api/users/" + user.id, { method: "PUT", body });
                },
            });
            if (ok) { ZT.toast(user ? "User updated." : "User created.", "success"); ZT.refresh(); }
        }
    },
};
