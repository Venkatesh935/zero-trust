/* Account and application settings. */
"use strict";

ZT.pages.settings = {
    title: "Settings",
    subtitle: "Your account and platform configuration",
    async render(view, ctx) {
        const esc = ZT.esc;
        const settings = await ZT.api("/api/settings");
        if (!ctx.isCurrent()) return;
        const admin = ZT.isAdmin();
        const u = ZT.user;

        view.innerHTML = `
          <div class="grid grid-2">
            <div class="card">
              <div class="card-head"><h2>My account</h2></div>
              <dl class="kv">
                <dt>Username</dt><dd>${esc(u.username)}</dd>
                <dt>Full name</dt><dd>${esc(u.fullName || "-")}</dd>
                <dt>Role</dt><dd>${ZT.roleBadge(u.role)}</dd>
                <dt>Last sign-in</dt><dd>${esc(ZT.fmtDate(u.lastLoginAt))}</dd>
              </dl>
              <h3 class="mt mb">Change password</h3>
              <form id="pw-form" novalidate>
                <div class="field mb"><label for="pw-cur">Current password</label><input id="pw-cur" name="currentPassword" type="password" autocomplete="current-password" required></div>
                <div class="field mb"><label for="pw-new">New password</label><input id="pw-new" name="newPassword" type="password" autocomplete="new-password" required>
                  <div class="help">At least 8 characters with upper-case, lower-case, a digit and a special character.</div></div>
                <div class="field mb"><label for="pw-conf">Confirm new password</label><input id="pw-conf" name="confirm" type="password" autocomplete="new-password" required></div>
                <button class="btn btn-primary" type="submit">${ZT.icon("key")}Update password</button>
              </form>
            </div>
            <div class="stack">
              ${admin ? `
              <div class="card">
                <div class="card-head"><h2>Access control</h2></div>
                <label class="switch"><input type="checkbox" id="reg-toggle" ${settings.registrationEnabled ? "checked" : ""}><span class="track"></span>
                  Allow self-registration</label>
                <p class="small muted mt">Self-registered users receive the ANALYST role and stay disabled until an administrator enables them in User Management.</p>
              </div>` : ""}
              <div class="card">
                <div class="card-head"><h2>Security policy</h2><span class="hint">read-only, from application.properties</span></div>
                <dl class="kv">
                  <dt>Account lockout</dt><dd>${esc(settings.maxFailedLogins)} failed logins &rarr; locked ${esc(settings.lockoutMinutes)} min</dd>
                  <dt>Session</dt><dd>HttpOnly, SameSite=Strict cookie; re-verified on every request; 30 min idle timeout</dd>
                  <dt>Password storage</dt><dd>BCrypt (cost 12)</dd>
                  <dt>CSRF protection</dt><dd>Enabled for all state-changing requests</dd>
                </dl>
              </div>
              <div class="card">
                <div class="card-head"><h2>Scanner limits</h2><span class="hint">SSRF protection &amp; resource limits</span></div>
                <dl class="kv">
                  <dt>Allowed ports</dt><dd>${esc([...settings.allowedPorts].sort((a, b) => a - b).join(", "))}</dd>
                  <dt>Connect / read timeout</dt><dd>${esc(settings.connectTimeoutMs)} ms / ${esc(settings.readTimeoutMs)} ms</dd>
                  <dt>Max redirects</dt><dd>${esc(settings.maxRedirects)} (each destination re-validated)</dd>
                  <dt>Max header size</dt><dd>${esc(Math.round(settings.maxHeaderBytes / 1024))} KB (response body never read)</dd>
                  <dt>Manual scan cooldown</dt><dd>${esc(settings.manualScanCooldownSeconds)} s per website</dd>
                  <dt>Monitoring interval</dt><dd>${esc(settings.monitoringMinIntervalMinutes)} - ${esc(settings.monitoringMaxIntervalMinutes)} minutes</dd>
                  <dt>Blocked destinations</dt><dd>localhost, private / loopback / link-local / multicast / reserved IP ranges, cloud metadata endpoints, internal hostnames</dd>
                </dl>
              </div>
            </div>
          </div>`;

        const form = view.querySelector("#pw-form");
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (form.newPassword.value !== form.confirm.value) {
                ZT.toast("New passwords do not match.", "error");
                return;
            }
            const btn = form.querySelector("button");
            btn.disabled = true;
            try {
                await ZT.api("/api/auth/password", { method: "PUT", body: { currentPassword: form.currentPassword.value, newPassword: form.newPassword.value } });
                form.reset();
                ZT.toast("Password changed.", "success");
            } catch (err) {
                ZT.toast(err.message, "error");
            } finally {
                btn.disabled = false;
            }
        });

        const toggle = view.querySelector("#reg-toggle");
        if (toggle) toggle.addEventListener("change", async () => {
            try {
                await ZT.api("/api/settings", { method: "PUT", body: { registrationEnabled: toggle.checked } });
                ZT.toast(toggle.checked ? "Self-registration enabled." : "Self-registration disabled.", "success");
            } catch (e) {
                toggle.checked = !toggle.checked;
                ZT.toast(e.message, "error");
            }
        });
    },
};
