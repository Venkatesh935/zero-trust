/* Login and registration pages. */
"use strict";

(function () {
    const page = document.body.dataset.page;
    const messageEl = document.getElementById("message");

    function showMessage(text, type) {
        messageEl.hidden = false;
        messageEl.className = "alert alert-" + (type || "error") + " mb";
        messageEl.textContent = text;
    }

    async function init() {
        // Obtain the CSRF cookie before any form is submitted.
        try { await fetch("/api/auth/csrf", { credentials: "same-origin" }); } catch (e) { /* shown on submit */ }

        if (page === "login") {
            const pending = ZT.takeSessionMessage("zt-login-msg");
            if (pending) showMessage(pending, "warn");
            const params = new URLSearchParams(location.search);
            if (params.has("registered")) showMessage("Registration submitted. You can sign in once an administrator approves your account.", "ok");
            if (params.has("logout")) showMessage("You have been signed out.", "info");

            // Already signed in? Go straight to the dashboard.
            try {
                await ZT.api("/api/auth/me", { noRedirect: true });
                location.replace("/");
                return;
            } catch (e) { /* not signed in */ }

            try {
                const status = await ZT.api("/api/auth/registration-status");
                document.getElementById("registerLink").hidden = !status.enabled;
            } catch (e) { /* ignore */ }
            setupLogin();
        } else {
            try {
                const status = await ZT.api("/api/auth/registration-status");
                if (!status.enabled) {
                    showMessage("Self-registration is currently disabled. Ask an administrator to create your account.", "warn");
                    document.getElementById("submitBtn").disabled = true;
                }
            } catch (e) { /* ignore */ }
            setupRegister();
        }
    }

    function setupLogin() {
        const form = document.getElementById("loginForm");
        const btn = document.getElementById("submitBtn");
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const username = form.username.value.trim();
            const password = form.password.value;
            if (!username || !password) {
                showMessage("Enter your username and password.");
                return;
            }
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Verifying...';
            try {
                await ZT.api("/api/auth/login", { method: "POST", body: { username, password } });
                location.replace("/");
            } catch (err) {
                showMessage(err.message);
                form.password.value = "";
                form.password.focus();
                btn.disabled = false;
                btn.textContent = "Sign in";
            }
        });
    }

    function setupRegister() {
        const form = document.getElementById("registerForm");
        const btn = document.getElementById("submitBtn");
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const data = ZT.formData(form);
            if (!data.username || !form.password.value) {
                showMessage("Username and password are required.");
                return;
            }
            if (form.password.value !== form.confirm.value) {
                showMessage("Passwords do not match.");
                return;
            }
            btn.disabled = true;
            try {
                await ZT.api("/api/auth/register", {
                    method: "POST",
                    body: { username: data.username, fullName: data.fullName, email: data.email || null, password: form.password.value },
                });
                location.replace("/login.html?registered=1");
            } catch (err) {
                showMessage(err.message);
                btn.disabled = false;
            }
        });
    }

    init();
})();
