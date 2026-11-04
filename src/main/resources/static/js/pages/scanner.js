/* Security Scanner: run a passive assessment of a registered website. */
"use strict";

ZT.pages.scanner = {
    title: "Security Scanner",
    subtitle: "Passive HTTPS, TLS, header, cookie and response assessment",
    async render(view, ctx) {
        const esc = ZT.esc;
        const websites = await ZT.api("/api/websites");
        if (!ctx.isCurrent()) return;

        const preselect = ctx.params.get("website");
        view.innerHTML = `
          <div class="grid grid-main">
            <div class="card">
              <div class="card-head"><h2>Start a passive assessment</h2></div>
              ${websites.length === 0 ? ZT.empty("No websites available",
                  ZT.isAdmin() ? "Register an authorized website first." : "No websites are assigned to you.",
                  ZT.isAdmin() ? '<a class="btn btn-primary" href="#/targets?new=1">Register website</a>' : "") : `
              <div class="row">
                <div class="field spacer">
                  <label for="scan-target">Registered website</label>
                  <select id="scan-target">${websites.map((w) => `<option value="${esc(w.id)}" ${String(w.id) === preselect ? "selected" : ""}>${esc(w.name)} - ${esc(w.url)}</option>`).join("")}</select>
                </div>
                <button class="btn btn-primary" id="scan-btn">${ZT.icon("play")}Run scan</button>
              </div>
              <p class="small muted mt">Only registered, authorized websites can be scanned - arbitrary URLs are never accepted.</p>`}
            </div>
            <div class="card">
              <div class="card-head"><h3>What is checked</h3></div>
              <ul class="small text-2 timeline">
                <li class="tl-item"><b>HTTPS</b> - availability, HTTP→HTTPS redirect, downgrades</li>
                <li class="tl-item"><b>TLS certificate</b> - trust, hostname, expiry, protocol</li>
                <li class="tl-item"><b>Security headers</b> - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy</li>
                <li class="tl-item"><b>Cookies</b> - Secure, HttpOnly, SameSite (values never stored)</li>
                <li class="tl-item"><b>Response</b> - status, time, content type, redirects, technology disclosure</li>
              </ul>
            </div>
          </div>
          <div data-result class="mt"></div>`;

        const resultEl = view.querySelector("[data-result]");
        const button = view.querySelector("#scan-btn");
        if (!button) return;
        const select = view.querySelector("#scan-target");

        async function runScan(websiteId) {
            if (websiteId) select.value = String(websiteId);
            const site = websites.find((w) => String(w.id) === select.value);
            button.disabled = true;
            select.disabled = true;
            resultEl.innerHTML = `
              <div class="card center">
                <div class="radar"><div class="sweep"></div></div>
                <h3 class="mt">Assessing ${esc(site.name)}</h3>
                <p class="small muted">${esc(site.url)}</p>
                <ul class="scan-steps">
                  ${["Validating URL and resolved IP addresses (SSRF protection)", "Checking HTTPS availability and TLS certificate",
                     "Checking HTTP to HTTPS redirect", "Analysing security headers and cookies", "Calculating risk score"]
                     .map((s) => `<li><span class="dot"></span>${esc(s)}</li>`).join("")}
                </ul>
              </div>`;
            const steps = resultEl.querySelectorAll(".scan-steps li");
            let i = 0;
            steps[0].classList.add("active");
            const timer = setInterval(() => {
                if (i < steps.length - 1) {
                    steps[i].classList.replace("active", "done");
                    steps[++i].classList.add("active");
                }
            }, 1400);
            try {
                const scan = await ZT.api("/api/scans", { method: "POST", body: { websiteId: Number(select.value) } });
                clearInterval(timer);
                if (!ctx.isCurrent()) return;
                ZT.renderScan(resultEl, scan, { rescan: (id) => runScan(id) });
                ZT.toast(scan.summary.status === "COMPLETED"
                    ? `Scan finished: score ${scan.summary.score}/100 (${scan.summary.riskLabel}).`
                    : "Scan finished, but the website could not be assessed.", scan.summary.status === "COMPLETED" ? "success" : "warn");
            } catch (e) {
                clearInterval(timer);
                resultEl.innerHTML = `<div class="alert alert-error">${ZT.icon("alert")}<div>${esc(e.message)}</div></div>`;
            } finally {
                button.disabled = false;
                select.disabled = false;
            }
        }

        button.addEventListener("click", () => runScan());
        if (ctx.params.get("run") && preselect) {
            history.replaceState(null, "", "#/scanner?website=" + encodeURIComponent(preselect));
            runScan(preselect);
        }
    },
};
