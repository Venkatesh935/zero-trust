/* Security findings with filters. */
"use strict";

ZT.pages.findings = {
    title: "Security Findings",
    subtitle: "Issues identified by passive checks, with evidence and recommendations",
    async render(view, ctx) {
        const esc = ZT.esc;
        const websites = await ZT.api("/api/websites");
        if (!ctx.isCurrent()) return;
        const state = {
            websiteId: ctx.params.get("website") || "",
            severity: ctx.params.get("severity") || "",
            category: "",
            from: "",
            to: "",
            latestOnly: true,
            includePassed: false,
            page: 0,
        };
        const categories = [["HTTPS", "HTTPS Transport"], ["TLS", "TLS Certificate"], ["SECURITY_HEADERS", "Security Headers"],
            ["COOKIES", "Cookie Security"], ["HTTP_RESPONSE", "HTTP Response"], ["INFORMATION_DISCLOSURE", "Information Disclosure"]];

        view.innerHTML = `
          <div class="card">
            <div class="filters">
              <div class="field"><label for="f-site">Website</label>
                <select id="f-site" data-k="websiteId"><option value="">All websites</option>
                ${websites.map((w) => `<option value="${esc(w.id)}" ${String(w.id) === state.websiteId ? "selected" : ""}>${esc(w.name)}</option>`).join("")}</select></div>
              <div class="field"><label for="f-sev">Severity</label>
                <select id="f-sev" data-k="severity"><option value="">All severities</option>
                ${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((s) => `<option ${s === state.severity ? "selected" : ""}>${s}</option>`).join("")}</select></div>
              <div class="field"><label for="f-cat">Category</label>
                <select id="f-cat" data-k="category"><option value="">All categories</option>
                ${categories.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("")}</select></div>
              <div class="field"><label for="f-from">Scan date from</label><input id="f-from" type="date" data-k="from"></div>
              <div class="field"><label for="f-to">Scan date to</label><input id="f-to" type="date" data-k="to"></div>
            </div>
            <div class="row">
              <label class="switch"><input type="checkbox" data-k="latestOnly" checked><span class="track"></span>Latest scan of each website only</label>
              <label class="switch"><input type="checkbox" data-k="includePassed"><span class="track"></span>Include passed checks</label>
            </div>
          </div>
          <div class="card" data-list></div>`;

        const list = view.querySelector("[data-list]");
        view.querySelectorAll("[data-k]").forEach((el) => el.addEventListener("change", () => {
            state[el.dataset.k] = el.type === "checkbox" ? el.checked : el.value;
            if (el.dataset.k === "from" || el.dataset.k === "to") {
                // choosing a date range implies searching history, not just the latest scans
                const latest = view.querySelector('[data-k="latestOnly"]');
                if (el.value && latest.checked) { latest.checked = false; state.latestOnly = false; }
            }
            state.page = 0;
            load();
        }));

        async function load() {
            list.innerHTML = ZT.loading("Loading findings...");
            const query = ZT.qs({
                websiteId: state.websiteId, severity: state.severity, category: state.category,
                from: state.from ? new Date(state.from + "T00:00:00").toISOString() : "",
                to: state.to ? new Date(new Date(state.to + "T00:00:00").getTime() + 86400000).toISOString() : "",
                latestOnly: state.latestOnly, includePassed: state.includePassed, page: state.page, size: 20,
            });
            try {
                const page = await ZT.api("/api/findings" + query);
                if (!ctx.isCurrent()) return;
                if (page.totalElements === 0) {
                    list.innerHTML = ZT.empty("No findings match these filters", state.latestOnly ? "Scan a website or turn off 'Latest scan only' to search history." : "Try different filters.");
                    return;
                }
                list.innerHTML = `
                  <div class="card-head"><h3>${esc(page.totalElements)} result(s)</h3><span class="hint">click a finding for details</span></div>
                  ${page.content.map((f) => ZT.findingCard(f, { showWebsite: true })).join("")}
                  ${ZT.pager(page)}`;
                ZT.bindPager(list, (p) => { state.page = p; load(); });
            } catch (e) {
                list.innerHTML = ZT.errorBox(e.message);
            }
        }
        load();
    },
};
