/* Application shell: session check, role-aware navigation and hash router. */
"use strict";

(function () {
    const NAV = [
        { section: "Overview" },
        { route: "dashboard", label: "Dashboard", icon: "dashboard" },
        { section: "Assessment" },
        { route: "targets", label: "Website Targets", icon: "globe" },
        { route: "scanner", label: "Security Scanner", icon: "radar" },
        { route: "findings", label: "Security Findings", icon: "bug" },
        { route: "risk", label: "Risk Assessment", icon: "gauge" },
        { route: "monitoring", label: "Continuous Monitoring", icon: "activity" },
        { route: "history", label: "Scan History", icon: "history" },
        { section: "Governance" },
        { route: "audit", label: "Audit Logs", icon: "list", admin: true },
        { route: "reports", label: "Reports", icon: "file" },
        { route: "users", label: "User Management", icon: "users", admin: true },
        { route: "settings", label: "Settings", icon: "settings" },
    ];

    const view = document.getElementById("view");
    const titleEl = document.getElementById("pageTitle");
    const subtitleEl = document.getElementById("pageSubtitle");
    let renderToken = 0;

    function buildNav() {
        const nav = document.getElementById("nav");
        const isAdmin = ZT.user.role === "ADMIN";
        nav.innerHTML = NAV.filter((n) => !n.admin || isAdmin).map((n) => n.section
            ? `<div class="nav-section">${ZT.esc(n.section)}</div>`
            : `<a href="#/${n.route}" data-route="${n.route}">${ZT.icon(n.icon)}<span>${ZT.esc(n.label)}</span></a>`).join("")
            + `<a href="#" class="logout" id="logoutLink">${ZT.icon("logout")}<span>Logout</span></a>`;
        document.getElementById("logoutLink").addEventListener("click", async (e) => {
            e.preventDefault();
            try { await ZT.api("/api/auth/logout", { method: "POST" }); } catch (err) { /* session may already be gone */ }
            location.replace("/login.html?logout=1");
        });
        nav.addEventListener("click", (e) => {
            if (e.target.closest("a")) document.body.classList.remove("nav-open");
        });

        const u = ZT.user;
        document.getElementById("sidebarUser").innerHTML = `
            <div class="avatar">${ZT.esc((u.fullName || u.username).charAt(0).toUpperCase())}</div>
            <div class="spacer"><div class="name">${ZT.esc(u.fullName || u.username)}</div>
            <div class="role">${ZT.esc(u.username)} &middot; ${ZT.esc(u.role)}</div></div>`;
    }

    function parseHash() {
        const raw = location.hash.replace(/^#\/?/, "");
        const [path, query] = raw.split("?");
        const parts = path.split("/").filter(Boolean);
        return { route: parts[0] || "dashboard", args: parts.slice(1), params: new URLSearchParams(query || "") };
    }

    async function render() {
        const { route, args, params } = parseHash();
        const page = ZT.pages[route];
        const token = ++renderToken;
        document.querySelectorAll("#nav a[data-route]").forEach((a) => {
            const active = a.dataset.route === route || (route === "scans" && a.dataset.route === "history");
            a.classList.toggle("active", active);
            if (active) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
        });
        ZT.tooltip.hide();
        if (!page || (page.admin && ZT.user.role !== "ADMIN")) {
            titleEl.textContent = "Not found";
            subtitleEl.textContent = "";
            view.innerHTML = ZT.empty("Page not available", "This page does not exist or requires the ADMIN role.",
                '<a class="btn" href="#/dashboard">Back to dashboard</a>');
            return;
        }
        titleEl.textContent = page.title;
        subtitleEl.textContent = page.subtitle || "";
        document.title = page.title + " | Zero Trust";
        view.innerHTML = ZT.loading();
        view.classList.remove("view");
        void view.offsetWidth; // restart the fade-in animation
        view.classList.add("view");
        try {
            await page.render(view, { args, params, isCurrent: () => token === renderToken });
        } catch (e) {
            if (token === renderToken) view.innerHTML = ZT.errorBox(e.message || "Something went wrong.");
        }
        if (token === renderToken) view.focus({ preventScroll: true });
    }

    ZT.navigate = function (hash) {
        if (location.hash === hash) render(); else location.hash = hash;
    };
    ZT.refresh = render;
    ZT.isAdmin = () => ZT.user && ZT.user.role === "ADMIN";

    async function start() {
        document.getElementById("menuToggle").innerHTML = ZT.icon("menu");
        document.getElementById("menuToggle").addEventListener("click", () => document.body.classList.toggle("nav-open"));
        try {
            ZT.user = await ZT.api("/api/auth/me");
        } catch (e) {
            if (e.status !== 401) view.innerHTML = ZT.errorBox(e.message);
            return;
        }
        buildNav();
        window.addEventListener("hashchange", () => {
            window.scrollTo(0, 0);
            render();
        });
        if (!location.hash) history.replaceState(null, "", "#/dashboard");
        render();
    }

    document.addEventListener("DOMContentLoaded", start);
})();
