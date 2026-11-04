/* Shared helpers: API client (session cookie + CSRF), escaping, formatting, toasts, modals, icons. */
"use strict";

const ZT = window.ZT || {};
window.ZT = ZT;
ZT.pages = ZT.pages || {};

class ApiError extends Error {
    constructor(message, status, errors) {
        super(message);
        this.status = status;
        this.errors = errors || null;
    }
}
ZT.ApiError = ApiError;

/* ---------- CSRF ---------- */
function readCookie(name) {
    const match = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
    return match ? decodeURIComponent(match.substring(name.length + 1)) : null;
}

async function ensureCsrf() {
    let token = readCookie("XSRF-TOKEN");
    if (!token) {
        const res = await fetch("/api/auth/csrf", { credentials: "same-origin", headers: { Accept: "application/json" } });
        const json = await res.json().catch(() => null);
        token = readCookie("XSRF-TOKEN") || (json && json.data && json.data.token);
    }
    return token;
}

/* ---------- API client ---------- */
ZT.api = async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = { Accept: "application/json" };
    let body;
    if (options.body !== undefined) {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(options.body);
    }
    if (method !== "GET" && method !== "HEAD") {
        headers["X-XSRF-TOKEN"] = await ensureCsrf();
    }
    let res;
    try {
        res = await fetch(path, { method, headers, body, credentials: "same-origin" });
    } catch (e) {
        throw new ApiError("Cannot reach the server. Is the application running?", 0);
    }
    if (res.status === 401 && !path.startsWith("/api/auth/login") && !options.noRedirect) {
        const json = await res.json().catch(() => null);
        sessionStorageSafeSet("zt-login-msg", (json && json.message) || "Your session has ended. Please sign in again.");
        window.location.href = "/login.html";
        throw new ApiError("Authentication required.", 401);
    }
    if (options.raw) {
        if (!res.ok) {
            const json = await res.json().catch(() => null);
            throw new ApiError((json && json.message) || "Request failed (HTTP " + res.status + ").", res.status);
        }
        return res;
    }
    const json = await res.json().catch(() => null);
    if (!res.ok || (json && json.success === false)) {
        throw new ApiError((json && json.message) || "Request failed (HTTP " + res.status + ").", res.status, json && json.errors);
    }
    return json ? json.data : null;
};

ZT.qs = function qs(params) {
    const p = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") p.append(k, v);
    });
    const s = p.toString();
    return s ? "?" + s : "";
};

function sessionStorageSafeSet(key, value) {
    try { sessionStorage.setItem(key, value); } catch (e) { /* storage unavailable */ }
}
ZT.takeSessionMessage = function (key) {
    try {
        const v = sessionStorage.getItem(key);
        sessionStorage.removeItem(key);
        return v;
    } catch (e) {
        return null;
    }
};

/* ---------- Escaping & formatting ---------- */
ZT.esc = function esc(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
};
const esc = ZT.esc;

ZT.fmtDate = function (iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return isNaN(d) ? "-" : d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
};
ZT.fmtDay = function (iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return isNaN(d) ? "-" : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
};
ZT.relTime = function (iso) {
    if (!iso) return "never";
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    const future = diff < 0;
    const s = Math.abs(diff);
    let txt;
    if (s < 60) txt = Math.round(s) + "s";
    else if (s < 3600) txt = Math.round(s / 60) + "m";
    else if (s < 86400) txt = Math.round(s / 3600) + "h";
    else txt = Math.round(s / 86400) + "d";
    return future ? "in " + txt : txt + " ago";
};
ZT.yesNo = function (v) {
    if (v === null || v === undefined) return '<span class="muted">Not determined</span>';
    return v ? '<span class="badge st-PASS">Yes</span>' : '<span class="badge st-FAILED">No</span>';
};

/* ---------- Badges ---------- */
ZT.sevBadge = (sev) => `<span class="badge sev-${esc(sev)}">${esc(sev === "INFORMATIONAL" ? "INFO" : sev)}</span>`;
ZT.statusBadge = (st) => `<span class="badge st-${esc(st)}">${esc(String(st || "").replace(/_/g, " "))}</span>`;
ZT.roleBadge = (r) => `<span class="badge plain role-${esc(r)}">${esc(r)}</span>`;
ZT.riskBadge = function (level, label) {
    if (!level) return '<span class="badge risk-NONE">Not scanned</span>';
    return `<span class="badge risk-${esc(level)}">${esc(label || level)}</span>`;
};
ZT.scoreClass = (s) => (s === null || s === undefined ? "muted" : s >= 75 ? "score-ok" : s >= 50 ? "score-mid" : "score-bad");
ZT.scorePill = function (score) {
    if (score === null || score === undefined) return '<span class="muted">-</span>';
    return `<span class="score-pill ${ZT.scoreClass(score)}">${esc(score)}<small>/100</small></span>`;
};

/* ---------- UI states ---------- */
ZT.loading = (text) => `<div class="loading"><div class="spinner"></div><span>${esc(text || "Loading...")}</span></div>`;
ZT.empty = (title, text, action) => `<div class="empty">${ZT.icon("inbox")}<h3>${esc(title)}</h3><p>${esc(text || "")}</p>${action ? '<div class="mt">' + action + "</div>" : ""}</div>`;
ZT.errorBox = (message) => `<div class="error-box">${ZT.icon("alert")}<p>${esc(message)}</p></div>`;

/* ---------- Pagination ---------- */
ZT.pager = function (page) {
    if (page.totalPages <= 1) return "";
    return `<div class="pagination"><span>Page ${page.page + 1} of ${page.totalPages} &middot; ${page.totalElements} items</span>
      <div class="btn-group"><button class="btn btn-sm" data-page="${page.page - 1}" ${page.page === 0 ? "disabled" : ""}>Previous</button>
      <button class="btn btn-sm" data-page="${page.page + 1}" ${page.page + 1 >= page.totalPages ? "disabled" : ""}>Next</button></div></div>`;
};
ZT.bindPager = function (root, go) {
    root.querySelectorAll("[data-page]").forEach((b) => b.addEventListener("click", () => go(Number(b.dataset.page))));
};

/* ---------- Toasts ---------- */
ZT.toast = function (message, type) {
    let host = document.getElementById("toasts");
    if (!host) {
        host = document.createElement("div");
        host.id = "toasts";
        document.body.appendChild(host);
    }
    const el = document.createElement("div");
    el.className = "toast " + (type || "info");
    el.setAttribute("role", type === "error" ? "alert" : "status");
    el.textContent = message;
    host.appendChild(el);
    setTimeout(() => {
        el.classList.add("leaving");
        setTimeout(() => el.remove(), 300);
    }, type === "error" ? 6000 : 3800);
};

/* ---------- Modals ---------- */
ZT.modal = function ({ title, body, submitLabel, size, onSubmit, onOpen, danger, hideSubmit }) {
    return new Promise((resolve) => {
        const root = document.createElement("div");
        root.className = "modal-backdrop";
        root.innerHTML = `
          <div class="modal ${size === "small" ? "small" : ""}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
            <form novalidate>
              <div class="modal-head"><h3>${esc(title)}</h3>
                <button type="button" class="btn btn-ghost icon-btn" data-close aria-label="Close">${ZT.icon("x")}</button></div>
              <div class="modal-body"><div class="form-error" hidden></div>${body}</div>
              <div class="modal-foot">
                <button type="button" class="btn" data-close>Cancel</button>
                ${hideSubmit ? "" : `<button type="submit" class="btn ${danger ? "btn-danger" : "btn-primary"}">${esc(submitLabel || "Save")}</button>`}
              </div>
            </form>
          </div>`;
        document.body.appendChild(root);
        const form = root.querySelector("form");
        const errorEl = root.querySelector(".form-error");
        const close = (value) => {
            document.removeEventListener("keydown", onKey);
            window.removeEventListener("hashchange", onRoute);
            root.remove();
            resolve(value);
        };
        const onKey = (e) => { if (e.key === "Escape") close(null); };
        const onRoute = () => close(null);
        document.addEventListener("keydown", onKey);
        window.addEventListener("hashchange", onRoute);
        root.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => close(null)));
        root.addEventListener("mousedown", (e) => { if (e.target === root) close(null); });
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!onSubmit) return close(true);
            const btn = form.querySelector('button[type="submit"]');
            btn.disabled = true;
            errorEl.hidden = true;
            try {
                const result = await onSubmit(form);
                close(result === undefined ? true : result);
            } catch (err) {
                errorEl.hidden = false;
                errorEl.innerHTML = `<div class="alert alert-error">${ZT.icon("alert")}<div>${esc(err.message)}</div></div>`;
                btn.disabled = false;
            }
        });
        if (onOpen) onOpen(form);
        const first = form.querySelector("input:not([type=hidden]):not([type=checkbox]), select, textarea");
        (first || form.querySelector('button[type="submit"]') || form).focus();
    });
};

ZT.confirm = function (title, message, confirmLabel) {
    return ZT.modal({
        title, size: "small", danger: true, submitLabel: confirmLabel || "Confirm",
        body: `<p class="text-2">${esc(message)}</p>`,
    }).then((v) => v === true);
};

ZT.formData = function (form) {
    const data = {};
    new FormData(form).forEach((v, k) => { data[k] = typeof v === "string" ? v.trim() : v; });
    return data;
};

/* ---------- Downloads ---------- */
ZT.downloadReport = async function (scanId, button) {
    if (button) button.disabled = true;
    try {
        const res = await ZT.api(`/api/reports/${encodeURIComponent(scanId)}/pdf`, { raw: true });
        const blob = await res.blob();
        const disposition = res.headers.get("Content-Disposition") || "";
        const match = /filename="?([^";]+)"?/.exec(disposition);
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = match ? match[1] : `ZeroTrust_Report_scan${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
        ZT.toast("PDF report downloaded.", "success");
    } catch (e) {
        ZT.toast(e.message, "error");
    } finally {
        if (button) button.disabled = false;
    }
};

/* ---------- Icons (inline SVG, stroke = currentColor) ---------- */
const ICONS = {
    shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 3 3.5 6 3.5 9s-1 6-3.5 9c-2.5-3-3.5-6-3.5-9s1-6 3.5-9z"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/><circle cx="12" cy="12" r="1" />',
    bug: '<path d="M8 8a4 4 0 018 0v1H8V8z"/><rect x="7" y="9" width="10" height="10" rx="5"/><path d="M3 13h4M17 13h4M4 7l3 3M20 7l-3 3M4 19l3-2M20 19l-3-2M12 9v10"/>',
    gauge: '<path d="M4 16a8 8 0 1116 0"/><path d="M12 16l4-5"/><circle cx="12" cy="16" r="1.5"/>',
    activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    history: '<path d="M3 12a9 9 0 103-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 3"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
    file: '<path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M14 3v6h6M9 14h6M9 17h4"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0113 0"/><path d="M16 4.5a3.5 3.5 0 010 7M18 14a6 6 0 013.5 6"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.6 1.6 0 00-1.8-.3 1.6 1.6 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.6 1.6 0 00-1-1.5 1.6 1.6 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.6 1.6 0 00.3-1.8 1.6 1.6 0 00-1.5-1H3a2 2 0 110-4h.1a1.6 1.6 0 001.5-1 1.6 1.6 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.6 1.6 0 001.8.3H9a1.6 1.6 0 001-1.5V3a2 2 0 114 0v.1a1.6 1.6 0 001 1.5 1.6 1.6 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.6 1.6 0 00-.3 1.8V9a1.6 1.6 0 001.5 1H21a2 2 0 110 4h-.1a1.6 1.6 0 00-1.5 1z"/>',
    logout: '<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    play: '<path d="M7 4l13 8-13 8z"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    alert: '<path d="M12 3l9.5 17H2.5z"/><path d="M12 10v4M12 17.5v.01"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/>',
    check: '<path d="M5 12l5 5L20 7"/>',
    lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    inbox: '<path d="M3 13l3-8h12l3 8v6H3z"/><path d="M3 13h5l1 3h6l1-3h5"/>',
    refresh: '<path d="M20 11a8 8 0 00-14.9-3M4 13a8 8 0 0014.9 3"/><path d="M4 4v4h4M20 20v-4h-4"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
};
ZT.icon = function (name) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ""}</svg>`;
};

/* ---------- Shared tooltip ---------- */
ZT.tooltip = (function () {
    let el;
    function ensure() {
        if (!el) {
            el = document.createElement("div");
            el.className = "tooltip";
            el.hidden = true;
            document.body.appendChild(el);
        }
        return el;
    }
    return {
        show(html, x, y) {
            const t = ensure();
            t.innerHTML = html;
            t.hidden = false;
            const w = t.offsetWidth;
            const h = t.offsetHeight;
            t.style.left = Math.min(window.innerWidth - w - 8, x + 14) + "px";
            t.style.top = Math.max(8, y - h - 10) + "px";
        },
        hide() { if (el) el.hidden = true; },
    };
})();
