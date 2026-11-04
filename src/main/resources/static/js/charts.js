/* Lightweight, dependency-free charts (DOM + inline SVG), compatible with the strict CSP. */
"use strict";

ZT.charts = (function () {
    const esc = ZT.esc;

    /**
     * Horizontal bar chart. items: [{ label, value, cls, hint }]. Every bar is
     * direct-labelled with its value; hovering shows a tooltip.
     */
    function bars(container, items, options) {
        const opts = options || {};
        const max = Math.max(1, opts.max || 0, ...items.map((i) => i.value));
        container.innerHTML = `<div class="bars" role="list">${items.map((item, idx) => `
            <div class="bar-row bar-hit" role="listitem" data-idx="${idx}">
              <span class="bar-label">${esc(item.label)}</span>
              <span class="bar-track"><span class="bar-fill fill-${esc(item.cls || "ACCENT")}"></span></span>
              <span class="bar-value">${esc(opts.format ? opts.format(item.value) : item.value)}</span>
            </div>`).join("")}</div>`;
        const rows = container.querySelectorAll(".bar-row");
        requestAnimationFrame(() => {
            rows.forEach((row, idx) => {
                const v = items[idx].value;
                row.querySelector(".bar-fill").style.width = (v === 0 ? 0 : Math.max(2, (v / max) * 100)) + "%";
            });
        });
        rows.forEach((row, idx) => {
            const item = items[idx];
            row.addEventListener("mousemove", (e) => ZT.tooltip.show(
                `<strong>${esc(item.label)}</strong>${esc(opts.format ? opts.format(item.value) : item.value)}${item.hint ? " " + esc(item.hint) : ""}`,
                e.clientX, e.clientY));
            row.addEventListener("mouseleave", () => ZT.tooltip.hide());
        });
    }

    function scoreColor(score) {
        if (score === null || score === undefined) return "#5b6478";
        if (score >= 90) return "#0ca30c";
        if (score >= 75) return "#1baf7a";
        if (score >= 50) return "#fab219";
        if (score >= 25) return "#ec835a";
        return "#d03b3b";
    }

    /** Circular gauge for a 0-100 score. */
    function gauge(container, score, options) {
        const opts = options || {};
        const r = 52;
        const c = 2 * Math.PI * r;
        const value = score === null || score === undefined ? 0 : Math.max(0, Math.min(100, score));
        container.innerHTML = `
          <div class="gauge ${opts.small ? "small" : ""}" role="img" aria-label="Security score ${esc(score ?? "not available")} out of 100">
            <svg viewBox="0 0 120 120">
              <circle class="g-track" cx="60" cy="60" r="${r}" fill="none" stroke-width="10"/>
              <circle class="g-value" cx="60" cy="60" r="${r}" fill="none" stroke-width="10" stroke-linecap="round"
                      stroke="${scoreColor(score)}" stroke-dasharray="${c.toFixed(2)}" stroke-dashoffset="${c.toFixed(2)}"/>
            </svg>
            <div class="g-center"><div><div class="g-score">${score === null || score === undefined ? "-" : esc(score)}</div>
              <div class="g-of">${esc(opts.caption || "out of 100")}</div></div></div>
          </div>`;
        const arc = container.querySelector(".g-value");
        requestAnimationFrame(() => {
            arc.style.strokeDashoffset = String(c * (1 - value / 100));
        });
    }

    /** Line chart of scores over time with hover crosshair. points: [{ t: iso, y: number|null, label }] */
    function scoreLine(container, points) {
        const data = points.filter((p) => p.y !== null && p.y !== undefined);
        if (data.length === 0) {
            container.innerHTML = ZT.empty("No score data yet", "Scores appear after the first successful check.");
            return;
        }
        const W = 640, H = 220, L = 34, R = 14, T = 12, B = 26;
        const times = data.map((p) => new Date(p.t).getTime());
        const tMin = Math.min(...times), tMax = Math.max(...times);
        const x = (t) => (tMax === tMin ? L + (W - L - R) / 2 : L + ((t - tMin) / (tMax - tMin)) * (W - L - R));
        const y = (v) => T + (1 - v / 100) * (H - T - B);
        const coords = data.map((p, i) => [x(times[i]), y(p.y)]);
        const path = coords.map((c, i) => (i ? "L" : "M") + c[0].toFixed(1) + " " + c[1].toFixed(1)).join(" ");
        const area = path + ` L${coords[coords.length - 1][0].toFixed(1)} ${y(0)} L${coords[0][0].toFixed(1)} ${y(0)} Z`;
        const grid = [0, 25, 50, 75, 100].map((v) =>
            `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text class="axis-text" x="${L - 6}" y="${y(v) + 3}" text-anchor="end">${v}</text>`).join("");
        const labels = [0, data.length - 1].filter((v, i, a) => a.indexOf(v) === i).map((i) =>
            `<text class="axis-text" x="${coords[i][0]}" y="${H - 8}" text-anchor="${i === 0 && data.length > 1 ? "start" : "end"}">${esc(ZT.fmtDay(data[i].t))}</text>`).join("");
        container.innerHTML = `
          <div class="line-chart">
            <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Security score history">
              <defs><linearGradient id="scoreArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#22d3ee" stop-opacity="0.28"/><stop offset="100%" stop-color="#22d3ee" stop-opacity="0"/></linearGradient></defs>
              ${grid}
              <path class="area" d="${area}"/>
              <path class="series" d="${path}" vector-effect="non-scaling-stroke"/>
              <line class="crosshair" x1="0" x2="0" y1="${T}" y2="${H - B}" visibility="hidden" vector-effect="non-scaling-stroke"/>
              ${coords.map((c) => `<circle class="dot" cx="${c[0].toFixed(1)}" cy="${c[1].toFixed(1)}" r="4" vector-effect="non-scaling-stroke"/>`).join("")}
              ${labels}
            </svg>
          </div>`;
        const svg = container.querySelector("svg");
        const cross = svg.querySelector(".crosshair");
        svg.addEventListener("mousemove", (e) => {
            const rect = svg.getBoundingClientRect();
            const px = ((e.clientX - rect.left) / rect.width) * W;
            let best = 0;
            coords.forEach((c, i) => { if (Math.abs(c[0] - px) < Math.abs(coords[best][0] - px)) best = i; });
            cross.setAttribute("x1", coords[best][0]);
            cross.setAttribute("x2", coords[best][0]);
            cross.setAttribute("visibility", "visible");
            const p = data[best];
            ZT.tooltip.show(`<strong>Score ${esc(p.y)}/100</strong>${esc(ZT.fmtDate(p.t))}${p.label ? "<br>" + esc(p.label) : ""}`, e.clientX, e.clientY);
        });
        svg.addEventListener("mouseleave", () => {
            cross.setAttribute("visibility", "hidden");
            ZT.tooltip.hide();
        });
    }

    return { bars, gauge, scoreLine, scoreColor };
})();
