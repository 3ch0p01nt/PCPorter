/* PCPorter report kit: virtual table, SVG bar chart and heatmap, URL-hash state, copy and CSV helpers.
   Shared by the offline reports. No network access, no HTML parsing: every text goes in through textContent. */
const PCK = (() => {
  "use strict";
  const SVGNS = "http://www.w3.org/2000/svg";
  const coll = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

  function el(tag, props = {}, kids = [], attrs = {}) {
    const e = document.createElement(tag);
    Object.assign(e, props);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    for (const k of kids) if (k != null) e.append(k);
    return e;
  }

  function svg(tag, attrs = {}, kids = []) {
    const e = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
    for (const k of kids) if (k != null) e.append(k);
    return e;
  }

  const truncate = (s, n) => s.length > n ? s.slice(0, n - 3) + "..." : s;

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch {
      const ta = el("textarea", { value: text });
      document.body.append(ta); ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch { /* clipboard blocked */ }
      ta.remove();
      return ok;
    }
  }

  /** CSV cell: quoted when needed; a leading = + - @ or tab is defused so spreadsheets do not run it as a formula. */
  function csvEscape(v) {
    let s = v == null ? "" : String(v);
    if (/^[=+\-@\t]/.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) || s.startsWith("'") ? `"${s.replace(/"/g, '""')}"` : s;
  }

  function download(name, text, type) {
    const a = el("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /** State kept in the address after '#', so a view can be bookmarked or reloaded. */
  const hashState = {
    get(key) { return new URLSearchParams(location.hash.slice(1)).get(key); },
    set(values) {
      const p = new URLSearchParams(location.hash.slice(1));
      for (const [k, v] of Object.entries(values)) { if (v === "" || v == null) p.delete(k); else p.set(k, String(v)); }
      const h = p.toString();
      if (("#" + h) === location.hash || (h === "" && location.hash === "")) return;
      try { history.replaceState(null, "", h ? "#" + h : location.pathname + location.search); } catch { /* not allowed here */ }
    },
  };

  /**
   * Virtual table: only the visible rows exist in the page, so 100,000 rows scroll smoothly.
   * columns: [{ label, get(row) (sort value), text(row) (display, default String(get)), width (CSS grid track),
   *             filter: true | "select", descFirst, csv(row) }]
   * opts: { name, height, rowHeight, placeholder, filter(row) (extra page filter), sort (column index), desc,
   *         onSelect(row), onChange(), toolbar: [elements], emptyText }
   */
  function vtable(host, columns, rows, opts = {}) {
    const RH = opts.rowHeight || 30, H = opts.height || 520;
    const tracks = columns.map(c => c.width || "minmax(0,1fr)").join(" ");
    const cell = (c, r) => { const v = c.text ? c.text(r) : c.get(r); return v == null ? "" : String(v); };
    let all = [], view = [], sortCol = opts.sort ?? -1, desc = !!opts.desc, sel = -1;
    const colFilter = columns.map(() => "");

    const q = el("input", { type: "search", className: "vt-q", placeholder: opts.placeholder || "Filter these rows" }, [], { "aria-label": "Filter " + (opts.name || "rows") });
    const count = el("span", { className: "vt-count" }, [], { "aria-live": "polite" });
    const csvBtn = el("button", { type: "button", textContent: "Export CSV", title: "Save the rows shown as a spreadsheet file" });
    const bar = el("div", { className: "vt-bar" }, [q, ...(opts.toolbar || []), count, csvBtn]);
    const head = el("div", { className: "vt-head vt-grid" }, [], { role: "row" });
    const filters = el("div", { className: "vt-filters vt-grid" });
    head.style.gridTemplateColumns = filters.style.gridTemplateColumns = tracks;
    const heads = columns.map((c, i) => {
      const b = el("button", { type: "button", className: "vt-h", textContent: c.label, title: "Sort by " + c.label }, [], { role: "columnheader" });
      b.onclick = () => { if (sortCol === i) desc = !desc; else { sortCol = i; desc = !!c.descFirst; } apply(); };
      head.append(b);
      let f = el("span");
      if (c.filter === "select") {
        f = el("select", {}, [el("option", { value: "", textContent: "All" })]);
        f.addEventListener("change", () => { colFilter[i] = f.value; apply(); });
      } else if (c.filter) {
        f = el("input", { type: "search", placeholder: "Filter" });
        let t = 0;
        f.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { colFilter[i] = f.value.trim().toLowerCase(); apply(); }, 150); });
      }
      if (f.tagName !== "SPAN") f.setAttribute("aria-label", "Filter " + c.label);
      filters.append(f);
      return { b, f };
    });
    const spacer = el("div", { className: "vt-spacer" });
    const vp = el("div", { className: "vt-vp", tabIndex: 0 }, [spacer], { role: "grid", "aria-label": opts.name || "Table" });
    vp.style.height = H + "px";
    const empty = el("div", { className: "vt-empty", hidden: true, textContent: opts.emptyText || "Nothing matches these filters." });
    host.replaceChildren(bar, head, filters, vp, empty);

    let qt = 0;
    q.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(apply, 150); });

    const key = it => it.k ??= columns.map(c => cell(c, it.r)).join(" \u0001 ").toLowerCase();

    function fillSelects() {
      columns.forEach((c, i) => {
        if (c.filter !== "select") return;
        const values = [...new Set(all.map(it => cell(c, it.r)))].filter(v => v !== "").sort(coll.compare).slice(0, 500);
        const f = heads[i].f, keep = f.value;
        f.replaceChildren(el("option", { value: "", textContent: "All" }), ...values.map(v => el("option", { value: v, textContent: v })));
        f.value = values.includes(keep) ? keep : "";
        colFilter[i] = f.value;
      });
    }

    function compare(c) {
      const g = c.sortKey || c.get;
      return (a, b) => {
        const x = g(a.r), y = g(b.r);
        if (x == null || x === "") return y == null || y === "" ? 0 : 1;
        if (y == null || y === "") return -1;
        const d = typeof x === "number" && typeof y === "number" ? x - y : coll.compare(String(x), String(y));
        return desc ? -d : d;
      };
    }

    function apply() {
      const qs = q.value.trim().toLowerCase();
      const extra = opts.filter;
      view = all.filter(it => (!extra || extra(it.r)) && (!qs || key(it).includes(qs)) &&
        colFilter.every((f, i) => !f || (columns[i].filter === "select" ? cell(columns[i], it.r) === f : cell(columns[i], it.r).toLowerCase().includes(f))));
      if (sortCol >= 0) view.sort(compare(columns[sortCol]));
      heads.forEach(({ b }, i) => {
        b.classList.toggle("asc", i === sortCol && !desc); b.classList.toggle("desc", i === sortCol && desc);
        b.setAttribute("aria-sort", i === sortCol ? (desc ? "descending" : "ascending") : "none");
      });
      spacer.style.height = view.length * RH + "px";
      vp.style.height = Math.min(H, view.length * RH + 2) + "px";      // short lists do not leave a tall empty box
      vp.hidden = view.length === 0;
      vp.setAttribute("aria-rowcount", String(view.length));
      count.textContent = `${view.length.toLocaleString()} of ${all.length.toLocaleString()} shown`;
      empty.hidden = view.length > 0;
      sel = Math.min(sel, view.length - 1);
      for (const n of rendered.values()) n.remove();
      rendered.clear();
      draw();
      if (opts.onChange) opts.onChange();
    }

    const rendered = new Map();
    function draw() {
      const top = vp.scrollTop;
      const from = Math.max(0, Math.floor(top / RH) - 10), to = Math.min(view.length, Math.ceil((top + H) / RH) + 10);
      for (const [i, n] of rendered) if (i < from || i >= to) { n.remove(); rendered.delete(i); }
      for (let i = from; i < to; i++) {
        if (rendered.has(i)) continue;
        const it = view[i];
        const row = el("div", { className: "vt-row vt-grid" + (i === sel ? " sel" : "") },
          columns.map(c => { const t = cell(c, it.r); return el("div", { className: "vt-c" + (c.cls ? " " + c.cls : ""), textContent: t, title: t }, [], { role: "gridcell" }); }),
          { role: "row", "aria-rowindex": String(i + 1) });
        row.style.gridTemplateColumns = tracks; row.style.top = i * RH + "px"; row.style.height = RH + "px";
        row.onclick = () => { select(i); vp.focus({ preventScroll: true }); };
        spacer.append(row); rendered.set(i, row);
      }
    }
    let raf = 0;
    vp.addEventListener("scroll", () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; draw(); }); }, { passive: true });

    function select(i, scroll) {
      if (!view.length) return;
      sel = Math.max(0, Math.min(view.length - 1, i));
      if (scroll) {
        const y = sel * RH;
        const vh = vp.clientHeight || H;
        if (y < vp.scrollTop) vp.scrollTop = y; else if (y + RH > vp.scrollTop + vh) vp.scrollTop = y + RH - vh;
        draw();
      }
      for (const [k, n] of rendered) n.classList.toggle("sel", k === sel);
      if (opts.onSelect) opts.onSelect(view[sel].r);
    }
    vp.addEventListener("keydown", e => {
      const page = Math.max(1, Math.floor(H / RH) - 1);
      const t = { ArrowDown: sel + 1, ArrowUp: sel - 1, PageDown: sel + page, PageUp: sel - page, Home: 0, End: view.length - 1 }[e.key];
      if (t === undefined) return;
      e.preventDefault(); select(t, true);
    });

    csvBtn.onclick = () => {
      const lines = [columns.map(c => csvEscape(c.label)).join(",")]
        .concat(view.map(it => columns.map(c => csvEscape(c.csv ? c.csv(it.r) : cell(c, it.r))).join(",")));
      download((opts.name || "table").toLowerCase().replace(/[^a-z0-9]+/g, "-") + ".csv", "﻿" + lines.join("\r\n"), "text/csv");
    };

    function setRows(rs) { all = rs.map(r => ({ r, k: null })); fillSelects(); apply(); }
    setRows(rows);
    return {
      refresh: apply, setRows, select,
      rows: () => view.map(it => it.r),
      query: () => q.value,
      setQuery(v) { q.value = v || ""; apply(); },
      focus() { vp.focus(); },
    };
  }

  /**
   * Bar chart. data: [{ label, value, title }]. opts: { horizontal, width, height, labelWidth, onClick(d), axis: [left, right] }.
   */
  function barChart(svgEl, data, opts = {}) {
    const W = opts.width || 900;
    const H = opts.horizontal ? Math.max(40, data.length * 22) : (opts.height || 170);
    svgEl.replaceChildren();
    svgEl.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svgEl.setAttribute("role", "img");
    if (!data.length) return;
    const max = Math.max(1, ...data.map(d => d.value));
    const bar = (d, kids) => {
      const g = svg("g", { class: "bar" + (opts.onClick ? " click" : "") }, [svg("title", {}, [d.title || `${d.label}: ${d.value.toLocaleString()}`]), ...kids]);
      if (opts.onClick) {
        g.setAttribute("tabindex", "0"); g.setAttribute("role", "button"); g.setAttribute("aria-label", d.title || d.label);
        g.addEventListener("click", () => opts.onClick(d));
        g.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); opts.onClick(d); } });
      }
      svgEl.append(g);
    };
    if (opts.horizontal) {
      const lw = opts.labelWidth || 260, rh = H / data.length;
      data.forEach((d, i) => {
        const w = (W - lw - 70) * d.value / max, y = i * rh;
        bar(d, [
          svg("text", { x: lw - 8, y: y + rh * 0.68, "text-anchor": "end", class: "lbl" }, [truncate(d.label, 40)]),
          svg("rect", { x: lw, y: y + rh * 0.15, width: Math.max(1, w), height: rh * 0.7, rx: 2 }),
          svg("text", { x: lw + w + 6, y: y + rh * 0.68, class: "val" }, [d.value.toLocaleString()]),
        ]);
      });
    } else {
      const base = H - 20, bw = W / data.length, gap = bw > 4 ? 1 : 0;
      data.forEach((d, i) => {
        const h = d.value ? Math.max(1, (base - 6) * d.value / max) : 0;
        bar(d, [svg("rect", { x: i * bw, y: base - h, width: Math.max(0.5, bw - gap), height: h })]);
      });
      svgEl.append(svg("line", { x1: 0, y1: base + 0.5, x2: W, y2: base + 0.5, class: "axis" }));
      if (opts.axis) {
        svgEl.append(svg("text", { x: 0, y: H - 4, class: "lbl" }, [opts.axis[0]]));
        svgEl.append(svg("text", { x: W, y: H - 4, "text-anchor": "end", class: "lbl" }, [opts.axis[1]]));
      }
    }
  }

  /** Heatmap of a rows x columns matrix (e.g. 7 weekdays x 24 hours). opts: { rows, cols, unit }. */
  function heatmap(svgEl, matrix, opts = {}) {
    const rows = opts.rows || matrix.map((_, i) => String(i)), cols = opts.cols || matrix[0].map((_, i) => String(i));
    const cw = 30, ch = 22, lx = 44, ty = 18;
    const W = lx + cols.length * cw, H = ty + rows.length * ch;
    svgEl.replaceChildren();
    svgEl.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svgEl.setAttribute("role", "img");
    const max = Math.max(1, ...matrix.flat());
    cols.forEach((c, j) => { if (j % 3 === 0) svgEl.append(svg("text", { x: lx + j * cw + 2, y: 12, class: "lbl" }, [c])); });
    matrix.forEach((row, i) => {
      svgEl.append(svg("text", { x: lx - 6, y: ty + i * ch + 15, "text-anchor": "end", class: "lbl" }, [rows[i]]));
      row.forEach((v, j) => {
        svgEl.append(svg("rect", { x: lx + j * cw, y: ty + i * ch, width: cw - 2, height: ch - 2, rx: 3, class: "hm", "fill-opacity": v ? (0.15 + 0.85 * v / max).toFixed(3) : 0.04 },
          [svg("title", {}, [`${rows[i]} ${cols[j]}: ${v.toLocaleString()} ${opts.unit || ""}`.trim()])]));
      });
    });
  }

  return { el, svg, vtable, barChart, heatmap, hashState, copyText, csvEscape, download, truncate, coll };
})();
