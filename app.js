// @ts-check
// What Bitview can see: reads data/ (written by pull.py) and draws it. No framework, no build.

/**
 * @typedef {{
 *   requests?: number, cachedRequests?: number, bytes?: number, cachedBytes?: number, pageViews?: number, uniques?: number,
 *   sampleInterval?: number, firewall?: number, origin?: { p50?: number, p95?: number, sampleInterval: number },
 *   [field: string]: any
 * }} Rec  One stored day or hour; a day's breakdowns are Sampled, an hour's status is plain counts
 * @typedef {Rec & { date: string, hours?: Record<string, Rec> }} Day
 * @template T @typedef {{ counts: T, sampleInterval: number }} Sampled  One stored breakdown; 1 in sampleInterval counted
 * @typedef {{ note: string, approx: boolean }} Coverage
 * @typedef {'sum' | 'avg' | 'ratio'} Total
 * @typedef {{ id: string, label: string, about: string, num: (d: Rec) => number | undefined, den?: (d: Rec) => number | undefined, total: Total, fmt: (n: number) => string, daily?: boolean }} Metric
 * @typedef {{ name: string, color: string, values: (number | null)[] }} Series
 * @typedef {{ labels: string[], when: (i: number) => string, rank: (i: number) => number, series: Series[], fmt: (n: number) => string, height: number, title: string }} ChartSpec
 * @typedef {{ key: string, label: string, sub?: string, value: number }} Row
 * @typedef {{ key: string, title: string, group?: string, unit?: string, about?: string, label?: (k: string) => string, limit?: number }} Breakdown
 * @typedef {{ unit: 'hour' | 'day' | 'week' | 'month', keys: string[], recs: Rec[][], size: number[], label: (i: number) => string, when: (i: number) => string, rank: (i: number) => number }} Buckets  rank: how round a bucket is to label, as midnight over 06:00
 * @typedef {{ what: string, mark: string, how: string, fields: string[], kept: string }} Policy  One row of pull.py's POLICY
 * @typedef {{ scope: string, name: string, kept: string, read: boolean, visitors: boolean, fields: string[] }} Dataset
 * @typedef {{ policy: Policy[], datasets: Dataset[] }} Inventory  data/inventory.json, written by pull.py
 * @typedef {{ hosts: string[], public: boolean, status: string, connections: number }} Tunnel  public: serves a host Bitview's home page names
 * @typedef {{ pulled: string, through: string, tunnels: Tunnel[] }} Now  data/now.json: the last pull
 * @typedef {(typeof RANGES)[number]} Range
 * @typedef {{ range: Range, b: Buckets, prev: Buckets | null, start: string, last: string, listDays: Day[], note: string }} Frame
 *   What one chart shows: its range (the chosen one, or the widest its history covers), buckets, and the days for lists
 */

/** Ranges: id, label, length in days (0: all), and whether its charts go by hour or by day. */
const RANGES = /** @type {const} */ ([
  ['24h', '24 h', 1, true], ['7d', '7 d', 7, true], ['30d', '30 d', 30, false], ['90d', '90 d', 90, false], ['1y', '1 y', 365, false], ['all', 'All', 0, false],
]);
/** A chart takes a range when its stored history covers this share of it: Cloudflare's year of days falls a day short,
 * and its month of firewall events a day short of 30. */
const COVERED = 0.95;
const KINDS = /** @type {const} */ ([['API', 'var(--s1)'], ['Pages', 'var(--s2)'], ['MCP', 'var(--s3)']]);
const HOME = 'bitview.space';
const LIST = 10;
const HOUR = 36e5;

const compactFormat = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
const decimalFormat = new Intl.NumberFormat('en', { maximumFractionDigits: 1 });
const pctFormat = new Intl.NumberFormat('en', { style: 'percent', maximumFractionDigits: 1 });
const finePctFormat = new Intl.NumberFormat('en', { style: 'percent', maximumSignificantDigits: 2 });
const regions = new Intl.DisplayNames(['en'], { type: 'region' });
const dayFormat = new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', timeZone: 'UTC' });
const longDayFormat = new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
const monthFormat = new Intl.DateTimeFormat('en', { month: 'short', year: 'numeric', timeZone: 'UTC' });
const clockFormat = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });

/** @param {number} n */
const count = (n) => compactFormat.format(n);
/** @param {number} n */
const pct = (n) => pctFormat.format(n);
/** Small shares keep two significant digits, so 0.012% doesn't read as 0%. */
/** @param {number} n */
const finePct = (n) => (n && n < 0.01 ? finePctFormat.format(n) : pctFormat.format(n));
/** @param {number} n */
const ms = (n) => `${Math.round(n)} ms`;
/** @param {number} n */
function bytes(n) {
  const units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) (n /= 1000), i++;
  return `${decimalFormat.format(n)} ${units[i]}`;
}
/** @param {(n: number) => string} fmt @param {boolean} approx */
const estimated = (fmt, approx) => (approx ? (/** @type {number} */ n) => `≈${fmt(n)}` : fmt);

/** A Cloudflare name for reading: "searchEngine" -> "Search engine". */
/** @param {string} s */
const words = (s) => s && s[0].toUpperCase() + s.slice(1).replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
const STATUS = { 1: 'Info', 2: 'Success', 3: 'Redirect', 4: 'Client error', 5: 'Server error' };
/** Cloudflare's security features, as its firewall events name them. */
const SOURCES = {
  bic: 'Browser integrity check', firewallManaged: 'Managed rules', firewallCustom: 'Custom rules', firewallRules: 'Firewall rules',
  securitylevel: 'Security level', ratelimit: 'Rate limiting', hot: 'Hotlink protection', l7ddos: 'DDoS protection',
  waf: 'WAF', uablock: 'User agent blocking', zonelockdown: 'Zone lockdown', validation: 'Request validation', botFight: 'Bot fight mode',
};
/** @param {string} k */
const source = (k) => SOURCES[/** @type {keyof SOURCES} */ (k)] ?? k;

/** Every stored daily breakdown, drawn as a ranked list; the ones with a group get their own card there. */
/** @type {Breakdown[]} */
const BREAKDOWNS = [
  { key: 'countries', title: 'Countries', label: (k) => country(k), limit: 10 },
  { key: 'status', title: 'Status codes', label: (k) => `${k} ${STATUS[/** @type {keyof STATUS} */ (k[0])] ?? ''}`, limit: 10 },
  { key: 'firewallRules', title: 'Firewall rules', unit: 'Events', label: source, limit: 6 },
  { key: 'browsers', title: 'Browsers', group: 'visitors', unit: 'Page views' },
  { key: 'os', title: 'Operating systems', group: 'visitors' },
  { key: 'devices', title: 'Devices', group: 'visitors', label: words },
  { key: 'bots', title: 'Verified bots', group: 'visitors', label: (k) => k || 'Not a verified bot' },
  { key: 'ipClasses', title: 'Client reputation', group: 'visitors', label: words, about: "Cloudflare's class for the client's network." },
  { key: 'contentTypes', title: 'Content types', group: 'delivery' },
  { key: 'cache', title: 'Cache status', group: 'delivery', label: words },
  { key: 'http', title: 'HTTP versions', group: 'delivery' },
  { key: 'tls', title: 'TLS versions', group: 'delivery' },
  { key: 'colos', title: 'Cloudflare edge locations', group: 'delivery' },
];

/** @type {Metric[]} */
const METRICS = [
  { id: 'requests', label: 'Requests', num: (d) => d.requests, total: 'sum', fmt: count,
    about: 'Every request Cloudflare answered for bitview.space and its subdomains: browsers, bots, API and MCP clients alike.' },
  { id: 'ips', label: 'Unique IPs a day', num: (d) => d.uniques, total: 'avg', fmt: count, daily: true,
    about: "Cloudflare's approximate count of distinct client IP addresses in a day. One person can use several and many can share one, and IPs can't be added up across days, so a range shows the daily average." },
  { id: 'views', label: 'Page views', num: (d) => d.pageViews, total: 'sum', fmt: count,
    about: "Cloudflare's own count of responses it judges to be pages (HTML), by its heuristic; API and file requests aren't in it." },
  { id: 'bandwidth', label: 'Bandwidth', num: (d) => d.bytes, total: 'sum', fmt: bytes,
    about: 'Bytes Cloudflare sent to clients.' },
  { id: 'cache', label: 'Served from cache', num: (d) => d.cachedRequests, den: (d) => d.requests, total: 'ratio', fmt: pct,
    about: "The share of requests Cloudflare answered from its cache, without asking Bitview's servers." },
  { id: 'saved', label: 'Bandwidth from cache', num: (d) => d.cachedBytes, total: 'sum', fmt: bytes,
    about: "Bytes Cloudflare sent from its cache: what Bitview's servers didn't have to send." },
];

// Days are UTC day strings, YYYY-MM-DD; hours are YYYY-MM-DDTHH.
/** @param {string} day */
const toDate = (day) => new Date(`${day}T00:00:00Z`);
/** @param {string} day @param {number} n */
const addDays = (day, n) => new Date(toDate(day).getTime() + n * 864e5).toISOString().slice(0, 10);
/** @param {string} a @param {string} b */
const daysBetween = (a, b) => Math.round((toDate(b).getTime() - toDate(a).getTime()) / 864e5);
/** @param {Date} t */
const hourKey = (t) => t.toISOString().slice(0, 13);

/** @param {Rec[]} recs @param {(d: Rec) => number | undefined} f */
const sum = (recs, f) => recs.reduce((s, d) => s + (f(d) ?? 0), 0);
/** @param {Rec[]} recs @param {(d: Rec) => unknown} f */
const having = (recs, f) => recs.filter((d) => f(d) != null);

/** A metric over some records: their sum, their mean, or a ratio of sums; null when none has it. */
/** @param {Metric} m @param {Rec[]} recs @param {Total} [total] */
function measure(m, recs, total = m.total) {
  const has = having(recs, m.num);
  if (!has.length) return null;
  if (total === 'ratio') return sum(has, m.num) / sum(has, /** @type {(d: Rec) => number} */ (m.den));
  const s = sum(has, m.num);
  return total === 'sum' ? s : s / has.length;
}

/** The status codes of a day (sampled breakdown) or an hour (plain counts). */
/** @param {Rec} d @returns {Record<string, number> | undefined} */
const statusOf = (d) => d.status?.counts ?? d.status;
/** Requests answered with a status matching `test`, out of all. */
/** @param {Rec[]} recs @param {(code: string) => boolean} test */
function statusShare(recs, test) {
  const has = recs.filter(statusOf);
  if (!has.length) return null;
  const hits = sum(has, (d) => Object.entries(statusOf(d) ?? {}).reduce((s, [k, v]) => s + (test(k) ? v : 0), 0));
  return hits / sum(has, (d) => Object.values(statusOf(d) ?? {}).reduce((s, v) => s + v, 0));
}
/** Cloudflare's codes for not reaching Bitview's servers: bad gateway, gateway timeout and its own 52x. */
/** @param {string} k */
const unreachable = (k) => k === '502' || k === '504' || /^52\d$/.test(k);
/** @param {Rec} d */
const firewallOf = (d) => d.firewall ?? (d.firewallActions ? Object.values(d.firewallActions.counts).reduce((s, v) => s + v, 0) : undefined);
/** @param {Rec[]} recs @param {'p50' | 'p95'} q */
const originTime = (recs, q) => {
  const has = recs.filter((d) => d.origin?.[q] != null);
  return has.length ? sum(has, (d) => d.origin?.[q]) / has.length : null;
};
/** Whether any of these records is a sampled estimate. */
/** @param {Rec[]} recs @param {(d: Rec) => number | undefined} [interval] */
const sampled = (recs, interval = (d) => d.sampleInterval) => recs.some((d) => (interval(d) ?? 1) > 1.005);

/** Hourly buckets: the `n` hours before `end`, newest last. */
/** @param {string} end @param {number} n @returns {Buckets} */
function hourBuckets(end, n) {
  const last = new Date(end).getTime() - HOUR;
  const times = Array.from({ length: n }, (_, i) => new Date(last - (n - 1 - i) * HOUR));
  const keys = times.map(hourKey);
  return {
    unit: 'hour',
    keys,
    recs: keys.map((k) => (hours.has(k) ? [/** @type {Rec} */ (hours.get(k))] : [])),
    size: keys.map(() => 1),
    label: (i) => (n > 24 && !times[i].getUTCHours() ? dayFormat.format(times[i]) : clockFormat.format(times[i])),
    rank: (i) => 5 - [24, 12, 6, 3, 1].findIndex((h) => times[i].getUTCHours() % h === 0),
    when: (i) => `${dayFormat.format(times[i])}, ${clockFormat.format(times[i])}–${clockFormat.format(new Date(times[i].getTime() + HOUR))} UTC`,
  };
}

/** Day buckets for a span: days up to ~3 months, then weeks (from Monday), then months. */
/** @param {string} start @param {string} end @returns {Buckets} */
function dayBuckets(start, end) {
  const span = daysBetween(start, end) + 1;
  const unit = span <= 92 ? 'day' : span <= 731 ? 'week' : 'month';
  /** @type {Map<string, string[]>} */
  const buckets = new Map();
  for (let day = start; day <= end; day = addDays(day, 1)) {
    const key = unit === 'day' ? day : unit === 'week' ? addDays(day, -((toDate(day).getUTCDay() + 6) % 7)) : `${day.slice(0, 8)}01`;
    buckets.get(key)?.push(day) ?? buckets.set(key, [day]);
  }
  const keys = [...buckets.keys()], members = [...buckets.values()];
  return {
    unit,
    keys,
    recs: members.map((ds) => /** @type {Rec[]} */ (ds.map((k) => byDate.get(k)).filter((d) => d?.requests != null))),
    size: members.map((ds) => ds.length),
    label: (i) => (unit === 'month' ? monthFormat : dayFormat).format(toDate(keys[i])),
    rank: (i) => {
      const d = toDate(keys[i]);
      const firsts = members[i].some((day) => day.endsWith('-01'));
      return unit === 'month' ? (d.getUTCMonth() % 3 ? 1 : 2) : firsts ? (members[i].some((day) => day.endsWith('-01-01')) ? 4 : 3) : d.getUTCDay() === 1 ? 2 : 1;
    },
    when: (i) => (unit === 'day' ? longDayFormat.format(toDate(keys[i])) : unit === 'week' ? `Week of ${longDayFormat.format(toDate(keys[i]))}` : monthFormat.format(toDate(keys[i]))),
  };
}

// ---------------------------------------------------------------------------------------------------------------- charts

const SVG = 'http://www.w3.org/2000/svg';
/** @param {string} tag @param {Record<string, string | number>} attrs @param {Element} [parent] */
function svg(tag, attrs, parent) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  parent?.append(el);
  return el;
}
/** @param {string} tag @param {string} [className] @param {string} [text] */
function html(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

/** A clean axis step for a maximum, so ticks read 0 / 250K / 500K. */
/** @param {number} max @param {number} steps */
function niceStep(max, steps) {
  const raw = max / steps || 1;
  const p = 10 ** Math.floor(Math.log10(raw));
  return ([1, 2, 2.5, 5, 10].find((m) => m * p >= raw) ?? 10) * p;
}

/** @type {WeakMap<HTMLElement, ChartSpec & { width?: number }>} */
const charts = new WeakMap();
const resize = new ResizeObserver((entries) => {
  for (const { target } of entries) {
    const spec = charts.get(/** @type {HTMLElement} */ (target));
    if (spec && spec.width !== /** @type {HTMLElement} */ (target).clientWidth) drawChart(/** @type {HTMLElement} */ (target), spec);
  }
});

/** A line chart, one y-axis, with a crosshair that snaps to buckets (pointer, touch and arrow keys). */
/** @param {HTMLElement} el @param {ChartSpec} spec */
function drawChart(el, spec) {
  charts.set(el, { ...spec, width: el.clientWidth });
  resize.observe(el);
  const { labels, series, fmt, height } = spec;
  const W = el.clientWidth;
  const n = labels.length;
  const all = /** @type {number[]} */ (series.flatMap((s) => s.values).filter((v) => v != null));
  const step = niceStep(Math.max(0, ...all), 4);
  const max = Math.max(step, step * Math.ceil(Math.max(0, ...all) / step));
  const ticks = Array.from({ length: Math.round(max / step) + 1 }, (_, i) => i * step);
  const left = 8 + Math.max(...ticks.map((t) => fmt(t).length)) * 6.6;
  const top = 8, bottom = 24, right = 8;
  const plotW = Math.max(1, W - left - right), plotH = height - top - bottom;
  /** @param {number} i */
  const x = (i) => left + (n > 1 ? (i * plotW) / (n - 1) : plotW / 2);
  /** @param {number} v */
  const y = (v) => top + plotH * (1 - v / max);

  const root = svg('svg', { width: W, height, viewBox: `0 0 ${W} ${height}`, role: 'img', tabindex: 0, 'aria-label': `${spec.title}. The table below lists every value.` });
  for (const t of ticks) {
    svg('line', { x1: left, x2: W - right, y1: y(t), y2: y(t), stroke: t ? 'var(--grid)' : 'var(--axis)', 'stroke-width': 1, 'shape-rendering': 'crispEdges' }, root);
    svg('text', { x: left - 8, y: y(t) + 4, 'text-anchor': 'end' }, root).textContent = fmt(t);
  }
  // Labels on the roundest buckets (midnights, then 12:00, 06:00…) that still give at least half the room's worth,
  // newest first, none crowding another.
  const width = Math.max(84, Math.max(...labels.map((l) => l.length)) * 6.6 + 24);
  const fit = Math.max(2, Math.floor(plotW / width));
  const indices = Array.from({ length: n }, (_, i) => i);
  const levels = [...new Set(indices.map(spec.rank))].sort((a, z) => a - z);
  const level = levels.findLast((l) => indices.filter((i) => spec.rank(i) >= l).length >= Math.min(fit / 2, n)) ?? 0;
  const round = indices.filter((i) => spec.rank(i) >= level);
  /** @type {Set<number>} */
  const shown = new Set();
  let prior = Infinity;
  for (const i of round.reverse()) if (prior - x(i) >= width) (shown.add(i), (prior = x(i)));
  for (const i of shown) {
    const px = x(i), half = (labels[i].length * 6.6) / 2;
    const anchor = n === 1 ? 'middle' : px - half < left ? 'start' : px + half > W - right ? 'end' : 'middle';
    svg('text', { x: x(i), y: height - 6, 'text-anchor': anchor }, root).textContent = labels[i];
  }

  for (const s of series) {
    /** @type {[number, number][][]} */
    const runs = [];
    s.values.forEach((v, i) => {
      if (v == null) return;
      const last = runs.at(-1);
      if (last && s.values[i - 1] != null) last.push([x(i), y(v)]);
      else runs.push([[x(i), y(v)]]);
    });
    for (const run of runs) {
      const d = run.map(([px, py], k) => `${k ? 'L' : 'M'}${px.toFixed(1)},${py.toFixed(1)}`).join('');
      if (series.length === 1 && run.length > 1)
        svg('path', { d: `${d}L${run.at(-1)?.[0]},${y(0)}L${run[0][0]},${y(0)}Z`, fill: s.color, 'fill-opacity': 0.1 }, root);
      svg('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, root);
      if (run.length === 1) svg('circle', { cx: run[0][0], cy: run[0][1], r: 2.5, fill: s.color }, root);
    }
    const lastI = s.values.findLastIndex((v) => v != null);
    if (lastI >= 0) svg('circle', { cx: x(lastI), cy: y(/** @type {number} */ (s.values[lastI])), r: 4, fill: s.color, stroke: 'var(--surface)', 'stroke-width': 2 }, root);
  }

  const cross = svg('g', { visibility: 'hidden', 'pointer-events': 'none' }, root);
  const hair = svg('line', { y1: top, y2: top + plotH, stroke: 'var(--axis)', 'stroke-width': 1 }, cross);
  const dots = series.map((s) => svg('circle', { r: 4, fill: s.color, stroke: 'var(--surface)', 'stroke-width': 2 }, cross));
  const tip = html('div', 'tip');
  tip.hidden = true;
  let at = -1;
  /** @param {number} i */
  const show = (i) => {
    at = Math.max(0, Math.min(n - 1, i));
    const px = x(at);
    hair.setAttribute('x1', String(px));
    hair.setAttribute('x2', String(px));
    series.forEach((s, k) => {
      const v = s.values[at];
      dots[k].setAttribute('visibility', v == null ? 'hidden' : 'visible');
      if (v != null) (dots[k].setAttribute('cx', String(px)), dots[k].setAttribute('cy', String(y(v))));
    });
    cross.setAttribute('visibility', 'visible');
    tip.replaceChildren(html('div', 'when', spec.when(at)));
    for (const s of series) {
      const row = html('div', 'row');
      const key = html('span', 'key');
      key.style.background = s.color;
      const v = s.values[at];
      row.append(html('b', '', v == null ? 'no data' : fmt(v)), key, html('span', '', s.name));
      tip.append(row);
    }
    tip.hidden = false;
    const w = tip.offsetWidth;
    tip.style.left = `${px + 12 + w > W ? Math.max(0, px - 12 - w) : px + 12}px`;
  };
  const hide = () => ((tip.hidden = true), cross.setAttribute('visibility', 'hidden'), (at = -1));
  root.addEventListener('pointermove', (e) => show(Math.round(((e.offsetX - left) / plotW) * (n - 1))));
  root.addEventListener('pointerdown', (e) => show(Math.round(((e.offsetX - left) / plotW) * (n - 1))));
  root.addEventListener('pointerleave', hide);
  root.addEventListener('blur', hide);
  root.addEventListener('focus', () => show(n - 1));
  root.addEventListener('keydown', (e) => {
    const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -n, End: n };
    if (e.key in moves) (e.preventDefault(), show((at < 0 ? n - 1 : at) + moves[/** @type {keyof moves} */ (e.key)]));
    else if (e.key === 'Escape') hide();
  });
  el.replaceChildren(root, tip);
}

/** A chart's table twin: one row per bucket, newest first. */
/** @param {HTMLDetailsElement} details @param {string[]} heads @param {string[][]} rows */
function table(details, heads, rows) {
  const t = html('table');
  const head = t.createTHead().insertRow();
  for (const h of heads) head.append(html('th', '', h));
  const body = t.createTBody();
  for (const r of rows) {
    const tr = body.insertRow();
    for (const c of r) tr.insertCell().textContent = c;
  }
  /** @type {HTMLElement} */ (details.querySelector('.scroll')).replaceChildren(t);
}

/** A legend: a key per series, with a value. */
/** @param {HTMLElement} el @param {{ name: string, color: string, value: string }[]} items */
function legend(el, items) {
  el.replaceChildren(
    ...items.map((s) => {
      const item = html('span');
      const key = html('span', 'key');
      key.style.background = s.color;
      item.append(key, `${s.name}: ${s.value}`);
      return item;
    }),
  );
}

/** A ranked list: name over a share bar, value, share; the first few, then all. */
/** @type {Set<string>} */
const expanded = new Set();
/** @param {HTMLElement} el @param {Row[]} rows @param {(n: number) => string} fmt @param {string} valueHead @param {number} [limit] */
function rankList(el, rows, fmt, valueHead, limit = LIST) {
  rows.sort((a, b) => b.value - a.value);
  const total = rows.reduce((s, r) => s + r.value, 0);
  const top = rows[0]?.value || 1;
  const open = expanded.has(el.id);
  const head = html('div', 'rank-head');
  head.append(html('span', '', rows.length ? `${rows.length} in all` : 'No data in this range'), html('span', '', valueHead), html('span', '', 'Share'));
  const list = html('ol', 'rank');
  for (const r of open ? rows : rows.slice(0, limit)) {
    const li = html('li');
    const name = html('span', 'name');
    name.style.setProperty('--w', `${(r.value / top) * 100}%`);
    if (r.sub) name.append(html('small', '', r.sub));
    name.append(r.label);
    li.append(name, html('span', 'v', fmt(r.value)), html('span', 's', pct(total ? r.value / total : 0)));
    list.append(li);
  }
  const parts = [head, list];
  if (rows.length > limit) {
    const more = html('button', 'more', open ? 'Show fewer' : `Show all ${rows.length}`);
    more.setAttribute('aria-expanded', String(open));
    more.addEventListener('click', () => {
      open ? expanded.delete(el.id) : expanded.add(el.id);
      rankList(el, rows, fmt, valueHead, limit);
    });
    parts.push(more);
  }
  el.replaceChildren(...parts);
}

/** A row of toggle buttons; the pressed one is the current choice. */
/** @param {HTMLElement} el @param {[string, string][]} options @param {string} current @param {(id: string) => void} pick */
function segmented(el, options, current, pick) {
  el.replaceChildren(
    ...options.map(([id, label]) => {
      const b = html('button', '', label);
      b.type = 'button';
      b.setAttribute('aria-pressed', String(id === current));
      b.addEventListener('click', () => pick(id));
      return b;
    }),
  );
}

// ------------------------------------------------------------------------------------------------------------------ page

/** @param {string} id */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));
const params = new URLSearchParams(location.search);
const state = {
  range: RANGES.some(([id]) => id === params.get('range')) ? /** @type {string} */ (params.get('range')) : '24h',
  metric: METRICS.some((m) => m.id === params.get('metric')) ? /** @type {string} */ (params.get('metric')) : 'requests',
  kind: 'All',
  by: 'requests',
};

/** @type {Day[]} */
let days = [];
/** @type {Map<string, Day>} */
let byDate = new Map();
/** @type {Map<string, Rec>} */
let hours = new Map();
/** @type {Now} */
let now;

/** @param {string} code */
function country(code) {
  if (code === 'T1') return 'Tor';
  if (code === 'XX') return 'Unknown';
  try {
    return regions.of(code) ?? code;
  } catch {
    return code;
  }
}

/** Splits a stored route key into its host (left out for the main site) and path. */
/** @param {string} key */
function route(key) {
  const slash = key.indexOf('/');
  const host = key.slice(0, slash);
  return { sub: host === HOME ? undefined : host, label: key.slice(slash) };
}

/** The first stored day of each daily field, and the first stored hour (YYYY-MM-DDTHH) of each hourly one. */
/** @type {Map<string, string>} */
const firstDay = new Map();
/** @type {Map<string, string>} */
const firstHour = new Map();
/** Days whose totals are final, oldest first. */
/** @type {Day[]} */
let final = [];

/** A day count in words. */
/** @param {number} n */
const daysWord = (n) => `${n} day${n === 1 ? '' : 's'}`;

/** What a stored breakdown covers over some days: from when it's kept, the days it misses since, how sampled it was. */
/** @param {string} key @param {Day[]} range @param {string} start @param {string} last @returns {Coverage} */
function coverage(key, range, start, last) {
  const from = firstDay.get(key);
  if (!from) return { note: 'Not kept yet.', approx: false };
  const has = range.filter((d) => d[key]);
  const missing = Math.max(0, daysBetween(from > start ? from : start, last) + 1 - has.length);
  const worst = Math.max(1, ...has.map((d) => d[key].sampleInterval));
  const approx = worst > 1.005;
  const notes = [
    missing > 0 && `${daysWord(missing)} missing.`,
    approx && `≈ Estimates: Cloudflare counted as few as 1 in ${decimalFormat.format(worst)} on some days.`,
  ];
  return { note: notes.filter(Boolean).join(' '), approx };
}

/**
 * The checks an operator opens Cloudflare's dashboard for, over the last 24 hours against the 7 days before: a check
 * is off when its value passes `limit` and, when it has one, `times` its usual level. Each says what it reads.
 * @type {{ label: string, read: (hs: Rec[]) => number | null, fmt: (n: number) => string, limit: number, times?: number, low?: boolean, about: string }[]}
 */
const CHECKS = [
  { label: "Couldn't reach Bitview", read: (hs) => statusShare(hs, unreachable), fmt: finePct, limit: 0.002, times: 3,
    about: "Requests Cloudflare couldn't pass to Bitview's servers (502, 504, 52x). Off above 0.2% and 3× usual." },
  { label: 'Server errors (5xx)', read: (hs) => statusShare(hs, (k) => k[0] === '5'), fmt: finePct, limit: 0.005, times: 3,
    about: 'Off above 0.5% of requests and 3× usual.' },
  { label: 'Client errors (4xx)', read: (hs) => statusShare(hs, (k) => k[0] === '4'), fmt: pct, limit: 0.1, times: 2,
    about: 'Mostly scanners and mistyped addresses. Off above 10% and 2× usual.' },
  { label: 'Origin time, 95th pct', read: (hs) => originTime(hs, 'p95'), fmt: ms, limit: 1000, times: 2,
    about: "How long Bitview's servers took for the slowest 5% of requests. Off above 1 s and 2× usual." },
  { label: 'Firewall events a day', read: (hs) => (having(hs, firewallOf).length ? (sum(hs, firewallOf) / having(hs, firewallOf).length) * 24 : null), fmt: count, limit: 1000, times: 5,
    about: 'Requests a Cloudflare security feature acted on. Off above 1,000 a day and 5× usual.' },
  { label: 'Served from cache', read: (hs) => measure(/** @type {Metric} */ (METRICS.find((m) => m.id === 'cache')), hs), fmt: pct, limit: 0.05, times: 0.5, low: true,
    about: 'Off below half its usual share, or 5%.' },
];

/** The at-a-glance strip: every check, the tunnels and the pull, with a headline saying whether anything is off. */
function glance() {
  const last24 = hourBuckets(now.through, 24).recs.flat();
  const before = hourBuckets(new Date(new Date(now.through).getTime() - 24 * HOUR).toISOString(), 168).recs.flat();
  /** @type {{ label: string, value: string, off: boolean, about: string }[]} */
  const items = CHECKS.map((c) => {
    const v = c.read(last24), usual = c.read(before);
    const scaled = usual == null || !c.times ? true : c.low ? v != null && v < usual * c.times : v != null && v > usual * c.times;
    const off = v != null && (c.low ? v < c.limit || scaled : v > c.limit && scaled);
    const value = v == null ? 'no data' : c.fmt(v) + (usual == null ? '' : ` · usual ${c.fmt(usual)}`);
    return { label: c.label, value, off, about: c.about };
  });
  const serving = now.tunnels.filter((t) => t.public);
  const down = serving.filter((t) => t.status !== 'healthy');
  items.unshift({
    label: 'Tunnels to Bitview',
    value: down.length ? `${down.length} of ${serving.length} not healthy: ${down.map((t) => `${t.hosts.join(', ')} (${t.status})`).join('; ')}` : `All ${serving.length} healthy`,
    off: down.length > 0,
    about: `Cloudflare's status, at the last pull, for each tunnel serving a host Bitview's home page names. Tunnels to development hosts are listed below but don't count.`,
  });
  const age = (Date.now() - new Date(now.pulled).getTime()) / HOUR;
  items.push({
    label: 'This page',
    value: `Pulled ${clockFormat.format(new Date(now.pulled))} UTC${age >= 1 ? `, ${Math.floor(age)} h ago` : ''}`,
    off: age > 3,
    about: 'Pulled from Cloudflare every hour. Off when the last pull is over 3 hours old.',
  });
  const off = items.filter((i) => i.off);
  $('glance-title').textContent = off.length ? `${off.length} thing${off.length > 1 ? 's' : ''} to look at` : 'All fine';
  $('glance').dataset.off = String(off.length > 0);
  $('glance-sub').textContent = `The last 24 hours, to ${clockFormat.format(new Date(now.through))} UTC, against the 7 days before.`;
  $('checks').replaceChildren(
    ...[...off, ...items.filter((i) => !i.off)].map((i) => {
      const li = html('li');
      li.dataset.off = String(i.off);
      const mark = html('span', 'mark', i.off ? '!' : '✓');
      mark.setAttribute('aria-hidden', 'true');
      const text = html('div');
      text.append(html('span', 'label', i.label), html('span', 'value', `${i.off ? 'Off: ' : ''}${i.value}`));
      li.append(mark, text);
      return li;
    }),
  );
  /** @type {HTMLElement} */ ($('judged').querySelector('dl')).replaceChildren(...items.flatMap((i) => [html('dt', '', i.label), html('dd', '', i.about)]));
  table(/** @type {HTMLDetailsElement} */ ($('tunnels')), ['Serves', 'Public', 'Status', 'Connections'], now.tunnels.map((t) => [t.hosts.join(', '), t.public ? 'yes' : 'no, development', t.status, String(t.connections)]));
}

/** Whether a field's stored history covers a range: its days, or its hours for an hourly range. */
/** @param {Range} r @param {string} dayKey @param {string | null} hourKey */
function covers([, , length, hourly], dayKey, hourKey) {
  const last = /** @type {Day} */ (final.at(-1)).date;
  if (hourly && hourKey) {
    const from = firstHour.get(hourKey);
    return !!from && (new Date(now.through).getTime() - new Date(`${from}:00:00Z`).getTime()) / HOUR >= COVERED * length * 24;
  }
  const from = firstDay.get(dayKey);
  return !!from && (!length || daysBetween(from, last) + 1 >= COVERED * length);
}

/**
 * One chart's frame: the chosen range when its field's history covers it, else the widest shorter range that is
 * covered, said in `note`. Hourly ranges go by hour where the field has hours (hourKey), lists by their last days.
 * @param {string} dayKey @param {string | null} [hourKey]
 * @returns {Frame}
 */
function frame(dayKey, hourKey = dayKey) {
  const at = RANGES.findIndex(([id]) => id === state.range);
  const range = RANGES.slice(0, at + 1).reverse().find((r) => covers(r, dayKey, hourKey)) ?? RANGES[at];
  const [, label, length, hourly] = range;
  const last = /** @type {Day} */ (final.at(-1)).date;
  const first = firstDay.get(dayKey) ?? last;
  const start = length ? addDays(last, 1 - length) : first;
  const back = (/** @type {number} */ n) => new Date(new Date(now.through).getTime() - n * HOUR).toISOString();
  const byHour = hourly && !!hourKey;
  const b = byHour ? hourBuckets(now.through, length * 24) : dayBuckets(start, last);
  const prev = byHour ? hourBuckets(back(length * 24), length * 24) : length && addDays(start, -length) >= first ? dayBuckets(addDays(start, -length), addDays(start, -1)) : null;
  const note = range === RANGES[at] ? '' : `Kept from ${longDayFormat.format(toDate(first))}, so this shows ${label === 'All' ? 'all of it' : label}.`;
  return { range, b, prev, start, last, listDays: final.filter((d) => d.date >= start), note };
}

/** Bucket helpers for one frame: names, chart specs and table rows, saying how many hours or days hold data. */
/** @param {Frame} f */
function framed(f) {
  const { b } = f;
  const word = b.unit === 'hour' ? 'hour' : 'day';
  /** @param {Buckets} bk @param {number} i @param {(d: Rec) => unknown} has */
  const whenOf = (bk, i, has) => {
    const n = bk.recs[i].filter((d) => has(d) != null).length, of = bk.size[i];
    return bk.when(i) + (n === of ? '' : n ? ` · ${n} of ${of} ${word}s` : ' · no data');
  };
  return {
    word,
    unitNote: b.unit === 'hour' ? ' an hour' : b.unit === 'day' ? ' a day' : ` a day · ${b.unit}ly averages`,
    head: { hour: 'Hour', day: 'Day', week: 'Week of', month: 'Month' }[b.unit],
    /** @param {Omit<ChartSpec, 'labels' | 'when' | 'rank'>} chart @param {(d: Rec) => unknown} has @returns {ChartSpec} */
    over: (chart, has) => ({ labels: b.keys.map((_, i) => b.label(i)), when: (i) => whenOf(b, i, has), rank: b.rank, ...chart }),
    /** Table rows, newest first. */
    /** @param {(d: Rec) => unknown} has @param {((i: number) => string)[]} cols */
    rows: (has, cols) => b.keys.map((_, i) => [whenOf(b, i, has), ...cols.map((c) => c(i))]).reverse(),
  };
}

/** @param {number | null} v @param {(n: number) => string} fmt */
const cell = (v, fmt) => (v == null ? 'no data' : fmt(v));

function render() {
  const url = new URL(location.href);
  url.searchParams.set('range', state.range);
  url.searchParams.set('metric', state.metric);
  history.replaceState(null, '', url);

  // The range control offers what the longest-kept chart, the daily totals, covers.
  const offered = RANGES.filter((r) => covers(r, 'requests', 'requests'));
  if (!offered.some(([id]) => id === state.range)) state.range = '24h';
  segmented($('ranges'), offered.map(([id, label]) => [id, label]), state.range, (id) => ((state.range = id), render()));

  const main = frame('requests');
  const { b, prev } = main;
  const [, , length, hourly] = main.range;
  const { word, unitNote, head: bucketHead, over, rows } = framed(main);
  const recs = b.recs.flat();
  const missing = b.size.reduce((s, n) => s + n, 0) - recs.length;
  const span = length || daysBetween(main.start, main.last) + 1;
  const listWhen = (/** @type {Frame} */ f) => (f.listDays.length === 1 ? longDayFormat.format(toDate(f.listDays[0].date)) : `${longDayFormat.format(toDate(f.start))} to ${longDayFormat.format(toDate(f.last))}`);
  $('through').textContent = hourly
    ? `Charts: the last ${length === 1 ? '24 hours' : '7 days'} by hour, to ${dayFormat.format(new Date(now.through))} ${clockFormat.format(new Date(now.through))} UTC${missing ? ` · ${missing} hours missing` : ''}. Lists: ${listWhen(main)}, by day.`
    : `${listWhen(main)}, UTC${missing ? ` · ${daysWord(missing)} missing` : ''}. A chart with less history shows what it has, and says so.`;

  // Headline numbers, each a button that picks the main chart.
  const metrics = METRICS.filter((m) => !(hourly && m.daily));
  if (!metrics.some((m) => m.id === state.metric)) state.metric = 'requests';
  const approxTotals = sampled(recs);
  $('kpis').replaceChildren(
    ...metrics.map((m) => {
      const v = measure(m, recs);
      const before = prev?.recs.flat() ?? [];
      const p = prev && before.length === recs.length && recs.length ? measure(m, before) : null;
      const btn = html('button', 'kpi');
      btn.type = 'button';
      btn.setAttribute('aria-pressed', String(m.id === state.metric));
      const delta = v == null || p == null || !p ? '' : m.total === 'ratio' ? `${v >= p ? '↑' : '↓'} ${(Math.abs(v - p) * 100).toFixed(1)} pts` : `${v >= p ? '↑' : '↓'} ${pct(Math.abs(v / p - 1))}`;
      const sub = missing ? `Over ${recs.length} of ${recs.length + missing} ${word}s` : delta ? `${delta} vs the ${length === 1 ? '24 hours' : `${span} days`} before` : length ? 'No earlier period yet' : 'All kept days';
      btn.append(html('span', 'label', m.label), html('span', 'value', v == null ? 'no data' : estimated(m.fmt, approxTotals && m.total !== 'ratio')(v)), html('span', 'delta', sub));
      btn.addEventListener('click', () => ((state.metric = m.id), render()));
      return btn;
    }),
  );

  const metric = /** @type {Metric} */ (metrics.find((m) => m.id === state.metric));
  const perBucket = metric.total === 'ratio' ? metric : { ...metric, total: /** @type {Total} */ ('avg') };
  const title = metric.total === 'sum' ? `${metric.label}${unitNote}` : `${metric.label}${b.unit === 'week' || b.unit === 'month' ? ` · ${b.unit}ly averages` : ''}`;
  $('metric-title').textContent = title;
  $('metric-about').textContent = [metric.about, approxTotals && '≈ Some hours are estimates from sampled data.', main.note].filter(Boolean).join(' ');
  const mainValues = b.recs.map((rs) => measure(perBucket, rs));
  drawChart($('main-chart'), over({ series: [{ name: metric.label, color: 'var(--s1)', values: mainValues }], fmt: metric.fmt, height: 240, title }, metric.num));
  table(/** @type {HTMLDetailsElement} */ ($('main-table')), [bucketHead, title], rows(metric.num, [(i) => cell(mainValues[i], metric.fmt)]));


  // Every other chart and list takes its own frame, as its stored history allows.
  errorsChart();
  speedChart();
  firewallChart();
  routesCharts();
  lists();
}

/** Errors: small multiples, each on its own scale, as 5xx is a sliver of 4xx. */
function errorsChart() {
  const f = frame('status');
  const { b, unitNote, head: bucketHead, over, rows } = { ...f, ...framed(f) };
  const recs = b.recs.flat();
  $('errors-note').textContent = ['Shares of all requests.', f.note].filter(Boolean).join(' ');
  const errors = /** @type {const} */ ([
    ['Client errors (4xx)', (/** @type {string} */ k) => k[0] === '4', 'var(--s2)'],
    ['Server errors (5xx)', (/** @type {string} */ k) => k[0] === '5', 'var(--s1)'],
    ["Couldn't reach Bitview (502, 504, 52x)", unreachable, 'var(--s3)'],
  ]).map(([name, test, color]) => {
    const values = b.recs.map((rs) => statusShare(rs, test));
    const box = html('div');
    const h = html('h3', '', name);
    const chart = html('div', 'chart');
    box.append(h, html('div', 'big', cell(statusShare(recs, test), finePct)), chart);
    return { name, color, values, box, chart };
  });
  $('errors').replaceChildren(...errors.map((e) => e.box));
  for (const e of errors) drawChart(e.chart, over({ series: [e], fmt: finePct, height: 110, title: `${e.name}, share of requests${unitNote}` }, statusOf));
  table(/** @type {HTMLDetailsElement} */ ($('errors-table')), [bucketHead, ...errors.map((e) => e.name)], rows(statusOf, errors.map((e) => (i) => cell(e.values[i], finePct))));
}

/** Speed: how long Bitview's servers took to answer what Cloudflare passed on. */
function speedChart() {
  const f = frame('origin');
  const { b, unitNote, head: bucketHead, over, rows } = { ...f, ...framed(f) };
  const recs = b.recs.flat();
  const speed = /** @type {const} */ ([['Median', 'p50', 'var(--s1)'], ['95th percentile', 'p95', 'var(--s2)']]).map(([name, q, color]) => ({
    name, color, values: b.recs.map((rs) => originTime(rs, q)), total: originTime(recs, q),
  }));
  const originHas = (/** @type {Rec} */ d) => d.origin?.p50;
  $('speed-note').textContent = `Only requests Cloudflare passed to Bitview's servers, not those it answered from its cache. ≈ From Cloudflare's sampled data.${b.unit === 'hour' ? '' : ' A day is its own median and 95th percentile; longer buckets average them.'}${f.note ? ` ${f.note}` : ''}`;
  legend($('speed-legend'), speed.map((s) => ({ ...s, value: cell(s.total, ms) })));
  drawChart($('speed-chart'), over({ series: speed, fmt: ms, height: 180, title: `Origin response time${unitNote}` }, originHas));
  table(/** @type {HTMLDetailsElement} */ ($('speed-table')), [bucketHead, ...speed.map((s) => s.name)], rows(originHas, speed.map((s) => (i) => cell(s.values[i], ms))));
}

/** Security: firewall events over time, and what acted on them. */
function firewallChart() {
  const f = frame('firewallActions', 'firewall');
  const { b, listDays, unitNote, head: bucketHead, over, rows } = { ...f, ...framed(f) };
  const recs = b.recs.flat();
  const fwValues = b.recs.map((rs) => (having(rs, firewallOf).length ? sum(rs, firewallOf) / (b.unit === 'week' || b.unit === 'month' ? having(rs, firewallOf).length : 1) : null));
  const fwTotal = having(recs, firewallOf).length ? sum(recs, firewallOf) : null;
  /** @type {Map<string, number>} */
  const actions = new Map();
  for (const d of listDays) for (const [k, v] of Object.entries(d.firewallActions?.counts ?? {})) actions.set(k, (actions.get(k) ?? 0) + v);
  const actionTotal = [...actions.values()].reduce((s, v) => s + v, 0);
  $('firewall-big').textContent = fwTotal == null ? 'no data' : `≈${count(fwTotal)}`;
  $('firewall-note').textContent = `Requests a Cloudflare security feature acted on. ≈ From Cloudflare's sampled events.${actionTotal ? ` Actions: ${[...actions].sort((a, z) => z[1] - a[1]).map(([k, v]) => `${words(k)} ${pct(v / actionTotal)}`).join(', ')}.` : ''}${f.note ? ` ${f.note}` : ''}`;
  drawChart($('firewall-chart'), over({ series: [{ name: 'Firewall events', color: 'var(--s1)', values: fwValues }], fmt: count, height: 150, title: `Firewall events${unitNote}` }, firewallOf));
  table(/** @type {HTMLDetailsElement} */ ($('firewall-table')), [bucketHead, `Firewall events${unitNote}`], rows(firewallOf, [(i) => cell(fwValues[i], (n) => `≈${count(n)}`)]));
}

/** API, pages and MCP: daily, from the routes, each on its own scale, as MCP is a sliver of API. */
function routesCharts() {
  const f = frame('routes', null);
  const db = f.b;
  const { over, rows } = framed(f);
  const routed = f.listDays.filter((d) => d.routes);
  const routeCover = coverage('routes', f.listDays, f.start, f.last);
  const approx = (/** @type {(n: number) => string} */ fmt) => estimated(fmt, routeCover.approx);
  const routeNote = [f.note, routeCover.note].filter(Boolean).join(' ');
  $('kinds-note').textContent = routeNote;
  /** @param {Rec} d @param {string} kind */
  const kindOf = (d, kind) => Object.values(d.routes?.counts[kind] ?? {}).reduce((s, /** @type {[number, number]} */ [r]) => s + r, 0);
  const kindTotal = sum(routed, (d) => KINDS.reduce((s, [k]) => s + kindOf(d, k), 0));
  const kinds = KINDS.map(([kind, color]) => {
    const total = sum(routed, (d) => kindOf(d, kind));
    const values = db.recs.map((ds) => {
      const r = ds.filter((d) => d.routes);
      return r.length ? sum(r, (d) => kindOf(d, kind)) / r.length : null;
    });
    const box = html('div');
    const h = html('h3', '', `${kind} requests`);
    h.append(html('span', '', kindTotal ? `${pct(total / kindTotal)} of all` : ''));
    const chart = html('div', 'chart');
    box.append(h, html('div', 'big', routed.length ? approx(count)(total) : 'no data'), chart);
    return { kind, color, values, box, chart };
  });
  $('kinds').replaceChildren(...kinds.map((k) => k.box));
  const kindUnit = db.unit === 'day' ? ' a day' : ` a day · ${db.unit}ly averages`;
  for (const { kind, color, values, chart } of kinds)
    if ((chart.hidden = db.keys.length < 2)) chart.replaceChildren();
    else drawChart(chart, over({ series: [{ name: kind, color, values }], fmt: approx(count), height: 130, title: `${kind} requests${kindUnit}` }, (d) => d.routes));
  table(/** @type {HTMLDetailsElement} */ ($('kinds-table')), ['Day', ...KINDS.map(([k]) => `${k}${kindUnit}`)], rows((d) => d.routes, kinds.map((k) => (i) => cell(k.values[i], approx(count)))));

  // Top routes, by requests or bandwidth, in one kind or all.
  segmented($('route-kind'), [['All', 'All'], ...KINDS.map(([k]) => /** @type {[string, string]} */ ([k, k]))], state.kind, (id) => ((state.kind = id), render()));
  segmented($('route-by'), [['requests', 'Requests'], ['bytes', 'Bandwidth']], state.by, (id) => ((state.by = id), render()));
  $('routes-note').textContent = routeNote;
  /** @type {Map<string, number>} */
  const routes = new Map();
  for (const d of routed)
    for (const [kind, rs] of Object.entries(d.routes?.counts ?? {}))
      if (state.kind === 'All' || state.kind === kind)
        for (const [key, [req, by]] of Object.entries(rs)) routes.set(key, (routes.get(key) ?? 0) + (state.by === 'bytes' ? by : req));
  rankList($('routes'), [...routes].map(([key, value]) => ({ key, ...route(key), value })), approx(state.by === 'bytes' ? bytes : count), state.by === 'bytes' ? 'Bandwidth' : 'Requests');
}

/** Every breakdown's ranked list, over its own frame's days. */
function lists() {
  for (const bd of BREAKDOWNS) {
    const f = frame(bd.key, null);
    const cover = coverage(bd.key, f.listDays, f.start, f.last);
    /** @type {Map<string, number>} */
    const tally = new Map();
    for (const d of f.listDays) for (const [k, v] of Object.entries(d[bd.key]?.counts ?? {})) tally.set(k, (tally.get(k) ?? 0) + v);
    const lead = bd.key === 'bots' ? botsLead(tally) : '';
    $(`${bd.key}-note`).textContent = [lead, bd.about, f.note, cover.note].filter(Boolean).join(' ');
    rankList($(bd.key), [...tally].map(([key, value]) => ({ key, label: bd.label?.(key) ?? key, value })), estimated(count, cover.approx), bd.unit ?? 'Requests', bd.limit ?? 6);
  }
}

/** Bot or human, as far as this plan can tell: only bots Cloudflare has verified are known. */
/** @param {Map<string, number>} tally */
function botsLead(tally) {
  const all = [...tally.values()].reduce((s, v) => s + v, 0);
  if (!all) return '';
  const bots = all - (tally.get('') ?? 0);
  return `${pct(bots / all)} of requests came from bots Cloudflare has verified. The rest mixes people and other bots: telling them apart takes Cloudflare's bot score, which this plan doesn't include.`;
}

/** pull.py's marks, in the order a visitor cares about: what is held back first. */
const MARKS = [
  ['not published', '○ Not published', 'Cloudflare offers it; nothing of ours reads it.'],
  ['grouped', '◐ Published grouped', 'Read, then reduced before anything is written.'],
  ['published', '● Published', 'As Cloudflare gives it, counted per day or hour.'],
];
const SCOPES = { zone: "bitview.space's requests", account: 'Web Analytics' };

/** The "What we can see" table and the dataset list, from what Cloudflare's API lists for this account. */
/** @param {Inventory} inv */
function inventory(inv) {
  const last = inv.policy[inv.policy.length - 1];
  const groups = MARKS.map(([mark, title, meaning]) => {
    const group = html('div', 'marks');
    const h = html('h3', '', title);
    h.append(html('span', '', meaning));
    const list = html('ul', 'inv');
    for (const r of inv.policy.filter((r) => r.mark === mark)) {
      const li = html('li');
      const how = html('div', 'how', r.how);
      how.append(html('code', '', r === last ? `${r.fields.length} more field names, listed in data/inventory.json` : r.fields.join(' · ')));
      li.append(html('div', 'what', r.what), how, html('div', 'kept', `kept up to ${r.kept}`));
      list.append(li);
    }
    group.append(h, list);
    return group;
  });
  $('inventory').replaceChildren(...groups);
  const toggle = $('show-fields');
  toggle.onclick = () => {
    const on = $('inventory').classList.toggle('show-fields');
    toggle.setAttribute('aria-pressed', String(on));
    toggle.textContent = `${on ? 'Hide' : 'Show'} Cloudflare's field names`;
  };

  const read = inv.datasets.filter((d) => d.read);
  $('reads').textContent = `${read.map((d) => d.name).join(', ')} (${read.length} of the ${inv.datasets.length} datasets Cloudflare offers)`;
  const details = /** @type {HTMLDetailsElement} */ ($('datasets'));
  /** @type {HTMLElement} */ (details.querySelector('summary')).textContent = `All ${inv.datasets.length} datasets`;
  const rank = (/** @type {Dataset} */ d) => Number(!d.read) + Number(!d.visitors);
  const list = [...inv.datasets].sort((a, z) => rank(a) - rank(z) || a.name.localeCompare(z.name));
  table(details, ['Dataset', 'Records', 'Kept', 'Fields', 'Read by pull.py'], list.map((d) => [
    d.name, d.visitors ? SCOPES[/** @type {keyof SCOPES} */ (d.scope)] : "Cloudflare's other products", d.kept, String(d.fields.length), d.read ? 'yes' : '',
  ]));
}

async function load() {
  /** @param {string} path */
  const get = async (path) => {
    const r = await fetch(path, { cache: 'no-cache' });
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return r.json();
  };
  const [{ months }, inv, latest] = await Promise.all([get('data/index.json'), get('data/inventory.json'), get('data/now.json')]);
  now = latest;
  inventory(inv);
  const files = await Promise.all(months.map((/** @type {string} */ m) => get(`data/${m}.json`)));
  days = files.flatMap((f) => Object.entries(f).map(([date, d]) => ({ date, ...d }))).sort((a, z) => (a.date < z.date ? -1 : 1));
  byDate = new Map(days.map((d) => [d.date, d]));
  hours = new Map(days.flatMap((d) => Object.entries(d.hours ?? {}).map(([h, rec]) => [`${d.date}T${h}`, /** @type {Rec} */ (rec)])));
  final = days.filter((d) => d.requests != null);
  for (const d of final) for (const key of Object.keys(d)) if (!firstDay.has(key)) firstDay.set(key, d.date);
  for (const [k, h] of [...hours].sort((a, z) => (a[0] < z[0] ? -1 : 1))) for (const key of Object.keys(h)) if (!firstHour.has(key)) firstHour.set(key, k);
  for (const [id, from] of [['from-totals', firstDay.get('requests')], ['from-sampled', firstDay.get('routes')], ['from-hours', firstHour.get('requests')?.slice(0, 10)]])
    $(id).textContent = from ? longDayFormat.format(toDate(from)) : 'not yet';
  for (const bd of BREAKDOWNS) {
    if (!bd.group) continue;
    const card = html('section', 'card');
    card.setAttribute('aria-labelledby', `${bd.key}-title`);
    const title = html('h2', '', bd.title);
    title.id = `${bd.key}-title`;
    const note = html('p', 'note');
    note.id = `${bd.key}-note`;
    const list = html('div');
    list.id = bd.key;
    card.append(title, note, list);
    $(bd.group).append(card);
  }
  glance();
  render();
  document.querySelector('main')?.classList.remove('loading');
}

load().catch((e) => {
  $('glance-title').textContent = `Couldn't load the data (${e.message}).`;
  throw e;
});
