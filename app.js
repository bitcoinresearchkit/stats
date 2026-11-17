// @ts-check
// What Bitview can see: reads data/ (written by pull.py) and draws it. No framework, no build.

/**
 * @typedef {{
 *   requests?: number, cachedRequests?: number, bytes?: number, cachedBytes?: number, pageViews?: number, uniques?: number,
 *   sampleInterval?: number, firewall?: number, origin?: { p50?: number, p95?: number, sampleInterval: number },
 *   [field: string]: any
 * }} Rec  One stored day or hour; a day's breakdowns are Sampled, an hour's status is plain counts
 * @typedef {Rec & { date: string, hours?: Record<string, Rec> }} Day
 * @typedef {{ note: string, approx: boolean }} Coverage
 * @typedef {'sum' | 'avg' | 'ratio'} Total
 * @typedef {{ id: string, label: string, about: string, num: (d: Rec) => number | undefined, den?: (d: Rec) => number | undefined, total: Total, fmt: (n: number) => string, daily?: boolean }} Metric
 * @typedef {{ name: string, color: string, values: (number | null)[] }} Series
 * @typedef {{ labels: string[], when: (i: number) => string, rank: (i: number) => number, series: Series[], fmt: (n: number) => string, height: number, title: string, ticks?: number }} ChartSpec
 *   fmt: values, with ≈ when they are estimates; the axis shows the same numbers without it
 * @typedef {{ key: string, label: string, sub?: string, value: number }} Row
 * @typedef {{ key: string, title: string, unit?: string, about?: string, label?: (k: string) => string }} Breakdown
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
const KINDS = ['API', 'Pages', 'MCP'];
const HOME = 'bitview.space';
const LIST = 8;
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
/** @param {number | null} v @param {(n: number) => string} fmt */
const cell = (v, fmt) => (v == null ? 'no data' : fmt(v));

/** A Cloudflare name for reading: "searchEngine" -> "Search engine". */
/** @param {string} s */
const words = (s) => s && s[0].toUpperCase() + s.slice(1).replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
/** HTTP's names for the codes Bitview answers with, else the code's class. */
const STATUS = {
  200: 'OK', 202: 'Accepted', 204: 'No content', 206: 'Partial content', 301: 'Moved permanently', 302: 'Found',
  304: 'Not modified', 307: 'Temporary redirect', 308: 'Permanent redirect', 400: 'Bad request', 401: 'Unauthorized',
  403: 'Forbidden', 404: 'Not found', 405: 'Method not allowed', 408: 'Request timeout', 413: 'Content too large',
  429: 'Too many requests', 499: 'Client closed request', 500: 'Internal server error', 502: 'Bad gateway',
  503: 'Service unavailable', 504: 'Gateway timeout', 520: 'Unknown error', 521: 'Web server is down',
  522: 'Connection timed out', 523: 'Origin is unreachable', 524: 'A timeout occurred', 525: 'SSL handshake failed',
  526: 'Invalid SSL certificate', 530: 'Origin DNS error',
  1: 'Info', 2: 'Success', 3: 'Redirect', 4: 'Client error', 5: 'Server error',
};
/** Cloudflare's security features, as its firewall events name them. */
const SOURCES = {
  bic: 'Browser integrity check', firewallManaged: 'Managed rules', firewallCustom: 'Custom rules', firewallRules: 'Firewall rules',
  securitylevel: 'Security level', ratelimit: 'Rate limiting', hot: 'Hotlink protection', l7ddos: 'DDoS protection',
  waf: 'WAF', uablock: 'User agent blocking', zonelockdown: 'Zone lockdown', validation: 'Request validation', botFight: 'Bot fight mode',
};
/** @param {string} k */
const source = (k) => SOURCES[/** @type {keyof SOURCES} */ (k)] ?? k;
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

/** Every stored daily breakdown, drawn as a ranked list. */
/** @type {Record<string, Breakdown>} */
const BREAKDOWNS = Object.fromEntries(/** @type {Breakdown[]} */ ([
  { key: 'status', title: 'Status codes', label: (k) => `${k} ${STATUS[/** @type {keyof STATUS} */ (k)] ?? STATUS[/** @type {keyof STATUS} */ (k[0])] ?? ''}` },
  { key: 'firewallRules', title: 'By rule', unit: 'Events', label: source },
  { key: 'countries', title: 'Countries', label: country },
  { key: 'colos', title: 'Edge locations', about: "Cloudflare's data centers that answered." },
  { key: 'browsers', title: 'Browsers', unit: 'Page views' },
  { key: 'os', title: 'Systems' },
  { key: 'devices', title: 'Devices', label: words },
  { key: 'bots', title: 'Verified bots', label: (k) => k || 'Not a verified bot' },
  { key: 'ipClasses', title: 'Reputation', label: words, about: "Cloudflare's class for the client's network." },
  { key: 'contentTypes', title: 'Content' },
  { key: 'cache', title: 'Cache', label: words },
  { key: 'http', title: 'HTTP' },
  { key: 'tls', title: 'TLS' },
]).map((b) => [b.key, b]));
/** Breakdown cards: each a title and its tabs. Routes is its own card, with its own controls. */
const CARDS = [
  ['Status codes', ['status']],
  ['Where from', ['countries', 'colos']],
  ['Browsers and systems', ['browsers', 'os', 'devices']],
  ['Bots and networks', ['bots', 'ipClasses']],
  ['Delivery', ['contentTypes', 'cache', 'http', 'tls']],
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

// ------------------------------------------------------------------------------------------------------------- data

// Days are UTC day strings, YYYY-MM-DD; hours are YYYY-MM-DDTHH.
/** @param {string} day */
const toDate = (day) => new Date(`${day}T00:00:00Z`);
/** @param {string} day @param {number} n */
const addDays = (day, n) => new Date(toDate(day).getTime() + n * 864e5).toISOString().slice(0, 10);
/** @param {string} a @param {string} b */
const daysBetween = (a, b) => Math.round((toDate(b).getTime() - toDate(a).getTime()) / 864e5);
/** @param {Date} t */
const hourKey = (t) => t.toISOString().slice(0, 13);
/** @param {number} n */
const daysWord = (n) => `${n} day${n === 1 ? '' : 's'}`;

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
/** @param {Rec[]} recs */
const sampled = (recs) => recs.some((d) => (d.sampleInterval ?? 1) > 1.005);

/** @type {Day[]} */
let final = [];
/** @type {Map<string, Day>} */
let byDate = new Map();
/** @type {Map<string, Rec>} */
let hours = new Map();
/** @type {Now} */
let now;
/** The first stored day of each daily field, and the first stored hour (YYYY-MM-DDTHH) of each hourly one. */
/** @type {Map<string, string>} */
const firstDay = new Map();
/** @type {Map<string, string>} */
const firstHour = new Map();

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
    when: (i) => `${dayFormat.format(times[i])}, ${clockFormat.format(times[i])} to ${clockFormat.format(new Date(times[i].getTime() + HOUR))} UTC`,
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

/** What a stored breakdown covers over some days: the days it misses since it's kept, and how sampled it was. */
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

/** Bucket helpers for one frame: chart specs and table rows, saying how many hours or days hold data. */
/** @param {Frame} f */
function framed(f) {
  const { b } = f;
  const word = b.unit === 'hour' ? 'hour' : 'day';
  /** @param {number} i @param {(d: Rec) => unknown} has */
  const whenOf = (i, has) => {
    const n = b.recs[i].filter((d) => has(d) != null).length, of = b.size[i];
    return b.when(i) + (n === of ? '' : n ? `, ${n} of ${of} ${word}s` : ', no data');
  };
  return {
    unitNote: b.unit === 'hour' ? ' an hour' : b.unit === 'day' ? ' a day' : ` a day, ${b.unit}ly averages`,
    head: { hour: 'Hour', day: 'Day', week: 'Week of', month: 'Month' }[b.unit],
    /** @param {Omit<ChartSpec, 'labels' | 'when' | 'rank'>} chart @param {(d: Rec) => unknown} has @returns {ChartSpec} */
    over: (chart, has) => ({ labels: b.keys.map((_, i) => b.label(i)), when: (i) => whenOf(i, has), rank: b.rank, ...chart }),
    /** Table rows, newest first. */
    /** @param {(d: Rec) => unknown} has @param {((i: number) => string)[]} cols */
    rows: (has, cols) => b.keys.map((_, i) => [whenOf(i, has), ...cols.map((c) => c(i))]).reverse(),
  };
}

// ---------------------------------------------------------------------------------------------------------- drawing

/** @param {string} id */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));
/** @param {string} tag @param {string} [className] @param {string} [text] */
function html(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}
const SVG = 'http://www.w3.org/2000/svg';
/** @param {string} tag @param {Record<string, string | number>} attrs @param {Element} [parent] */
function svg(tag, attrs, parent) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  parent?.append(el);
  return el;
}

/** The page's few icons, as 24-unit stroke paths. */
const ICONS = {
  ok: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM8.5 12.2l2.4 2.3 4.6-4.9',
  off: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7.8v5M12 16.2v.1',
  hidden: 'M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.2A9.8 9.8 0 0 1 12 5c5 0 8.5 4.5 9.5 7a13 13 0 0 1-2.4 3.4M6.6 6.6C4.4 8 3 10.2 2.5 12c1 2.5 4.5 7 9.5 7 1.7 0 3.2-.5 4.5-1.2',
  grouped: 'M12 3l9 5-9 5-9-5 9-5ZM3 13l9 5 9-5',
  published: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
  chevron: 'M9 6l6 6-6 6',
};
/** @param {keyof ICONS} name @param {Element} [into] An existing <svg> to fill, else a new one */
function icon(name, into) {
  const el = into ?? svg('svg', { class: 'icon', viewBox: '0 0 24 24', 'aria-hidden': 'true' });
  el.replaceChildren(svg('path', { d: ICONS[name] }));
  return el;
}

/** Text width at the chart size, for laying out axis labels. */
const measurer = /** @type {CanvasRenderingContext2D} */ (document.createElement('canvas').getContext('2d'));
/** @param {string} s */
const textWidth = (s) => measurer.measureText(s).width;

/** A clean axis step for a maximum, so ticks read 0 / 250K / 500K. */
/** @param {number} max @param {number} steps */
function niceStep(max, steps) {
  const raw = max / steps || 1;
  const p = 10 ** Math.floor(Math.log10(raw));
  return ([1, 2, 2.5, 5, 10].find((m) => m * p >= raw) ?? 10) * p;
}

/** @type {WeakMap<HTMLElement, ChartSpec & { width: number }>} */
const charts = new WeakMap();
const resize = new ResizeObserver((entries) => {
  for (const { target } of entries) {
    const el = /** @type {HTMLElement} */ (target), spec = charts.get(el);
    if (spec && spec.width !== el.clientWidth) drawChart(el, spec);
  }
});

/** A line chart on one y-axis, the first series filled when it stands alone, with a crosshair that snaps to buckets
 * (pointer, touch and arrow keys) and one tooltip listing every series. */
/** @param {HTMLElement} el @param {ChartSpec} spec */
function drawChart(el, spec) {
  const W = el.clientWidth;
  charts.set(el, { ...spec, width: W });
  resize.observe(el);
  const { labels, series, fmt, height } = spec;
  const n = labels.length;
  const all = /** @type {number[]} */ (series.flatMap((s) => s.values).filter((v) => v != null));
  const top = Math.max(0, ...all);
  const step = niceStep(top, spec.ticks ?? 4);
  const max = Math.max(step, step * Math.ceil(top / step));
  const ticks = Array.from({ length: Math.round(max / step) + 1 }, (_, i) => i * step);
  const tick = (/** @type {number} */ t) => fmt(t).replace('≈', '');
  const left = 8 + Math.max(...ticks.map((t) => textWidth(tick(t))));
  const pad = 8, bottom = 24, right = 4;
  const plotW = Math.max(1, W - left - right), plotH = height - pad - bottom;
  /** @param {number} i */
  const x = (i) => left + (n > 1 ? (i * plotW) / (n - 1) : plotW / 2);
  /** @param {number} v */
  const y = (v) => pad + plotH * (1 - v / max);

  const root = svg('svg', { width: W, height, viewBox: `0 0 ${W} ${height}`, role: 'img', tabindex: 0, 'aria-label': `${spec.title}. The table lists every value.` });
  for (const t of ticks) {
    svg('line', { x1: left, x2: W - right, y1: y(t), y2: y(t), stroke: t ? 'var(--line)' : 'var(--line2)', 'shape-rendering': 'crispEdges' }, root);
    svg('text', { x: left - 8, y: y(t) + 4, 'text-anchor': 'end' }, root).textContent = tick(t);
  }
  // Labels on the roundest buckets (midnights, then 12:00, 06:00…) that fill about half the room, newest first,
  // none crowding another.
  const gap = 24 + Math.max(...labels.map(textWidth));
  const fit = Math.max(2, Math.floor(plotW / gap));
  const indices = Array.from({ length: n }, (_, i) => i);
  const levels = [...new Set(indices.map(spec.rank))].sort((a, z) => a - z);
  const level = levels.findLast((l) => indices.filter((i) => spec.rank(i) >= l).length >= Math.min(fit / 2, n)) ?? 0;
  let prior = Infinity;
  for (const i of indices.filter((i) => spec.rank(i) >= level).reverse()) {
    if (prior - x(i) < gap) continue;
    prior = x(i);
    const half = textWidth(labels[i]) / 2;
    const anchor = n === 1 ? 'middle' : x(i) - half < left ? 'start' : x(i) + half > W - right ? 'end' : 'middle';
    svg('text', { x: x(i), y: height - 6, 'text-anchor': anchor }, root).textContent = labels[i];
  }

  const fill = series.filter((s) => s.color !== 'var(--spark)').length === 1;
  for (const s of series) {
    /** @type {[number, number][][]} */
    const runs = [];
    s.values.forEach((v, i) => {
      if (v == null) return;
      if (s.values[i - 1] != null) runs.at(-1)?.push([x(i), y(v)]);
      else runs.push([[x(i), y(v)]]);
    });
    const muted = s.color === 'var(--spark)';
    for (const run of runs) {
      const d = run.map(([px, py], k) => `${k ? 'L' : 'M'}${px.toFixed(1)},${py.toFixed(1)}`).join('');
      if (fill && !muted && run.length > 1)
        svg('path', { d: `${d}L${run.at(-1)?.[0]},${y(0)}L${run[0][0]},${y(0)}Z`, fill: s.color, 'fill-opacity': 0.08 }, root);
      svg('path', { d, fill: 'none', stroke: s.color, 'stroke-width': muted ? 1.5 : 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, root);
      if (run.length === 1) svg('circle', { cx: run[0][0], cy: run[0][1], r: 2.5, fill: s.color }, root);
    }
  }

  const cross = svg('g', { visibility: 'hidden', 'pointer-events': 'none' }, root);
  const hair = svg('line', { y1: pad, y2: pad + plotH, stroke: 'var(--line2)' }, cross);
  const dots = series.map((s) => svg('circle', { r: 4, fill: s.color, stroke: 'var(--panel)', 'stroke-width': 2 }, cross));
  const tip = html('div', 'tip');
  tip.hidden = true;
  let at = -1;
  /** @param {number} i */
  const show = (i) => {
    at = Math.max(0, Math.min(n - 1, i));
    const px = x(at);
    hair.setAttribute('x1', String(px));
    hair.setAttribute('x2', String(px));
    tip.replaceChildren(html('div', 'when', spec.when(at)));
    series.forEach((s, k) => {
      const v = s.values[at];
      dots[k].setAttribute('visibility', v == null ? 'hidden' : 'visible');
      if (v != null) (dots[k].setAttribute('cx', String(px)), dots[k].setAttribute('cy', String(y(v))));
      const row = html('div', 'row');
      const key = html('span', 'key');
      key.style.background = s.color;
      row.append(key, html('b', '', cell(v, fmt)), html('span', '', s.name));
      tip.append(row);
    });
    cross.setAttribute('visibility', 'visible');
    tip.hidden = false;
    const w = tip.offsetWidth;
    // A transform, not `left`: following the pointer moves no layout.
    tip.style.transform = `translateX(${px + 12 + w > W ? Math.max(0, px - 12 - w) : px + 12}px)`;
  };
  const hide = () => ((tip.hidden = true), cross.setAttribute('visibility', 'hidden'), (at = -1));
  /** @param {PointerEvent} e */
  const point = (e) => show(Math.round(((e.offsetX - left) / plotW) * (n - 1)));
  root.addEventListener('pointermove', point);
  root.addEventListener('pointerdown', point);
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

/** A sparkline: the last `recent` points in the accent, the ones before in grey. Decorative: its numbers are beside it. */
/** @param {(number | null)[]} values @param {number} recent */
function sparkline(values, recent) {
  const W = 72, H = 20, n = values.length;
  const max = Math.max(...values.map((v) => v ?? 0)) || 1;
  const root = svg('svg', { class: 'spark', viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true' });
  /** @param {number} from @param {number} to @param {string} color */
  const line = (from, to, color) => {
    const d = values.slice(from, to).map((v, k) => (v == null ? '' : `${k && values[from + k - 1] != null ? 'L' : 'M'}${(((from + k) / (n - 1)) * W).toFixed(1)},${(H - 1 - (v / max) * (H - 2)).toFixed(1)}`)).join('');
    if (d) svg('path', { d, fill: 'none', stroke: color, 'stroke-width': color === 'var(--s1)' ? 2 : 1.5, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, root);
  };
  line(0, n - recent + 1, 'var(--spark)');
  line(n - recent, n, 'var(--s1)');
  return root;
}

/** A chart's table twin, in a closed disclosure: one row per bucket, newest first. */
/** @param {HTMLElement} details @param {string[]} heads @param {string[][]} rows */
function table(details, heads, rows) {
  const summary = html('summary');
  summary.append(icon('chevron'), 'Table');
  const t = html('table');
  const head = /** @type {HTMLTableElement} */ (t).createTHead().insertRow();
  for (const h of heads) head.append(html('th', '', h));
  const body = /** @type {HTMLTableElement} */ (t).createTBody();
  for (const r of rows) {
    const tr = body.insertRow();
    for (const c of r) tr.insertCell().textContent = c;
  }
  const scroll = html('div', 'scroll');
  scroll.append(t);
  details.replaceChildren(summary, scroll);
}

/** A row of toggle buttons; the pressed one is the current choice. */
/** @param {HTMLElement} el @param {[string, string][]} options @param {string} current @param {(id: string) => void} pick */
function choices(el, options, current, pick) {
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

/** A ranked list: name over a bar of its share of the top one, value, share of all; the first few, then all. */
/** @type {Set<string>} */
const expanded = new Set();
/** @param {HTMLElement} el @param {string} id @param {Row[]} rows @param {(n: number) => string} fmt @param {string} valueHead */
function rankList(el, id, rows, fmt, valueHead) {
  rows.sort((a, b) => b.value - a.value);
  if (!rows.length) return el.replaceChildren(html('p', 'empty', 'No data in this range.'));
  const total = rows.reduce((s, r) => s + r.value, 0);
  const open = expanded.has(id);
  const head = html('div', 'rank-head');
  head.append(html('span', '', `${rows.length} in all`), html('span', '', valueHead), html('span', '', 'Share'));
  const list = html('ol', 'rank');
  for (const r of open ? rows : rows.slice(0, LIST)) {
    const li = html('li');
    const name = html('span', 'name');
    name.style.setProperty('--w', `${(r.value / rows[0].value) * 100}%`);
    if (r.sub) name.append(html('small', '', r.sub));
    // A path may break after any slash, never inside a word.
    name.append(...r.label.split(/(?<=\/)/).flatMap((part, k) => (k ? [html('wbr'), part] : [part])));
    const share = total ? r.value / total : 0;
    li.append(name, html('span', 'v', fmt(r.value)), html('span', 's', share && share < 0.001 ? '<0.1%' : pct(share)));
    list.append(li);
  }
  el.replaceChildren(head, list);
  if (rows.length > LIST) {
    const more = html('button', 'more', open ? 'Show fewer' : `Show all ${rows.length}`);
    more.append(icon('chevron'));
    more.setAttribute('aria-expanded', String(open));
    more.addEventListener('click', () => {
      open ? expanded.delete(id) : expanded.add(id);
      rankList(el, id, rows, fmt, valueHead);
    });
    el.append(more);
  }
}

/** One breakdown summed over its own frame's days, with what its numbers cover. */
/** @param {Breakdown} bd */
function tally(bd) {
  const f = frame(bd.key, null);
  const cover = coverage(bd.key, f.listDays, f.start, f.last);
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const d of f.listDays) for (const [k, v] of Object.entries(d[bd.key]?.counts ?? {})) counts.set(k, (counts.get(k) ?? 0) + v);
  return { counts, fmt: estimated(count, cover.approx), notes: [bd.about, f.note, cover.note] };
}

// ------------------------------------------------------------------------------------------------------------- page

const params = new URLSearchParams(location.search);
const state = {
  range: RANGES.some(([id]) => id === params.get('range')) ? /** @type {string} */ (params.get('range')) : '24h',
  metric: METRICS.some((m) => m.id === params.get('metric')) ? /** @type {string} */ (params.get('metric')) : 'requests',
  kind: 'All',
  by: 'requests',
  /** @type {Record<string, string>} The open tab of each breakdown card */
  tabs: Object.fromEntries(CARDS.map(([title, keys]) => [title, keys[0]])),
};

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
  { label: 'Firewall events a day', read: (hs) => (having(hs, firewallOf).length ? (sum(hs, firewallOf) / having(hs, firewallOf).length) * 24 : null), fmt: (n) => `≈${count(Math.round(n))}`, limit: 1000, times: 5,
    about: 'Requests a Cloudflare security feature acted on. Off above 1,000 a day and 5× usual.' },
  { label: 'Served from cache', read: (hs) => measure(/** @type {Metric} */ (METRICS.find((m) => m.id === 'cache')), hs), fmt: pct, limit: 0.05, times: 0.5, low: true,
    about: 'Off below half its usual share, or 5%.' },
];

/** The status card: a verdict, then every check with its last week by hour, the tunnels and the pull. */
function status() {
  const recent = hourBuckets(now.through, 24).recs.flat();
  const week = hourBuckets(now.through, 192).recs;
  const before = week.slice(0, 168).flat();
  /** @type {{ label: string, value: string, usual: string, off: boolean, about: string, spark?: (number | null)[], extra?: HTMLElement }[]} */
  const items = CHECKS.map((c) => {
    const v = c.read(recent), usual = c.read(before);
    const scaled = usual == null || !c.times ? true : c.low ? v != null && v < usual * c.times : v != null && v > usual * c.times;
    const off = v != null && (c.low ? v < c.limit || scaled : v > c.limit && scaled);
    return { label: c.label, value: cell(v, c.fmt), usual: usual == null ? '' : `usual ${c.fmt(usual)}`, off, about: c.about, spark: week.map((h) => c.read(h)) };
  });
  const serving = now.tunnels.filter((t) => t.public);
  const down = serving.filter((t) => t.status !== 'healthy');
  const tunnels = html('details', 'table');
  table(tunnels, ['Serves', 'Public', 'Status', 'Connections'], now.tunnels.map((t) => [t.hosts.join(', '), t.public ? 'yes' : 'no, development', t.status, String(t.connections)]));
  items.unshift({
    label: 'Tunnels to Bitview',
    value: down.length ? `${down.length} of ${serving.length} down: ${down.map((t) => `${t.hosts.join(', ')} (${t.status})`).join('; ')}` : `${serving.length} of ${serving.length} healthy`,
    usual: '',
    off: down.length > 0,
    about: "Cloudflare's status, at the last pull, for each tunnel serving a host Bitview's home page names. Tunnels to development hosts are listed here but don't count.",
    extra: tunnels,
  });
  const age = (Date.now() - new Date(now.pulled).getTime()) / HOUR;
  const pulled = `${clockFormat.format(new Date(now.pulled))} UTC`;
  items.push({
    label: 'This page',
    value: age >= 1 ? `Pulled ${Math.floor(age)} h ago` : 'On time',
    usual: '',
    off: age > 3,
    about: 'Pulled from Cloudflare every hour. Off when the last pull is over 3 hours old.',
  });
  const off = items.filter((i) => i.off);
  $('updated').textContent = `Updated ${pulled}`;
  $('verdict').textContent = off.length ? `${off.length} thing${off.length > 1 ? 's' : ''} to look at` : 'All fine';
  icon(off.length ? 'off' : 'ok', $('verdict-icon'));
  $('status').dataset.off = String(off.length > 0);
  $('verdict-sub').textContent = `The last 24 hours, to ${clockFormat.format(new Date(now.through))} UTC, against the 7 days before. Open a check for how it's judged.`;
  $('checks').replaceChildren(
    ...[...off, ...items.filter((i) => !i.off)].map((i) => {
      const li = html('li');
      li.dataset.off = String(i.off);
      const details = /** @type {HTMLDetailsElement} */ (html('details'));
      details.open = i.off;
      const summary = html('summary');
      const val = html('span', 'val');
      val.append(html('span', '', i.value));
      if (i.usual) val.append(html('span', 'usual', i.usual));
      if (i.spark) val.append(sparkline(i.spark, 24));
      summary.append(icon(i.off ? 'off' : 'ok'), html('span', 'label', i.label), val, icon('chevron'));
      const about = html('div', 'about', `${i.off ? 'Off now. ' : ''}${i.about}`);
      if (i.extra) about.append(i.extra);
      details.append(summary, about);
      li.append(details);
      return li;
    }),
  );
}

function render() {
  const url = new URL(location.href);
  url.searchParams.set('range', state.range);
  url.searchParams.set('metric', state.metric);
  history.replaceState(null, '', url);

  // The range control offers what the longest-kept chart, the daily totals, covers.
  const offered = RANGES.filter((r) => covers(r, 'requests', 'requests')).map(([id]) => id);
  if (!offered.includes(state.range)) state.range = '24h';
  for (const b of /** @type {NodeListOf<HTMLButtonElement>} */ ($('ranges').querySelectorAll('button'))) {
    b.hidden = !offered.includes(b.value);
    b.setAttribute('aria-pressed', String(b.value === state.range));
    b.onclick = () => ((state.range = b.value), render());
  }

  overview();
  kinds();
  errors();
  speed();
  firewall();
  cards();
}

/** The headline numbers, each a tab of the main chart, which draws the period before in grey. */
function overview() {
  const main = frame('requests');
  const { b, prev } = main;
  const [, , length, hourly] = main.range;
  const { unitNote, head, over, rows } = framed(main);
  const recs = b.recs.flat();
  const missing = b.size.reduce((s, n) => s + n, 0) - recs.length;
  const word = b.unit === 'hour' ? 'hour' : 'day';
  const span = length || daysBetween(main.start, main.last) + 1;
  const period = length === 1 ? '24 hours' : `${span} days`;
  const through = new Date(now.through);
  $('through').textContent = hourly
    ? `The last ${period} by hour, to ${dayFormat.format(through)}, ${clockFormat.format(through)} UTC${missing ? `, ${missing} hours missing` : ''}. Lists cover ${main.listDays.length === 1 ? longDayFormat.format(toDate(main.listDays[0].date)) : `${dayFormat.format(toDate(main.start))} to ${dayFormat.format(toDate(main.last))}`}, by day.`
    : `${longDayFormat.format(toDate(main.start))} to ${longDayFormat.format(toDate(main.last))}, UTC${missing ? `, ${daysWord(missing)} missing` : ''}. A chart with less history shows what it has, and says so.`;

  const metrics = METRICS.filter((m) => !(hourly && m.daily));
  if (!metrics.some((m) => m.id === state.metric)) state.metric = 'requests';
  const approx = sampled(recs);
  const before = prev?.recs.flat() ?? [];
  $('kpis').replaceChildren(
    ...metrics.map((m) => {
      const v = measure(m, recs);
      const p = prev && before.length === recs.length && recs.length ? measure(m, before) : null;
      const btn = html('button', 'kpi');
      btn.type = 'button';
      btn.setAttribute('aria-pressed', String(m.id === state.metric));
      const delta = v == null || p == null || !p ? '' : m.total === 'ratio' ? `${v >= p ? '↑' : '↓'} ${(Math.abs(v - p) * 100).toFixed(1)} pts` : `${v >= p ? '↑' : '↓'} ${pct(Math.abs(v / p - 1))}`;
      const sub = missing ? `Over ${recs.length} of ${recs.length + missing} ${word}s` : delta ? `${delta} vs prior ${main.range[1]}` : length ? 'No earlier period' : 'Every kept day';
      btn.append(html('span', 'k', m.label), html('span', 'v', v == null ? 'no data' : estimated(m.fmt, approx && m.total !== 'ratio')(v)), html('span', 'd', sub));
      btn.addEventListener('click', () => ((state.metric = m.id), render()));
      return btn;
    }),
  );

  const metric = /** @type {Metric} */ (metrics.find((m) => m.id === state.metric));
  const perBucket = metric.total === 'ratio' ? metric : { ...metric, total: /** @type {Total} */ ('avg') };
  const title = metric.total === 'sum' ? `${metric.label}${unitNote}` : `${metric.label}${b.unit === 'week' || b.unit === 'month' ? `, ${b.unit}ly averages` : ''}`;
  const values = b.recs.map((rs) => measure(perBucket, rs));
  const earlier = prev && prev.keys.length === b.keys.length ? prev.recs.map((rs) => measure(perBucket, rs)) : null;
  /** @type {Series[]} */
  const series = [{ name: metric.label, color: 'var(--s1)', values }];
  if (earlier) series.push({ name: `The ${period} before`, color: 'var(--spark)', values: earlier });
  $('metric-about').textContent = [`${title}.`, metric.about, earlier && `Grey: the ${period} before.`, approx && '≈ Some hours are estimates from sampled data.', main.note].filter(Boolean).join(' ');
  drawChart($('main-chart'), over({ series, fmt: metric.fmt, height: 260, title }, metric.num));
  table($('main-table'), [head, title, ...(earlier ? [`The ${period} before`] : [])], rows(metric.num, [(i) => cell(values[i], metric.fmt), ...(earlier ? [(/** @type {number} */ i) => cell(earlier[i], metric.fmt)] : [])]));
}

/** Small multiples, each on its own scale, under a heading and its figure. */
/** @param {HTMLElement} el @param {{ name: string, figure: string, aside?: string, values: (number | null)[] }[]} items @param {(spec: Omit<ChartSpec, 'labels' | 'when' | 'rank'>) => ChartSpec} spec @param {(n: number) => string} fmt @param {string} unit */
function multiples(el, items, spec, fmt, unit) {
  const boxes = items.map((it) => {
    const box = html('div');
    const h = html('h3', '', it.name);
    if (it.aside) h.append(html('span', '', it.aside));
    const chart = html('div', 'chart');
    chart.style.setProperty('--h', '120px');
    box.append(h, html('div', 'figure', it.figure), chart);
    return { it, chart, box };
  });
  el.replaceChildren(...boxes.map((b) => b.box));
  for (const { it, chart } of boxes)
    if ((chart.hidden = it.values.length < 2)) chart.replaceChildren();
    else drawChart(chart, spec({ series: [{ name: it.name, color: 'var(--s1)', values: it.values }], fmt, height: 120, ticks: 2, title: `${it.name}${unit}` }));
}

/** API, pages and MCP: daily, from the routes, each on its own scale, as MCP is a sliver of API. */
function kinds() {
  const f = frame('routes', null);
  const { over, rows } = framed(f);
  const routed = f.listDays.filter((d) => d.routes);
  const cover = coverage('routes', f.listDays, f.start, f.last);
  const fmt = estimated(count, cover.approx);
  /** @param {Rec} d @param {string} kind */
  const kindOf = (d, kind) => Object.values(d.routes?.counts[kind] ?? {}).reduce((s, /** @type {[number, number]} */ [r]) => s + r, 0);
  const all = sum(routed, (d) => KINDS.reduce((s, k) => s + kindOf(d, k), 0));
  const unit = f.b.unit === 'day' ? ' a day' : ` a day, ${f.b.unit}ly averages`;
  const items = KINDS.map((kind) => {
    const total = sum(routed, (d) => kindOf(d, kind));
    const values = f.b.recs.map((ds) => {
      const r = ds.filter((d) => d.routes);
      return r.length ? sum(r, (d) => kindOf(d, kind)) / r.length : null;
    });
    return { name: `${kind} requests`, figure: routed.length ? fmt(total) : 'no data', aside: all ? `${pct(total / all)} of all` : '', values };
  });
  multiples($('kinds'), items, (s) => over(s, (d) => d.routes), fmt, unit);
  $('kinds-note').textContent = [`Requests${unit}, by what they asked for.`, f.note, cover.note].filter(Boolean).join(' ');
  table($('kinds-table'), ['Day', ...KINDS.map((k) => `${k}${unit}`)], rows((d) => d.routes, items.map((k) => (i) => cell(k.values[i], fmt))));
}

/** Errors: small multiples, each on its own scale, as 5xx is a sliver of 4xx. */
function errors() {
  const f = frame('status');
  const { unitNote, head, over, rows } = framed(f);
  const recs = f.b.recs.flat();
  const items = /** @type {const} */ ([
    ['Client errors (4xx)', (/** @type {string} */ k) => k[0] === '4'],
    ['Server errors (5xx)', (/** @type {string} */ k) => k[0] === '5'],
    ["Couldn't reach Bitview (502, 504, 52x)", unreachable],
  ]).map(([name, test]) => ({ name, figure: cell(statusShare(recs, test), finePct), values: f.b.recs.map((rs) => statusShare(rs, test)) }));
  multiples($('errors'), items, (s) => over(s, statusOf), finePct, `, share of requests${unitNote}`);
  $('errors-note').textContent = ['Shares of all requests.', f.note].filter(Boolean).join(' ');
  table($('errors-table'), [head, ...items.map((e) => e.name)], rows(statusOf, items.map((e) => (i) => cell(e.values[i], finePct))));

}

/** Speed: how long Bitview's servers took to answer what Cloudflare passed on. */
function speed() {
  const f = frame('origin');
  const { b, unitNote, head, over, rows } = { ...f, ...framed(f) };
  const recs = b.recs.flat();
  const lines = /** @type {const} */ ([['Median', 'p50', 'var(--s1)'], ['95th percentile', 'p95', 'var(--s2)']]).map(([name, q, color]) => ({
    name, color, values: b.recs.map((rs) => originTime(rs, q)), total: originTime(recs, q),
  }));
  const has = (/** @type {Rec} */ d) => d.origin?.p50;
  $('speed-legend').replaceChildren(
    ...lines.map((s) => {
      const item = html('span');
      const key = html('span', 'key');
      key.style.background = s.color;
      item.append(key, `${s.name} `, html('b', '', cell(s.total, ms)));
      return item;
    }),
  );
  $('speed-note').textContent = `Only requests Cloudflare passed to Bitview's servers, not those it answered from its cache. ≈ From Cloudflare's sampled data.${b.unit === 'hour' ? '' : ' A day is its own median and 95th percentile; longer buckets average them.'}${f.note ? ` ${f.note}` : ''}`;
  drawChart($('speed-chart'), over({ series: lines, fmt: ms, height: 200, title: `Origin response time${unitNote}` }, has));
  table($('speed-table'), [head, ...lines.map((s) => s.name)], rows(has, lines.map((s) => (i) => cell(s.values[i], ms))));
}

/** Security: firewall events over time, what acted on them, and by which rule. */
function firewall() {
  const f = frame('firewallActions', 'firewall');
  const { b, listDays, unitNote, head, over, rows } = { ...f, ...framed(f) };
  const recs = b.recs.flat();
  const values = b.recs.map((rs) => (having(rs, firewallOf).length ? sum(rs, firewallOf) / (b.unit === 'week' || b.unit === 'month' ? having(rs, firewallOf).length : 1) : null));
  const total = having(recs, firewallOf).length ? sum(recs, firewallOf) : null;
  /** @type {Map<string, number>} */
  const actions = new Map();
  for (const d of listDays) for (const [k, v] of Object.entries(d.firewallActions?.counts ?? {})) actions.set(k, (actions.get(k) ?? 0) + v);
  const actionTotal = [...actions.values()].reduce((s, v) => s + v, 0);
  $('firewall-total').textContent = total == null ? 'no data' : `≈${count(total)}`;
  drawChart($('firewall-chart'), over({ series: [{ name: 'Firewall events', color: 'var(--s1)', values }], fmt: count, height: 160, title: `Firewall events${unitNote}` }, firewallOf));
  table($('firewall-table'), [head, `Firewall events${unitNote}`], rows(firewallOf, [(i) => cell(values[i], (n) => `≈${count(n)}`)]));

  $('firewall-note').textContent = `Requests a Cloudflare security feature acted on. ≈ From Cloudflare's sampled events.${actionTotal ? ` Actions: ${[...actions].sort((a, z) => z[1] - a[1]).map(([k, v]) => `${words(k)} ${pct(v / actionTotal)}`).join(', ')}.` : ''}${f.note ? ` ${f.note}` : ''}`;
  const t = tally(BREAKDOWNS.firewallRules);
  rankList($('firewall-rules'), 'firewallRules', [...t.counts].map(([key, value]) => ({ key, label: source(key), value })), t.fmt, 'Events');
}

/** The breakdown cards: routes with its kind and measure, then the rest, each with its tabs. */
function cards() {
  const grid = $('cards');
  grid.replaceChildren(routesCard(), ...CARDS.map(([title, keys]) => {
    const key = state.tabs[title];
    const bd = BREAKDOWNS[key];
    const t = tally(bd);
    const card = html('section', 'panel');
    const header = html('header');
    const h = html('h2', '', title);
    header.append(h);
    if (keys.length > 1) {
      const tabs = html('div', 'tabs');
      tabs.setAttribute('role', 'group');
      tabs.setAttribute('aria-label', title);
      choices(tabs, keys.map((k) => [k, BREAKDOWNS[k].title]), key, (k) => ((state.tabs[title] = k), cards()));
      header.append(tabs);
    }
    const list = html('div');
    rankList(list, key, [...t.counts].map(([k, value]) => ({ key: k, label: bd.label?.(k) ?? k, value })), t.fmt, bd.unit ?? 'Requests');
    const lead = key === 'bots' ? botsLead(t.counts) : '';
    card.append(header, list, html('p', 'note', [lead, ...t.notes].filter(Boolean).join(' ')));
    return card;
  }));
}

/** Top routes, by requests or bandwidth, in one kind or all. */
function routesCard() {
  const f = frame('routes', null);
  const cover = coverage('routes', f.listDays, f.start, f.last);
  const card = html('section', 'panel');
  const header = html('header');
  const tabs = html('div', 'tabs');
  tabs.setAttribute('role', 'group');
  tabs.setAttribute('aria-label', 'Kind');
  choices(tabs, [['All', 'All'], ...KINDS.map((k) => /** @type {[string, string]} */ ([k, k]))], state.kind, (id) => ((state.kind = id), cards()));
  header.append(html('h2', '', 'Routes'), tabs);
  const by = html('div', 'seg');
  by.setAttribute('role', 'group');
  by.setAttribute('aria-label', 'Rank by');
  choices(by, [['requests', 'Requests'], ['bytes', 'Bandwidth']], state.by, (id) => ((state.by = id), cards()));
  by.style.marginBottom = '12px';
  /** @type {Map<string, number>} */
  const routes = new Map();
  for (const d of f.listDays)
    for (const [kind, rs] of Object.entries(d.routes?.counts ?? {}))
      if (state.kind === 'All' || state.kind === kind)
        for (const [key, [req, b]] of Object.entries(rs)) routes.set(key, (routes.get(key) ?? 0) + (state.by === 'bytes' ? b : req));
  const list = html('div');
  rankList(list, 'routes', [...routes].map(([key, value]) => {
    const slash = key.indexOf('/'), host = key.slice(0, slash);
    return { key, sub: host === HOME ? undefined : host, label: key.slice(slash), value };
  }), estimated(state.by === 'bytes' ? bytes : count, cover.approx), state.by === 'bytes' ? 'Bandwidth' : 'Requests');
  card.append(header, by, list, html('p', 'note', ["Each path reduced to its route: the API template, or the page's first folder, else (other).", f.note, cover.note].filter(Boolean).join(' ')));
  return card;
}

/** Bot or human, as far as this plan can tell: only bots Cloudflare has verified are known. */
/** @param {Map<string, number>} counts */
function botsLead(counts) {
  const all = [...counts.values()].reduce((s, v) => s + v, 0);
  if (!all) return '';
  return `${pct((all - (counts.get('') ?? 0)) / all)} of requests came from bots Cloudflare has verified. The rest mixes people and other bots: telling them apart takes Cloudflare's bot score, which this plan doesn't include.`;
}

/** pull.py's marks, in the order a visitor cares about: what is held back first. */
const MARKS = /** @type {const} */ ([
  ['not published', 'hidden', 'Not published', 'Cloudflare offers it; nothing of ours reads it.'],
  ['grouped', 'grouped', 'Published grouped', 'Read, then reduced before anything is written.'],
  ['published', 'published', 'Published', 'As Cloudflare gives it, counted per day or hour.'],
]);
const SCOPES = { zone: "bitview.space's requests", account: 'Web Analytics' };

/** The summary under the intro, the full "What we can see" list and the dataset list, from what Cloudflare's API
 * lists for this account. */
/** @param {Inventory} inv */
function inventory(inv) {
  const last = inv.policy[inv.policy.length - 1];
  $('marks').replaceChildren(
    ...MARKS.map(([mark, ic, title, meaning]) => {
      const rows = inv.policy.filter((r) => r.mark === mark);
      const li = html('li');
      const a = html('a');
      a.setAttribute('href', `#mark-${ic}`);
      a.append(icon(ic), html('b', '', `${title}: ${rows.length} kinds`), html('p', '', meaning));
      li.append(a);
      return li;
    }),
  );
  $('inventory-list').replaceChildren(
    ...MARKS.map(([mark, ic, title, meaning]) => {
      const group = html('div', 'inv-group');
      group.id = `mark-${ic}`;
      const h = html('h3');
      h.append(icon(ic), title, html('small', '', meaning));
      const list = html('ul', 'inv');
      for (const r of inv.policy.filter((r) => r.mark === mark)) {
        const li = html('li');
        const how = html('div', 'how', r.how);
        how.append(html('code', '', r === last ? `${r.fields.length} more field names, listed in data/inventory.json` : r.fields.join(', ')));
        li.append(html('div', 'what', r.what), how, html('div', 'kept', `kept up to ${r.kept}`));
        list.append(li);
      }
      group.append(h, list);
      return group;
    }),
  );
  const toggle = $('show-fields');
  toggle.onclick = () => {
    const on = $('inventory-list').classList.toggle('show-fields');
    toggle.setAttribute('aria-pressed', String(on));
    toggle.textContent = `${on ? 'Hide' : 'Show'} Cloudflare's field names`;
  };

  const read = inv.datasets.filter((d) => d.read);
  $('reads').textContent = `${read.length} of the ${inv.datasets.length} datasets Cloudflare offers`;
  const rank = (/** @type {Dataset} */ d) => Number(!d.read) + Number(!d.visitors);
  const list = [...inv.datasets].sort((a, z) => rank(a) - rank(z) || a.name.localeCompare(z.name));
  table($('datasets'), ['Dataset', 'Records', 'Kept', 'Fields', 'Read by pull.py'], list.map((d) => [
    d.name, d.visitors ? SCOPES[/** @type {keyof SCOPES} */ (d.scope)] : "Cloudflare's other products", d.kept, String(d.fields.length), d.read ? 'yes' : '',
  ]));
  /** @type {HTMLElement} */ ($('datasets').querySelector('summary')).lastChild.textContent = `All ${inv.datasets.length} datasets`;
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
  /** @type {Day[]} */
  const days = files.flatMap((f) => Object.entries(f).map(([date, d]) => ({ date, ...d }))).sort((a, z) => (a.date < z.date ? -1 : 1));
  byDate = new Map(days.map((d) => [d.date, d]));
  hours = new Map(days.flatMap((d) => Object.entries(d.hours ?? {}).map(([h, rec]) => [`${d.date}T${h}`, /** @type {Rec} */ (rec)])));
  final = days.filter((d) => d.requests != null);
  for (const d of final) for (const key of Object.keys(d)) if (!firstDay.has(key)) firstDay.set(key, d.date);
  for (const [k, h] of [...hours].sort((a, z) => (a[0] < z[0] ? -1 : 1))) for (const key of Object.keys(h)) if (!firstHour.has(key)) firstHour.set(key, k);
  for (const [id, from] of [['from-totals', firstDay.get('requests')], ['from-sampled', firstDay.get('routes')], ['from-hours', firstHour.get('requests')?.slice(0, 10)]])
    $(id).textContent = from ? longDayFormat.format(toDate(from)) : 'not yet';
  await document.fonts.load('12px Inter');
  measurer.font = `12px ${getComputedStyle(document.body).fontFamily}`;
  status();
  render();
  document.documentElement.classList.remove('loading');
  // The traffic bar draws its hairline only once it sticks.
  const bar = $('bar');
  new IntersectionObserver(([e]) => bar.classList.toggle('stuck', e.intersectionRatio < 1), { threshold: 1, rootMargin: '-1px 0px 0px 0px' }).observe(bar);
}

load().catch((e) => {
  document.documentElement.classList.remove('loading');
  $('verdict').textContent = `Couldn't load the data (${e.message}).`;
  throw e;
});
