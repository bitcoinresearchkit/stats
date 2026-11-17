#!/usr/bin/python3
"""Pull Bitview's traffic from Cloudflare's GraphQL Analytics API into data/, then commit and push.

Run every hour by a LaunchAgent. Only counts reach the disk, per day or per hour, by dimensions that can't point to a
person: each request path is mapped in memory to its route (see Routes), and no IP, raw user agent, referrer, ASN,
query string or account id is ever stored.

Per UTC hour H, complete once it has ended, stored under its day as "hours":
  H inside the exact hourly window (~3 days)   -> totals, status codes and origin time rewritten each run (late data)
  H older, inside the sampled window (~31 days) -> the same from sampled data, pulled once when missing
  H inside the firewall window (~30 days)       -> firewall event count rewritten each run, 0 when none
  H older than that                             -> kept as stored
Each run also writes data/now.json: when it ran, the last complete hour, and the status of the tunnels serving the zone.

Per UTC day D, "final" meaning D ended over an hour ago:
  D final, inside the daily window (~1 year)     -> totals and their breakdowns (MAPS) rewritten each run in one query
  D final, inside the sampled window (~31 days)  -> routes and DIMENSIONS pulled for D when missing, routes paged
  D final, inside the firewall window (~30 days) -> firewall events by action, feature and rule rewritten each run
  D final, all of them stored                    -> skipped: a final day doesn't change
  D not final                                 -> not pulled
  D older than Cloudflare keeps               -> kept as stored, never touched
  run stops midway (error, Mac asleep)        -> each day is saved as soon as it's pulled; the next run commits it
  push fails (offline)                        -> the commit stays local and goes out with the next run's push
  Cloudflare or network error                 -> exit non-zero with the message (launchd's log)
"""
import json, re, subprocess, sys, urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree

REPO = Path(__file__).resolve().parent
INVENTORY_START, INVENTORY_END = "<!-- inventory: written by pull.py -->", "<!-- end of inventory -->"
DATA = REPO / "data"
ZONE = "bitview.space"
SITE = f"https://{ZONE}"
CF = "https://api.cloudflare.com/client/v4"
CF_LOGIN = Path.home() / "Library/Preferences/cloudflare/config/default.json"
PAGE = 10000  # the most rows Cloudflare returns per query
DAILY, HOURLY, SAMPLED = "httpRequests1dGroups", "httpRequests1hGroups", "httpRequestsAdaptiveGroups"
OVERVIEW, FIREWALL = "httpRequestsOverviewAdaptiveGroups", "firewallEventsAdaptive"
# The only datasets this script queries; besides them it reads the zone's DNS names and its tunnels' status and hosts.
READ = {("zone", DAILY), ("zone", HOURLY), ("zone", SAMPLED), ("zone", OVERVIEW), ("zone", FIREWALL)}

# What this repository does with each field Cloudflare offers: (what, mark, how or why, field names). Every field of the
# datasets that record visitors lands in one row by name (see field_name); the last row takes the rest. Rows no such
# dataset has are left out.
POLICY = (
    ("Requests, bandwidth, cached share, page views, unique IPs", "published", "Totals per day, and per hour but for unique IPs.",
     {"requests", "bytes", "cachedRequests", "cachedBytes", "pageViews", "uniques", "count", "edgeResponseBytes"}),
    ("Country", "published", "Daily counts per country.", {"clientCountryName", "countryName"}),
    ("Status code", "published", "Counts per code, per day and per hour.", {"edgeResponseStatus"}),
    ("Firewall event", "published", "Counts per hour, and per day by action, by security feature and by rule name.",
     {"action", "source", "description"}),
    ("Origin response time", "published", "The median and the 95th percentile, per day and per hour.",
     {"originResponseDurationMs", "originResponseDurationMsP50", "originResponseDurationMsP95"}),
    ("Browser", "published", "Daily counts per browser family, without version.", {"uaBrowserFamily", "userAgentBrowser"}),
    ("Operating system", "published", "Daily counts per system, without version.", {"userAgentOS"}),
    ("Device type", "published", "Daily counts: desktop, mobile, tablet.", {"clientDeviceType", "deviceType"}),
    ("Verified bot", "published", "Daily counts per Cloudflare bot category.", {"verifiedBotCategory"}),
    ("IP reputation class", "published", "Daily counts per Cloudflare class (search engine, Tor…), never the IP.", {"ipType", "clientIPClass"}),
    ("Content type", "published", "Daily counts per type.", {"edgeResponseContentTypeName"}),
    ("Cache status", "published", "Daily counts per status.", {"cacheStatus"}),
    ("HTTP version", "published", "Daily counts per version.", {"clientHTTPProtocol", "clientRequestHTTPProtocol"}),
    ("TLS version", "published", "Daily counts per version.", {"clientSSLProtocol"}),
    ("Cloudflare location", "published", "Daily counts per Cloudflare data center.", {"coloCode", "coloName", "edgeColoName"}),
    ("Day, sample rate", "published", "Every count is per UTC day or hour, with Cloudflare's sample rate.", {"date", "sampleInterval"}),
    ("Time", "grouped", "Reduced to the hour for totals, status codes, firewall events and origin times; everything else "
     "is per day.",
     {"datetime", "datetimeHour"}),
    ("Host", "grouped", "Kept when it is a name in bitview.space's DNS, else (other).", {"clientRequestHTTPHost", "requestHost"}),
    ("Path", "grouped", "Reduced to its route: the API template from openapi.json, or a first folder the sitemap or home "
     "page names, else (other). A path holds the address, transaction or search someone looked up.",
     {"clientRequestPath", "requestPath"}),
    ("IP address", "not published", "Identifies a person or a household.",
     {"clientIP", "sourceIP", "ip", "destinationIP", "originIP", "upstreamIP"}),
    ("Device model, email sender, user id", "not published", "Point to one person or one device.",
     {"deviceModel", "deviceVendor", "headerFrom", "fraudUserId"}),
    ("Full user agent", "not published", "Detailed enough to single out one browser.", {"userAgent"}),
    ("Network (ASN)", "not published", "On a small network it points to a person or a company.", {"clientAsn", "clientASNDescription"}),
    ("Query string", "not published", "Holds what people looked up.", {"clientRequestQuery"}),
    ("Referring site and page", "not published", "Where someone came from. Published as hosts until 2026-11-17, from Web "
     "Analytics, which was then turned off and the counts deleted.", {"clientRefererHost", "refererHost", "clientRefererPath", "clientRefererQuery", "refererPath"}),
    ("Page address in Web Analytics", "not published", "The full address of a page someone viewed, which holds what they "
     "looked up.", {"url", "pageUrl", "urlPath", "urlParams", "largestContentfulPaintPath", "largestContentfulPaintObjectPath",
     "cumulativeLayoutShiftPath", "firstInputDelayPath", "interactionToNextPaintPath"}),
    ("Request and session ids", "not published", "Tie a record to one request or one visitor.",
     {"rayName", "originatorRayName", "sessionId", "sessionIdHash", "apiGatewayMatchedSessionIdentifier", "messageId"}),
    ("Minutes", "not published", "Hours at most: on a quiet minute, a breakdown can single out one visit.",
     {"datetimeMinute", "datetimeFiveMinutes", "datetimeFifteenMinutes", "datetimeHalfOfHour"}),
    ("Everything else", "not published", "Not read: browser and system versions, security rules and "
     "their matches, performance timings, and fields of other Cloudflare features.", set()),
)

# Breakdowns of the exact daily rollups (a year back): stored key -> (map, its dimension, its count).
MAPS = {
    "countries": ("countryMap", "clientCountryName", "requests"),
    "status": ("responseStatusMap", "edgeResponseStatus", "requests"),
    "browsers": ("browserMap", "uaBrowserFamily", "pageViews"),
    "contentTypes": ("contentTypeMap", "edgeResponseContentTypeName", "requests"),
    "http": ("clientHTTPVersionMap", "clientHTTPProtocol", "requests"),
    "tls": ("clientSSLMap", "clientSSLProtocol", "requests"),
    "ipClasses": ("ipClassMap", "ipType", "requests"),
}
# Breakdowns only the sampled per-request data has (a month back): stored key -> dimension, counted in requests.
DIMENSIONS = {
    "os": "userAgentOS",
    "devices": "clientDeviceType",
    "bots": "verifiedBotCategory",
    "cache": "cacheStatus",
    "colos": "coloCode",
}


def fetch(url, body=None, token=None):
    headers = {"User-Agent": "bitview-stats", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data, headers), timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403) and token:  # Cloudflare answers a revoked token 401, an unknown one 403
            raise Unauthorized(url) from None
        sys.exit(f"{url}: HTTP {e.code} {e.read()[:300].decode(errors='replace')}")


class Unauthorized(Exception):
    pass


def cloudflare_token():
    # The cf CLI's own login: running it refreshes the short-lived OAuth token when it has expired.
    subprocess.run(["cf", "auth", "whoami", "-q"], check=True, stdout=subprocess.DEVNULL)
    return json.loads(CF_LOGIN.read_text())["oauth_token"]


class Zone:
    def __init__(self):
        self.token = cloudflare_token()
        zones = self.api(f"{CF}/zones?name={ZONE}")["result"]
        if len(zones) != 1:
            sys.exit(f"Cloudflare: expected one zone named {ZONE}, found {len(zones)}")
        self.tag, self.account = zones[0]["id"], zones[0]["account"]["id"]
        records = self.api(f"{CF}/zones/{self.tag}/dns_records?per_page=5000")["result"]
        self.hosts = {r["name"] for r in records}
        self.tunnels = {}  # tunnel id -> the zone's hosts it serves, from their CNAMEs to <id>.cfargotunnel.com
        for r in records:
            if r["type"] == "CNAME" and r["content"].endswith(".cfargotunnel.com"):
                self.tunnels.setdefault(r["content"].split(".")[0], []).append(r["name"])

    def api(self, url, body=None):
        # A 401 or 403 means the cf login's token expired or was rotated by another cf run (one 11-17 pull failed that way
        # between two calls): read the login again, once.
        try:
            return json.loads(fetch(url, body, self.token))
        except Unauthorized:
            self.token = cloudflare_token()
        try:
            return json.loads(fetch(url, body, self.token))
        except Unauthorized:
            sys.exit(f"{url}: refused (401 or 403) with a freshly read cf login")

    def graphql(self, query):
        r = self.api(f"{CF}/graphql", {"query": query})
        if r.get("errors"):
            sys.exit("Cloudflare GraphQL: " + "; ".join(e["message"] for e in r["errors"]))
        return r["data"]

    def query(self, fields, account=False):
        """One GraphQL query on the zone (or its account); its result's fields by alias."""
        scope, key, tag = ("accounts", "accountTag", self.account) if account else ("zones", "zoneTag", self.tag)
        return self.graphql('{viewer{%s(filter:{%s:"%s"}){%s}}}' % (scope, key, tag, fields))["viewer"][scope][0]

    def datasets(self, account=False):
        """{dataset: {"notOlderThan": seconds, "fields": [...]}} for every dataset the plan enables on the zone (or its
        account), as Cloudflare's own settings list them."""
        kind = "AccountSettings" if account else "ZoneSettings"
        names = [f["name"] for f in self.graphql('{__type(name:"%s"){fields{name}}}' % kind)["__type"]["fields"]]
        settings = self.query("settings{%s}" % " ".join(f"{n}{{enabled notOlderThan availableFields}}" for n in names), account)
        return {n: {"notOlderThan": s["notOlderThan"], "fields": s["availableFields"]} for n, s in settings["settings"].items() if s and s["enabled"]}


def sample_interval(estimate, kept):
    """Cloudflare's sampled data scales each row's count up by its sample interval: the estimate over the requests it
    actually kept is the day's 1-in-N, 1 meaning every request was counted."""
    return round(estimate / kept, 2) if kept else 1


def breakdown(rows):
    """{"counts": {key: count}, "sampleInterval": N} from (key, count, sample interval) rows, zero counts left out."""
    counts, kept = {}, 0
    for k, n, interval in rows:
        if n:
            counts[str(k)] = counts.get(str(k), 0) + n
            kept += n / interval
    return {"counts": counts, "sampleInterval": sample_interval(sum(counts.values()), kept)}


class Routes:
    """Maps a request path to a public route template, so no looked-up value (address, txid, hash) is ever kept.

    Only what Bitview and its zone publish is kept, as a request's host, path and even its status can carry whatever
    was typed (the site once answered 200 to any path). API paths take their template from openapi.json, the most
    literal one winning (/api/blocks/tip/height over /api/blocks/{height}). Any other path keeps only its first segment,
    when that is a section in sitemap.xml, an API root or a folder or file the home page refers to. A host is kept when
    the zone has a DNS record for it. Everything else is one bucket.
    """

    OTHER = "(other)"

    def __init__(self, zone):
        spec = json.loads(fetch(f"{SITE}/openapi.json"))
        self.api = {}
        for p in spec["paths"]:
            segs = p.strip("/").split("/")
            self.api.setdefault(len(segs), []).append(segs)
        self.api_roots = {segs[0] for group in self.api.values() for segs in group}
        locs = ElementTree.fromstring(fetch(f"{SITE}/sitemap.xml")).iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
        sections = {loc.text.split("/")[3] for loc in locs}
        home = fetch(f"{SITE}/").decode()
        linked = set(re.findall(r"""["'`(]/([\w.-]+)[/"'`)]""", home))
        self.public = (sections | linked | self.api_roots) - {""}
        self.hosts = zone.hosts
        # The zone's hosts Bitview publishes: the ones its home page names (bitview.space, mcp.bitview.space).
        self.named = {h for h in zone.hosts if re.search(rf"//{re.escape(h)}\b", home)}

    def __call__(self, host, path):
        """(category, route) for one request."""
        host = host.lower().split(":")[0]
        if host not in self.hosts:
            host = self.OTHER
        segs = path.strip("/").split("/")
        template = self.api_template(segs)
        if host.split(".")[0] == "mcp":
            category = "MCP"
        elif template:
            return "API", host + template
        else:
            category = "API" if segs[0] in self.api_roots and len(segs) > 1 else "Pages"
        if path == "/":
            return category, host + "/"
        if segs[0] in self.public:
            return category, host + "/" + segs[0] + ("/…" if len(segs) > 1 else "/" if path.endswith("/") else "")
        return category, host + "/" + self.OTHER

    def api_template(self, segs):
        matches = [t for t in self.api.get(len(segs), ()) if all(a[0] == "{" or a == b for a, b in zip(t, segs))]
        if not matches:
            return None
        best = max(matches, key=lambda t: [a[0] != "{" for a in t])
        return "/" + "/".join(":" + a[1:-1] if a[0] == "{" else a for a in best)


def first_day(now, seconds):
    """The first whole UTC day inside a window reaching `seconds` back from now."""
    start = now - timedelta(seconds=seconds)
    return start.date() + timedelta(days=1 if start.time() != datetime.min.time() else 0)


def totals(zone, start, end):
    """{day: totals and MAPS} for each day in [start, end], from the daily rollups."""
    maps = " ".join(f"{m}{{{dim} {n}}}" for m, dim, n in MAPS.values())
    rows = zone.query(
        'd: %s(limit:%d, filter:{date_geq:"%s", date_leq:"%s"}, orderBy:[date_ASC]){'
        "dimensions{date} uniq{uniques} sum{requests cachedRequests bytes cachedBytes pageViews %s}}" % (DAILY, PAGE, start, end, maps)
    )["d"]
    out = {}
    for r in rows:
        s = r["sum"]
        out[r["dimensions"]["date"]] = {
            "requests": s["requests"],
            "cachedRequests": s["cachedRequests"],
            "bytes": s["bytes"],
            "cachedBytes": s["cachedBytes"],
            "pageViews": s["pageViews"],
            "uniques": r["uniq"]["uniques"],
            **{key: breakdown((c[dim], c[n], 1) for c in s[m]) for key, (m, dim, n) in MAPS.items()},
        }
    return out


def dimensions(zone, day, keys):
    """{key: breakdown of requests} for one day, one aliased query per DIMENSIONS key, all in one request."""
    r = zone.query(" ".join(
        '%s: %s(limit:%d, filter:{date:"%s"}){count avg{sampleInterval} dimensions{%s}}'
        % (k, SAMPLED, PAGE, day, DIMENSIONS[k])
        for k in keys
    ))
    for k in keys:
        if len(r[k]) == PAGE:
            sys.exit(f"Cloudflare: {DIMENSIONS[k]} fills a whole page on {day}")
    return {k: breakdown((x["dimensions"][DIMENSIONS[k]], x["count"], x["avg"]["sampleInterval"]) for x in r[k]) for k in keys}


def paged(zone, dataset, where, fields, key, value, after=None):
    """Every row of a query too big for one page, in `key` order from `after` on. A page ends partway through the rows
    of its last key, so those are dropped and the next page starts at that key; `value` reads the key from a row."""
    while True:
        bound = "" if after is None else f", {key}_geq:{json.dumps(after)}"
        rows = zone.query("g: %s(limit:%d, filter:{%s%s}, orderBy:[%s_ASC]){%s}" % (dataset, PAGE, where, bound, key, fields))["g"]
        if len(rows) < PAGE:
            yield from rows
            return
        after = value(rows[-1])
        rows = [r for r in rows if value(r) != after]
        if not rows:
            sys.exit(f"Cloudflare: one {key} fills a whole page of {dataset} ({where})")
        yield from rows


def routes(zone, route, day):
    """{"counts": {category: {route: [requests, bytes]}}, "sampleInterval": N} for one day, every (path, host)."""
    out, kept = {}, 0
    rows = paged(zone, SAMPLED, f'date:"{day}"', "count avg{sampleInterval} sum{edgeResponseBytes} "
                 "dimensions{clientRequestPath clientRequestHTTPHost}", "clientRequestPath", lambda r: r["dimensions"]["clientRequestPath"])
    for r in rows:
        d = r["dimensions"]
        category, key = route(d["clientRequestHTTPHost"], d["clientRequestPath"])
        cell = out.setdefault(category, {}).setdefault(key, [0, 0])
        cell[0] += r["count"]
        cell[1] += r["sum"]["edgeResponseBytes"]
        kept += r["count"] / r["avg"]["sampleInterval"]
    requests = sum(c[0] for routes in out.values() for c in routes.values())
    return {"counts": out, "sampleInterval": sample_interval(requests, kept)}


def hour_key(iso):
    """"2026-11-17T09:00:00Z" -> ("2026-11-17", "09")."""
    return iso[:10], iso[11:13]


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def hours_exact(zone, start, end):
    """{(day, hour): totals and status codes} for each hour in [start, end), from the exact hourly rollups."""
    rows = zone.query(
        'h: %s(limit:%d, filter:{datetime_geq:"%s", datetime_lt:"%s"}){dimensions{datetime} '
        "sum{requests cachedRequests bytes cachedBytes pageViews responseStatusMap{edgeResponseStatus requests}}}"
        % (HOURLY, PAGE, stamp(start), stamp(end))
    )["h"]
    out = {}
    for r in rows:
        s = r["sum"]
        out[hour_key(r["dimensions"]["datetime"])] = {
            **{k: s[k] for k in ("requests", "cachedRequests", "bytes", "cachedBytes", "pageViews")},
            "status": {str(c["edgeResponseStatus"]): c["requests"] for c in s["responseStatusMap"] if c["requests"]},
            "sampleInterval": 1,
        }
    return out


def hours_sampled(zone, start, end):
    """The same as hours_exact from the sampled overview, for hours the hourly rollups no longer keep."""
    out, kept = {}, {}
    rows = paged(zone, OVERVIEW, f'datetime_geq:"{stamp(start)}", datetime_lt:"{stamp(end)}"',
                 "avg{sampleInterval} sum{requests cachedRequests bytes cachedBytes pageViews} dimensions{datetimeHour edgeResponseStatus}",
                 "datetimeHour", lambda r: r["dimensions"]["datetimeHour"])
    for r in rows:
        key, s = hour_key(r["dimensions"]["datetimeHour"]), r["sum"]
        h = out.setdefault(key, {"requests": 0, "cachedRequests": 0, "bytes": 0, "cachedBytes": 0, "pageViews": 0, "status": {}})
        for k in ("requests", "cachedRequests", "bytes", "cachedBytes", "pageViews"):
            h[k] += s[k]
        if s["requests"]:
            h["status"][str(r["dimensions"]["edgeResponseStatus"])] = s["requests"]
        kept[key] = kept.get(key, 0) + s["requests"] / r["avg"]["sampleInterval"]
    for key, h in out.items():
        h["sampleInterval"] = sample_interval(h["requests"], kept[key])
    return out


def origin_times(zone, where, by):
    """{key: {"p50", "p95", "sampleInterval"}}: how long Bitview's servers took to answer, in ms, per `by` (date or
    datetimeHour), from the sampled requests that went to them."""
    rows = zone.query(
        "o: %s(limit:%d, filter:{%s, originResponseDurationMs_gt:0}){count avg{sampleInterval} "
        "quantiles{originResponseDurationMsP50 originResponseDurationMsP95} dimensions{%s}}" % (SAMPLED, PAGE, where, by)
    )["o"]
    if len(rows) == PAGE:
        sys.exit(f"Cloudflare: origin times fill a whole page ({where})")
    return {r["dimensions"][by]: {"p50": r["quantiles"]["originResponseDurationMsP50"], "p95": r["quantiles"]["originResponseDurationMsP95"],
                                  "sampleInterval": round(r["avg"]["sampleInterval"], 2)} for r in rows}


def firewall(zone, start, end):
    """(hours, days) for [start, end): firewall events per hour, and per day breakdowns by action, by security feature
    (source) and by rule name, the feature's own name when the rule has none. Only these fields of each event are read."""
    hours, days = {}, {}
    rows = paged(zone, FIREWALL, f'datetime_lt:"{stamp(end)}"', "action source description sampleInterval datetime",
                 "datetime", lambda r: r["datetime"], stamp(start))
    for r in rows:
        day, hour = hour_key(r["datetime"])
        n = r["sampleInterval"]
        hours[day, hour] = hours.get((day, hour), 0) + n
        for key, value in (("firewallActions", r["action"]), ("firewallSources", r["source"]), ("firewallRules", r["description"] or r["source"])):
            days.setdefault(day, {}).setdefault(key, []).append((value, n, n))
    return hours, {day: {k: breakdown(rows) for k, rows in fields.items()} for day, fields in days.items()}


def tunnels(zone, named):
    """The status of each tunnel the zone's DNS points to, by the zone's hosts its ingress serves (its DNS names when it
    has no config at Cloudflare), and whether one is a host Bitview publishes (`named`); never its id, name, services or
    addresses. A dev tunnel is listed, not public."""
    account = f"{CF}/accounts/{zone.account}/cfd_tunnel"
    by_id = {t["id"]: t for t in zone.api(f"{account}?is_deleted=false&per_page=1000")["result"]}
    out = []
    for i, dns in zone.tunnels.items():
        config = zone.api(f"{account}/{i}/configurations")["result"] or {}
        ingress = {r.get("hostname") for r in (config.get("config") or {}).get("ingress") or []}
        hosts = sorted(ingress & zone.hosts or dns)
        t = by_id.get(i, {"status": "deleted", "connections": []})
        out.append({"hosts": hosts, "public": bool(named & set(hosts)), "status": t["status"], "connections": len(t["connections"])})
    return sorted(out, key=lambda t: (not t["public"], t["hosts"]))


def field_name(field):
    """A settings field's plain name: "dimensions_clientIP" -> "clientIP", "sum_countryMap_clientCountryName" ->
    "clientCountryName"."""
    name = re.sub(r"^(dimensions|sum|avg|uniq|ratio|quantiles|max|min)_", "", field)
    return name.split("Map_", 1)[1] if "Map_" in name else name


def inventory(datasets):
    """Every dataset on the plan, and POLICY's rows with their fields and the longest any dataset keeps them."""
    rows = [{"what": w, "mark": m, "how": h, "fields": set(), "days": 0} for w, m, h, _ in POLICY]
    owner = {f: rows[i] for i, (_, _, _, fields) in enumerate(POLICY) for f in fields}
    out = []
    for scope, group in datasets.items():
        for name, d in sorted(group.items()):
            days = round(d["notOlderThan"] / 86400, 1)
            # The zone's datasets record bitview.space's requests, and on the account Web Analytics (rum*) records its
            # page loads; the account's other datasets are Cloudflare's other products, listed but not about visitors.
            visitors = scope == "zone" or name.startswith("rum")
            out.append({"scope": scope, "name": name, "kept": kept(days), "read": (scope, name) in READ, "visitors": visitors,
                        "fields": sorted(d["fields"])})
            if not visitors:
                continue
            for f in d["fields"]:
                row = owner.get(field_name(f), rows[-1])
                row["fields"].add(field_name(f))
                row["days"] = max(row["days"], days)
    for row in rows:
        row["fields"], row["kept"] = sorted(row["fields"]), kept(row.pop("days"))
    return {"policy": [r for r in rows if r["fields"]], "datasets": out}


def kept(days):
    """Retention in words: 3 days, 6 months, 1 year."""
    n, months = round(days), round(days / 30.5)
    return f"{round(n / 365)} year{'s' * (n >= 730)}" if n >= 360 else f"{months} month{'s' * (months > 1)}" if n >= 28 else f"{n} day{'s' * (n != 1)}"


def readme_inventory(inv):
    """The README's inventory table, from the same data the page reads."""
    lines = ["| What Cloudflare records | Here | How or why | Cloudflare keeps it | Fields |", "|---|---|---|---|---|"]
    for r in inv["policy"]:
        fields = ", ".join(f"`{f}`" for f in r["fields"]) if r["what"] != POLICY[-1][0] else f"{len(r['fields'])} more, in `data/inventory.json`"
        lines.append(f"| {r['what']} | {r['mark']} | {r['how']} | up to {r['kept']} | {fields} |")
    read = ", ".join(f"`{d['name']}` ({d['kept']})" for d in inv["datasets"] if d["read"])
    visitors = sum(d["visitors"] for d in inv["datasets"])
    lines += ["", f"Cloudflare offers this account {len(inv['datasets'])} datasets. The table covers the {visitors} that record "
              f"Bitview's visitors: bitview.space's own, and Web Analytics. The other {len(inv['datasets']) - visitors} belong "
              f"to Cloudflare's other products on the account. `pull.py` reads {read}."]
    return "\n".join(lines)


def write_inventory(inv):
    """data/inventory.json for the page, and the same table between the README's markers."""
    (DATA / "inventory.json").write_text(json.dumps(inv, separators=(",", ":")) + "\n")
    readme = (REPO / "README.md").read_text()
    start, end = readme.index(INVENTORY_START) + len(INVENTORY_START), readme.index(INVENTORY_END)
    (REPO / "README.md").write_text(readme[:start] + "\n" + readme_inventory(inv) + "\n" + readme[end:])


def month_path(month):
    return DATA / f"{month}.json"


def load(month):
    p = month_path(month)
    return json.loads(p.read_text()) if p.exists() else {}


def save(month, days):
    """One day per line, keys sorted, so a day's change is a one-line diff; written whole, then renamed into place."""
    lines = (json.dumps(d) + ":" + json.dumps(days[d], sort_keys=True, separators=(",", ":"), ensure_ascii=False) for d in sorted(days))
    tmp = month_path(month).with_suffix(".tmp")
    tmp.write_text("{\n" + ",\n".join(lines) + "\n}\n")
    tmp.replace(month_path(month))


def merge(fresh):
    """Merge {day: fields} into the stored days, one write per month. A day's "hours" merge hour by hour and field by
    field, as their fields come from different queries; every other field is replaced whole."""
    by_month = {}
    for day, fields in fresh.items():
        by_month.setdefault(day[:7], {})[day] = fields
    for month, fresh in by_month.items():
        days = load(month)
        for day, fields in fresh.items():
            stored = days.setdefault(day, {})
            for hour, values in fields.pop("hours", {}).items():
                stored.setdefault("hours", {}).setdefault(hour, {}).update(values)
            stored.update(fields)
        save(month, days)


def by_day(hours, field=None):
    """{(day, hour): values} -> {day: {"hours": {hour: values}}}, each value under `field` when given."""
    out = {}
    for (day, hour), v in hours.items():
        out.setdefault(day, {"hours": {}})["hours"][hour] = {field: v} if field else v
    return out


def hour_keys(start, end):
    """The (day, hour) keys of the hours in [start, end)."""
    return [hour_key(stamp(start + timedelta(hours=i))) for i in range(int((end - start) / timedelta(hours=1)))]


def stored_hours(start, end):
    """{(day, hour): its stored fields} for the hours in [start, end)."""
    months = {m: load(m) for m in {day[:7] for day, _ in hour_keys(start, end)}}
    return {(day, hour): months[day[:7]].get(day, {}).get("hours", {}).get(hour, {}) for day, hour in hour_keys(start, end)}


def ceil_hour(t):
    floor = t.replace(minute=0, second=0, microsecond=0)
    return floor if floor == t else floor + timedelta(hours=1)


def main():
    now = datetime.now(timezone.utc)
    last = (now - timedelta(hours=1)).date() - timedelta(days=1)
    end = now.replace(minute=0, second=0, microsecond=0)  # hours before this one are complete
    zone = Zone()
    datasets = {"zone": zone.datasets(), "account": zone.datasets(account=True)}
    window = lambda scope, name: first_day(now, datasets[scope][name]["notOlderThan"])
    # The first hour a query may still ask a dataset for, an hour inside its limit as the run takes time.
    since = lambda name: ceil_hour(now - timedelta(seconds=datasets["zone"][name]["notOlderThan"])) + timedelta(hours=1)
    DATA.mkdir(exist_ok=True)

    write_inventory(inventory(datasets))

    merge(totals(zone, window("zone", DAILY), last))

    def hourly_origin(start, stop):
        """Origin times for every hour in [start, stop), an empty one where no request reached Bitview's servers."""
        times = origin_times(zone, f'datetime_geq:"{stamp(start)}", datetime_lt:"{stamp(stop)}"', "datetimeHour")
        times = {hour_key(k): v for k, v in times.items()}
        merge(by_day({k: times.get(k, {"sampleInterval": 1}) for k in hour_keys(start, stop)}, "origin"))

    # Hours: exact ones rewritten, older sampled ones pulled when missing, a week per query. Origin times are written
    # last for every hour, so a stored one means the hour was pulled.
    exact, t = since(HOURLY), max(since(OVERVIEW), since(SAMPLED))  # origin times come from SAMPLED
    stored = stored_hours(t, exact)
    while t < exact:
        if "origin" in stored[hour_key(stamp(t))]:
            t += timedelta(hours=1)
            continue
        stop = min(exact, t + timedelta(days=7))
        merge(by_day(hours_sampled(zone, t, stop)))
        hourly_origin(t, stop)
        print(f"{stamp(t)} to {stamp(stop)}: hours", flush=True)
        t = stop
    merge(by_day(hours_exact(zone, exact, end)))
    hourly_origin(exact, end)

    # Firewall events: every hour and every final day of the window rewritten, zero when there were none.
    walls = max(since(FIREWALL), end - timedelta(days=30))  # 30 days: the longest span one query may cover
    events, rules = firewall(zone, walls, end)
    merge(by_day({k: events.get(k, 0) for k in hour_keys(walls, end)}, "firewall"))
    empty = {k: {"counts": {}, "sampleInterval": 1} for k in ("firewallActions", "firewallSources", "firewallRules")}
    day = walls.date() + timedelta(days=1 if walls.hour else 0)
    while day <= last:
        merge({str(day): rules.get(str(day), empty)})
        day += timedelta(days=1)

    route = Routes(zone)
    tunnels_now = tunnels(zone, route.named)

    day = window("zone", SAMPLED)
    while day <= last:
        stored = load(str(day)[:7]).get(str(day), {})
        missing = [k for k in ("routes", "origin", *DIMENSIONS) if "sampleInterval" not in stored.get(k, {})]
        if missing:
            dims = [k for k in missing if k in DIMENSIONS]
            fields = dimensions(zone, day, dims) if dims else {}
            if "origin" in missing:
                fields["origin"] = origin_times(zone, f'date:"{day}"', "date").get(str(day), {"sampleInterval": 1})
            if "routes" in missing:
                fields["routes"] = routes(zone, route, day)
            merge({str(day): fields})
            print(f"{day}: {', '.join(missing)}", flush=True)
        day += timedelta(days=1)

    months = sorted(p.stem for p in DATA.glob("????-??.json"))
    (DATA / "index.json").write_text(json.dumps({"months": months}) + "\n")
    (DATA / "now.json").write_text(json.dumps({"pulled": stamp(now.replace(second=0)), "through": stamp(end), "tunnels": tunnels_now}) + "\n")

    git = lambda *a: subprocess.run(["git", "-C", str(REPO), *a], check=True)
    git("add", "data", "README.md")
    if subprocess.run(["git", "-C", str(REPO), "diff", "--cached", "--quiet"]).returncode:
        git("commit", "-q", "-m", f"Data through {stamp(end)}")
    git("push", "-q", "origin", "HEAD")
    print(f"done through {stamp(end)}")


if __name__ == "__main__":
    main()
