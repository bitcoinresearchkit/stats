# Bitview stats

What Bitview's operators can see about its visitors, and its traffic in the open: <https://stats.bitview.space>

## What we can see

Bitview is served through Cloudflare, which records every request it answers and offers the operators its records
through an analytics API. The table below lists every kind of field Cloudflare offers this account on its plan, built
from the API's own list of datasets and fields each day, and what this repository does with each.

The operators could query the fields marked *not published*. Nothing of ours does: the one script,
[`pull.py`](pull.py), reads only the datasets named under the table every hour, plus the zone's name, its DNS host
names and the status of the tunnels that carry its requests.

<!-- inventory: written by pull.py -->
| What Cloudflare records | Here | How or why | Cloudflare keeps it | Fields |
|---|---|---|---|---|
| Requests, bandwidth, cached share, page views, unique IPs | published | Totals per day, and per hour but for unique IPs. | up to 1 year | `bytes`, `cachedBytes`, `cachedRequests`, `count`, `edgeResponseBytes`, `pageViews`, `requests`, `uniques` |
| Country | published | Daily counts per country. | up to 1 year | `clientCountryName`, `countryName` |
| Status code | published | Counts per code, per day and per hour. | up to 1 year | `edgeResponseStatus` |
| Firewall event | published | Counts per hour, and per day by action, by security feature and by rule name. | up to 1 month | `action`, `description`, `source` |
| Origin response time | published | The median and the 95th percentile, per day and per hour. | up to 1 month | `originResponseDurationMs`, `originResponseDurationMsP50`, `originResponseDurationMsP95` |
| Browser | published | Daily counts per browser family, without version. | up to 1 year | `uaBrowserFamily`, `userAgentBrowser` |
| Operating system | published | Daily counts per system, without version. | up to 6 months | `userAgentOS` |
| Device type | published | Daily counts: desktop, mobile, tablet. | up to 6 months | `clientDeviceType`, `deviceType` |
| Verified bot | published | Daily counts per Cloudflare bot category. | up to 1 month | `verifiedBotCategory` |
| IP reputation class | published | Daily counts per Cloudflare class (search engine, Tor…), never the IP. | up to 1 year | `clientIPClass`, `ipType` |
| Content type | published | Daily counts per type. | up to 1 year | `edgeResponseContentTypeName` |
| Cache status | published | Daily counts per status. | up to 1 month | `cacheStatus` |
| HTTP version | published | Daily counts per version. | up to 1 year | `clientHTTPProtocol`, `clientRequestHTTPProtocol` |
| TLS version | published | Daily counts per version. | up to 1 year | `clientSSLProtocol` |
| Cloudflare location | published | Daily counts per Cloudflare data center. | up to 1 month | `coloCode`, `coloName`, `edgeColoName` |
| Day, sample rate | published | Every count is per UTC day or hour, with Cloudflare's sample rate. | up to 1 year | `date`, `sampleInterval` |
| Time | grouped | Reduced to the hour for totals, status codes, firewall events and origin times; everything else is per day. | up to 1 year | `datetime`, `datetimeHour` |
| Host | grouped | Kept when it is a name in bitview.space's DNS, else (other). | up to 6 months | `clientRequestHTTPHost`, `requestHost` |
| Path | grouped | Reduced to its route: the API template from openapi.json, or a first folder the sitemap or home page names, else (other). A path holds the address, transaction or search someone looked up. | up to 6 months | `clientRequestPath`, `requestPath` |
| IP address | not published | Identifies a person or a household. | up to 1 month | `clientIP`, `destinationIP`, `ip`, `originIP`, `sourceIP`, `upstreamIP` |
| Device model, email sender, user id | not published | Point to one person or one device. | up to 1 month | `deviceModel`, `deviceVendor`, `fraudUserId`, `headerFrom` |
| Full user agent | not published | Detailed enough to single out one browser. | up to 1 month | `userAgent` |
| Network (ASN) | not published | On a small network it points to a person or a company. | up to 1 month | `clientASNDescription`, `clientAsn` |
| Query string | not published | Holds what people looked up. | up to 1 month | `clientRequestQuery` |
| Referring site and page | not published | Where someone came from. Published as hosts until 2026-11-17, from Web Analytics, which was then turned off and the counts deleted. | up to 6 months | `clientRefererHost`, `clientRefererPath`, `clientRefererQuery`, `refererHost`, `refererPath` |
| Page address in Web Analytics | not published | The full address of a page someone viewed, which holds what they looked up. | up to 6 months | `cumulativeLayoutShiftPath`, `firstInputDelayPath`, `interactionToNextPaintPath`, `largestContentfulPaintObjectPath`, `largestContentfulPaintPath`, `pageUrl`, `url`, `urlParams`, `urlPath` |
| Request and session ids | not published | Tie a record to one request or one visitor. | up to 1 month | `apiGatewayMatchedSessionIdentifier`, `messageId`, `originatorRayName`, `rayName`, `sessionId`, `sessionIdHash` |
| Minutes | not published | Hours at most: on a quiet minute, a breakdown can single out one visit. | up to 1 year | `datetimeFifteenMinutes`, `datetimeFiveMinutes`, `datetimeHalfOfHour`, `datetimeMinute` |
| Everything else | not published | Not read: browser and system versions, security rules and their matches, performance timings, and fields of other Cloudflare features. | up to 1 year | 624 more, in `data/inventory.json` |

Cloudflare offers this account 247 datasets. The table covers the 49 that record Bitview's visitors: bitview.space's own, and Web Analytics. The other 198 belong to Cloudflare's other products on the account. `pull.py` reads `firewallEventsAdaptive` (1 month), `httpRequests1dGroups` (1 year), `httpRequests1hGroups` (3 days), `httpRequestsAdaptiveGroups` (1 month), `httpRequestsOverviewAdaptiveGroups` (1 month).
<!-- end of inventory -->

The full list, dataset by dataset and field by field, is in [`data/inventory.json`](data/inventory.json).

### Server logs

Bitview's own server logs one line per request: the time, the method, the status, the path with its query, and how
long the answer took. No IP address, no user agent, nothing else about who sent it. The lines are kept in daily files
that the server deletes after seven days. The last 1,000 lines are public, on the [Logs page](https://bitview.space/logs/)
and at [`/api/server/logs`](https://bitview.space/api/server/logs). The MCP server logs only its start. Bitview's
[privacy page](https://bitview.space/privacy/) says the same.

## What these numbers are

**Source.** Cloudflare's own counts of the requests it answered for bitview.space and its subdomains, pulled every
hour from its GraphQL Analytics API. Nothing was added to Bitview's pages for them. Days and hours are UTC.

**Referring sites** ended on 2026-11-17. They came from Cloudflare Web Analytics, a script Cloudflare added to Bitview's
pages for visitors outside the EU, and it was turned off that day. The counts were deleted, history included.

- **Requests:** every request Cloudflare answered: browsers, bots, API and MCP clients alike.
- **Unique IPs** (`uniques`): Cloudflare's approximate count of distinct client IP addresses in a day. One person can
  use several and many can share one, and they can't be added up across days.
- **Page views** (`pageViews`): Cloudflare's own count of responses it judges to be pages (HTML), by its heuristic.
- **Bandwidth** (`bytes`): bytes sent to clients; `cachedRequests` and `cachedBytes` are the part served from cache.
- **Origin times** (`origin`): how long Bitview's servers took to answer the requests Cloudflare passed on, as the
  median (`p50`) and 95th percentile (`p95`) in milliseconds.
- **Firewall events** (`firewall`, `firewallActions`, `firewallSources`, `firewallRules`): requests a Cloudflare
  security feature acted on, per hour, and per day by action, by feature and by rule name.

**Layout.** `data/YYYY-MM.json` holds one line per day; a day's `hours` holds its hours, keyed `00` to `23`.
`data/now.json` says when the last pull ran, its last complete hour, and the status of each tunnel carrying requests
to Bitview, by the hosts its ingress serves, with `public` true when Bitview's home page names one of them. Only public
tunnels count toward the page's check; the others serve development hosts.

**Exact or estimated.** Each breakdown is stored as `{"counts": {...}, "sampleInterval": N}`, and each hour and
origin time carries its own `sampleInterval`. Daily totals and the breakdowns of Cloudflare's daily rollups (countries,
status codes, browsers by page view, content types, HTTP and TLS versions, client reputation) count every request, and
so do the hours of the last three days: N is 1. Older hours, routes, operating systems, devices, verified bots, cache
status, edge locations, origin times and firewall events come from Cloudflare's sampled data, which
keeps one request in N on busy days and scales its counts up; N is the estimate over the requests Cloudflare kept.

**Routes.** Each request is reduced to its route in memory, before anything is written: an API path to its template in
Bitview's [OpenAPI spec](https://bitview.space/openapi.json) (`/api/address/:address/txs`), any other path to its first
folder when Bitview's [sitemap](https://bitview.space/sitemap.xml) or home page names it, and its host kept when it is
in bitview.space's DNS. Everything else counts as `(other)`. A path, and even a host, can carry whatever was typed, so
this is what keeps lookups private.

**How far back.** On Bitview's plan Cloudflare keeps a year of daily totals, a month of
sampled data and three days of exact hours. The pull started on 2026-11-17 and keeps every day and hour from then on,
so the history starts that far before it and only grows. A day or hour missing from the data is missing, never zero.
