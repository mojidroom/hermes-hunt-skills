# Narrow Recon — Full Workflow (from user notebook + additions)

## Phase Zero
- Work with the website like a normal user
- Build a mind-map for the application
- Use a proxy to save traffic (Burp / mitmproxy)
- Do not fall into the rabbit hole
- Figure out as many functionalities as possible
- Manage to pay for paid plans (if needed to unlock features)

## What to Look

### What is the app used for
- Overall business logic
- Failure of confidentiality
- Failure of integrity

### Does it have a certain threat model?
- Revealing user's phone in authentication
- Changing a property of my organization without permissions

### How does the app pass data?
- Legacy / all-in-one (UI + backend)
- Simple web app + jQuery
- SPA + REST API
- SPA + GraphQL
- WebSocket communication
- [ADD] detect via: bundles (React/Vue), `X-Powered-By`, response shape, /graphql or /api/ paths, ws:// upgrades

### How does the app handle users?
- Auth scheme: cookie / token / JWT, etc
- 2FA implementations
- Account delegations
- Other user levels / roles
- Authentication transfer / SSO

### Past vulnerabilities?
- Public reports on platform (hacktivity)
- Collaborating with other hunters

### Third-parties?
- For what purpose (data storage?)
- Do third-parties have bug bounties?
- Well-known or not? (unknown = bigger surface)

### API documentation?
- Does the app expose OpenAPI/Swagger/Postman? — take time to read it
- Documented APIs often more vulnerable (defined but loosely validated)

### Eye-catchings
- Auth class (OAuth all providers, account linking)
- Switching among applications
- Sensitive APIs
- Uploader sections
- Links / HTML inputs
- Application-specific sections
- JavaScript redirects (open redirect / client-side)
- postMessages (CSPT / DOM clobbering)
- Unusual status codes

## Increasing Attack Surface

- Side applications: mobile + desktop apps
- Hidden surfaces: `https://github.com/<org>/narrow-app`, hidden params/paths/files, paid/forgotten/custom features, staging instances (even out of scope)

### Passive crawling (no HTTP to target — existing data)
- **Search engine dorking** (sensitive info / interesting paths):
  - keywords + operators: `-`, `ext:`, `site:`, `ext:do`, `ext:action`, `ext:&`, `ext:php`, `ext:jsp`, `ext:jspx`, `ext:asp`, `ext:aspx`, `ext:htm`
  - `site:*.*.target.*` (any sub/tld), `site:*.target.com`, `inurl:&`
  - Google AND Bing AND DuckDuckGo (not "or") — repeat with omitted results included (bottom of page)
  - Build target-specific dork strings
- **Wayback machine** (archive.org):
```bash
# CDX API
https://web.archive.org/cdx/search/cdx?url=https://icollab.info
https://web.archive.org/web/20211208105512if_/http://icollab.info
https://web.archive.org/cdx/search/cdx?url=*.capcut.com/*&fl=original&collapse=digest
https://web.archive.org/cdx/search/cdx?url=*.capcut.com/*&fl=original&collapse=urlkey
https://web.archive.org/cdx/search/cdx?url=*.capcut.com/*&fl=timestamp,original&collapse=digest
```
- **Tools:** `waybackurls` (best; clean output; use with main domain) · `gau` (sources: archive.org, commoncrawl, virustotal, alienvault, urlscan) — clean output, main domain

### Active crawling
- `katana` — not for DOM-based apps; config per target
- JavaScript — **manual review is best**; scripts help but human > tool

## Fuzzing

- Fuzzing = send malformed/unexpected HTTP requests → trigger unexpected behavior → discover hidden/unlinked resources (files, params, headers)
- Balance fuzzing conditions; **follow the least-change principle** (`/search?q=keyword` → `/FUZZ/?q=keyword`, one part at a time)
- Hidden resources: unlinked dirs/files, dev/testing envs, API endpoints, config files

### Tools
`ffuf` · `x8`, `arjun` (params) · `paramminer` (params) · `recollapse` · `crunch` · `GAP` · `ffuf for headers/params` · `Fallparams` · `IIS Shortname Scanner`

### Checking phase (validate fuzz works)
- Find a **hook** (static files are best) + verify the fuzzing by the hook
- May need to repeat several times

### Inputs / WAF / validations bypass
- Checker function / restriction / validation / WAF bypass
- **Character ranges:** `0x00-0x2F`, `0x3A-0x40`, `0x5B-0x60` (special chars URL parsers mishandle)
- Bypass a checker function (case, encoding, unicode, overlong, duplicated)

### Files
- Recognize web server architecture (route-based: flask/rails/express vs filesystem)
- Recognize filename pattern: `login.php`, `loginUser.php`, `LoginUser.php` (case variants)
- Fuzz for JavaScript files
- Fuzz on various status codes (200/301/302/403/405 — not just 404)

### Endpoints
- Route-based frameworks (Flask/Rails/Express) — use ffuf partially:
  - `/api/Users/all` → `/api/users/all/FUZZ`, `/api/users/FUZZ`, `/api/FUZZ/all`, `/api/FUZZ`
- Least-change principle

### Parameters
- **Magic parameters** — every app has hidden params:
  - Field name findable in the app
  - Name similar to others (`use_local_engine`, `use_local_frontend`)
  - Brand-new names
- Programmers reuse param names across pages
- Where to look: all params in HTTP requests, HTML form names/ids, JS variable names, JSON objects in JS files
- Query string params can be increased as long as server accepts them ("chunk" = number of params per request)
- Fuzz on various status codes (including 40x = app logic)
- Header fuzzing = same as param fuzzing
- Fuzz BOTH GET and POST methods
- [ADD] JSON body param fuzzing too (dup keys, mass assignment, type confusion)

### Wordlists
- Famous: `orwagodfather/My-WordLISTs`, assetnote (`raft lists`, `uncertainty_underscores`), `Bo0oM/fuzz.txt`, `0xPugal/fuzz4bounty`, `portswigger/param-miner`
- Make your own: 3 `(._-)` + 4 alphanumeric; ASCII chars good to fuzz; use tools but verify by hand

### Over CDN / WAF fuzzing
- Lower threads (even 1) + add delay
- Capture via Burp and add corresponding headers
- Proxy through Burp with **HTTP/2** enabled

## [ADD] Consolidated narrow flow → attack
1. Profile auth (cookie/token/JWT) + API style (REST/GraphQL/WS) — skip CSRF/CORS on token sites
2. Function-map every feature (mind-map + duplicate-key password)
3. Dork + wayback + gau → old endpoints → test forgotten ones
4. JS manual review → endpoints/api hidden params
5. Fuzz (ffuf/x8/gap, least-change, GET+POST) → status code not-found triage
6. Per-endpoint TEST EVERYTHING (method × param × encoding × auth) — see narrow-recon TEST EVERYTHING Loop
7. Probe each discovery: route to matching hunt-* skill