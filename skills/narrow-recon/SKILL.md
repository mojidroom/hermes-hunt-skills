---
name: narrow-recon
description: Deep recon on known surface. JS, params, API discovery.
version: 1.0.0
author: mojtaba
license: MIT
metadata:
  hermes:
    tags: [recon, narrow, js-analysis, api-discovery]
    related_skills: [recon-methodology, idor-methodology]
---

# Narrow Recon — Deep Analysis

## JS Intelligence
- Extract endpoints: `grep -rohP '(fetch|axios|request)\(\/' *.js`
- Hidden params: `grep -rohP '(siteId|accountId|userId|spaceId)' *.js`
- Magic params: `admin|debug|test|role|type|filter|sort|order`
- LinkFinder for SPA routes
- Next.js `_buildManifest.js` for route map

## URL Parameter Discovery
- Arjun for blind discovery
- Common: `userId, account_id, isAdmin, role, admin, debug, test`
- **Magic params:** re-used names → `use_local_engine`, `use_local_frontend`; find via HTTP requests, HTML form names/ids, JS variables, JSON objects in JS
- **Chunk the query:** params can grow as long as the server accepts them
- Fuzz BOTH GET and POST; also JSON-body params (dup keys / mass assignment / type confusion)
- Fuzz headers like params; watch 40x codes (they reveal app logic), not just 404
- [ADD] Least-change principle: `/search?q=x` → `/FUZZ/?q=x` (one part at a time)

## Fuzzing Tools (hidden resources)
- `ffuf` (dir/param/header) · `x8`/`arjun`/`paramminer`/`Fallparams` (params) · `GAP` · `recollapse` · `IIS Shortname Scanner`
- Over CDN/WAF: lower threads (1) + delay; proxy via Burp + HTTP/2; add captured headers
- Validate fuzzing via a **hook** (static file) — proves fuzzer works before trusting results
- Wordlists: assetnote raft, `Bo0oM/fuzz.txt`, `0xPugal/fuzz4bounty`, orwagodfather lists; make your own 3(. _-)+4alnum
- File patterns: `login.php / loginUser.php / LoginUser.php` — fuzz case variants + JS files + all status codes

## Passive (old endpoints/etc)
- Dorks (Google+Bing+DDG, not "or"): `site:*.*.tld`, `ext:php/jsp/aspx`, `inurl:&`, repeat with omitted results
- Wayback CDX API + `waybackurls` + `gau` (archive/commoncrawl/virustotal/alienvault/urlscan) → old endpoints
- Manual JS review > scripts for endpoint extraction

## Mask Detection
- Change param value → same? = MASK (ignored)
- Remove param → same? = MASK
- Different → might be IDOR

## Status Codes
400=wrong params, 401=wrong auth, 403=bypass, 405=wrong method, 422=FastAPI probe, 500=stack trace

## Env Vars → Subdomains
NEXT_PUBLIC_* → 30+ hidden subdomains → test with main cookie

## TEST EVERYTHING Loop (MANDATORY — every discovered surface)
For EVERY endpoint/param/feature found (JS, wayback, fuzz, params, features):
1. **Every method**: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE
   - Verb tampering: same path different method → 405/403 may become 200 (authz drift)
2. **Every parameter**: known params + value swap (IDOR) + remove param (MASK check) + add blind params (`admin, debug, test, role, isAdmin, source, trace, dev, bypass`)
3. **Every encoding**: plain, base64, URL-encoded, JSON duplicate keys, unicode
4. **Every auth state**: no auth, main token, alt token, cookie vs header vs query
5. **Diff EVERY response**: status code, body length, error message, timing → 400≠404 rule
6. **Old endpoints from wayback**: legacy versions (`/v1`, `/api/old`, `/admin`, renamed features) — often unpatched
7. New endpoint/param/feature discovered → re-run the loop on IT (recursive)
8. Every bug found → test MORE on same surface → chain → escalate

## Full Workflow Reference
Complete narrow-recon notebook (phase-zero, what-to-look, threat model, attack-surface, passive/active crawl, fuzzing, magic params, wordlists, over-CDN):
`references/narrow-recon-full-workflow.md`

## Verdict Quick-Check
**Trigger:** load when the target surface is already known (one domain/host) — deep-dive JS, params, API discovery.
- JS-found endpoints, hidden params, env-var subdomains = **leads**, not findings
- Each lead → live request → if 200 with private data → IDOR/BAC finding (route to `hunt-idor` / `target-auth-profile`)
- `NEXT_PUBLIC_*` subdomains → test with the main cookie (cross-subdomain cookie bleed)
