---
name: hunt-information-disclosure
description: Hunt error leakage, DVCS exposure, source maps, config files, and differential oracles.
category: redteam
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, httpx
tags: [redteam, information-disclosure, error-leakage, source-maps, config, enumeration]
related_skills:
  - source-leak-hunt
  - js-secrets-extraction
  - error-log-mining
  - web-enumeration
---

# Information Disclosure Hunting

Hunt for information exposure through stack traces, debug endpoints, versioned path discovery, source maps, and differential oracles. Each disclosure amplifies other vulnerabilities — a version number enables CVE targeting, a server path enables LFI, a schema leak enables auth bypass, and an error message reveals internal infrastructure.

## When to Use

- Applications return verbose error messages with stack traces, file paths, or SQL fragments.
- Source maps (.js.map) are deployed to production.
- Versioned static assets reveal framework/CMS versions.
- API responses differ by object existence (user enumeration by status/length/time).
- Debug endpoints, health checks, or status pages expose internal state.

## Quick Detection

```bash
# Trigger errors on common paths
for path in "/nonexistent" "/%00" "/.." "/error" "/debug"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" | grep -iE "stack|trace|exception|error|warning|debug|line [0-9]+" | head -5
done
```

## Procedure

### Phase 1 — Error & Exception Leakage

```bash
# Trigger errors with malformed input
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users?id='"
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/login" -d '{"username":null}'
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/search?q=%00"

# Check response for sensitive data
# Stack traces → file paths, line numbers, framework version
# SQL errors → table names, column names, DB type
# Deserialization errors → class names, serialization format
# Template errors → template paths, engine type

# Fuzz for debug endpoints
for path in "/debug" "/__debug__" "/debugbar" "/_debug_toolbar" "/.well-known/debug" \
            "/actuator" "/actuator/info" "/actuator/env" "/actuator/health"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" -w "\n%{http_code} — $path\n" -o /dev/null
done
```

### Phase 2 — DVCS & Config File Discovery

```bash
# Git, SVN, Mercurial exposure
for path in "/.git/HEAD" "/.git/config" "/.svn/entries" "/.hg/store/"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" -w "%{http_code} — $path\n" -o /dev/null
done

# Config and env files
for pattern in ".env" ".env.local" ".env.production" ".env.staging" \
               "config.json" "config.yml" "settings.py" "settings.php" \
               "wp-config.php" "web.config" "app.config"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/$pattern" -w "%{http_code} — $pattern\n" -o /dev/null
done

# Backup files
for pattern in "backup.zip" "backup.sql" "dump.sql" "db.sql" \
               "database.sql" "export.sql" "site.tar.gz" "backup.tar.gz"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/$pattern" -w "%{http_code} — $pattern\n" -o /dev/null
done
```

### Phase 3 — Source Map Exploitation

```bash
# Find .js.map files
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo '[^"\s]+\.js\.map' | sort -u

# Download and extract
wget "https://target.com/static/app.js.map"
node -e "
const m=require('./app.js.map');
m.sources.forEach((s,i)=>require('fs').writeFileSync(s.split('/').pop(),m.sourcesContent[i]));
console.log('Extracted '+m.sources.length+' files');
"

# Look for NEXT_PUBLIC env vars in extracted source
grep -r "NEXT_PUBLIC_" extracted_files/ | cut -d= -f1 | sort -u
```

### Phase 4 — Differential Oracles

```bash
# User enumeration via status code
for id in {1..50}; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users/$id" -w "$id — %{http_code}\n" -o /dev/null
done

# Object existence via response size
for id in {1..100}; do
  size=$(curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/orders/$id" -w "%{size_download}" -o /dev/null)
  echo "$id — $size bytes"
done | awk '$2 > 100 {print "EXISTS: "$0}'

# Timing oracle for blind enumeration
for id in {1..50}; do
  time curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users/$id" -o /dev/null -w "%{time_total}s $id\n"
done | sort -rn

# ETag/304 oracle
for id in {1..10}; do
  etag=$(curl --max-time 30 --connect-timeout 10 -skI "https://target.com/api/users/$id" | grep -i etag)
  echo "$id: $etag"
done
```

### Phase 5 — Version & Technology Discovery

```bash
# Framework version from static assets
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/static/admin/css/base.css" | head -5
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo '(?:Django|Laravel|Rails|Express|Next\.js|Nuxt)[\s/]*v?[0-9.]+'

# Package manager lock files
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.version) | "\(.name)@\(.version)"' 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/package-lock.json" | jq -r '.packages | to_entries[] | "\(.key)@\(.value.version)"' 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/yarn.lock" | head -30
```

### Phase 6 — Chaining Disclosures

Each disclosure type provides inputs for other attack vectors:

| Disclosure | Chains to |
|---|---|
| Framework version | CVE database lookup |
| Server path | LFI path traversal |
| Internal IP | SSRF target |
| API schema | Auth bypass via undocumented endpoint |
| Dependency version | Supply chain vulnerability |
| NEXT_PUBLIC variables | API key/Supabase/Firebase access |
| SQL error | SQL injection confirmation + DB type |

## Pitfalls

- **Not every error message is exploitable.** A generic "An error occurred" page with no details is not a finding.
- **Source maps may be empty or stripped.** Verify extracted content before reporting.
- **Differential oracles are statistical.** Confirm with at least 3 samples before reporting.
- **`.git` exposure must contain actual repo data, not just HTTP 200 on a path.** A catch-all SPA may return 200 for `/.git/HEAD` without serving git data.
- **Version disclosure alone is usually LOW severity.** Chain it — version → CVE → exploit.

## MDPsec Verified Patterns (real info-disclosure reports)

Real-world primitives from mdpsec.com reports:

1. **Vite dev server in production** — CMS admin served by Vite dev server; `/@fs/` serves files from allowlist root with no auth; out-of-allowlist requests → 403 that discloses allowlist root path → single GET downloads 6.1MB SQLite DB (6 admin bcrypt accounts, registration tokens, API tokens, all content); all source readable (admin JWT secret, token salts, app keys); `.git/` accessible → GitHub PAT in remote URL, full commit history, cloud region + private IP (118).
2. **High-cardinality metrics labels** — Prometheus `/metrics` with raw request path as label → 3,200 unique xpubs in one response (84); login-count labels carry real person emails + org + product (63).
3. **Config endpoints leaking auth policy** — public config endpoint declares `LocalIDP.SelfRegister: DISALLOWED` while backend accepts self-registration → frontend-only enforcement proof (1).
4. **Staging data consistency proof** — staging assistant API serves live production data: exfiltrated row matched a live public event listing char-for-char same day; row counts decremented real-time over 2 hours as tickets sold/redeemed/cancelled (35).
5. **Enum echo in validation errors** — invalid enum value returns full enum → internal role names (31, 42).
6. **Public JS/bundle secrets** — token in bundle served `cache-control: immutable` → year-long edge exposure (21); `NEXT_PUBLIC_*` provider key (74); RPC gateway key in URL path (95).
7. **Feature-flag admin exposure** — 116 feature flags, token inventory with wildcard production client token, segment definitions with 23 privileged user ID hashes + SSO user IDs; flag-evaluation with leaked userId flips SSO/testnet; token-validation endpoint = brute-force oracle (42).
8. **`/proc/self/environ` via sandbox escape** — script sandbox allows reading job environment → live production API key; key outlives logout + refresh-token revocation (81).
9. **Exec dashboard unauth** — single aggregation endpoint `GET /internal/dashboard` returns 200 unauth while sibling endpoints 401; `dt_produced_next` timestamp proves live data; ~$30M reserves + full operational telemetry + top referrer usernames (112).
10. **CVV stored in cleartext via GraphQL (23)** — no payment tokenization at all (no Stripe/Braintree/Adyen SDK in dependency graph); `saveCard` mutation stores `cardCvv`; `CurrentCards` query returns CVV + unmasked PAN behind only session bearer token; `getInjectScript` embeds card creds as string literals for auto-fill on four gateways; no cert pinning, cleartext traffic in manifest → full PCI DSS non-compliance.
11. **Insurance quote mass extraction (57, 58)** — mint anonymous bearer (no-auth endpoint) → retrieve-token endpoint with query flag skipping DOB+postcode verification → per-quote retrieval token → full home dossier: identity, mortgagee bank plaintext, saved card (last4+expiry+token), direct-debit BSB, alarm configuration; 215-quote sweep → 26 records in ~3 min zero throttling; phone→PII via message-centre lookup (populated-vs-empty oracle) chains customer numbers → full records across 5 brands.
12. **Plaintext creds in public cloud blob (66)** — Android pulls runtime config from anonymously listable container; one plaintext file holds production secrets incl. `ReCaptchaBypass` static header; client-credentials grant → 24h RS256 JWT defeats WAF/bot protection across 3 country sites; static `Request-Key` header disables server-side CAPTCHA on voucher/gift-card endpoints (differential: with header → 400 processed; without → 403 captcha blocked).
13. **Mutable identity claim (67)** — backend derives authenticated principal from user-editable custom identity field in signed access token; every token carries self-service scope → overwrite own identity to victim's code (harvested from roster endpoint) → re-login → victim's account; attribute-update accepts any 32-char value with no validation.
14. **WebView header leak to third-party origins (126)** — central WebView wrapper unconditionally injects auth headers on every URL it loads with no domain check (`map.put("auth-token", token); webView.loadUrl(url, map)`); normal-use triggers (meme coin chart, staking screen, "Login with Telegram") each receive full 30-day session token in HTTP headers; desktop unaffected → Android-wrapper-specific; token replayed from VPS: profile, balances, orders, spot orders no 2FA.

Cross-ref `mdpsec-report-knowledge` for the full index.

## Verification

1. Error message contains actionable internal data (file path, SQL query, framework version).
2. Source map extraction produces real source files with identifiable code (not just webpack bootstrap).
3. Differential oracle consistently distinguishes between existing and non-existing resources.
4. Chain the disclosure to another vulnerability before reporting — standalone info disclosure is rarely critical.
5. For config files: the leaked data must contain credentials, API keys, or connection strings (not just generic config).

## Related Skills

- **`source-leak-hunt`** — Focused on `.env`, `.git`, and config file leakage.
- **`js-secrets-extraction`** — API keys and tokens in JavaScript bundles.
- **`error-log-mining`** — PHP error logs with credential and query leakage.
- **`web-enumeration`** — Path discovery that reveals sensitive endpoints.
