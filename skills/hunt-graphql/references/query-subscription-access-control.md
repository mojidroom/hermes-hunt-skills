# GraphQL Query & Subscription Access Control Testing

> **Trigger:** load after schema mapping — test EVERY query and subscription for object-level (IDOR) and field-level access control, not just mutations. Mutations get the authz love; queries and subscriptions are where IDOR hides.
> ⚠️ Payloads are generic templates — adapt field/type names to the target schema.

---

## Part A — Query-side Access Control

### A1. Field-level authz differential (the #1 GraphQL PII bug)

Same query, three sessions: **admin / normal / anon**. Compare which fields return vs null vs error.

```graphql
query { user(id: "VICTIM_ID") { id email phone nationalId role } }
```

- admin → all fields
- normal → email only? or `null` on sensitive fields? or full object?
- anon → error / partial

**Verdict:** normal/anon user reads fields that admin-only should see → **field-level authz failure (High)**. Real case: backend migration introduced a `User` type with no field-level authz → any authenticated user enumerated all users' PII (H1, broken field-level authorization subclass).

### A2. Argument IDOR (object-level)

Every query taking an ID argument is an IDOR candidate:

```graphql
query { user(id: 1) { id email } }
query { post(id: 42) { content } }
query { order(id: 1001) { total cardLast4 } }
query { invoice(id: "INV-2026-001") { ... } }
```

- swap to the victim's ID (other tenant / other user)
- try vague values: `0`, `-1`, `00000000-0000-0000-0000-000000000000` (null UUID), email-as-ID, base64 variants
- repeat the same query with TWO sessions (A owns id=1, B queries id=1)

**Verdict:** data from another user's object → IDOR (High/Critical).

### A3. `node()` / GID IDOR

Global IDs encode type+id, usually base64: `base64("User:42")` → `VXNlcjo0Mg==`.

```graphql
# decode → swap id → re-encode → query
query { node(id: "VXNlcjo0Mg==") { ... on User { id email role } } }
query { node(id: "VXNlcjowMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDA=") { ... on User { id } } }
```

**Verdict:** node() resolves a cross-tenant/cross-user object → IDOR via GID (High).

### A4. Alias batching — fast IDOR verification (one request, many IDs)

```graphql
query {
  u1: user(id: 1) { id email }
  u2: user(id: 2) { id email }
  u3: user(id: 3) { id email }
}
```

- verify horizontal access in a single request
- also bypasses naive per-request rate limits (amplifier)

**Verdict:** any alias returns data you shouldn't see → IDOR; combined with rate-limit bypass → report the amplification.

### A5. Connection / pagination access control

`first`/`after` cursors can skip connection-level authz:

```graphql
query { users(first: 100) { edges { node { id email role } } pageInfo { hasNextPage endCursor } } }
```

- normal user paginates ALL users → broken connection-level authz (High)
- replay a cursor captured in the victim's session inside YOUR session → cross-tenant pagination (Critical)

### A6. Introspection-adjacent field discovery

```graphql
query { __type(name: "User") { fields { name type { name kind } } } }
```

Reveals hidden field names → feed them into A1/A2 (field-level authz + argument IDOR).

---

## Part B — Subscription Access Control (WebSocket)

### B1. Subscription IDOR (channel / chat / room swap)

```graphql
subscription { messageAdded(chatId: "VICTIM_CHAT_ID") { text sender } }
subscription { orderUpdated(orderId: "VICTIM_ORDER") { status total } }
subscription { locationPushed(userId: "VICTIM_USER") { lat lng } }
```

**Real case (H1 #1649817):** change `chatId` in the subscription → receive other users' real-time messages.

**Verdict:** victim's events delivered to your subscription → **Critical (real-time data leak)**.

### B2. Auth on connect vs per-event

**Real case (H1 #1585593):** WebSocket subscription validated the token only on connect, not on each event dispatch → attacker reads all real-time messages.

**Test:**
1. Connect WS with valid token → subscribe to a channel.
2. Open a SECOND connection with another user's token (or no token).
3. Do events dispatch to BOTH connections for the same channel?

**Verdict:** connect-time-only authz → Critical (any event broadcast to unauthorized listener).

### B3. Stale subscription / revoke bypass

1. Subscribe to victim's channel (legitimately or via B1).
2. Revoke access via REST (`DELETE /chats/{id}/members/{me}` or permission removal).
3. Do events STILL arrive on the open subscription?

**Verdict:** revoke doesn't kill the open WS subscription → persistent access after revocation (High/Critical, mirrors the REST/GraphQL desync pattern).

### B4. Field-level authz on subscription payloads

Same differential as A1 but on the real-time payload: subscribe as normal user, check if the event carries sensitive fields (payment, location, message content, presence) that should be admin-only.

### B5. Subscription resource exhaustion

Subscribe to many channels/rooms in parallel → per-connection resource DoS (each WS holds server-side state). Report only with a measurable impact (connection cap, memory, latency).

---

## Verdict Quick-Check

| Test | Signal | Severity |
|---|---|---|
| A1 field differential | normal user reads admin-only field | High |
| A2/A3/A4 argument/node/alias | other-user object data returned | High/Critical |
| A5 pagination | full dataset via first/cursor | High/Critical |
| B1 channel swap | victim's real-time events | Critical |
| B2 connect-only auth | second conn receives events | Critical |
| B3 stale subscription | events after revoke | High/Critical |
| B4 payload fields | sensitive fields in event | High |

- Proof standard: two accounts, exact query/subscription, before/after responses
- CSRF/CORS on token-based GraphQL → skip (see `target-auth-profile` matrix)
