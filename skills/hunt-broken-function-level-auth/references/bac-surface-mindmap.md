# Broken Access Control — Full-Surface Playbook

> Source: `Broken Access Control.pdf` (XMind mind map, OCR-extracted). Restructured as a **priority-ranked playbook**.
> **Trigger:** load when mapping/abusing authorization on any REST API, or whenever a 403 "should" be 200.
> **Order:** classify protections → fuzz values + structure → tamper (dup keys / case / verb / extension) → write-gap.
> ⚠️ Payloads are **generic templates** — adapt to the target. Verify each response before claiming a finding.

---

## Step 0 — Protection Classification (2 min per endpoint)

Map each endpoint before attacking:

| Class | Signal | Meaning / action |
|---|---|---|
| Public | 404 on missing resource | doesn't exist or hides — fuzz deeper |
| Authed | 403 with valid session | permission check works — try bypass |
| **No-access-mode** | 200 / silent block | exists but hard-blocks → **verb/param tamper candidate** |

**Test:** for each `/api/[FUZZ]/[FUZZ]`, hit `/api[FUZZ]/me` and `/api/user/[FUZZ]` (path-shortening + parameter-position fuzz) to find the no-access-mode class.

---

## Step 1 — Fuzz Values (implicit) & Structure (explicit)

| Implicit (values) | Explicit (structure) |
|---|---|
| `/api/user/me`, `/api/users`, `/api/users/41` | `/N2[FUZZ]/12`, `/N2-[FUZZ]/get_data/12` |
| `/api/v1/messages?msg_id=43`, `?userid=665` | encoded separators: `%26` (&), `%23` (#), `%2f` |
| swap IDs: 41→42, 665→other | dot-segments: `/N2/get_data/.%2f13` |
| email as ID | **case confusion: `Userld` vs `userId`** (`v3/medicalHistory/9102301/Condition?Userld=9114305`) |

**Why:** encoded separators change how the router splits params; case variants skip server-side key validation; dot-segments traverse normalization.

**Payload (template):**
```bash
curl -sk "https://target/api/v2/get_data/13%26"           # encoded &
curl -sk "https://target/api/v2/get_data/13%23"           # encoded #
curl -sk "https://target/api/N2/get_data/.%2f13"          # dot-segment
curl -sk "https://target/v3/medicalHistory/9102301/Condition?Userld=9114305"  # case confusion
```

**Verdict:** any 200 with other-user data → IDOR/BFLA. **Chain:** `hunt-idor`.

---

## Step 2 — Tampering Matrix (on any 403 / should-be-403)

| Technique | Payload (template) |
|---|---|
| **JSON duplicate keys** (parser-dependent first/last wins) | `{"id":"9999","id":"5543"}` / `{"id":"5443","id":"9999"}` |
| Mass assignment (profile/registration/update) | inject `role`, `is_admin`, `verified`, `tier` |
| Case variants | `Userld`, `user_id`, `UID`, `USERID` |
| Extension append (different handler/authz) | `/api/users/41.json`, `.config`, `.xml` |
| Verb tamper | `GET /admin/users` → `POST` / `PATCH` / `DELETE` |
| Fields from responses | leak hidden field names → inject them back |
| Parameter pollution | `?user=100&user=101`, `id=5543&id=9999` |

**Why:** these change which parser/handler/middleware sees the request → different authorization path.

**Verdict:** state change / data read you shouldn't reach → BFLA/mass-assignment (High/Critical). **Chain:** `hunt-broken-function-level-auth` main phases, `hunt-api-misconfig`.

---

## Step 3 — Real-World IDOR Value Corpus

Use these values in Step 1 fuzzing:

- UUIDs: `/users/ib04c196-89f4-426a-b18b-ed85924ce283`
- **Null UUID:** `/users/00000000-0000-0000-0000-000000000000` (default/fallback record)
- Emails as IDs: `/users/namos.toooo@gmail.com` (guessable — no UUID needed)
- MongoDB ObjectIDs, encoded values, base64 IDs

**Verdict:** null-UUID or email-ID access → object-level exposure (High). **Chain:** `hunt-idor`, `api-noauth-hunt`.

---

## Step 4 — Write-Gap: Delete / Modify with Extra Param (Critical)

**The canonical pattern:**
```
(session) → DELETE /api/v1/messages/54           → 200   (own message)
(session) → DELETE /api/v1/messages/105          → 404   (someone else's)
(session) → DELETE /api/v1/messages/105?user=100 → 200   ← extra user param OVERRIDES ownership check
```

**Why:** the ownership check uses `from_user=77886 OR to_user=77886` — the OR-window is itself a bug, and an attacker-supplied `user=` param can satisfy it.

**Test:**
1. Find a resource with owner semantics (messages, orders, docs).
2. Try DELETE/PATCH on a resource you don't own → expect 403/404.
3. Replay with extra identifying param: `?user=`, `?owner_id=`, `&user_id=`, `?to_user=`.
4. Test BOTH directions: `from_user` (came from someone) and `to_user` (sent to someone).

**Payload (template):**
```bash
curl -sk -X DELETE "https://target/api/v1/messages/105?user=100" -H "Authorization: Bearer ***"
```

**Verdict:** 200 on resource you don't own → Critical (write-gap / BFLA). **Chain:** `hunt-write-gap` (home pattern), `hunt-idor`.

---

## How to use

1. Run Step 0 on every discovered endpoint (classify → focus on no-access-mode).
2. Fuzz implicit + explicit in parallel (Step 1) with the value corpus (Step 3).
3. Any 200 that should be 403 → Step 2 tampering matrix.
4. Any write endpoint → Step 4 write-gap replay with extra params.
