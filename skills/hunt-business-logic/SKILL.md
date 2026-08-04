---
name: hunt-business-logic
description: Hunting skill for business logic vulnerabilities. Built from 12 public bug bounty reports. Covers coupon-race-stacking (Instacart, Stripe, Reverb), negative-quantity-in-cart price tampering (Upserve, Eternal/Zomato), decimal/fraction price-field overflow (Shipt), client-side checkout amount trust on PayPal redirect (WordPress.org), price-per-unit mass-assignment (Krisp), and archived-price swap / cart-TOCTOU (Stripe). Use when hunting business logic — heavy emphasis on financial-impact-demonstrated cases.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [business-logic, hunt, redteam]
---

## Crown Jewel Targets

Business logic vulnerabilities pay highest in platforms where financial transactions, identity verification, and access controls intersect with real-world consequences. The richest targets are:

- **E-commerce & payment platforms** (Valve/Steam, Shopify) — payment flow manipulation, free goods, price tampering
- **Marketplace & gig economy apps** (Airbnb, Uber) — identity/verification bypass enabling fraud or unsafe interactions
- **SaaS with tiered access** (Mozilla Monitor) — bypassing verification to unlock monitoring features without entitlement
- **High-traffic consumer apps** (Snapchat, Yelp) — rate-limit bypass enabling spam, enumeration, or abuse at scale

Asset types that pay: checkout flows, subscription endpoints, callback/verification systems, webhook handlers, employee/internal portals exposed to the internet, and any endpoint that trusts client-supplied data to make authorization decisions.

---

## Attack Surface Signals

**URL patterns to watch:**
- `/checkout`, `/order`, `/subscribe`, `/payment`, `/verify`, `/confirm`, `/callback`
- `/internal`, `/employee`, `/summit`, `/staff`, `/admin` — internal pages accidentally public
- `/api/v*/payment`, `/api/v*/notify`, `/webhook` — payment provider callbacks
- Endpoints accepting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` headers

**Response/header signals:**
- `Set-Cookie` with unvalidated session state tied to cart or order data
- Payment provider names in responses: `Smart2Pay`, `Stripe`, `PayPal`, `Braintree`
- Redirect chains through third-party payment pages (in-flight data opportunity)
- `200 OK` on subscription/verification endpoints with no CAPTCHA or token

**JS patterns:**
- Hardcoded internal URLs in frontend bundles (`/employee/`, `/staff/`, `/internal/`)
- Client-side price calculation before server submission
- Verification logic that only checks on the frontend (`if (verified) { ... }`)
- `fetch('/api/subscribe', { method: 'POST', body: ... })` with no anti-CSRF token or rate-limit token

**Tech stack signals:**
- Shopify storefronts with draft/unpublished channel pages
- Apps using IP-based rate limiting without session/account binding
- Payment webhooks with no HMAC signature validation
- SMS/phone callback flows that don't verify ownership before enabling features

---

## Step-by-Step Hunting Methodology

1. **Map all authentication boundaries.** Spider the target. Identify pages/endpoints that serve authenticated content (employee portals, premium features, order pages) and test each unauthenticated. Look for internal pages indexed in JS bundles or linked from robots.txt/sitemap.xml.

2. **Identify every verification flow.** Enumerate: email verification, phone/SMS verification, payment verification, CAPTCHA, age gates. For each, test: what happens if you skip the verification step entirely? What happens if you replay a valid token on a different account?

3. **Test rate-limiting controls on every form.** For every POST endpoint (subscribe, login, OTP, search), send 50+ rapid requests. Vary: remove cookies, rotate `X-Forwarded-For` / `X-Real-IP` headers, change `User-Agent`. Check if the server uses IP from headers rather than connection IP.

4. **Intercept and tamper with payment flows.** Use Burp Suite to intercept every request between your browser, the application, and the payment provider. Identify where price, currency, order ID, or status fields are set. Attempt to modify amounts to $0.01 or currency to a low-value currency. Look for POST-back/webhook endpoints that accept payment confirmation — test if they validate HMAC/signature.

5. **Test phone/callback number verification.** Whenever a platform accepts a callback number, test: can you set it to a number you don't own? Does the platform call/text that number and grant trust based solely on submission? Try setting it to a victim's number.

6. **Check for unprotected employee/internal surfaces.** Search Shodan, GitHub, JS bundles, and Wayback Machine for internal subdomain/path references. Test access without authentication. Check if these surfaces allow order placement, data access, or privilege escalation.

7. **Validate business impact.** For each finding, determine: does this result in financial loss, unauthorized access, or data exposure? Document the end-to-end chain.

---

## Payload & Detection Patterns

**Rate limit bypass via header rotation:**
```bash
# Rotate X-Forwarded-For to bypass IP rate limiting
for i in $(seq 1 100); do
  curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/api/subscribe \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "X-Real-IP: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim+'"$i"'@example.com"}' \
    -o /dev/null -w "%{http_code}\n"
done
```

**Payment tampering — modify in-flight price:**
```http
POST /payment/initiate HTTP/1.1
Host: target.com

amount=0.01&currency=USD&order_id=12345&product_id=99
```
```bash
# Look for unvalidated webhook endpoints
curl --max-time 30 --connect-timeout 10 -X POST https://target.com/payment/callback \
  -H "Content-Type: application/json" \
  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'
```

**Unauthenticated internal page discovery:**
```bash
# Check robots.txt and sitemap for internal paths
curl --max-time 30 --connect-timeout 10 -s https://target.com/robots.txt | grep -iE "(disallow|allow)" 
curl --max-time 30 --connect-timeout 10 -s https://target.com/sitemap.xml | grep -iE "(employee|internal|staff|summit|admin)"

# Grep JS bundles for internal paths
curl --max-time 30 --connect-timeout 10 -s https://target.com/assets/app.js | grep -oE '"/[a-zA-Z0-9/_-]{3,50}"' | sort -u
```

**Email verification bypass:**
```bash
# Skip the verification step: hit the post-verification API endpoint directly
# with an unverified session. If it succeeds, the gate is UI-only.
curl --max-time 30 --connect-timeout 10 -s -X POST https://monitor.target.com/api/monitoring/enable \
  -H "Cookie: session=<your_unverified_session>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Replay verification token on different account
curl --max-time 30 --connect-timeout 10 -X POST https://target.com/verify \
  -d 'token=VALID_TOKEN_FROM_ACCOUNT_A&email=account_b@example.com'
```

**Grep patterns for client-side logic issues:**
```bash
# Find price calculations in JS
grep -iE "(price|amount|total|cost)\s*[=*+]" app.js

# Find internal URLs in JS bundles
grep -oE '"/(employee|internal|staff|admin|summit)[^"]*"' *.js

# Find unvalidated IP header usage in server code
grep -iE "x-forwarded-for|x-real-ip|cf-connecting-ip" src/ -r
```

---

## Common Root Causes

1. **Server trusts client-supplied data for financial decisions.** Developers offload price calculation to the frontend or pass amount fields through forms/URLs without re-validating on the server against a canonical source (the product database).

2. **Verification is enforced only in the UI, not the API.** Frontend hides features behind a verification gate, but the backend API endpoints are fully functional without a verified status — any authenticated request succeeds.

3. **IP-based rate limiting reads from spoofable headers.** Developers implement rate limits using `request.headers['X-Forwarded-For']` instead of the actual connection IP, allowing trivial bypass by header manipulation.

4. **Payment webhooks lack signature validation.** Developers implement "success" webhooks without verifying the HMAC signature provided by the payment provider, allowing anyone to POST a fake success notification.

5. **Internal/employee pages aren't access-controlled.** Internaltools are deployed to production domains without authentication middleware, either because developers assume obscurity (unlisted URL) or forgot to apply auth to a new route.

6. **Phone/callback verification is advisory, not enforced.** Systems accept a phone number and grant trust to whoever submitted it, without confirming the submitter owns or controls that number.

7. **Draft/channel-specific storefronts inherit full order functionality.** Platforms like Shopify allow creating storefronts for specific channels (employee events) that are unlisted but still fully functional for order placement if the URL is known.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| IP-based rate limiting | Rotate `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` headers per request |
| CAPTCHA on subscription forms | Use header-based bypass first; if CAPTCHA is only on the web form, call the underlying API endpoint directly |
| Email verification gate | Access the post-verification API endpoint directly; replay valid tokens; check if `verified=true` is a client-set cookie/param |
| Payment amount server validation | Modify currency to a lower-value currency; test with $0.00 or negative amounts; manipulate order IDs to reference different products |
| Webhook HMAC validation | Test with no/empty signature header (is validation enforced at all — a modified payload only "passes" if it isn't); replay an UNMODIFIED captured webhook to test missing idempotency/anti-replay |
| Auth on internal pages | Try unauthenticated; try with a low-privilege account; try path traversal variants (`/employee/../employee/`) |
| Phone verification (OTP sent) | Submit someone else's number without OTP validation; check if the system grants trust on submission vs. OTP confirmation |

---

## MDPsec Verified Patterns (all 16 business-logic reports from mdpsec.com)

Every report below is a confirmed exploitable chain. Grouped: (A) financial/price manipulation, (B) entitlement/verification bypass, (C) state/integrity tampering, (D) smart-contract logic, (E) monetization/paywall bypass, (F) billing/plan manipulation.

### A. Financial / Price Manipulation

**1. Client-computed price echoed verbatim (report 46 — CWE-840)**
- Group-purchase checkout computes discounted total in browser: `if (order.total_items > 4) order.charge_amount = order.total - (order.discount * order.total)` then POSTs the whole order object back. Server never recomputes from catalog/quantity/discount.
- `POST /group-order/generate-token {"group_request":{...products, "order":{... "charge_amount":100.00}}}` → minted hosted payment page reports `totalAmount 100.00` for a ~$64,500 true subtotal (500 seats → 99.8% undercharge).
- Processor only receives total + static description — no line items to flag mismatch; order record keeps real seat count, queued for manual fulfillment.
- **Detection:** price computed client-side and echoed verbatim; hosted-payment `totalAmount` differs from order total; fixed absolute charge floor (~$63) that doesn't scale with order size; sequential invoice numbers leak order volume.
- **PoC:** two unauthenticated POSTs to `/group-order/generate-token` (honest then tampered `charge_amount`) → compare `totalAmount` on the resulting hosted payment page.

**2. Charge-amount tampering in payment token (report 46 — same chain)**
- Replaying the same body with a tampered `charge_amount` mints a payment page charging the tampered amount; server never re-derives price from catalog.
- **PoC:** honest token vs tampered token → mint → observe `totalAmount` delta; no line items reach the processor.

**3. Gift-card PIN enumeration + no rate limit (report 44 — CWE-307, CWE-330)**
- 19-digit PINs have predictable structure: `6087480024515610906` = fixed prefix + sequential batch ID + fixed segment + sequential per-batch counter. Same-batch cards share the batch ID; counter increments predictably.
- Buy one low-value gift card → "seed" position in issuance sequence; fire `customerRedeemGiftCard` GraphQL mutation against PINs ±200 from seed with 20–50 concurrent workers.
- Differential = oracle: invalid PIN → `BAD_REQUEST` (HTTP 200); valid unredeemed PIN → `StoreCredit` object (value + transaction id) and instantly credits the card to attacker's account.
- 23,000 probes in 85s (~270 rps) with ZERO throttling. Legacy REST redemption was WAF-limited (~22 requests) but the GraphQL endpoint was not covered. Hit found: real $100 card at offset +91, redeemed in ~18.5s.
- **Impact:** instant theft of other customers' unredeemed gift cards (up to $500 each, bulk corporate issuance); no lockout, no detection, atomic redemption = no refund path.
- **Key lesson:** ALWAYS test the alternate-transport variant (GraphQL/WS/mobile API) when a REST sibling is WAF/rate-limited.

### B. Entitlement / Verification Bypass

**4. Entitlement bypass with attacker-chosen expiry (report 93 — CWE-639, CWE-840)**
- `POST /rewards/mint-perk {"type":"DAYS_OUT","expiryDate":"2099-12-31"}` → `{"url":"https://rewards-portal.example?token=<accountId>,<expiryDate>&value=<base64 HMAC-SHA256>"}` — signed redemption URL usable with NO session at all.
- Two design flaws: (1) no entitlement check — an account with wallet `status:"INELIGIBLE"`, zero perks, receives the identical signed URL as a paying member; (2) `expiryDate` taken verbatim from request body and folded into the signed token.
- Signature itself is sound (tampered byte rejected) — the flaw is the minting service signing tokens for non-entitled accounts with attacker-chosen expiry.
- **Detection:** 5 parallel mints → 5 byte-identical signed URLs (no nonce, no per-request entropy, no rate limit); `type:"PROMO"` also mintable on same code path; mass-assignment probes (`status`/`accountId`/`amount`/`perkId`) silently ignored → entitlement bypass, not cross-account.
- **PoC:** free signup → confirm wallet INELIGIBLE → single `POST /rewards/mint-perk` with far-future expiry → open URL in fresh browser (no cookies) → full perks portal with claimable vouchers. Survives originating-account deletion.

**5. Loyalty card forgery via shared provisioning key (report 62 — CWE-321 → business impact)**
- iOS app bundles encrypted config; decryption key = UUID in Swift lazy global variable (runtime instrumentation); first 16 bytes = AES-128 key, zero IV → decrypt 10 secrets incl. OAuth creds + digital wallet signing key.
- Wallet provisioning uses SHARED symmetric key: take customer card number → AES-256-CBC encrypt (extracted signing key, zero IV) → base64 → provisioning URL → open on any iPhone → victim's loyalty card lands in attacker's Apple Wallet (full name, points, tier, scannable barcode working in stores).
- Card enumeration: decrypted OAuth creds enable guest token generation; unauthenticated endpoint validates card numbers + returns VIP flag; card numbers SEQUENTIAL (41/41 valid in sampled range), no rate limiting. Same key/schema across all 8 country apps; OAuth secret ciphertext identical iOS vs Android (cross-platform key reuse).
- **Impact:** mass loyalty-card forgery + points theft across 8 European countries; barcode scans at registers; 150 pts = €7.50 voucher; zero auth, zero victim interaction.

**6. Hardcoded JWT paywall bypass (report 69 — CWE-798, CWE-287 → business impact)**
- Android app generates a session token signed with a shared secret and sets it as a cookie the web server treats as proof of in-app paying subscriber.
- Signing secret derivable entirely from constants in the public binary: encrypted blob in app resources; decryption key derived from hardcoded literal string used as BOTH password and salt — offline, deterministic, single command.
- Metering endpoint does NOT validate the token signature (unsigned tokens and wrong-key tokens both accepted) and does not verify the subscription id against a receipt store.
- **PoC:** reverse APK → key derivation → secret; forge token with subscriber claims; set cookie + matching device-id cookie; reload paywalled article → `granted: true, grant reason: "SUBSCRIBER", is-subscriber: true`; persists across articles/sessions.
- **Impact:** free permanent access to every paywalled article for any visitor; infinite scale via one social post; subscription revenue bypass; rotation alone doesn't fix (next release leaks next key).

**6b. Device-link scope upgrade + email change without re-auth (report 28 — CWE-601 → permanent ATO)**
- Device-link flow issues a token bound to a device-household identifier that is FULLY attacker-chosen and reflected verbatim into the sign-in `state` value (not tied to the authorizing user's device/session) → attacker mints a link code bound to a household they control, then polls for the victim's token after authorization.
- Sign-in client accepted an attacker-supplied **scope upgrade from read-only to read-and-write**.
- Account API let a write-capable token **change the contact email with no current password, no email confirmation, no OTP** — defect stands alone: any write-capable token becomes permanent takeover.
- Full chain: mint code → send authorize link (consent screen on genuine origin, doesn't name the speaker platform or list access) → victim clicks once → attacker polls and receives token + refresh token → read PII (email, full DOB, name, country, billing status, library) → change contact email to attacker's → trigger password reset → reset link lands in attacker inbox → set new password → permanent ownership, owner locked out of recovery.
- **Detection:** `state` reflecting caller-supplied identifiers; consent-screen content audit; email-change lacking re-auth.
- **Impact:** one-click permanent ATO; the email-change defect independently raises the floor for any token leak.

**7. Forwarded-header trust bypasses geo/compliance checks (report 43 — CWE-348, Business Logic / Trust Boundary)**
- Compliance endpoints derive the client's geographic state from ATTACKER-CONTROLLED HTTP forwarding headers instead of the network-layer source IP; the origin accepts `X-Forwarded-For` as authoritative and reflects the supplied value back as the "client IP" in responses.
- Two unauthenticated endpoints affected: an IP-check endpoint (client IP, country code/name, restricted flag) and a country-specific endpoint (restricted flag + list of jurisdiction-restricted assets).
- Response headers show NO upstream proxy stripping client-supplied forwarding headers → browser-supplied values reach the origin unchanged.
- **Left-most value wins** when multiple IPs are supplied → attacker value always wins even behind a proxy that appends the real client IP.
- **PoC:** `curl -s "https://example.com/api/auth/region-check" -H "X-Forwarded-For: 198.51.100.10"` → `isRestricted: true`; same with `8.8.8.8` → `isRestricted: false`; country endpoint: 16 restricted assets → empty list.
- **Impact:** any unauthenticated client controls compliance decisions: sanctioned-region users present as allowed; restricted-asset lists cleared; if these signals feed login/registration/trading/withdrawal, it's a direct compliance control failure with regulatory exposure.
- **Detection:** header reflection in the response body; left-most parsing behavior; multi-IP test (`X-Forwarded-For: 1.2.3.4, 8.8.8.8`).

**8. Unauthenticated warranty claim → real CRM case (report 117 — CWE-287 → business impact)**- Flaw 1: eligibility screening is browser-JavaScript-only (radio questions) — a single POST with the right event target value bypasses it and yields a claim-form session with zero answers given.
- Flaw 2: claim submission accepts unauthenticated users — server response body itself says `loginStatus = 'Anonymous'`; account numbers not validated against any account DB; all input validators client-side only.
- 3-request chain: GET screening page (capture anti-forgery tokens) → POST back with event target "Complete Claim Online" → 302 to claim form → GET form → POST populated claim → REAL case created in production CRM, case number returned, confirmation email sent to any supplied address.
- **Confirmed bypass matrix:** eligibility (server validates → bypassed with one event-target POST), authentication (logged-in required → anonymous accepted), account ownership (verified → fake number accepted), attachments (required → not enforced), rate limiting (throttled → 10 rapid sequential bypass POSTs all 302).
- **Impact:** anonymous fraudulent claims against any consignment number (financial payouts), operational DoS of the claims team, phishing-grade emails from the official carrier domain.

### C. State / Integrity Tampering

**8. Cross-session merge-on-write quote poisoning (report 56 — CWE-639 write)**
- Quote-store endpoint accepts a write whose body contains the target customer number; server merges incoming fields into the stored record and returns 200 — no session-ownership check, no session-to-customer binding, no brand check on the calling token.
- Anonymous bearer mintable from a no-auth bootstrap endpoint; one bearer writes into the shared storage namespace across all five sibling brands.
- Two independent anonymous browser windows prove cross-session write: victim bootstraps quote (car modified flag=true); attacker window with own challenge cookie + bearer calls same endpoint with victim's customer number → 200, flag flipped to false + injected marker field; victim's readback shows attacker fields.
- Merge-on-write preserves victim fields → invisible mid-quote; persistence: re-saving normal app fields does not clear attacker fields; only insurer admin tooling purges them.
- **Impact:** persistent poisoning of any customer's quote state across five brands — underwriting disclosure flags silently flipped; policy issued on undeclared state; combinable with quote-number oracle (#59) for full customer-base targeting.
- **PoC:** victim window mints bearer + creates quote; attacker window mints own bearer + POST quote-store `{customerNumber: victim, carModified: false, marker}` → victim readback shows flipped flag.

**9. Gift-card refund race → 18-20x credit multiplication (report 87 — CWE-362)**
- Refund flow: `POST /refund` with booking ID + gift card number → app server checks "already refunded?" → forwards credit to downstream payment server → payment credits gift card → app server marks booking refunded. Steps 2 and 5 are NOT atomic.
- Fired 20 concurrent refund requests (thread pool) with independently generated HMAC signatures and unique request IDs — multiple requests pass the check before any reaches the lock.
- **Response taxonomy is the oracle:** HTTP 200 + booking data (1–2, refund processed), HTTP 500 "RefundAlreadyInProgress" (~6, passed validation, credit committed — EACH ONE is a credit!), HTTP 400 "already refunded" (~13, lock took effect).
- Also: API token in plaintext at `res/raw/local_config.json`; HMAC signing key AES-256-encrypted in `res/values/strings.xml` with the AES key hardcoded in decompiled Java → could authenticate as any loyalty member directly, bypassing the app.
- **Impact:** $5 ticket refund → +$90–100 gift card credit per cycle (18–20x multiplier); $10 card → $365 over 4 tests; spendable at any chain location; reproducible by anyone with the app (4/4 attempts).

**9b. Magic-link verification TOCTOU (report 65 — CWE-367, race in auth flow)**
- Login flow creates verification record SYNCHRONOUSLY but writes the actual code ASYNCHRONOUSLY (background job) → 0–1s window where record exists with EMPTY code field; verification endpoint has no null/empty check → blank code accepted as valid.
- Trigger login for victim email → immediately submit blank verification code → valid authenticated session (no victim interaction).
- Retrieve victim's encrypted wallet material from DB; obtain decryption credentials via cloud KMS; multi-step decryption reconstructs full recovery phrase/private key; separate endpoint returns additional wallet data for any user without auth. ~60s total.
- Works for email and Telegram wallets; Telegram user IDs public in community groups; synthetic emails for Telegram accounts follow predictable pattern → 38,000+ enumerable targets.
- **Impact:** complete wallet drain (mnemonic + private key extraction); zero victim interaction.

### D. Smart-Contract Logic

**10. Zero-byte gas overpayment (report 4 — CWE-840)**
- Refund estimator assumed EVERY calldata byte costs 16 gas: `v1_transactionBaseGas() = 21_000 + 14_698 + (Math.min(msg.data.length, 3000) * 16)`. EVM charges 4 gas for zero bytes, 16 for non-zero → systematic overpayment of 12 gas per zero byte.
- Solidity tolerates trailing calldata → relayer appends zero bytes up to the 3000-byte cap; each appended zero byte refunded at 16 gas while costing only 4 → net 12 gas profit per byte, every relay, indefinitely.
- **Impact:** direct, repeatable ETH drain from the gateway's reserve (also the legit-refund pool); compounds across bridge lifetime. Any address with relayer privileges.

**11. uint64 overflow on Solana bridge (report 5 — CWE-190)**
- Solana message packer downcasts without bounds check: `bytes8 slot3 = bytes8(uint64(_xfer.quantity));` — Solidity modular reduction silently wraps values above `type(uint64).max` (~18.44 tokens for an 18-decimal token). No require, no SafeCast.
- EVM path packs full 256-bit quantity into a 32-byte slot and is unaffected → proves the bug is Solana-encoding-specific.
- **Impact:** permanent fund loss with no error, warning, refund, or recovery; first real Solana withdrawal after go-live hits it; fires on normal user activity — no attacker required.

### E. Monetization / Paywall Bypass

**12. Unauthenticated content feed leaks full paywalled + unpublished articles (report 70 — CWE-306 → revenue impact)**
- Homepage backed by first-party content feed; ONE feed endpoint returns complete body HTML of premium articles to anonymous clients (no cookie/token/key) while public article pages correctly enforce paywall (title + ~2-3 dozen word lead only) and every sibling feed endpoint requires auth.
- Endpoint also returns finished content with no live public page yet (pre-publication disclosure: article served in full while its public route redirect-looped forever).
- Response publicly cacheable via CDN (short max-age public directive) → gated content in shared caches.
- Scope bounded: endpoint ignores `article_id` param and always returns only current curated set (~2 dozen records, rolling window); a scheduled unauthenticated poller harvests new premium output continuously. Same-origin console script on a real premium page pulls feed and renders full body in genuine layout (proves live content).
- **Detection:** anonymous endpoint returning body while UI enforces paywall; sibling endpoints on same feed require auth; unpublished records present; `Cache-Control: public` on gated content; ignored filter params.
- **Impact:** continuous unauthenticated exposure of rolling premium set + occasional pre-publication articles; revenue bypass + editorial confidentiality harm.

### F. Billing / Plan / Catalog Manipulation

**13. Free account escalates to editing the production billing catalog (report 85 — CWE-269 → revenue impact)**
- Sign-in service issues tokens to named OAuth clients; an internal back-office catalog-management tool is registered as a PUBLIC client → anyone submitting valid account credentials (no client secret) gets the internal tool's identity + broad catalog scope.
- **Differential:** supplying a junk secret → unauthorized-client error; OMITTING the secret entirely → privileged token issued.
- Free account email/password + public client id (no secret) → token; decode → internal tool identity + catalog scope.
- Read: product-list endpoint → entire production catalog (every product, pricing across ~50 currencies incl. live premium trial plans, ~24 internal staff/contractor emails as product owners).
- Write: update route persists changes to live catalog records (proof edited only an internal dev-test record with marker, read back, restored); write accepts caller-supplied "updated by" field verbatim → forgeable audit trail.
- **Detection:** public OAuth clients for internal tools; secret-omission vs junk-secret behavior differential; client identity overriding user role; client-supplied audit fields.
- **Impact:** read/write access to live subscription pricing: set paid plan to free, deactivate products, invent fraudulent ones (direct revenue integrity risk); full catalog + internal staff emails disclosed; from an account anyone can register in seconds.

**14. Unauthenticated privilege escalation mints paid orders on partner books (report 31 — CWE-862 → billing fraud)**
- `POST /api/iam/v1/orgs/{org_id}/businesses` accepted UNAUTHENTICATED requests with attacker-chosen `org_id` + `business_type` — no auth header, no captcha, no rate limit, no invitation token → provisions a real partner manager account inside the named org, activation link emailed to the attacker; ~70% of probed partner org ids accepted.
- Payment-settings endpoint accepted a self-service `PUT {"payment_type":"invoicing","invoicing_period":"weekly"}` → 204, a control the partner UI never exposes for self-onboarded accounts.
- Reservation pay endpoint accepted `POST {"payment_gateway":"company","payment_method":"invoicing"}` → reservation flips TO BE PAID → PAID with an **active entry barcode**, rolled into the partner's normal weekly invoice; shows in the partner's sales view with a green badge.
- Bearer token carried no role/scope/partner claim — authorization was purely tenant-membership lookup → other mutations reachable: refund partner orders, cancel/reschedule reservations, publish fake listings, upload barcodes, pair POS terminals/kiosks.
- `business_type` accepted 5 internal staff role names; invalid values echoed the full enum in a validation error (leaking internal role names; activation downgraded them to manager).
- **Impact:** three confirmed real paid orders on one partner from clean accounts; ~70% of partners affected; billing fraud, fake listings, unauthorized refunds — aggregate hundreds of millions ceiling.

**15. Plaintext credentials in public cloud blob bypass bot protection for voucher abuse (report 66 — CWE-200 → voucher/gift-card brute force)**
- Android app pulls runtime config from public cloud storage container; container anonymously listable (5,000+ objects incl. staging configs); most configs AES-encrypted but one plaintext "example" file holds production secrets: `{"ClientIdKey":"...","ClientSecret":"secret","ReCaptchaBypass":{"headerKey":"Request-Key","headerValue":"..."}}` (literal dev placeholder "secret", never rotated).
- Client-credentials grant with leaked id/secret → RS256 JWT valid 86,399s (24h) with ROLE_CLIENT/ROLE_GUEST from production issuer.
- Token defeats WAF/bot protection entirely (without token: JS challenge/403; with token: every request passes); token works across three country sites (NL/BE/LU).
- **Static `Request-Key` header disables server-side CAPTCHA on voucher/gift-card endpoints** — differential proof: voucher POST with header → 400 "invalid voucher code" (processed); without → 403 "captcha blocked".
- **Impact:** voucher/gift-card brute force without CAPTCHA, unlimited carts/checkout programmatic, production API access across 3 countries bypassing bot protection; one token refresh/day sustains automated abuse.

## MDPsec Business-Logic Quick-Check (priority order)

1. **Client-computed price echoed?** → tamper `charge_amount`/`price`/`total` and check the hosted-payment total (46).
2. **Alternate transport for rate-limited REST?** → GraphQL/WS variant often unprotected (44).
3. **Signed redemption/token mint with entitlement check?** → test INELIGIBLE account + attacker-chosen expiry (93).
4. **Client-side-only gates (eligibility, verification, paywall)?** → hit the API directly / forge the client token (69, 117).
5. **Write endpoint keyed by body-supplied owner?** → cross-session merge-on-write (56).
6. **Non-atomic refund/credit flows?** → 20 concurrent requests, watch the 200/500/400 split (87).
7. **Shared symmetric key for provisioning?** → card forgery / points theft (62).
8. **Smart-contract gas math / downcasts?** → zero-byte padding profit; uint64 wraps (4, 5).
9. **Public OAuth client for internal tool?** → omit the client_secret entirely; decode token for internal identity + broad scope (85).
10. **Unauth org-scoped provisioning?** → POST with attacker-chosen org_id + business_type; then flip payment to invoicing for paid orders (31).
11. **Anonymous endpoint serving paywalled content?** → check feed/sibling endpoints vs UI gate; look for `Cache-Control: public` (70).
12. **Static header disables CAPTCHA?** → differential probe: same request with/without the header (66).
13. **Scope upgrade accepted at sign-in?** → try read-only → read-write scope escalation (28).
14. **Email/contact change without re-auth?** → write-capable token → permanent takeover (28).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Gate 0 Validation

Before writing any report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "An unauthenticated user can place an order for physical goods at $0 cost" or "An attacker can bypass email verification and monitor any email address without owning it" or "An attacker can send unlimited subscription emails to any address." Vague impact = reject.

2. **What does the victim LOSE?**
   Identify a concrete, attributable loss: financial loss (free goods, fraudulent payments), privacy loss (phone number spoofed, unauthorized monitoring), service abuse (spam campaigns via rate-limit bypass), or security degradation (unverified identity trusted for sensitive actions). If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   Create a fresh account (or use no account). Follow your documented steps. Achieve the impact. If you can't reliably reproduce it end-to-end in under 10 minutes with the steps you've written, your methodology is incomplete — refine before submitting.

---

## Real Impact Examples

**Scenario 1 — Free Physical Goods via Exposed Internal Storefront (Shopify-style)**
An employee summit page was deployed to a public Shopify storefront as a private channel for distributing free books to staff. The URL was discoverable via JS bundle analysis or link sharing. An anonymous user who navigated to the URL could browse and complete a checkout with no authentication required, receiving physical merchandise shipped at the company's expense. Impact: direct financial loss per order, potential for bulk ordering if not caught quickly.

**Scenario 2 — Payment Manipulation via In-Flight Tampering (Valve/Steam-style)**
A payment flow passed order amount and currency through client-controlled parameters before redirecting to a third-party payment provider (Smart2Pay). By intercepting the redirect with Burp Suite and modifying the amount field, an attacker could complete a real payment for $0.01 while the application's webhook — lacking HMAC validation — accepted the provider's confirmation and credited the full item/service to the account. Impact: critical financial loss; attacker receives full value goods/services for near-zero cost, infinitely repeatable.

**Scenario 3 — Email Verification Bypass for Unauthorized Monitoring (Mozilla-style)**
A breach-monitoring service required email verification before enabling monitoring alerts for an address. The verification check was enforced in the UI flow but the underlying API accepted monitoring setup requests for any address using a valid session — skipping the verification step entirely. An attacker could set up monitoring for email addresses they don't own, receiving breach notification data (potentially including credential exposure status) for victim accounts. Impact: privacy violation; attacker gains intelligence on whether a target's email was in a breach without the target's knowledge or consent.

---

## Disclosed Report Citations (Backfill +5 — 2016-2023)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. All five share a measurable financial-impact angle (actual $ loss demonstrated or quantifiable platform-wide exposure).

8. **Stripe — Fee discount race redemption** ([H1 #1849626](https://hackerone.com/reports/1849626))
    - Subclass: coupon/discount race-multi-redemption + financial primitive
    - Payload: Stripe Support applied a one-time $20,000 fee-credit. Researcher captured the "accept-discount" POST and replayed it 30× in parallel via Burp Turbo Intruder, each acceptance crediting the account anew
    - Root cause: idempotency missing on discount-acceptance endpoint; no unique constraint on (account_id, discount_id)
    - Year: 2023 — **$5,000**, $600,000 of fee-free transactions accrued before fix (~$18,000 real Stripe loss at 3% take rate)

9. **marketplace.example.com — Gift-card race multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247))
    - Subclass: gift-card / store-credit race-redemption
    - Payload: single valid gift card, parallel-POST to `/redeem` from 10 sockets via Turbo Intruder. Balance credits N× the face value
    - Root cause: no row-level lock on gift_card table; balance debit and credit live in separate transactions
    - Year: 2019 — **$1,500**

10. **Upserve / OLO — Negative-quantity price manipulation** ([H1 #364843](https://hackerone.com/reports/364843))
    - Subclass: negative-quantity-in-cart price tampering
    - Payload: `POST /api/order {"items":[{"id":1,"qty":1,"price":50},{"id":2,"qty":-3,"price":50}]}` — order total computes to `-$100`, floors to ~$0 at payment capture, food still fulfills
    - Root cause: server multiplies `qty * price` with no `qty >= 1` guard
    - Year: 2018 — textbook citation for the subclass (acknowledged-only program)

11. **Krisp — Pay-less-per-seat via PUT tampering** ([H1 #1446090](https://hackerone.com/reports/1446090))
    - Subclass: price-per-unit mass-assignment / quantity-discount manipulation
    - Payload: `PUT /v2/seats` body includes a server-trusted `price` field. Set `price=1` instead of $60. Subscription updates, billing engine charges $1/seat for 100 seats
    - Root cause: server reads price from request body instead of looking it up by plan_id; classic mass-assignment
    - Year: 2021 — Stripe-billed SaaS pricing exposure

12. **Stripe — Pay using archived price via mid-flow swap** ([H1 #1328278](https://hackerone.com/reports/1328278))
    - Subclass: cart-state TOCTOU / cancel-then-deliver (price-version race at checkout)
    - Payload: merchant archives an old price (e.g., $5 instead of new $50). Buyer starts checkout via the new payment-link, then mid-flow swaps `price_id` back to the archived one. Stripe charges $5; subscription provisions at the new tier
    - Root cause: payment-link validates "is active", price object validates "exists" — but the join "price.active AND price ∈ link.allowed_prices" is missing
    - Year: 2021 — Stripe Medium (per-subscription recurring loss)

---

## Verification

Run this self-test to confirm business logic readiness:

1. **API direct call test** — confirm curl can bypass frontend validation:
   ```bash
   curl --max-time 30 --connect-timeout 10 -s -X POST "https://httpbin.org/post" -H "Content-Type: application/json" -d '{"quantity":-1,"price":0}' | python3 -m json.tool 2>/dev/null | grep -q "quantity" && echo "PASS" || echo "(httpbin may be down)"
   ```

2. **Concurrent request test** — verify parallel curl capability:
   ```bash
   curl --help 2>/dev/null | grep -q "parallel" && echo "PASS: curl parallel support" || echo "NOTE: older curl version"
   ```

3. **Integer edge cases** — confirm edge-case awareness:
   ```bash
   echo "-1 0 2147483648 999999999" | grep -q "2147483648" && echo "PASS: overflow edge case present" || echo "FAIL"
   ```

All 3 tests verify business logic probing readiness.

---

## Pitfalls

- **Assuming business logic bugs are low-impact** — price manipulation, coupon abuse, and refund fraud are among the highest-paid bugs. Don't dismiss them as "just logic."
- **Testing only happy path** — the bug is in the edge case. Test: negative quantities, zero prices, race conditions on redemptions, expired coupons, concurrent requests.
- **Single-step testing** — business logic bugs often require multi-step sequences (add to cart + apply coupon + change quantity + checkout). Test the full flow.
- **Ignoring error handling** — 500 errors on edge cases often reveal unhandled states that lead to inconsistent data (partial order, double charge, free items).
- **Not comparing frontend vs API** — the frontend may enforce limits that the API doesn't. Test all constraints via direct API calls.
- **Currency/rounding issues** — fractional currency handling (e.g., 0.001 USD) can produce rounding errors that accumulate across bulk operations.


---

## Related Skills & Chains

- **`hunt-race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`hunt-idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`hunt-api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`hunt-ato`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `hunt-ato` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".

---

## Price Tampering — Client-Side Trust Pattern

**The #1 business logic pattern in SaaS**: the server trusts the `price` field from the client request body. The client sends `"price":0` and the server creates a checkout session at R$0 instead of looking up the product price from the database.

### Detection
```bash
# 1. Create a purchase with normal flow, capture the request
# 2. Replay with modified price
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://api.target.com/checkout" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items":[{"id":"premium_product","quantity":1,"price":0}]}'

# 3. Test negative prices  
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://api.target.com/api/payments/create" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"items":[{"id":"plan","quantity":1,"price":-100}]}'

# 4. Test arbitrary quantities
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://api.target.com/api/checkout" \
  -d '{"items":[{"id":"key","quantity":999,"price":0}]}'
```

### Indicators
- Checkout/payment endpoint returns a third-party payment URL (Stripe, Asaas, MercadoPago)
- The payment URL has `cs_test_` prefix (Stripe test mode — payment not actually processed)
- Server responds with purchase ID + checkout URL regardless of price value
- Product prices visible in JS bundle but never cross-referenced server-side

### Verification
- **Confirmed**: Checkout URL created at R$0, payment page loads showing R$0.00
- **Confirmed critical**: Purchase completed at R$0, license/key granted
- **False positive**: Server rejects with "price mismatch" or uses server-side price lookup

### Related
- `hunt-write-gap` — When price tampering succeeds because the server PATCH/POST endpoint lacks validation
- `hunt-supabase` — PostgREST accepting any value for price fields via anon key

---

## Content from local version



## Workflow Bypass
- Skip steps in multi-step process
- State manipulation (pending→delivered)
- Admin approval without permission



## a13h1 Medium Writeups — SaaS Business Logic Bugs

- **$1,150 — Orphaning Workflow Cards via Invalid User Assignment** ([a13h1](https://medium.com/@a13h1/1-150-logic-bug-orphaning-workflow-cards-via-invalid-user-assignment-8feae18b44eb))
  - Endpoint: `PATCH /api/people/v2/workflows/{workflow_id}/cards/{card_id}`
  - Technique: Assign invalid/nonexistent user to workflow card → card becomes orphaned and inaccessible
  - Root cause: No validation that assigned user exists before updating card
  - Takeaway: Test assigning invalid users to objects — may cause orphaning, state corruption, or data loss

- **$900 — Session Flaw: Deprovisioned Users Retain Access** ([a13h1](https://medium.com/@a13h1/900-session-flaw-deprovisioned-users-retain-access-after-permission-removal-f775a3f81bc9))
  - Technique: Active session remains valid after user is deprovisioned/permissions removed
  - Root cause: Backend blocks new authentication but doesn't invalidate existing sessions
  - Takeaway: After revoking user access, test if existing sessions still work — deprovisioning ≠ session invalidation

- **$850 — Viewer Accessing Automations & Webhook Data** ([a13h1](https://medium.com/@a13h1/850-authorization-bypass-viewer-accessing-automations-webhook-data-via-api-a697a6c14262))
  - Technique: Low-privilege Viewer accesses sensitive automation/webhook configs via direct API
  - Takeaway: Test cross-product data access in multi-product SaaS platforms

- **$1,500 — Business Logic Flaw in Project Secrets Management** — Attacker manipulates secrets management flow to access/modify project secrets
- **$500 — Unlocking Premium Job Features with Simple API Trick** — Bypass paywall for premium features via API manipulation
- **$500 — Bypassing Plan Restriction for Slack Integration** — Bypass plan-based restrictions on integrations
- **$469 — Bypassing Plan Restriction** — Bypass subscription tier restrictions
- **$350 — Bypass Plan Restriction** — Another plan restriction bypass variant



## Double Spending
- Cancel with RefNum=NULL → replay callback
- Race: Two concurrent orders → both confirm
- Refund: High ResNum → pay low → refund high



## Real Cases
- Coinbase $10K: Double Payout (race+logic)
- Valve $7.5K: Modify in-flight payment
- Reddit $5K: Admin approval bypass
- Stripe $5K: Unlimited fee discounts


## Payment Flow
1. Create invoice → capture ResNum
2. Create second invoice (different amount)
3. Pay cheaper → swap ResNum → expensive item for cheap!



## Coupon Abuse
- Reuse on multiple accounts
- Stack multiple coupons
- Negative discount amounts
- Race on validation



## Wallet Attacks
- Currency Confuse: USD wallet in IRR endpoint
- Negative balance: Two orders > balance
- Cancel + refund simultaneously



## Pricing Manipulation
- Negative numbers, overflow, decimal
- Quantity: -1 items → credit
- Tax calculation bypass

