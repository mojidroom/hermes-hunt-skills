---
name: hunt-novel-techniques
description: "Hunt the NOVEL/emerging web exploit classes surfaced by the webhacklist research archive (2024-2026) that classic hunt-* skills under-cover: parser differentials & encoding confusion, CSS/browser side-channel exfiltration (ETag, fontleak, inline-style, CSS bomb), cache-key injection & cache deception chains, CSPT gadget chains via CDN proxies, HTTP desync evolution (CL.0/TE.0/CRLF-powered/funky chunks/single-packet), OAuth code-injection & cookie-tossing, passkey/FIDO attacks, Python/Ruby class pollution, ZIP/archive parser semantic gaps, and the 2026 wave of AI-agent / MCP / agentic-browser / LLM-cache attacks. Triggers: target is modern (Next.js, cloud CDN, OAuth, agentic/LLM features) or you've exhausted classic vectors. Each class has test steps + source URL."
version: 1.0.0
revision_date: 2026-08-13
license: MIT
category: redteam
tags: [novel, emerging, redteam, webhacklist, 2026]
---

# Hunt: Novel & Emerging Techniques (webhacklist 2024–2026)

Aggregated from the [Web Hacking Techniques Index](https://webhacklist.com) (irsdl) —
the emerging classes that the stable `hunt-*` skills under-cover. Raw archive lives in
`data/webhacklist/` (catalog CSV/JSON of 1,545 techniques). Use this *alongside* the
classic `hunt-*` skills — these are the modern edges to chain once classic vectors land.

> Each entry: **class → what to look for → test steps → source**. Validate before report.

---

## 1. Parser Differentials / Encoding Confusion

The web now has many parsers (URL, HTTP, JSON, charset, MIME, HTML) that disagree.
"Confusion Attacks" on Apache (2024 #1) and "Unicode normalization" (2025) made these
mainstream. The bug = two components parse the same bytes differently.

**What to look for:** a URL/path/header/body is validated by the front WAF/CDN/router but
interpreted differently by the backend ORM/parser/framework.

**Test steps:**
- **URL parser confusion:** submit `//attacker.com` vs `/\attacker.com` vs
  `https://attacker.com@trusted` vs backslash `\`/`\\.` — find a validated-then-rerouted hop.
  See *Caching the Un-cacheables / URL parser confusions* and *Google Cloud ATO via URL
  parsing confusion* (2025).
- **Charset / encoding differentials:** send the same bytes under different
  `charset=` / `Content-Type` (UTF-16, UTF-7, Unicode normalization NFC/NFD, overlong
  UTF-8). Use encoder weapons: see *WorstFit (Windows ANSI)*, *Encoding Differentials:
  Why Charset Matters*, *Lost in Translation* (2024/2025).
- **MIME validation bypass → XSS:** submit file/response with a MIME the validator
  accepts but the browser renders as HTML. See *Parse and Parse: MIME Validation Bypass
  to XSS via Parser Differential* (2026), *XSS using dirty Content Type in cloud era* (2024).
- **JSON parsing:** duplicate keys, `{"a":1,"a":2}` — one parser takes first, other takes last.
- **HTTP parser differentials:** vary the path with `;`, `%2e`, path normalization
  (`/admin/../admin`), trailing `/`, double-encoding — see *Exploiting HTTP Parsers
  Inconsistencies* (2023), *Go's parser footguns* (2025), *Under the Beamer*.

**Sources:** 2024 #1 *Confusion Attacks (Apache)*; 2025 *Lost in Translation (Unicode)*;
2025 *Parser Differentials*; 2026 *Parse and Parse*.

---

## 2. CSS / Browser Side-Channel Exfiltration

A hot 2024–2026 family: leaking data **without** network requests, via browser rendering
(CSS, fonts, ETag, timing). High signal — works even with strict CSP/no endpoint.

**What to look for:** any way to inject CSS (style attribute, `<style>`, SVG, email
HTML) or to observe a length/origin/timing difference across origins.

**Test steps / classes:**
- **Fontleak / ligature exfil:** render attacker-supplied text in a font where ligatures
  change measured width; use `@font-face` + CSS to binary-search characters.
  See *Fontleak: exfiltrating text using CSS and Ligatures* (2025).
- **Inline-style exfiltration:** chain CSS `@media`/attribute-selector conditionals to
  leak data via a series of `style=` snippets. See *Inline Style Exfiltration* (2025).
- **CSS bomb / CSS in email:** heavy CSS used for fingerprinting/exfil in email clients.
  See *CSS: the bomb inside your inbox* (2026), *Cascading Spy Sheets* (2025).
- **Cross-Site ETag Length Leak:** reflect attacker data in `ETag` of a cross-origin
  resource, then measure response cache/length to infer a secret. See *Cross-Site ETag
  Length Leak* (2025).
- **Bench Press / text-node floor:** CSS `text-transform`/`::first-line`+`@font-face`
  to leak text nodes without JS. See *Bench Press: Leaking Text Nodes with CSS* (2024).
- **Blind CSS exfiltration:** use `@import`/attribute selectors against a trusted page
  when you can inject CSS but not JS. See *Blind CSS Exfiltration* (2023).

**Test steps:** inject CSS → confirm rendering callback (e.g. `background: url(collab)` on
a condition) → use condition-driven attribute-selector (`input[value^="a"]`) to enumerate.

**Sources:** 2025 Fontleak / Inline Style Exfiltration / ETag leak; 2026 CSS bomb.

---

## 3. Cache-Key Injection & Cache Deception Chains

Modern cache layers (CDN, Next.js, proxy) poison or deceive via **unkeyed input** that
reaches a confidential response.

**What to look for:** a cache-keyed URL serving personalized/private content; attacker-
controllable unkeyed header/param (Host, `X-Forwarded-Host`, `X-Original-URL`, query
controlled by Next.js).

**Test steps:**
- **Cache key injection:** find a header reflecting into a public cached page while
  `X-Cache: hit` serves it — poison cache for others. See *Let's Dance in the Cache* (2022),
  *Gotta cache 'em all* (2024).
- **Web cache deception:** request `/dashboard/somecss.css` where the app renders the
  private dashboard and the CDN caches it because of the `.css` extension.
  See *ChatGPT ATO via Wildcard Web Cache Deception* (2024 #9).
- **Next.js cache chains:** Next.js `fetch` default caching + weird headers/query →
  unkeyed cache poisoning. See *Next.js, cache, and chains: the stale elixir* (2025 #7),
  *Next.js and cache poisoning: quest for the black hole* (2024), *Cache Key Injection:
  Smuggling Poison* (2026 watchlist).
- **Unkeyed query/port/scheme poisoning:** vary `?`, `:port`, `http://` vs `https://`.

**Sources:** 2024 #9 ChatGPT WCD; 2025 #7 Next.js stale elixir; 2022 #7 Akamai poison.

---

## 4. CSPT Gadget Chains (Client-Side Path Traversal)

Client-Side Path Traversal + a **gadget** (a proxy/CDN/service that follows the URL) =
cross-origin read. Classic CSPT climbs to a real leak.

**What to look for:** a client that fetches a URL derived from user input (an image proxy,
a `<script src>`, a fetch with a path you control, an SPA route param passed to `fetch`).

**Test steps:**
- Find input reflected into a **client-side fetch/URL** (no server round trip).
- Use it to make the browser include `..` to reach same/origin-restricted resources.
- Chain a **gadget** like Cloudflare Image Proxy (`/cdn-cgi/image/...`) which will fetch
  and reflect arbitrary URLs — see *Cloudflare Image Proxy as a CSPT Gadget: A
  Cross-Origin CSPT Exploit* (2025).
- Escalate: *From an Innocent CSPT to Account Takeover* (2023), *Exploiting CSPT to perform
  CSRF (CSPT2CSRF)* (2024), *Bypassing CSP with New Relic Custom Events* (2025).

**Sources:** 2023 From CSPT to ATO; 2024 CSPT2CSRF; 2025 Cloudflare CSPT gadget.

---

## 5. HTTP Desync Evolution (post-classic smuggling)

The classic CL.TE/TE.CL is mature; the new wave is **CL.0**, **TE.0**, **CRLF-powered**,
**funky chunks**, **single-packet desync**, and request tunneling. These bypass modern
front-end fixes and reuse the front-end as a confused deputy.

**What to look for:** stack of front-end proxy + backend, any request-pipelining behavior,
HTTP/2→1 conversion, trailers, chunked parser quirks.

**Test steps:**
- **CL.0 / TE.0:** send a request with `Content-Length: 0` (or TE) after a body chunk and
  see if the backend reads the *next* pipelined request as part of a smuggled body.
  See *Unveiling TE.0* (2024 #3), *The Quiet Side Channel… CL.0 for C2* (2025).
- **CRLF-powered desync:** inject CRLF into chunk size/separators to desync. See
  *CRLF-Powered Desync Attacks: Beheading HTTP Streams* (2026), *Funky chunks: ambiguous
  chunk terminators* (2025).
- **Single-packet request tunneling (SMUGGLE/GOBBLE):** split a single TCP packet into
  two requests where the front-end sees one desynced stream. See *The Single-Packet
  Shovel: Desync-Powered Request Tunnelling* (2025).
- **Trailers:** parser treats `Trailer` header / `0\r\n` differently. See *Trailing
  Danger: HTTP Trailer parsing discrepancies* (2025).
- **HTTP/2 CONNECT:** abuse `CONNECT`/`:authority`. See *Playing with HTTP/2 CONNECT* (2025).
- **Ghost/ambiguous ACL:** variants using `Content-Length` vs `Transfer-Encoding`.

Tooling: `smuggler.py`, PortSwigger *HTTP Request Smuggler*, `crlf-powered-desync-scanner`.

**Sources:** 2023 #5 HTTP parser inconsistencies; 2024 #3 TE.0; 2025 Funky chunks/CL.0/
Single-Packet; 2026 CRLF-powered desync.

---

## 6. OAuth Modern: Code Injection, Cookie Tossing, Dirty Dancing

Beyond classic redirect_uri: **authorization-code injection**, **cookie tossing**,
**OAuth dirty dancing** (replaying a token across flows), **non-happy path**.

**What to look for:** any OAuth provider/consumer; sign-in flows; multiple apps sharing
an IdP cookie domain.

**Test steps:**
- **Cookie tossing:** inject your own cookie into the shared auth domain (parent domain)
  to hijack the OAuth/session state of a subdomain flow. See *Hijacking OAuth flows via
  Cookie Tossing* (2024 #10), *Cookie Crumbles: Web Session Integrity* (2023).
- **Authorization-code injection:** swap/craft a code for a victim's token. See *Attacks
  via New OAuth flow, Authorization Code Injection* (2025).
- **Dirty dancing:** dance a token between two OAuth clients. See *Account hijacking using
  "dirty dancing"* (2022 #1), *Zoom Session Takeover* (2024).
- **Non-Happy Path:** replay an unexpired `id_token`/code in a second client. See *OAuth
  Non-Happy Path to ATO* (2024 #8), *Oh-Auth* (2023).

**Sources:** 2022 #1 dirty dancing; 2024 #8/#10; 2025 code injection.

---

## 7. Passkey / FIDO / WebAuthn Attacks (2025–2026)

Passkeys are new attack surface — device, credential store, and protocol.

**What to look for:** any app using WebAuthn/FIDO2/passkeys; "passkey auth bypass"
(StrongKey FIDO CVE-2025-26788).

**Test steps:**
- **Passkey replay / pass-the-passkey:** export and replay a passkey credential across
  relying parties / time. See *Pass-the-Passkey Family of Attacks* (2026).
- **Protocol confusion:** passkey challenge/allowlist confusion, backup-key as
  non-backed-up. See *Passkey Authentication Bypass in StrongKey FIDO Server*
  (CVE-2025-26788).
- **Borrowing keys:** use a device-bound key from another service.

**Sources:** 2025 StrongKey CVE-2025-26788; 2026 Pass-the-Passkey.

---

## 8. Python / Ruby Class & Prototype Pollution

Beyond JS `__proto__` — **Python class pollution** (via `__class__`/`__init__`/
`__globals__` on recursive merges) and **Ruby class pollution**.

**What to look for:** recursive merge/deep-merge functions, YAML/dict load, `.update()`,
config merges, template context merging (server-side).

**Test steps:**
- Feed a nested `{"__class__": {"__init__": {"__globals__": ...}}}` (Python) into a
  merge. See *Get Set, Exploit! Python Class Pollution In-the-Wild* (2026), *Prototype
  Pollution in Python* (2023), *Server-side prototype pollution black-box* (2023).
- Ruby: `{"__class__".to_sym => ...}` or `merge`. See *Class Pollution in Ruby* (2024).
- Chain to RCE via gadgets: *Silent Spring: Prototype Pollution → RCE in Node.js* (2022),
  *Undefined-oriented Programming* (2024), *GHunter* (2024).

**Sources:** 2023 PP in Python; 2024 Class Pollution in Ruby; 2026 Python Class Pollution.

---

## 9. ZIP / Archive Parser Semantic Gaps

Archives are parsed by many tools that disagree (ZIP path, compression, name). Malicious
archives slip past one parser to hit another.

**What to look for:** file upload that unzips/extracts, archive preview, tar/zip
processing.

**Test steps:** craft archive with ambiguous path separators, duplicate entries, `../`,
UTF-16 names, polyglot headers. See *My ZIP isn't your ZIP: Semantic Gaps Between ZIP
Parsers* (2025), *Disguises Zip Past Path Traversal* (2025).

---

## 10. Arbitrary File Write → RCE (modern)

Modern AFW→RCE goes beyond webshell: **write shared-object files** (`.so`), **overwrite
bytecode** (`.pyc`), **Rails/Ruby paths**, **Node/Ruby callbacks**.

**Test steps:** with any arbitrary file-write primitive, write a dynamically-loaded file
(`.so`, `.pyc`, `.pth`, `.rb`, `.jar`), or overwrite config. See *Python Dirty Arbitrary
File Write to RCE via Writing Shared Object/Bytecode* (2025), *Write Once, Shell
Everywhere* (2026), *From Arbitrary File Write to RCE in Restricted Rails apps* (2024),
*Remote Code Execution in Google Cloud with Single Directory Deletion* (2026).

---

## 11. 2026 Wave: AI-Agent / MCP / Agentic-Browser / LLM-Cache

The frontier — attack the **agent**, not just the model. Combine with `hunt-llm-ai` and
`hunt-mcp-security`.

**What to look for:** any LLM/agent/MCP integration, agentic browser, AI infra, cloud
AI services, coding agents.

**Test steps / classes:**
- **LLM cache poisoning (vLLM/GPTCache):** poison a shared semantic/prefix cache so
  another tenant's prompt returns attacker data. See *Cache Me, Catch You* (2026).
- **No-tools post-injection exploitation:** after a prompt injection, drive the agent's
  tool/code path. See *No Tools Required* (2026), *ChatMate: sandbox escape* (2026).
- **Agentic browser SOP:** agentic browsers mishandle cross-origin; test SOP boundaries.
  See *Agentic Browsers and the Same-Origin Policy* (2026).
- **Credentials exfiltration via agent (CoreBreak):** agent's tools leak stored creds.
  See *CoreBreak* (2026).
- **MCP auth:** enumerate remote MCP servers for missing/weak auth. See *Authentication
  Security in Real-World Remote MCP Servers* (2026).
- **CoT forgery / role confusion:** inject fake reasoning blocks. See *Prompt Injection
  as Role Confusion (CoT Forgery)* (2026).
- **Supply-chain agent takeover:** poison a repo/issue the coding agent reads. See
  *Poisoning Claude Code* (2026), *Your WAF Blocked Us… Agent takeover* (2026), *LGTM:
  bypassing LLM build gate* (2026).

**Also 2026 CI/CD-supply:** *Angular compromise via GitHub Actions cache poisoning*,
*Deployment Poisoning*, *Hack the Source of the Source*.

---

## False-Positive Gate

- **Parser differentials:** prove two *distinct* components disagree — a single parser
  behaving as documented is not a vuln. Reproduce with two tools (curl vs browser).
- **CSS exfil:** only a confirmed OOB callback or window-rendered data across origin
  counts; "I can inject `<style>`" alone is not a leak.
- **Cache:** require a *confidential* response to hit a *public* cache (and it serves to
  another principal), or a poison visible to victims — not just `X-Cache: hit` on your
  own public page.
- **OAuth/passkey:** require actual cross-principal impact (other user's account), not a
  spec deviation.
- **AI/agent:** require OOB/verifiable cross-tenant artifact or code execution — never a
  model "saying" something. See `hunt-llm-ai` False-Positive Gate.

## Chain-first mindset

These classes rarely stand alone. Common chains: parser differential → cache poison →
ATO; CSPT + CDN gadget → cross-origin read → session theft; OAuth cookie toss + code
injection → full account takeover; AFW → RCE; agent injection → credentials exfil.
Escalate every finding to the highest impact you can *prove*.
