# Google Bug Hunters — Recent Notable Disclosures (2025–2026)

Curated from https://bughunters.google.com/report/reports (public reports feed). These are the most recent, high-impact, and technique-revealing Google VRP disclosures. Include the novel/unique ones not covered in existing knowledge.

## ⭐ AI / LLM Security (Nov 2025)
- **Workspace Antigravity RedTeam Prompt AI — Model: Gemini 3.0 Pro** (Mauro Risonho) — prompt injection against Gemini 3.0 in Antigravity. Novel LLM-agent prompt-injection surface. [report link](https://bughunters.google.com/report/reports#report)
- **Prototype Pollution in Gemini CLI Security Extension** — PP in CLI security tooling. [report](https://bughunters.google.com/report/reports#report)
- **Internal AI Summarization Tool Accessible to Consumer Google Accounts Without Authorization** (Hamza, Oct 2025) — unauthorized access to internal AI tool via consumer accounts.

## 🎯 RCE / Command Execution
- **Critical RCE in YouTube Studio via Closure Loader (`goog.loadModuleFromSource_`)** (Sean geofrey sani, Sep 2025) — RCE via Google Closure JS loader.
- **Arbitrary File Write leads to RCE in Antigravity Browser via SaveScreenRecording action** (Sudhanshu Rajbhar, Nov 2025) — file write → RCE in AI browser.
- **Arbitrary file write via Zip Slip leading to RCE in SecOps SOAR Server** (Jakub Domeracki, Jul 2025) — Zip Slip → RCE.
- **Zip Slip Vulnerability in Google Web Designer – Arbitrary File Write & PE** (Shaber Tseng, Mar 2025) — Zip Slip in Web Designer.
- **Vulnerable maven-bundle-plugin in Guava build leads to RCE (CVE-2021-42036)** (Sep 2025) — supply-chain build dep RCE.
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** (H1, Aug 2026, $12K) — GraphQL sift filter injection → RCE.

## 🔐 Access Control / Cross-Tenant (High Value)
- **Access control issue in Application Integration API — cross-tenant listing/reading/editing/executing integration test cases** (brutecat, Mar 2026) — cloud multi-tenancy broken object-level authz.
- **Cross-tenant compromise of Application Design Center spaces via bucket squatting** (Jakub Domeracki, Feb 2025) — S3 bucket squatting → cross-tenant.
- **Critical: Fitbit API allows unauthorized read/write of any user's device settings** (Sep 2025) — device API IDOR.
- **Access Control Misclassification Leading to Sensitive Report Disclosure** (Aiman, Aug 2025).
- **Low-Privilege User Can Bulk Data Export and Stop Export of Performance Data in Search Console** (Muhammad Alqi, Aug 2025).
- **Auth Bypass in https://one.google.com/ai-student** (Muhammad Aqib, Aug 2025).
- **Access to members-only YouTube video content** (Seqrity, Apr 2025).

## 🐛 Memory Safety / Kernel / Binary (Google VRP style)
- **unbounded HTTP request body reads enable memory exhaustion DoS (certificate-transparency-go)** (Oleh Konko, Jan 2026) — unbounded body read → DoS.
- **draco_transcoder glTF accessor range validation bug causes heap-buffer-overflow** (0xkato, Jan 2026).
- **Go TLS 1.3 Handshake Desynchronization via Injected Plaintext Handshake Fragments** (Coia Prant, Nov 2025) — TLS desync novel technique.
- **kernelCTF exp424: UAF in net/xfrm affecting COS-6.6.105 and Linux up until 6.16.9** (Oct 2025).
- **2 vulnerabilities in Civetweb web server: SSI stack exhaustion (DDOS) + heap BOF** (buddurid, Aug 2025).

## 📱 XSS / CSP / Client-Side
- **Reflected XSS (HTML Injection because of CSP Policy)** (mohammed aloli, Nov 2025).
- **Blind XSS payloads fire at admin panel of Notebook feedback summary report** (Shobhit, Oct 2025) — blind XSS at admin.
- **Client-Side Path Traversal in Gmail Layouts** (Abdel Adim smaury, May 2025).
- **Reflected XSS Vulnerability** (Leutrim Berisha, May 2025).

## 🍪 Auth / Session
- **No Session Expiry after log-out, attacker can reuse old cookies** (Khalafallah, Nov 2025) — session fixation/invalid-session-after-logout.
- **Authenticated Member Can Reconstruct Redacted Emails in Google Groups** (Lahcen, Jun 2025).
- **Real-time Support API leaks PII of Google Support customers and deanonymises agents** (Michael Dalton, Jun 2025) — API PII leak + deanonymization.
- **postMessage targetOrigin bypass opens room for OAuth authorization code stealing** (Jakub Domeracki, May 2025) — postMessage origin bypass → OAuth.
- **Access token leak via insufficient URL validation of yum repo baseurl** (Jakub Domeracki, Feb 2025).
- **Missing CSRF Token in Delete Account Request on androidenterprise.dev** (Syed, Jan 2025).

## 🌐 Info Disclosure / Recon / Misc
- **Public exposure of service version details and commit hashes at /version endpoint** (RAVI KUMAR, Mar 2025) — version fingerprinting for recon.
- **Exposed Solar EV Dashboard** (Maniesh, Oct 2025).
- **Unauthorized overwrite of user-shared images in https://photobooth.flutter.dev** (Oct 2025) — object write.
- **Query users data by email** (Sep 2025).
- **Python traceback expose filepath in devicecertification.youtube** (Ritik Singh, Jun 2025).
- **Unauthenticated Path Traversal → Arbitrary File Read (Repository & Host OS)** (k1rnt, Jun 2025).
- **Google Docs "Generate document" feature leaks sensitive data through clickjacking** (Rebane, Jul 2025) — clickjacking data leak.
- **Google Cloud CDN cache poisoning with classic app LB when using certain origin servers (Lighttpd, FastHTTP) — forwarding extra spaces after URIs** (Ben Kallus, Mar 2025) — cache poisoning novel vector.
- **Rxss** (Jul 2025).
- **HTTPS Certificate Issue for mkto-sj380051.com (Linked to email.mandiant.com)** (Jan 2025).

## 💡 Key Takeaways for Hunting
1. **AI/LLM agent surfaces are now prime targets** — Gemini CLI, Antigravity browser, internal AI tools. Prompt injection + agent file-write → RCE.
2. **Cloud cross-tenant issues** (Application Integration API, bucket squatting) are top severity — test multi-tenant object references.
3. **Zip Slip & file-write chains** keep paying — Web Designer, SOAR Server, Antigravity.
4. **Novel parser/desync bugs** (Go TLS handshake desync, Cloud CDN cache poisoning via extra spaces, Civetweb SSI) show parser-differential hunting pays.
5. **Session/logout flaws** still accepted — no session expiry after logout.
6. **Unbounded request-body reads** → memory exhaustion DoS.
