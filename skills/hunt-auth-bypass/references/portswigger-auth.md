# PortSwigger Authentication Labs — Complete Reference

## Username Enumeration
- `Invalid username` vs `Incorrect password` — different responses leak valid usernames
- **Bypass:** Use `X-Forwarded-For: IP` rotation for rate limiting

## Password Brute Force
- **Rate limit bypass:** `X-Forwarded-For: 127.0.0.1`, rotate IPs per request
- **IP block bypass:** Wait for block to expire, or use IP rotation

## 2FA Bypass
1. Navigate directly to post-login page (force-browse)
2. Reuse OTP within same session (OTP not invalidated)
3. Change response `"verified": false` → `true`
4. CSRF on 2FA setup — attacker can set up their own 2FA

## Password Reset
- Token in URL: predictable (timestamp, email hash, sequential)
- Host header poisoning: reset link sent to attacker's server
- Email parameter manipulation: change email to attacker's
- Token reuse: use old valid token

## OAuth-based Authentication
- `redirect_uri` manipulation → steal auth code
- No `state` parameter → CSRF on OAuth callback
- Pre-fill token reuse → login as victim
