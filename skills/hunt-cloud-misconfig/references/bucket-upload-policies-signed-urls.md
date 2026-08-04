# Bypassing and Exploiting Bucket Upload Policies & Signed URLs

## Source
Frans Rosén, Aug 2018
https://www.detectify.com/blog/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls

## Bucket Upload Policies (POST — AWS S3 / Google Cloud Storage)
Policy = base64-encoded JSON signed with secret key, defines allowed upload conditions.

### Common Policy Mistakes

#### 1. starts-with $key is empty
```json
["starts-with", "$key", ""]
```
→ Upload to ANY location in bucket → overwrite ANY object

#### 2. starts-with $key has no path separator
```json
["starts-with", "$key", "acc_1322342m3423"]
```
→ Upload to root directory → place AppCache manifest → steal URLs from other users

#### 3. starts-with $Content-Type is empty
```json
["starts-with", "$Content-Type", ""]
```
→ Upload `text/html` → serve JavaScript on bucket domain → XSS/AppCache

#### 4. starts-with $Content-Type bypass
```json
["starts-with", "$Content-Type", "image/jpeg"]
```
→ Bypass: `Content-type: image/jpegz;text/html` → served as text/html!

### Exploitation Conditions
- **Access=Yes:** File accessible after upload (ACL = public-read or signed URL)
- **Inline=Yes:** Can modify content-disposition to serve inline

### Impact
- XSS on bucket domain
- AppCache manifest → steal URLs
- Overwrite existing objects
- Full bucket compromise

## Signed URLs / Pre-Signed URLs (GET/PUT/DELETE)

### Common Custom Logic Mistakes

#### 1. Path traversal in get-image endpoint
```
GET /api/get-image?key=../../../&document=xyz
```
→ Returns signed URL for bucket root → **full file listing!**

#### 2. URL regex parsing bypass
```json
{"url":"https://.x./example-bucket"}
```
→ Returns signed URL for `s3.amazonaws.com/example-bucket` → **file listing!**

#### 3. Abusing temporary signed URL links
```json
{"s3_key":"/"}
```
→ Redirect goes to `s3.amazonaws.com/?Signature=...` → **file listing!**

#### 4. Direct signing endpoint (worst case)
```
GET /api/multipart_signature?to_sign=GET%0A%0A%0A%0Ax-amz-date%3A...%2Fbucket-name%2F
```
→ Returns raw AWS signature → sign ANY request to ANY AWS service!

## Detection
- Upload policy: base64-encoded JSON in POST form
- Signed URL: `?Signature=xxx` or `?X-Goog-Signature=xxx`
- Direct signing: `to_sign=` parameter in URL
- Custom logic: `s3_key`, `key`, `url` parameters

## Mitigation
- `$key` should be fully defined (not starts-with) with random name in random path
- `content-disposition` should be `attachment`
- `acl` should be `private`
- `content-type` should be explicitly set (not starts-with)
- Signed URLs: NEVER derive from user-controlled parameters
- Use path-based S3 URLs for signed URLs (validate full path)
