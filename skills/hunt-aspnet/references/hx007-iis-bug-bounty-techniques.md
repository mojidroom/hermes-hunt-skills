# HX007 — Exploring IIS in Bug Bounties

**Author:** Abdallah Al Mahameed (HackerX007)
**Type:** Conference Presentation
**Topics:** ASP.NET Fuzzing, WAF Bypass, Cookieless Sessions, Path Manipulation, ASP.NET Secrets

---

## 1. Mastering ASP Fuzzing

### The Problem
> "Still fuzzing ASP.NET with just .aspx and .asp? You're missing the real bugs."

Most hunters only fuzz `.aspx` and `.asp` extensions. Throughout HX007's pentesting and bug bounty journey, many **other extensions** lead to easy P1s or reveal interesting information.

### Extensions to Fuzz (Beyond .aspx and .asp)

| Extension | What It Is | Real-World Examples |
|-----------|-----------|-------------------|
| `.xml` | XML config/data files | Database configs, app settings |
| `.txt` | Text files | Logs, readme, Access Control lists |
| `.zip` | ZIP archives | Backup files (`api.zip`, `wwwroot.zip`) |
| `.7z` | 7-Zip archives | Source code backups (`bin.7z`) |
| `.dll` | .NET assemblies | Dynamic link libraries (`web.dll`) |
| `.ashx` | HTTP Handlers | Upload handlers (`UploadHandler.ashx`) |
| `.asmx` | SOAP Web Services | Legacy API (`File_Manager.asmx`) |
| `.svc` | WCF Services | Service endpoints (`Service1.svc`) |
| `.html` / `.htm` | HTML pages | Login pages, old versions (`login.htm`) |
| `.js` | JavaScript files | Client-side code with secrets |
| `.json` | JSON data | App settings (`appsettings.json`) |

### Headers to Fuzz
- `Cookie` — Manipulate session cookies for unauthorized access
- `User-Agent` — Some endpoints check UA for mobile/bot access
- `Accept: */*` — Trigger different content-type responses

### Tools
```bash
# FFUF with extension flag
ffuf -u "https://target.com/FUZZ" \
  -w directory-list-lowercase-2.3-medium.txt \
  -e .aspx,.asmx,.svc,.ashx,.xml,.txt,.zip,.7z,.dll,.html,.htm,.js,.json

# Fuzzuli - backup file discovery
# https://github.com/musana/Fuzzuli
fuzzuli -u "https://target.com/FUZZ" -w wordlist.txt

# Favorite wordlist
# directory-list-lowercase-2.3-medium.txt from DirBuster
```

### Real-World Scenarios
```bash
# ZIP backup file - contains full source code
curl -sk "https://target.com/api.zip" -o api_backup.zip

# 7Z archive - contains web root
curl -sk "https://target.com/bin.7z" -o bin.7z

# DLL file - .NET assembly with endpoints
curl -sk "https://target.com/bin/web.dll" -o web.dll

# HTML login page - old version
curl -sk "https://target.com/login.htm"

# Access control lists
curl -sk "https://target.com/Accesses.txt"

# App settings with credentials
curl -sk "https://target.com/appsettings.json"

# Upload handler - file upload without auth
curl -sk "https://target.com/UploadHandler.ashx"

# SOAP web service
curl -sk "https://target.com/File_Manager.asmx?WSDL"

# WCF service
curl -sk "https://target.com/Service1.svc?wsdl"
```

---

## 2. ASP.NET Cookieless Sessions — WAF Bypass

### What Is It?
ASP.NET supports cookieless sessions where the session ID is embedded in the URL instead of a cookie:
```
http://target.com/(S(lit3bz55ux5v3b45qyq3c155))/default.aspx
```

### Why It's Dangerous
- **Bypasses WAF rules** that check cookies — the session is in the URL
- **Can be used for session hijacking** — URL with session ID can be shared
- **Some WAFs don't inspect URL-embedded sessions** — they check Cookie header only

### Testing
```bash
# Get cookieless session
curl -sk "https://target.com/(S(COOKIELESS_SESSION_ID))/admin.aspx"

# Bypass WAF by moving session to URL
# Instead of: Cookie: ASP.NET_SessionId=abc123
# Use: https://target.com/(S(abc123))/protected-page.aspx
```

---

## 3. Breaking Auth with Unique Path Manipulation

### The Pattern (from HX007)
Same technique from "The Art of Authentication Bypass":
```
/ProtectedPage.aspx/UnprotectedPage.aspx
```

### ASP.NET-Specific Path Tricks
```bash
# Path traversal in URL
/admin/../login.aspx
/admin/./admin.aspx

# Extension confusion
/admin.aspx/login.aspx

# Cookieless session path abuse
/(S(sessionid))/admin.aspx/login.aspx

# Double extension
/admin.aspx.txt
/admin.aspx.zip
```

---

## 4. Secrets in ASP.NET JS Files

ASP.NET applications often embed sensitive data in JavaScript files:
- **WebResource.axd parameters** — Encoded resource paths
- **ScriptResource.axd** — Script references with assembly info
- **Telerik component paths** — Upload handler URLs
- **ViewState generators** — Hidden algorithms for __VIEWSTATEGENERATOR
- **API endpoint URLs** — REST or SOAP service paths

### What to Look For
```bash
# In ASP.NET JS files, search for:
# - .asmx references
# - .svc references
# - WebResource.axd
# - ScriptResource.axd
# - __doPostBack
# - PageMethods
# - Sys.Net.WebServiceProxy
# - Telerik.Web.UI
```

---

## 5. Critical ASP Paths Often Overlooked

| Path | Purpose | Risk |
|------|---------|------|
| `/trace.axd` | Application trace viewer | Critical — full request dump |
| `/elmah.axd` | Error log viewer | High — stack traces, credentials |
| `/Telerik.Web.UI.WebResource.axd` | Telerik upload handler | Critical — RCE if keys leaked |
| `/WebResource.axd` | Embedded resources | Medium — path disclosure |
| `/ScriptResource.axd` | Script resources | Medium — assembly info |
| `/*.asmx` | SOAP services | High — unauthenticated methods |
| `/*.svc` | WCF services | High — admin operations |
| `/*.ashx` | HTTP Handlers | High — file upload/download |
| `/appsettings.json` | App configuration | Critical — connection strings |
| `/web.config` | ASP.NET config | Critical — machineKey, DB strings |

---

## 6. Abusing ASP.NET_SessionId for Unauthorized Access

### Techniques
1. **Session prediction** — Sequential session IDs
2. **Session fixation** — Set victim's session ID to known value
3. **Cross-subdomain session reuse** — Same session ID on different subdomains
4. **Cookieless session hijack** — URL-based session ID theft
5. **Session ID in URL** — Shareable authenticated sessions

### Testing
```bash
# Check if session IDs are predictable
curl -sk -I "https://target.com" | grep "Set-Cookie"
# ASP.NET_SessionId=abc123 → is it sequential?

# Cross-subdomain test
curl -sk -c cookie.txt "https://app1.target.com/login"
curl -sk -b cookie.txt "https://admin.target.com/dashboard"
# Same cookie works? → cross-subdomain session reuse

# Cookieless session test
curl -sk "https://target.com/(S(TEST_SESSION_ID))/default.aspx"
```

---

## 7. WAF Bypass for ASP.NET (Akamai Case)

For bypassing WAFs like **Akamai**:
1. **AWS IP Rotation** — Fast but expensive
2. **Bright Data Rotating Proxies** — Residential IPs
3. **ASP.NET Cookieless Sessions** — URL-based session bypasses cookie inspection
4. **HTTP Method Tunneling** — Use different HTTP methods
5. **Protocol Downgrade** — HTTP/2 → HTTP/1.1 → HTTP/1.0
6. **Character Encoding** — Unicode, double encoding

---

## See Also
- **`hunt-aspnet`** — ASP.NET-specific vulnerabilities (ViewState, machineKey)
- **`web-enumeration`** — Sensitive file scanning, fuzzing
- **`http-403-bypass`** — WAF bypass techniques
- **`hunt-auth-bypass`** — Auth bypass methodology
- **`hunt-source-leak`** — Source code leak hunting
- **`auth-bypass-and-bac-chains`** — Auth bypass chains
