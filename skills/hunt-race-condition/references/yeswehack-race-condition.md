# Ultimate Bug Bounty guide to race condition vulnerabilities | YesWeHack

Source: https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities

## Table of Contents

- Concurrency exploits: The ultimate Bug Bounty guide to exploiting race condition vulnerabilities in web applications
- What are race condition vulnerabilities?
- Race condition attack vectors in web applications
- HTTP/1.1 last-byte synchronisation attacks
- HTTP/2 single-packet race condition attacks
- Hands-on Lab: exploiting race conditions with Burp Suite Turbo Intruder
- Real-world race condition CVEs
- Security impacts of race condition vulnerabilities
- Preventing race conditions: Mitigation best practices
- Conclusion: outrunning defences, making mayhem with milliseconds
- References & further reading
- Footer
- Products
- Researchers
- Resources
- Company

## Content

Imagine snapping up a $1,000 gadget for just $12 simply by triggering a race condition in the checkout flow.
Race condition vulnerabilities often lead to severe impacts – such as bypassing business logic, escalating privileges or stealing funds – that code reviews and automated scans readily overlook. With distributed systems and async frameworks making shared-state interactions increasingly complex and error-prone, race-condition exploitation is a skill well worth learning for Bug Bounty hunters.
In this guide, you'll learn how attackers exploit concurrency flaws, from last-byte synchronisation to single-packet attacks, and how to use Burp Suite's extension Turbo Intruder. You'll learn how race condition attacks work, understand the root causes of these timing bugs, and concrete strategies to bulletproof web applications against them.
What are race condition vulnerabilities?
A race condition vulnerability arises when multiple threads or processes concurrently access and modify shared resources without proper synchronisation, leading to unpredictable and potentially erroneous outcomes.
The final state depends on the order and timing of the concurrent operations – effectively creating a ‘race’ to modify the resource. This lack of controlled access can result in data corruption, inconsistent state, denial-of-service or privilege escalation, depending on the nature of the shared resource and the operations performed.
To illustrate a race condition, consider the following Go code snippet:
1
package
main
2
3
import
(
4
"fmt"
5
"sync"
6
)
7
8
var
counter int
=
0
9
var
wg sync
.
WaitGroup
10
11
func
increment
(
)
{
12
for
i
:
=
0
;
i
<
10000
;
i
++
{
13
counter
++
14
}
15
wg
.
Done
(
)
16
}
17
18
func
main
(
)
{
19
wg
.
Add
(
2
)
20
go
increment
(
)
21
go
increment
(
)
22
wg
.
Wait
(
)
23
fmt
.
Println
(
"Final counter value:"
,
counter
)
24
}
This code demonstrates a race condition where two goroutines run concurrently and increment a shared counter variable without synchronisation. The
counter++
operation is non-atomic, leading to lost updates. This most likely results in an incorrect counter result.
Web applications rely heavily on threads to handle multiple users concurrently. When multiple HTTP requests arrive at a web server, each request is typically assigned to a separate thread. This allows the server to handle each HTTP request individually and asynchronously.
When multiple HTTP requests are handled asynchronously and interact with shared data, such as during database updates or token generation, race conditions can easily occur. The risk is highest when the changes made by one request aren’t properly synchronised with other requests. This lack of synchronisation between threads can lead to inconsistent or incorrect data.
ALSO IN THIS SERIES:
The ultimate Bug Bounty guide to exploiting SQL injection vulnerabilities
Race condition attack vectors in web applications
Race conditions are a productive avenue for Bug Bounty hunters since they slip under the radar of conventional vulnerability scanners. This is because unearthing these vulnerabilities typically require a deep understanding of the target application’s inner workings.
Unlike easier-to-spot vulnerabilities such as cross-site scripting (XSS) bugs, a successful race condition attack may require numerous exploit attempts. This is because probabilistic exploitation must be timed precisely relative to the server's processing sequence.
Although some race conditions can be exploited deterministically with the right setup, exploitation is often a trial-and-error process.
Let's explore some specific ways race conditions can be exploited. Race conditions have been around for a long time and can occur almost anywhere in a system where multiple components access shared resources. This is because modern systems often run programs that handle multiple processes asynchronously or in parallel – opening doors to potential race condition flaws.
HTTP/1.1 last-byte synchronisation attacks
The most common attack technique is last-byte synchronisation, which abuses how HTTP/1.1 servers handle requests and responses. By keeping the first request open for the precise time window needed, you force the server to juggle two partially processed operations.
Last-byte synchronisation exploits this overlap to bypass security checks. Essentially, an attacker attempts to send two requests to the server almost simultaneously, carefully timing them so the server begins processing the second request while still handling the tail end of the first. The aim is to exploit this brief overlap in processing to trigger a race condition.
For example: If the first request is crafted to keep the connection open – while expecting further data – and the second request is timed perfectly, it can lead to bypassed security checks or access to restricted resources.
HTTP/2 single-packet race condition attacks
Despite being a more modern protocol, HTTP/2 still has its own exploitable quirks.
Multiplexing
makes HTTP/2 faster, but also creates unexpected timing gaps. Holding back fragments of each request lets you bundle them into a single packet – neatly bypassing network jitter and improving the reliability of race condition testing.
The trick here involves sending multiple HTTP requests over the same HTTP/2 connection. We deliberately hold back a small portion of each request just long enough to prevent the server from processing them immediately. Then, after a brief pause, we send the final fragment of each request. This ensures all requests are transmitted within a single TCP packet to the server, eliminating network jitter delays.
For more in-depth insights on how single-packet attacks work, I recommend reading James Kettle's fantastic article entitled
‘The single-packet attack: making remote race-conditions “local”’
.
Hands-on Lab: exploiting race conditions with Burp Suite Turbo Intruder
Turbo Intruder
is one of the best tools for detecting and exploiting race condition vulnerabilities. This Burp Suite extension supports both last-byte sync and single-packet attacks, and can easily be customised for novel attacks due to its Jython scripting engine.
Now we’re familiar with the theoretical aspects race condition attacks, let’s put our practical skills to the test.
The PortSwigger lab called
‘limit overrun race conditions’
challenges us to exploit a business logic flaw with a race condition. The vulnerability lies in how the coupon code is validated, allowing us to apply the discount multiple times. The goal is to buy a ‘Lightweight L33t Leather Jacket’ priced originally at €1,337 for the sum in our account balance – €50 – or less.
We add the jacket to the cart and apply coupon code PROMO20, but the price – a whopping €1069.60 – is still well beyond our budget.
So we intercept the request and send it to Turbo intruder, where we craft and launch
this single-packet attack
:
1
def
queueRequests
(
target
,
wordlists
)
:
2
3
#
if
the target supports
HTTP
/
2
,
use engine
=
Engine
.
BURP2
to trigger the single
-
packet attack
4
#
if
they only support
HTTP
/
1
,
use
Engine
.
THREADED
or
Engine
.
BURP
instead
5
#
for
more information
,
check out https
:
/
/
portswigger
.
net
/
research
/
smashing
-
the
-
state
-
machine
6
engine
=
RequestEngine
(
endpoint
=
target
.
endpoint
,
7
concurrentConnections
=
10
,
8
engine
=
Engine
.
BURP2
9
)
10
11
# the
'gate'
argument withholds part
of
each request until openGate is invoked
12
#
if
you see a negative timestamp
,
the server responded before the request was complete
13
for
i
in
range
(
20
)
:
14
engine
.
queue
(
target
.
req
,
gate
=
'race1'
)
15
16
# once every
'race1'
tagged request has been queued
17
# invoke engine
.
openGate
(
)
to send them
in
sync
18
engine
.
openGate
(
'race1'
)
19
20
21
def
handleResponse
(
req
,
interesting
)
:
22
table
.
add
(
req
)
The single-packet attack worked like a charm: we got a discount of €1,299.38 and a bargain basement price of €37.62!
Real-world race condition CV