# Delving Deeper into File Upload Attacks - Part 2 | YesWeHack Learning Bug Bounty

Source: https://www.yeswehack.com/learn-bug-bounty/file-upload-attacks-part-2

## Table of Contents

- File Upload Attacks (Part 2)
- File Upload Attacks
- Pixel Flood Attack
- Cross-Site Scripting
- CSV Injection
- Open Redirection
- Server-Side Request Forgery
- XML External Entities
- File Upload Bypasses
- Misc. File Upload Attacks
- Tools & Extensions
- Tips & Tricks
- Remediation Plans
- End Notes
- Footer
- Products
- Researchers
- Resources
- Company

## Content

File upload is one of the most common functionalities application has to offer. This functionality, however, is implemented in many different forms based on the application’s use case. While some applications only allow uploading a profile picture and support only image-related extensions, on the other hand, some applications support other extensions based on their business case. Storing and retrieving these files on the server-side is again a huge task and required to be handled with caution.
Due to the involved complexity and level of caution that is required to implement a file upload functionality, this becomes one of the interesting attack vectors and can open doors to multiple critical security vulnerabilities such as Remote Code Execution. In this blog series, we will be focusing on various File Upload Attacks, Bypasses, and some robust mitigation around them from both an attacker’s well a defender’s perspective.
File Upload Attacks
As discussed in the
File Upload Attacks: Part — 1
that the file upload functionality enables a great attack surface from a threat actor or attacker’s perspective.
In the final part of the File Upload Attacks series
, we will be discussing the remaining attacks that one may encounter while testing File Upload functionality. We will also talk about some of the general bypasses and some tips & tricks to execute a successful attack scenario.
The below Mindmap gives a picture of various attacks that are possible when an application implements File Upload Functionality. This series of blogs will be based on this mindmap itself.
Pixel Flood Attack
A very simple attack that can be tested whenever you see a file upload functionality accepting images. In Pixel Flood Attack, an attacker attempts to upload a file with a large pixel size that results in consuming server
resources
in a way that the application may end up crashing. This can lead to a simple application-level denial of service like scenario. A lot of modern application these days utilize third-party libraries to process heavy images and convert them into small-sized image in order to save storage and processing power. However, some of these libraries used for image processing may be vulnerable to Pixel Flood attack and can result in resource consumption or Application-Level Denial of Service attack.
In order to exploit Pixel Flood Attack, one can try the following steps:
Navigate to
https://www.resizepixel.com/
and resize an image with 64250*64250px.
Go to the vulnerable application having the option to upload an image file.
Upload the file generated from “step-1” and observe the server’s response.
If the server takes too long to respond or if the application became inaccessible, confirm with another device, if the lag/accessibility issue happens, the application is vulnerable to pixel flood attack.
Cross-Site Scripting
While performing testing on file upload functionality, there are multiple ways to execute a cross-site scripting attack scenario. Cross-site scripting can be performed via uploading malicious files such as an SVG or HTML file, by changing the file name to cross-site scripting payload and other ways as well.
Cross-Site Scripting via SVG File Upload:
An application that doesn’t sanitize and validates the content of an image file and allows to upload an SVG file, it is possible for an attacker to inject the SVG file with a malicious payload that may lead to cross-site scripting attack. This is one of the most common files that I have identified while testing the file upload functionalities.
In order to exploit XSS using SVG File, one can try the following steps:
Create an SVG file containing a cross-site scripting payload. For example:
1
<?xml version="1.0" standalone="no"?>
2
<!
DOCTYPE
svg
PUBLIC
"-//W3C//DTD SVG 1.1//EN"
"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"
>
3
<
svg
version
=
"
1.1
"
baseProfile
=
"
full
"
xmlns
=
"
http://www.w3.org/2000/svg
"
>
4
<
polygon
id
=
"
triangle
"
points
=
"
0,0 0,50 50,0
"
fill
=
"
#009900
"
stroke
=
"
#004400
"
/>
5
<
script
type
=
"
text/javascript
"
>
6
alert
(
document
.
domain
)
;
7
</
script
>
8
</
svg
>
2. Now, navigate to the file upload functionality and upload this malicious SVG file.
3. Open the SVG file or Go to the endpoint that calls the SVG file and if the application is vulnerable, you will observe a Cross-Site Scripting execution.
Payloads:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
Cross-Site Scripting via Image Name:
Similar to the Server-Side Injection via file upload attack, as discussed in part-1 of the series, it is possible to perform a Cross-Site Scripting attack by uploading a file having its name as “Cross-Site Scripting Payload”. When the application will render this file name, if there is a lack of input validation/sanitization, the payload will be processed and cross-site scripting execution will happen.
To check for this issue, one can follow below simple steps:
Create any file, for example, a PNG file and name it with Cross-Site Scripting payload like the following: <script>alert(document.domain)</script>.png
Navigate to the file upload functionality and upload this file and also capture the request with Burp Suite.
1
Original
Request
2
--
--
--
--
--
--
--
--
3
POST
/
upload
4
Host
:
target
.
com
5
...
.
6
other
headers
7
...
.
filename
=
<
script
>
alert
(
document
.
domain
)
<
/
script
>
.
png
&
data
=
{
file_content
}
3. Once, the file is uploaded successfully, navigate to the endpoint that calls the files or stores the files.
4. If the application is vulnerable, a cross-site scripting payload will be executed.
There are certainly other ways such as using different file types, chaining file upload with CSRF to convert a self filename XSS to a good XSS, etc. that an attacker may attempt. However, the basic concept remains the same, just being creative is a plus in forming different scenarios.
CSV Injection
CSV Injection/Formulae Injection/CSV Excel Macro injection is a vulnerability that is often seen in the “File Export” functionality instead of the “File Upload” functionality. However, in the past, I have seen certain scenarios, where an application properly sanitizes the user-supplied input and doesn’t allow adding malicious payload even by performing client-side validation bypass, this results in blocking the attack.
However, if an application allows uploading a CSV file and if the content of the uploaded CSV file is not sanitized, i.e. the malicious payload contained within the CSV file is reflected as it is in the application. An attacker may attempt to upload a CSV file having a malicious command execution payload, that when exported by some other user, may result in successful execution.
To check for this issue, one can follow below simple steps:
Upload a CSV file containing a malicious CSV Injection payload.
Export the uploaded content by using any other user of the application.
If the application fails to sanitize the user-supplied content while outputting the file, the attack may get executed successfully.
CSV Injection Payloads:
https://github.com/payloadbox/csv-injection-payloads
Open Redirection
Open Redirection a.k.a Arbitrary URL Redirection is an attack that is generally seen on “Jump” endpoints, for example, an application while login, adds an additional parameter called “returnTo=/account” and this parameter may accept arbitrary URLs, ultimately resulting in an Open Redirection attack. However, this attack with the File Upload functionality is not widely seen or talked about but still possible to execute under specific conditions.
If an application allows uploading files such as HTML and the files are executed on the “Application Endpoint” itself [not downloaded and executed on the local system] but the execution of cross-site scripting is limited and it is not possible to execute any alert, prompt, confirm, etc. In such scenarios, it is possible to create a JavaScript payload that results in redirecting users to