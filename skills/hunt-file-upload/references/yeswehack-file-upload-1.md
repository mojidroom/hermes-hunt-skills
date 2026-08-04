# Unveiling File Upload Attacks - Part 1 | YesWeHack Learning Bug Bounty

Source: https://www.yeswehack.com/learn-bug-bounty/file-upload-attacks-part-1

## Table of Contents

- File Upload Attacks (Part 1)
- File Upload Attacks
- Remote Code Execution
- Unrestricted File Upload
- File Overwrite Attack
- Path Traversal Attack
- Large File Denial of Service
- Server-Side Injection Attack
- Metadata Leakage
- ImageTragik Attack // ImageMagick Library Attacks
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
In the first part of the file upload attack series
,
we will look at an attack surface that one gets when there’s a file upload functionality and we will focus on some of the interesting file upload attacks.
The below mindmap gives a picture of various attacks that are possible when an application implements File Upload Functionality. This series of blogs will be based on this mindmap itself.
Remote Code Execution
One of the most interesting attacks that come into mind whenever there is a file upload functionality is Remote Code Execution. There are several ways to execute a code execution with malicious files, one of the most common is to upload a shell and gain further access.
Let’s assume a scenario where a PHP based application provides a file upload functionality and stores the files as it is on the server which can later be accessed.
In order to achieve remote code execution, one can try the following steps:
Create a PHP shell or use an existing shell.
Upload the shell (bypassing restrictions, if any)
After successful upload, navigate to the shell path, for example, https://testweb.com/files/shell.php to see if it is accessible.
If the shell is accessible, based on how the shell gets executed, attempt for the shell execution, for example, https://testweb.com/files/shell.php?cmd=whoami
Note:
We will talk about the file upload bypass techniques in the next part of the file upload attack series.
Unrestricted File Upload
ZipSlip Attack
ZipSlip attack is an interesting attack vector that can be tested when the application accepts archives in file upload functionality and later unarchive it for further processing.
According to
synk.io
: Zip Slip is a widespread critical archive extraction vulnerability, allowing attackers to write arbitrary files on the system, typically resulting in remote command execution. It was discovered and responsibly disclosed by the Snyk Security team ahead of public disclosure on 5th June 2018, and affects thousands of projects, including ones from HP, Amazon, Apache, Pivotal, and many more.
This repository:
https://github.com/snyk/zip-slip-vulnerability
contains all the information about this attack such as the affected libraries, projects, and other relative information.
To check for this issue, one can follow below simple steps:
Create a malicious file using this tool:
https://github.com/ptoomey3/evilarc
Upload the malicious file to the archive upload functionality and observe how the application responds.
File Overwrite Attack
File overwrite is an interesting attack during the file upload when a user can control and arbitrarily set the path where the file should be stored. This can be considered similar to the Zip Slip and Path Traversal attack but assuming the scenario where it is possible to directly upload a file and change its path to overwrite an existing system file, this is kept as a separate issue.
To check for this issue, one can follow below simple steps:
Create any system file such as
/etc/passwd
Navigate to the file upload functionality and upload this file while capturing the request with Burp Suite.
1
Original
Request
POST
/
upload
2
Host
:
testweb
.
com
3
...
.
4
other
headers
5
...
.
filename
=
/
etc
/
passwd
&
content
=
{
file_content
}
3. Now modify this request by changing the
filename parameter
to
../../../../etc/passwd
1
Modified
RequestPOST
/
upload
2
Host
:
testweb
.
com
3
...
.
4
other
headers
5
...
.
filename
=
.
.
/
.
.
/
.
.
/
.
.
/
etc
/
passwd
&
content
=
{
file_content
}
4. If the upload is successful, refresh the application and observe if there’s any misbehavior or crashes to confirm the vulnerability.
Path Traversal Attack
This attack may look similar to the attack mentioned above, i.e. File Overwrite attack, however, in this scenario we are assuming that
it is not possible to overwrite a system file due to implemented checks that can not be bypassed.
In this situation, we will attempt to create a file, outside the intended directory that may allow an attacker to injection malicious files, cause misbehavior in the application, or other security implications.
To check for this issue, one can follow below simple steps:
Navigate to the file upload functionality and upload a file while capturing the request with Burp Suite.
[Assume that the application stores files in the following directory: testweb.com/files/external/upload/folder/test/<uploaded_file>
1
Original
Request
2
POST
/
upload
3
Host
:
testweb
.
com
4
...
.
5
other
headers
6
...
.
path
=
/
folder
/
test
/
&
filename
=
test
.
png
&
content
=
{
file_content
}
2. Now modify this request by changing the
filename parameter
to ../../
../test.png
or by changing the
path parameter
to /folder/test/../../../
1
Modified
Request
-
1
2
3
POST
/
upload
4
Host
:
testweb
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
path
=
/
folder
/
test
/
&
filename
=
.
.
/
.
.
/
.
.
/
test
.
png
&
content
=
{
file_content
}
8
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
===
==
9
Modified
Request
-
2
10
11
POST
/
upload
12
Host
:
testweb
.
com
13
...
.
14
other
headers
15
...
.
path
=
/
folder
/
test
/
.
.
/
.
.
/
.
.
/
&
filename
=
test
.
png
&
content
=
{
file_content
}
3. If the upload is successful, try to access the file outside the expected directory and if it is possible to access the file, it can further be used to perform other attacks.
Large File Denial of Service
Often there is a size restriction associated with the File Upload functionality that may range from 5 MB to 200 MB or even smaller/larger depending upon the application logic. However, in certain situations, if this limit is not defined or the proper validation checks are not present, it may allow an attacker to upload a file with a relatively large size resulting in resource consumption that may lead to a Denial of Service situation.
To check for this issue, one can follow below simple steps:
Create a file that is larger in the size than defined upper limit. For example, an image file having a 500 MB file size.
Now, upload the file, and if the application accepts the file and starts processing it, browser the application from another device to see if there’s any sluggish behavior or connectivity error.
Server-Side Injection Attack
As we have observed so far that the file upload functionality is really interesting and can lead to multiple security vulnerabilities. It is possible to test for Server-Side Injection attacks such as SQL Injection, Command Injection, or others using the File Upload feature.
The most unnoticed or ignored method is to test the
filename
for testing server-side injection vulnerabilities. When the application is unsafely handling the uploaded file, storing or processing it on the server-side, a malformed filename containing some payload may get executed and result in a server-side injection vulnerability.
To check for this issue, one can follow below simple steps:
Let’s assume an application with file upload functionality is having the following request structure.
1
Original
Request
2
--
--
--
--
--
