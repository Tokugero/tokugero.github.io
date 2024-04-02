---
layout: post
title: "pwn blue-pants-on-fire"
date: 2024-04-01 00:00:00 -0700
categories: ctfs
description: 
parent: Cursed CTF '24
grand_parent: CTF Events
event: "cursed-ctf"
tags:
- "rust"
- "pwn"
- "reverse engineering"
- "bpf"
---

## Blue Pants On Fire (BPF) - PWN challenge
This challenge began with an anti-spam proof-of-work script that routed you into a qemu-looking boot sequence followed by 'The flag is at /flag.txt. Good Luck!'. The goal was to bypass bpf filters that would hijack the contents of the output of flag.txt before it sent the string to stdout.

### Recon
#### Tools

#### Logging in
```sh
[12:23:59] tokugero :: pangolin  ➜  ~ » nc fuzzbox.addisoncrump.info 5000 | tee output
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.IYecQs5WM8psI1QUf8xxYg==
solution:
```
```sh
[12:23:40] tokugero :: pangolin  ➜  ~ » curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.IYecQs5WM8psI1QUf8xxYg==

s.W2ACFYds5hFD0wgb6kr90ur/0b658a+OT1FoKUJNOPv5wAVuDlJhIzUNXG4M/L48Ood1xyWuFzvsLO9dhWkQw850ByS8Cp5X8D0/wblynsT8Qap4/hCu17yrtX3iHFSdoDqVj5nm6nEF2X8ADqQ/DH7b3WzEaIIx8odyO9bjvOz4fo+6I0SYqJEGyGlLZRLZDu7zqKpK1y3sGKfbbyhHYg==
```
```sh
[    2.754164] Run /init as init process


Boot took 2.77 seconds

┏┓ ╻  ╻ ╻┏━╸   ┏━┓┏━┓┏┓╻╺┳╸┏━┓   ┏━┓┏┓╻   ┏━╸╻┏━┓┏━╸
┣┻┓┃  ┃ ┃┣╸    ┣━┛┣━┫┃┗┫ ┃ ┗━┓   ┃ ┃┃┗┫   ┣╸ ┃┣┳┛┣╸
┗━┛┗━╸┗━┛┗━╸   ╹  ╹ ╹╹ ╹ ╹ ┗━┛   ┗━┛╹ ╹   ╹  ╹╹┗╸┗━╸

Good luck :) Flag is at /flag.txt

[    2.958757] input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/serio1/input/input3
[    3.may corrupt user memory!1] is installing a program with bpf_probe_write_user helper that 
[    3.165430] blue-pants-on-f[1] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
[    3.166298] blue-pants-on-f[1] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
/bin/sh: can't access tty; job control turned off
~ $ cat /flag.txt
cat /flag.txt
letmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletm~ $ 
```
#### Exfiltrating binary
```sh
tar -cf - /sbin/blue-pants-on-fire | base64
```
```sh
[14:08:47] tokugero :: pangolin  ➜  pwn/bluepantsonfire/tmp » cat output | tr -d '\r\n' | base64 -d | tar -xv
sbin/blue-pants-on-fire
[14:08:51] tokugero :: pangolin  ➜  pwn/bluepantsonfire/tmp » ls -alhn sbin
total 2.5M
drwxr-xr-x 2 1000 1000 4.0K Apr  2 14:08 .
drwxr-xr-x 3 1000 1000 4.0K Apr  2 14:08 ..
-rwxr-xr-x 1 1000 1000 2.4M Mar 29 20:21 blue-pants-on-fire
```
### Understanding
#### Tools
1. Ghidra
2. binwalk
3. objdump
4. strace
5. bpftools

```sh
[14:23:59] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » strings blue-pants-on-fire | grep let
state must have zero transitionsrelocating map by section index BPF_MAP_TYPE_REUSEPORT_SOCKARRAY/sys/devices/system/cpu/possiblethe program was already attachedenum relocation on non-enum type` overflows 16 bits offset fieldtwo or more symbols in section `index out of bounds: the len is library/core/src/fmt/builders.rslibrary/core/src/slice/memchr.rswarning: invalid regex filter - 
letmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutblue_pants_on_firesrc/main.rscouldn't read dentrycouldn't read name pointer is trying to read flagcouldn't read nameattempted read of flag, size: 
```
```sh
[14:25:47] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » binwalk blue-pants-on-fire                                                             130 ↵

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)
960605        0xEA85D         bix header, header size: 64 bytes, header CRC: 0x488B4D, created: 1974-04-15 08:43:32, image size: 21269365 bytes, Data Address: 0x4498B84, Entry Point: 0x24980200, data CRC: 0x490B84, image type: OS Kernel Image, compression type: none, image name: ""
1847008       0x1C2EE0        Unix path: /sys/devices/system/cpu/possiblethe program was already attachedenum relocation on non-enum type` overflows 16 bits offset field
1873152       0x1C9500        ELF, 64-bit LSB relocatable, version 1 (SYSV)
1970056       0x1E0F88        Unix path: /usr/local/bin:/bin:/usr/bin
```
```sh
[14:26:12] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » binwalk --dd='.*' blue-pants-on-fire 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)
960605        0xEA85D         bix header, header size: 64 bytes, header CRC: 0x488B4D, created: 1974-04-15 08:43:32, image size: 21269365 bytes, Data Address: 0x4498B84, Entry Point: 0x24980200, data CRC: 0x490B84, image type: OS Kernel Image, compression type: none, image name: ""
1847008       0x1C2EE0        Unix path: /sys/devices/system/cpu/possiblethe program was already attachedenum relocation on non-enum type` overflows 16 bits offset field
1873152       0x1C9500        ELF, 64-bit LSB relocatable, version 1 (SYSV)
1970056       0x1E0F88        Unix path: /usr/local/bin:/bin:/usr/bin
[14:26:22] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » ls _blue-pants-on-fire.extracted 
0  1C2EE0  1C9500  1E0F88  EA85D
[14:28:32] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » strings _blue-pants-on-fire.extracted/1C2EE0 | head -n 20
...<SNIP>...
letmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutblue_pants_on_firesrc/main.rscouldn't read dentrycouldn't read name pointer is trying to read flagcouldn't read nameattempted read of flag, size: 
```
```sh
[14:44:59] tokugero :: pangolin  ➜  tmp/sbin/_blue-pants-on-fire.extracted » objdump -h 1C9500

1C9500:     file format elf64-little

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         00000350  0000000000000000  0000000000000000  00000040  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 fentry/vfs_read 00001d90  0000000000000000  0000000000000000  00000390  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
  2 fexit/vfs_read 00000838  0000000000000000  0000000000000000  00002120  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
  3 .rodata       00000112  0000000000000000  0000000000000000  00002958  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 maps          00000054  0000000000000000  0000000000000000  00002a6c  2**2
                  CONTENTS, ALLOC, LOAD, DATA
```
```sh
[14:49:02] tokugero :: pangolin  ➜  tmp/sbin/_blue-pants-on-fire.extracted » objdump -d -mi386 1C9500
...<SNIP>...
Disassembly of section fentry/vfs_read:

0000000000000000 <fentry_blue_pants_on_fire_read>:
       0:       bf 16 00 00 00          mov    $0x16,%edi
       5:       00 00                   add    %al,(%eax)
       7:       00 85 00 00 00 0e       add    %al,0xe000000(%ebp)
       d:       00 00                   add    %al,(%eax)
       f:       00 7b 0a                add    %bh,0xa(%ebx)
      12:       d0 ff                   sar    $1,%bh
      14:       00 00                   add    %al,(%eax)
      16:       00 00                   add    %al,(%eax)
      18:       bf a2 00 00 00          mov    $0xa2,%edi
      1d:       00 00                   add    %al,(%eax)
      1f:       00 07                   add    %al,(%edi)
      21:       02 00                   add    (%eax),%al
      23:       00 d0                   add    %dl,%al
      25:       ff                      (bad)
      26:       ff                      (bad)
      27:       ff 18                   lcall  *(%eax)
      29:       01 00                   add    %eax,(%eax)
        ...
      37:       00 85 00 00 00 03       add    %al,0x3000000(%ebp)
      3d:       00 00                   add    %al,(%eax)
      3f:       00 79 69                add    %bh,0x69(%ecx)
      42:       08 00                   or     %al,(%eax)
      44:       00 00                   add    %al,(%eax)
      46:       00 00                   add    %al,(%eax)
      48:       79 63                   jns    ad <fentry_blue_pants_on_fire_read+0xad>
      4a:       00 00                   add    %al,(%eax)
      4c:       00 00                   add    %al,(%eax)
      4e:       00 00                   add    %al,(%eax)
      50:       07                      pop    %es
      51:       03 00                   add    (%eax),%eax
      53:       00 a0 00 00 00 bf       add    %ah,-0x41000000(%eax)
      59:       a1 00 00 00 00          mov    0x0,%eax
      5e:       00 00                   add    %al,(%eax)
      60:       07                      pop    %es
      61:       01 00                   add    %eax,(%eax)
      63:       00 d8                   add    %bl,%al
      65:       ff                      (bad)
      66:       ff                      (bad)
      67:       ff b7 02 00 00 08       push   0x8000002(%edi)
      6d:       00 00                   add    %al,(%eax)
      6f:       00 85 00 00 00 71       add    %al,0x71000000(%ebp)
      75:       00 00                   add    %al,(%eax)
      77:       00 55 00                add    %dl,0x0(%ebp)
      7a:       e5 00                   in     $0x0,%eax
      7c:       00 00                   add    %al,(%eax)
      7e:       00 00                   add    %al,(%eax)
      80:       79 a3                   jns    25 <fentry_blue_pants_on_fire_read+0x25>
      82:       d8 ff                   fdivr  %st(7),%st
      84:       00 00                   add    %al,(%eax)
      86:       00 00                   add    %al,(%eax)
      88:       07                      pop    %es
      89:       03 00                   add    (%eax),%eax
      8b:       00 28                   add    %ch,(%eax)
      8d:       00 00                   add    %al,(%eax)
      8f:       00 bf a1 00 00 00       add    %bh,0xa1(%edi)
      95:       00 00                   add    %al,(%eax)
      97:       00 07                   add    %al,(%edi)
      99:       01 00                   add    %eax,(%eax)
      9b:       00 d8                   add    %bl,%al
      9d:       ff                      (bad)
      9e:       ff                      (bad)
```
```sh
[14:53:20] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » sudo bpftool prog                                                                             
...<SNIP>...
39: tracing  name fentry_blue_pan  tag cbaa055b6728b557  gpl
        loaded_at 2024-04-02T14:52:06-0700  uid 0
        xlated 8104B  jited 4396B  memlock 8192B  map_ids 12,11,13,14
        pids blue-pants-on-f(14584)
40: tracing  name fexit_blue_pant  tag 0b1e0db2a5365e35  gpl
        loaded_at 2024-04-02T14:52:06-0700  uid 0
        xlated 2424B  jited 1339B  memlock 4096B  map_ids 12,11,13,14
        pids blue-pants-on-f(14584)
```
```sh
[15:05:39] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » sudo bpftool prog dump xlated id 39 | grep -E "(map|\#)" #sample output           1 ↵
   1: (85) call bpf_get_current_pid_tgid#216480
   5: (18) r1 = map[id:12]
   7: (85) call htab_lru_map_delete_elem#255808
  14: (85) call bpf_probe_read_kernel#-102192
  21: (85) call bpf_probe_read_kernel#-102192
  27: (18) r1 = map[id:11]
  29: (85) call percpu_array_map_lookup_elem#266064
  38: (18) r4 = map[id:13][0]+128
 130: (18) r4 = map[id:13][0]+146
 183: (18) r2 = map[id:13][0]+177
 238: (18) r2 = map[id:14]
 249: (18) r1 = map[id:11]
 251: (85) call percpu_array_map_lookup_elem#266064
 260: (18) r4 = map[id:13][0]+128
 352: (18) r4 = map[id:13][0]+146
 405: (18) r2 = map[id:13][0]+157
 448: (18) r2 = map[id:14]
 454: (85) call bpf_perf_event_output_raw_tp#-97168
 463: (85) call pc+482#bpf_prog_9af5d65f957a4f79_F
 467: (85) call bpf_probe_read_kernel_str#-101936
 489: (18) r1 = map[id:11]
 491: (85) call percpu_array_map_lookup_elem#266064
 501: (18) r5 = map[id:13][0]+128
 593: (18) r7 = map[id:13][0]+146
 645: (18) r2 = map[id:13][0]+226
 684: (18) r2 = map[id:14]
 694: (85) call pc+259#bpf_prog_574d635fd9d96149_F
 703: (18) r1 = map[id:11]
 705: (85) call percpu_array_map_lookup_elem#266064
 712: (18) r1 = map[id:12]
 715: (85) call htab_lru_map_update_elem#257456
 724: (18) r4 = map[id:13][0]+128
 816: (18) r3 = map[id:13][0]+146
 877: (85) call pc+112#bpf_prog_35afc7aded4e0a42_F
 881: (85) call pc+115#bpf_prog_14cae5e813865f9a_F
 889: (18) r2 = map[id:13][0]+203
 938: (18) r2 = map[id:14]
 944: (85) call bpf_perf_event_output_raw_tp#-97168
 ```

### Crafting the exploit
#### Tools

### Things that didn't work

### Conclusion
#### Links
https://www.youtube.com/watch?v=g6SKWT7sROQ
https://github.com/pathtofile/bad-bpf
https://blog.cloudflare.com/diving-into-proc-pid-mem
https://kerkour.com/shellcode-in-rust
