---
layout: post
title: "reverse quickscan"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
description: The "Quick Scan" challenge in the reverse engineering category involved analyzing an application accessible via Netcat, which generated hex-encoded binary data in base64 format. The objective was to determine the value randomly generated and thrown onto a stack memory address.
parent: HackTheBox - Apocolypse '24
grand_parent: CTF Events
event: "hackthebox-apocolypse"
tags:
- "reverse engineering"
- "Netcat"
- "GDB"
- "assembly"
- "Pwntools"
- "debugging"
---

## Reverse Engineering - Quick Scan

The "Quick Scan" challenge presented a reverse engineering puzzle where participants needed to dissect an application accessed through Netcat. The application generated hex-encoded binary data in base64 format, posing the task of deciphering the value it would randomly generate and deposit onto a stack memory address.

### Analysis Approach:
Upon initial attempts, I opted to execute the application to observe the value it landed on the stack address. This provided a sample of expected bytes, but my unfamiliarity with GDB hindered progress. After overcoming the learning curve with GDB, I managed to identify the sought-after value manually. Thinking linearly, I attempted to rewrite this process in Pwntools to automate the analysis using the debugger functions, but this yielded a response every 2 seconds, where I needed 2 results every second. This was far too slow.

### Refining the Approach:
Realizing the inefficiency of my initial method, I devised an alternative strategy utilizing a Pwntools script. This script parsed and saved the binary files while eschewing the cumbersome debugger attachment. Instead, I scrutinized the binary's instructions and leveraged an offset from the entry to pinpoint where the values would be loaded in the assembly code.

### Results:
With the refined approach, I navigated through the challenge more efficiently. By automating the process with a new Pwntools script, I significantly expedited the analysis, completing the required 128 iterations within the 60-second time limit. This enabled me to swiftly submit the solution back to the Netcat prompt within 30 seconds, successfully solving the problem.

```python
def findmem(bininput):
    # First I want the file on disk. This was initially because I was running it in a debugger, but later became convenient to leave this as I loaded it into an ELF parser to find the offset of the hidden bytes.
    try:
        os.remove("/tmp/sample")
    except:
        pass

    f = open("/tmp/sample", "wb")
    f.write(b64d(bininput)) # Note here that I'm doing a base64 decode on the original input before saving it to disk, so I'm left with the raw bytes.
    f.close()

    # This parsing method allows me to access the binary file as an ELF object, which I can then use to find the offset of the hidden bytes.
    elf = ELF("/tmp/sample")
 
    # Knowing that the "entry" function from the PLT is the first instruction executed, I can use this to find the offset of the hidden bytes. I located this by pouring through Ghidra asm instructions to find the first two bytes from the example output. This told me how many bytes away from the instruction "entry" to look.
    move_instruction_offset = elf.entry + 4
    # Using the pwntools disassembler function, I was able to programatically load that pointer address I identified with Ghidra so that I can read it here.
    hiddenbytes_offset = int(elf.disasm(move_instruction_offset, 7).split()[-1], 16)
    # Then I needed to pull the following 24 bytes from the binary, which I did by reading the memory at the offset I found.
    hiddenbytes = elf.read(hiddenbytes_offset, 24)
    # Then this is the answer to send back to the nc prompt.
    return hiddenbytes.hex()

io = start()

# Solve the warmup, validate the functions work as expected
print(io.recvuntil(b'warmup\n'))
elf = io.recvuntil(b'\n').split()[1].strip()
expectedbytes = io.recvuntil(b'Bytes?').split(b'\n')[0]
print(f'expected bytes: {expectedbytes}')

# Solve the riddle and send the command
io.sendline(findmem(elf))

# Do it again, 128 times, and grab a coffee or a snack.
io.recvuntil(b':)\n')
for i in range(128):
    elf = io.recvuntil(b'\n')
    print(elf)
    io.sendline(findmem(elf.split(b':')[1].strip()))
    print(f'Got through {i+1} iterations')

io.interactive()
```

### Conclusion:
The "Quick Scan" challenge underscored the importance of adaptability and resourcefulness in reverse engineering tasks. By iterating on different approaches and leveraging tools like Pwntools, I was able to overcome obstacles and efficiently solve the puzzle. This experience highlights the value of automation and strategic analysis in tackling complex reverse engineering challenges.
