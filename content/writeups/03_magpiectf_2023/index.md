+++
title = "magpieCTF 2023"
date = 2023-02-24
slug = "magpiectf-2023"
description = "trigonometry review and some easy rev"
+++

Overall a pretty easy CTF so only one writeup this time around. Because of team size restrictions, ret2rev split up, and ret2rev placed 10th while ret3rev placed 8th.

# Satshell
For this challenge we are given a binary and a user manual. Challenge files available [here](satshell.zip)

Reading provided user manual and running the first command "POSN" on the remote, we see that we need to fix some satellites. We need to make A point to B, B to C, and C to D in order to establish the connetion. Additionally, it explains how the orientation is described, as 3 angles off of the axes.

Not much rev to actually do here, looking at the binary gives you all the commands you can run, which you can guess the functionality of by running them and seeing their output:
- POSN - prints satellite positions
- STAT:A - prints the orientation of satellite A
- ORNT:A - reads and executes code to reorient satellite A
- CONN - Attempts to spawn a shell. only works if all satellites are correctly oriented

So the idea is to use POSN and STAT to gather info about the position and orientation of the sattelites, then use ORNT to reorient them using the ISA as described in the PDF. Finally, calling CONN should win if the sattelites are all oriented correctly.

Back in the user manual, we see which registers we need to interact with, as well as how they are represented in the satellite machine language.
```
$dx = 101
$dy = 110
$dz = 111
```

Additionally, we have the instructions we can use:
```
ADDI $rd $rs imm = 00
ORI  $rd $rs imm = 01
SLLI $rd $rs imm = 10
LUI  $rd imm     = 11
```

Looking at the CPU diagram, we can figure out the instruction format is as follows:
```
instructions: AABBBCCCDDDDDDDD
AA = ALU Control Operational Value
BBB = $rs
CCC = $rd
DDDDDDDD = imm
```

The final thing is figuring out the math, which after some research and trig review finds this thing called the [direction cosine](https://en.wikipedia.org/wiki/Direction_cosine).

Now we have all we need to craft the exploit. final solve script below and can also be downloaded [here](solve.py)

```py
from pwn import *
import struct
import math

class Satellite:
    def __init__(self, l):
        self.label = l
        self.x = 0
        self.y = 0
        self.z = 0
        self.tx = 0.0
        self.ty = 0.0
        self.tz = 0.0

    def __str__(self):
        return f'{self.label} = [x={self.x}, y={self.y}, z={self.z}, tx={self.tx}, ty={self.ty}, tz={self.tz}]'


def get_sat_states(r):
    r.sendline(b'POSN')
    pos = r.recvuntil(b'awaiting input...\n').decode('utf-8').split('\n')
    for i in pos:
        print(i)

    yx_graph = pos[3:15]
    for i in range(len(yx_graph)):
        yx_graph[i] = yx_graph[i][3:51]
        temp = ''
        for j in range(1, len(yx_graph[i]), 4):
            temp += yx_graph[i][j]
        yx_graph[i] = temp

    #print('yx_graph=')
    #for i in yx_graph:
    #    print(i)
    
    yz_graph = pos[18:30]
    for i in range(len(yz_graph)):
        yz_graph[i] = yz_graph[i][3:51]
        temp = ''
        for j in range(1, len(yz_graph[i]), 4):
            temp += yz_graph[i][j]
        yz_graph[i] = temp
    
    #print('yz_graph=')
    #for i in yz_graph:
    #    print(i)

    A = Satellite('A')
    B = Satellite('B')
    C = Satellite('C')
    D = Satellite('D')

    for i,l in enumerate(yx_graph):
        if 'A' in l:
            A.y = 11-i
            A.x = l.index('A')
        if 'B' in l:
            B.y = 11-i
            B.x = l.index('B')
        if 'C' in l:
            C.y = 11-i
            C.x = l.index('C')
        if 'D' in l:
            D.y = 11-i
            D.x = l.index('D')

    for l in yz_graph:
        if 'A' in l:
            A.z = l.index('A')
        if 'B' in l:
            B.z = l.index('B')
        if 'C' in l:
            C.z = l.index('C')
        if 'D' in l:
            D.z = l.index('D')
    
    r.sendline(b'STAT:A')
    a_info = r.recvuntil(b'awaiting input...\n').decode('utf-8').split('\n')[-3].split(' ')
    A.tx = float(a_info[1][:a_info[1].index('d')])
    A.ty = float(a_info[3][:a_info[3].index('d')])
    A.tz = float(a_info[5][:a_info[5].index('d')])

    r.sendline(b'STAT:B')
    b_info = r.recvuntil(b'awaiting input...\n').decode('utf-8').split('\n')[-3].split(' ')
    B.tx = float(b_info[1][:b_info[1].index('d')])
    B.ty = float(b_info[3][:b_info[3].index('d')])
    B.tz = float(b_info[5][:b_info[5].index('d')])

    r.sendline(b'STAT:C')
    c_info = r.recvuntil(b'awaiting input...\n').decode('utf-8').split('\n')[-3].split(' ')
    C.tx = float(c_info[1][:c_info[1].index('d')])
    C.ty = float(c_info[3][:c_info[3].index('d')])
    C.tz = float(c_info[5][:c_info[5].index('d')])

    print(A)
    print(B)
    print(C)
    print(D)

    return (A, B, C, D)


# orient V to point to U
def orient(r, V, U):
    # instructions: AABBBCCCDDDDDDDD
    # AA = ALU Control Operational Value
    # BBB = $rs
    # CCC = $rd
    # DDDDDDDD = imm

    dx = '101'
    dy = '110'
    dz = '111'

    opADD = '00' # ADDI $rd $rs imm
    opOR  = '01' # ORI  $rd $rs imm
    opSLL = '10' # SLLI $rd $rs imm
    opLUI = '11' # LUI  $rd imm


    # x = |v| * cos(a)
    # a = arccos(x/|v|)
    mag = math.sqrt(pow(V.x-U.x, 2) + pow(V.y-U.y, 2) + pow(V.z-U.z, 2))

    

    targetx = math.degrees(math.acos(abs(V.x-U.x) / mag))
    targety = math.degrees(math.acos(abs(V.y-U.y) / mag))
    targetz = math.degrees(math.acos(abs(V.z-U.z) / mag))

    if U.x < V.x:
        targetx = 180 - targetx
    if U.y < V.y:
        targety = 180 - targety
    if U.z < V.z:
        targetz = 180 - targetz


    deltax = struct.pack('>e', targetx - V.tx)
    deltay = struct.pack('>e', targety - V.ty)
    deltaz = struct.pack('>e', targetz - V.tz)
    print(f'Targets for {V.label}:')
    print(targetx)
    print(targety)
    print(targetz)

    r.sendline(f'ORNT:{V.label}')
    code = int(opLUI + dx + dx, 2).to_bytes(1, byteorder='big') + deltax[0:1]
    code += int(opADD + dx + dx, 2).to_bytes(1, byteorder='big') + deltax[1:2]
    code += int(opLUI + dy + dy, 2).to_bytes(1, byteorder='big') + deltay[0:1]
    code += int(opADD + dy + dy, 2).to_bytes(1, byteorder='big') + deltay[1:2]
    code += int(opLUI + dz + dz, 2).to_bytes(1, byteorder='big') + deltaz[0:1]
    code += int(opADD + dz + dz, 2).to_bytes(1, byteorder='big') + deltaz[1:2]
    r.sendline(code)
    print(r.recvuntil(b'awaiting input...\n').decode('utf-8'))


def main():
    r = remote("srv2.2023.magpiectf.ca", 31185)
    r.recvuntil(b'awaiting input...\n')
    
    (A, B, C, D) = get_sat_states(r)

    orient(r, A, B)
    orient(r, B, C)
    orient(r, C, D)

    r.sendline(b'CONN')

    r.interactive()


if __name__ == "__main__":
    main()
```
