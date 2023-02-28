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
