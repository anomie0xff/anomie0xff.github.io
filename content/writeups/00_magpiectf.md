+++
title = "magpieCTF 2022"
date = 2022-02-25
slug="magpieCTF-2022"
description = "A CTF hosted by UCalgary. Here's writeups for two of the interesting challenges I did."
+++

# Diversionary Havoc

## Challenge Description

Mom and Pops are about to celebrate the grand opening of their new flag cloning shop, and what better way to sneak in and take the template flag than by being loud and stylish? (By setting off all of their fireworks early as a distraction, of course.) All we have to do is get access to the launch controls.

`nc srv1.momandpopsflags.ca 20000`

Hint: I'm pretty sure g is a primitive root of p, but I wonder if g^a has as many powers?

## Investigation

when connecting to the remote, we get the following:
```
$ nc srv1.momandpopsflags.ca 20000
******************* Firework Control Console *********************

Note to employees: To prevent a repeat of our last yard party where ALL THE FIREWORKS WERE LAUNCHED IN BROAD DAYLIGHT, using the console now requires you to prove your identity with a Diffie Hellman private key. I'm told we're using an extra factor in p-1 and specifically choosing private keys for extra security. Whatever that means, Pops assures me he has no clue how anybody could accidently or intentionally mislaunch fireworks with this system in place.

With a randomly chosen b value, g^b (mod p) = 231992713285470981850740643082242790984142921358278216925864287373999324650360031590887943569061194959696720319289221427961210173309497291387131083845280917077834423559379481536528293484863706192421251261703949839113696667680618276012307558935461477558234961498533395977504134723662186352516556335442292260894904882878001319918793468066194447779141433418335703591401769170080108128919844671792195642698386936582008178669949319889997736078829993750206398058395202911294650247839755084311154730768033919836239608952061837742514150969154539853714561082777880628370277267125459397637741369227487326827953597823880137374982

To remind you of the system parameters:
g = 2
p = 291364672960661360732390600179163652760495776567157403012191007271117867345852429694177354768594912356546060408688801581208771564079289691264090539415835339562007270071055799241101973109916402946427873861941259115350086423758128025604479256975813512214915212476655355145842445657234043877460533779149377518778673024962702920037559405809163682972223714546253005553818771896152325455387487821654597710967381940497325265358975740848907260779827547116945150368872272714940935459628719691323922491481357293326633172345686438383645472670406205248151279624293890792248591429143403599876506848606018745605244492571342225709147
g^a (mod p) = 126471653193594503196317839397720756109354103444655552493815231218054633290830570569543806438134317014065068264818063743122187689609273544826564239222644926788620262089577749766832304162835603853307917657872522019672316602134045777714367257097200373221922212447230792164289177763021130837681200593039636579461760964485803840171261394703141332005036543660295999464519927734317685046724847789020959495436272478314658820318085199304361277652711258322558032701010409765336919339576513518634695438496718168790388718652093559283136731363294703693688223327128267135704439949128059416799299260927606164356607039849760090591119

Please enter g^ab (mod p) to prove you know a:
```

So it appears we need to find the diffie hellman secret key. Connecting a couple more times, we find that `g^b (mod p)` is unique every time, but `g`, `p`, and `g^a (mod p)` are the same.

p-1 is already factored here: [factordb](http://factordb.com/index.php?query=291364672960661360732390600179163652760495776567157403012191007271117867345852429694177354768594912356546060408688801581208771564079289691264090539415835339562007270071055799241101973109916402946427873861941259115350086423758128025604479256975813512214915212476655355145842445657234043877460533779149377518778673024962702920037559405809163682972223714546253005553818771896152325455387487821654597710967381940497325265358975740848907260779827547116945150368872272714940935459628719691323922491481357293326633172345686438383645472670406205248151279624293890792248591429143403599876506848606018745605244492571342225709146)

and we see its prime factors are 2, 79, and some really large number.

Using the hint, I checked what the order of `g^a (mod p)` was, and found it was 2 * 79 = 158. This means that `(g^a)^i (mod p)` forms a ring consisting of 158 elements, one of which will be our private key `g^ab = (g^a)^b (mod p)`

This means each time we connect, we can guess one of the 158 elements in the ring, and have a 1/158 chance of getting it right, very tractable for brute-force.

## Solve

Here's a python script that does just that:
``` python
from pwn import *
from random import choice

g_to_a = 126471653193594503196317839397720756109354103444655552493815231218054633290830570569543806438134317014065068264818063743122187689609273544826564239222644926788620262089577749766832304162835603853307917657872522019672316602134045777714367257097200373221922212447230792164289177763021130837681200593039636579461760964485803840171261394703141332005036543660295999464519927734317685046724847789020959495436272478314658820318085199304361277652711258322558032701010409765336919339576513518634695438496718168790388718652093559283136731363294703693688223327128267135704439949128059416799299260927606164356607039849760090591119

g = 2

p = 291364672960661360732390600179163652760495776567157403012191007271117867345852429694177354768594912356546060408688801581208771564079289691264090539415835339562007270071055799241101973109916402946427873861941259115350086423758128025604479256975813512214915212476655355145842445657234043877460533779149377518778673024962702920037559405809163682972223714546253005553818771896152325455387487821654597710967381940497325265358975740848907260779827547116945150368872272714940935459628719691323922491481357293326633172345686438383645472670406205248151279624293890792248591429143403599876506848606018745605244492571342225709147

n = p-1

ring = []

for i in range((2*79)):
    ring.append(pow(g_to_a, i, p))

print(len(ring))

count = 0
while True:
    io = remote("srv1.momandpopsflags.ca", 20000)
    io.recv()
    temp = str(choice(ring))
    io.sendline(temp)
    res = io.recv()
    print(f"attempt number {count}")
    print(res)
    if b"denied" not in res:
        print(temp)
        io.interactive()
    count += 1
```

Note: This script uses pwntools to connect to the remote server, but you can do this with whatever networking option you prefer

And after a while, we get the flag!
```
... Previous Output Omitted ...
[+] Opening connection to srv1.momandpopsflags.ca on port 20000: Done
attempt number 25
b'Access denied.\n'
[+] Opening connection to srv1.momandpopsflags.ca on port 20000: Done
attempt number 26
b'Access denied.\n'
[+] Opening connection to srv1.momandpopsflags.ca on port 20000: Done
attempt number 27
b'Access denied.\n'
[+] Opening connection to srv1.momandpopsflags.ca on port 20000: Done
attempt number 28
b'Access denied.\n'
[+] Opening connection to srv1.momandpopsflags.ca on port 20000: Done
attempt number 29
b'Access denied.\n'
[+] Opening connection to srv1.momandpopsflags.ca on port 20000: Done
attempt number 30
b'magpie{l1tiN9_U9_7He_D4yL1T_5kY}\n'
41376415954669027921049685304736221896599108719737879529092325536830349054833546143398183954481828893177931912242968220492882197919971584478968620807485497970371539301430947953266253877900757107797815827433013910010283965091625540032679533159381124674498965076691132830764784217842063074700233826981441358925863074279922874495186160579570774922795473112497626432721628115451879573992058028307068413528824796224647193629229110929840782386445420906543076038257970210740063908780075341123974916624623469060952930833280892668726904092858645594471996350378841177406387008043952884795725200328128583503086597243336228507422
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$  
```

# Followme

## Challenge Description

You have gained access to a company employee's home directory. He was the target of a specialized spear-fishing campaign where we successfully stole his credentials. More specifically, this user was targeted because our recon intel indicated that they have permissions to run a program which contains information on top secret patents. Currently we have a different program running which changes their password, as well as the port on which ssh connects. This password will be given to you and will be valid for the next ten minutes until which time the connection will close. Your task is to figure out exactly what this program is doing. You have been given a copy of the binary which you will need to further reverse engineer in this user's home directory.

Files Needed: https://s3.us-east-2.amazonaws.com/static.momandpopsflags.ca/ReverseEngineering/follow-me/locked-secret

Connection Link: http://srv5.momandpopsflags.ca/

Hint 1: xxd
Hint 2: sudo -l

## Investigating locally

Ghidra shows that the main function has an if statement that will never be true, and the binary just prints `You can't force me`.

``` C++
void main(void)

{
  if (x == 1) {
    run_at_root();
  }
  else {
    puts("You can\'t force me");
  }
  return;
```

`run_at_root()` appears to fork and have the child process execute different binary in the root directory, while the parent process does nothing and waits for the child to finish.

``` C++
void run_at_root(void)

{
  long in_FS_OFFSET;
  undefined local_24 [4];
  __pid_t local_20;
  int local_1c;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_20 = fork();
  if (local_20 == 0) {
    local_18 = 0;
    local_1c = execve("/root/followme",(char **)0x0,(char **)0x0);
                    /* WARNING: Subroutine does not return */
    exit(local_1c);
  }
  if (local_20 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  wait(local_24);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
```

### Local binpatch

We can binpatch it so that the statement is true and we execute the intersesting function. Additionally, you may want to put a file called followme in your root directory that does something like `echo hello world` to show that your binpatch was successful, although it should be obvious that it works when the program doesn't print "You can't force me".

First we need to find the instruction we want to patch. I started by finding where main was:
```
$ objdump -t locked-secret | grep main 
0000000000000000       F *UND*	0000000000000000              __libc_start_main@GLIBC_2.2.5
000000000000120f g     F .text	000000000000002d              main
```

So now we know main starts at `0x120f`. We want to modify the if statement so that it is true which means changing the 1 to a 0. Looking in ghidra, we can find the opcode for the comparison and everything around it:

```
0010120f 55              PUSH       RBP
00101210 48 89 e5        MOV        RBP,RSP
00101213 8b 05 43        MOV        EAX,dword ptr [x]                                = ??
         2e 00 00
00101219 83 f8 01        CMP        EAX,0x1
0010121c 75 0c           JNZ        LAB_0010122a
0010121e b8 00 00        MOV        EAX,0x0
         00 00
00101223 e8 61 ff        CALL       run_at_root                                      undefined run_at_root()
         ff ff
00101228 eb 0f           JMP        LAB_00101239
```

So we can look for the hex values in the hex dump of the binary, change the `01` to a `00`, recompile, and we should be good!

Generate the hexdump:
```
$ xxd locked-secret > hexdump
```

Modify the hexdump:

Before:
```
00001200: 0425 2800 0000 7405 e833 feff ffc9 c355  .%(...t..3.....U
00001210: 4889 e58b 0543 2e00 0083 f801 750c b800  H....C......u...
00001220: 0000 00e8 61ff ffff eb0f 488d 05e2 0d00  ....a.....H.....
00001230: 0048 89c7 e8f7 fdff ff90 5dc3 0f1f 4000  .H........]...@.
00001240: f30f 1efa 4157 4c8d 3d9b 2b00 0041 5649  ....AWL.=.+..AVI
```

After:
```
00001200: 0425 2800 0000 7405 e833 feff ffc9 c355  .%(...t..3.....U
00001210: 4889 e58b 0543 2e00 0083 f800 750c b800  H....C......u...     <-- Difference is here
00001220: 0000 00e8 61ff ffff eb0f 488d 05e2 0d00  ....a.....H.....
00001230: 0048 89c7 e8f7 fdff ff90 5dc3 0f1f 4000  .H........]...@.
00001240: f30f 1efa 4157 4c8d 3d9b 2b00 0041 5649  ....AWL.=.+..AVI
```

And recompile:
```
$ xxd -r binpached_hexdump > binpatched
```

Setting execute perms on `binpatched` and running it, we don't see the evil message anymore:
```
$ ./binpatched
$
```

## Pwning Remote
Now that we know it works locally, let's do it on the remote. This is where the second hint comes in. executing `sudo -l`, we discover we can run the command `strace -f ./*` with root privileges. Patching the binary like above, and then running `strace -f ./*`, we get the flag!

Note: you may have to put the patched executable in its own directory and run the strace from there for it to work.
```
[magpie@ec756b65d504 temp]$ sudo strace -f ./*
[pid    43] prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
[pid    43] munmap(0x7fbe4838a000, 19243) = 0
[pid    43] clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fbe483898d0) = 44
[pid    43] wait4(-1, strace: Process 44 attached
 <unfinished ...>
[pid    44] set_robust_list(0x7fbe483898e0, 24) = 0
[pid    44] execve("/bin/setfattr", ["-n", "flag", "-v", "magpie{1_gu3sz_y()u_c4ught_m3}", "lockbox.txt", 0xfd8f39f827860900, "", "H\215\5\374\r"], 0x7ffd1c390e68 /* 0 vars */) = -1 EFAULT (Bad address)
[pid    44] exit_group(-1)              = ?
[pid    44] +++ exited with 255 +++
[pid    43] <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 255}], 0, NULL) = 44
[pid    43] --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=44, si_uid=0, si_status=255, si_utime=0, si_stime=0} ---
[pid    43] newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}, AT_EMPTY_PATH) = 0
[pid    43] getrandom("\x98\x99\xb2\xc7\x94\xc2\x26\x22", 8, GRND_NONBLOCK) = 8
[pid    43] brk(NULL)                   = 0x557e0bcbc000
[pid    43] brk(0x557e0bcdd000)         = 0x557e0bcdd000
[pid    43] write(1, "You're not fast enough to follow"..., 38You're not fast enough to follow me. 
) = 38
[pid    43] exit_group(0)               = ?
[pid    43] +++ exited with 0 +++
<... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 43
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=43, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
exit_group(0)                           = ?
+++ exited with 0 +++
```
