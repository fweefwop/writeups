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


