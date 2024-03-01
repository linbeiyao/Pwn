if __name__ == '__main__':
    local = sys.argv[1]
    if local == '1':
        r= process(./pwn)
        elf = ELF(./pwn)
        libc = elf.libc
    else:
        r=remote(')
        elf = ELF(./pwn)
        libc = elf.libc
