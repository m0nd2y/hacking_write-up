from pwn import *
context.log_level = "debug"

r = process("./init")
r.recvuntil(">>> ")

r.sendline("W")
r.recvuntil(": ")
r.sendline("180")

print(r.recv())