---
title: KalmarCTF 2023
weight: 0
---
# KalmarCTF 2023

- [CTFTime](https://ctftime.org/event/1878)

- [Github](https://github.com/kalmarunionenctf/kalmarctf-2023)
  
## **crypto**

### BabyOneTimePad

- https://github.com/mohnad-0b/programming/tree/main/CTF/kalmarctf/Crypto/BabyOneTimePad

- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/KalmarCTF%202023/BabyOneTimePad

### EasyOneTimePad

- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/KalmarCTF%202023/EasyOneTimePad

### Reconstruction

### DreamHash

- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/KalmarCTF%202023/DreamHash

### I33t-generator

### Telepound

### Blind Security

### YoloProofs

  
  

## **pwn**

### mjs

- https://www.youtube.com/watch?v=7gEpVjwv9dM

- https://github.com/WilliamParks/ctf_writeups/tree/master/kalmar_ctf_2023/mjs

### js in my bs

- https://www.youtube.com/watch?v=IehTkvuZEm4

- https://www.aynakeya.com/ctf-writeup/2023/kalmar/pwn/js-in-my-bs/

### swedish memcpy

### Robber

- https://github.com/kalmarunionenctf/kalmarctf-2023/tree/main/pwn/robber

### FIPC

### hyper-k

  
  

## **rev**

### CycleChaser

- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/KalmarCTF%202023/CycleChaser

### Formula K

- https://gist.github.com/csn3rd/96f9960398b8ca52a38180668a5713eb

### Works on my machine

### CycleChaser Revenge

- https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/KalmarCTF%202023/CycleChaser%20Revenge

- https://gitlab.com/shalaamum/ctf-writeups/-/blob/master/KalmarCTF%202023/CycleChaser%20Revenge/solve.py

### Jumping on the SPU

### Jumping on the PPU

  
  

## **web**

### Invoiced

- https://github.com/olnor18/writeup/tree/master/CTF/KalmarCTF%202023/Invoiced

- https://boxmein.github.io/posts/2023-03-05-kalmarctf-invoiced/

### Ez web

- https://boxmein.github.io/posts/2023-03-05-kalmarctf-ezweb/

### Healthy Calc

### Password Homecoming

### 2Cool4School

- https://github.com/olnor18/writeup/tree/master/CTF/KalmarCTF%202023/2Cool4School

### XScapy

- https://github.com/olnor18/writeup/tree/master/CTF/KalmarCTF%202023/XScapy

  
  

## **misc**

### Renaissance Flag Music

- https://gist.github.com/csn3rd/96f9960398b8ca52a38180668a5713eb

- https://boxmein.github.io/posts/2023-03-05-kalmarctf-renaissance-flag-music/

### kalmarunionen-fun

- https://boxmein.github.io/posts/2023-03-05-kalmarctf-kalmarunionen-fun/

  
  

## **forensic**

### cards

{{< details title="yuzu#0233" open=false >}}

``` python

from binascii import unhexlify

from pyshark import FileCapture

  

packets = FileCapture('cards.pcap')

  

refs = {}

data = {}

flag = {}

  

for enum, packet in enumerate(packets):

tcp = packet.tcp

  

if hasattr(packet, 'ftp'):

val = refs.get(int(tcp.stream), list())

  

if  not val:

refs[int(tcp.stream)] = val

  

ftp = packet.ftp

if hasattr(ftp, 'request_arg'):

if ftp.request_command == 'CWD':

val.append(ftp.request_arg)

elif hasattr(ftp, 'response_arg'):

# Entering Passive mode

if ftp.response_code == '227':

val.append(ftp.passive_port)

val.append(enum + 1)

  

elif hasattr(packet, 'DATA'):

val = data.get(tcp.srcport, list())

if  not val:

data[tcp.srcport] = val

  

val.append((packet.DATA.data, enum + 1))

  

for key, value in refs.items():

path, port, offset = value

data_values = data[port]

  

for d in data_values:

if d[1] > offset:

flag[path] = unhexlify(d[0])

break

  

flag = dict(sorted(flag.items())).values()

print(b''.join(flag).decode())

```

{{< /details>}}

### IleHSyniT!

{{< details title="yuzu#0233" open=false >}}

```bash

# Ref: https://blog.didierstevens.com/2021/04/26/quickpost-decrypting-cobalt-strike-traffic/

$ data=$(tshark -r capture.pcap -Y http.request.method==POST -Tfields -e data | tail -1)

$ cs-extract-key.py  -c $data proc.dmp

$ cs-parse-traffic.py  -k  24a0f5e701439f460d52ef4810f592f3:3c4267894c6fee7a5aaa4d13e0289051  capture.pcap  -e

$ cat  payload-61ca2f3dc9212781c983f9e13a99be08.vir

```

{{< /details>}}

### sweing-waste-and-agriculture-leftovers

- https://ctftime.org/task/24374

- https://github.com/mohnad-0b/programming/tree/main/CTF/kalmarctf/forensic/sewing-waste-and-agriculture-leftovers
