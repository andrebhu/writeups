---
title: RITSEC CTF 2023
weight: 0
---

# RITSEC CTF 2023
- [CTFTime](https://ctftime.org/event/1860)
- [GitLab](https://gitlab.ritsec.cloud/competitions/ctf-2023-public)

## **pwn**
### User Application Firewall
### alphabet
- [Robbert1978#8023](/fa7986ef7f8d62bc74f1002ec5ae1db65729cf5e.py)
- [playoff-rondo#5665](/d5cd76441d2144e06928acc9286307d572a35832.py)
### assembly-hopping
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
### ret2win
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win
- https://rinnnt.github.io/ctf/2023/04/03/ritsecctf-2023-writeup.html
### Steg as a Service
- https://secvoid.xyz/2023/04/ritsec2023-steg/

## **ChandiBot**
### Chandi Bot 1
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot-1-6/
### Chandi Bot 2
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot-1-6/
### Chandi Bot 3
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot-1-6/
### Chandi Bot 4
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot-1-6/
### Chandi Bot 5
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot-1-6/
### Chandi Bot 6
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Chandi-Bot/Chandi-Bot-1-6/


## **crypto**
### A Fine Cipher
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://www.leoreading.com/blog/ritsec-ctf-2023/crypto/a-fine-cipher
### Binary To Based
### Either or Neither nor
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Crypto/Either-or-Neither-nor
- https://www.leoreading.com/blog/ritsec-ctf-2023/crypto/either-or-neither-nor


## **forensics**
### Ads
{{< details title="st4rn#0086" >}}
```python
from scapy.all import rdpcap, ICMP
import re

s = rdpcap("ads.pcapng")

def fltr(packet):
    return packet.src == "a4:83:e7:3c:76:79" and packet.haslayer(ICMP) and not (packet[ICMP].type == 8 or packet[ICMP].type == 0 or packet[ICMP].type == 3)

s = s.fltr(fltr)
len_s = len(s)
len_mod = len_s % 8

print(len_s, len_mod)

bits = "".join(str([0,1][packet[ICMP].type%2==0]) for packet in s)
print(bits)

char_list = re.findall(".{8}", bits)
decoded_str = "".join(chr(int(i, 2)) for i in char_list)
print(decoded_str)
```
{{< /details >}}
### Clocks
{{< details title="fumika0233" >}}
```bash
» tshark -r clocks.pcapng -Y 'ip.addr eq 129.21.1.111' -Tfields -e ntp.reftime -e ntp.org -e ntp.rec -e ntp.xmt | uniq | grep -oP 'Jan.*?UTC' | xargs -Iz date -d z +%s | awk '{ prev=cur; cur=$0; if (prev != "") print cur-prev; else print 0 }' | paste -sd '' | perl -lpe '$_=pack"B*", $_'
RS{Tim3_k33per!}
```
{{< /details >}}
### Web of Lies
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/
### Missing Piece Part 1
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1/
### Red Team Activity 1
- https://www.leoreading.com/blog/ritsec-ctf-2023/forensics/red-team-activity-1
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1-4/
### Red Team Activity 2
- https://www.leoreading.com/blog/ritsec-ctf-2023/forensics/red-team-activity-2
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1-4/
### Red Team Activity 3
- https://www.leoreading.com/blog/ritsec-ctf-2023/forensics/red-team-activity-3
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1-4/
### Red Team Activity 4
- https://www.leoreading.com/blog/ritsec-ctf-2023/forensics/red-team-activity-4
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Forensics/Red-Team-Activity-1-4/

## **misc**
### Connection Terminated
- https://www.leoreading.com/blog/ritsec-ctf-2023/misc/connection-terminated
### Frequent-Freqency
### New Hire
- https://www.leoreading.com/blog/ritsec-ctf-2023/misc/new-hire
### Wild Stocks

## **reversing**
### Cats At Play
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Reversing/Cats-At-Play/
### Guess the Password
- https://rinnnt.github.io/ctf/2023/04/03/ritsecctf-2023-writeup.html
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Reversing/Guess-the-Password/
### Jurassic Park
### gauntlet
- [doubledelete#0304](/7ad9f0c46d49d166013e5a83fb86f2cd53fd7a8e.py)


## **stego**
### QR
### bitmap
{{< details title="samiko#9262" >}}
![](/7698e466f9a974ffcdcafd7d8bf19d2602d72411.png)
{{< /details >}}
### turtle
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Steganography/turtle/
### Weird
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Steganography/Weird/

## **web**
### Broken Bot
- https://vasic.dev/blog/ritsec-ctf-broken-bot-writeup/
- https://www.leoreading.com/blog/ritsec-ctf-2023/web/broken-bot
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/Broken-Bot/
### Rick Roll
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://www.leoreading.com/blog/ritsec-ctf-2023/web/rick-roll
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/Rick-Roll/
### Echoes
- https://h4ckyou.github.io/posts/ctf/ritsec23/writeup.html
- https://www.leoreading.com/blog/ritsec-ctf-2023/web/echoes
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/Echoes/
### Pickle Store
- https://www.leoreading.com/blog/ritsec-ctf-2023/web/pickle-store
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/Pickle-Store/
- https://github.com/H31s3n-b3rg/CTF_Write-ups/tree/main/RITSEC_2023/WEB/Pickle%20Store
### X-Men Lore
- https://www.leoreading.com/blog/ritsec-ctf-2023/web/x-men-lore
- https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/X-Men-Lore/
- https://github.com/H31s3n-b3rg/CTF_Write-ups/tree/main/RITSEC_2023/WEB/X-Men%20Lore