---
title: UMassCTF 2023
weight: 0
---

# UMass CTF 2023

- [CTFTime](https://ctftime.org/event/1912)
- [Github](https://github.com/UMassCybersecurity/UMassCTF-2023-challenges-mirror)


## **web**

### JS-ON

- https://ctf.cve2k9.club/2023/js_on

### JS-ONv2

- https://ctf.cve2k9.club/2023/umass-2023-js_on_v2

### DeepFried

- https://ctf.cve2k9.club/2023/umass-2023-deepfried

- https://github.com/Kaiziron/umass_ctf_2023_writeup/blob/main/deepfried.md

### secureblocks

- https://github.com/Kaiziron/umass_ctf_2023_writeup/blob/main/secureblocks.md

### umassdining2

- https://github.com/Kaiziron/umass_ctf_2023_writeup/blob/main/umassdining2.md

  
  

## **misc**

### blackjack

### jeopardyv3

  
  

## **pwn**

### babysc

### last_minute_pwn

- https://ctf.cve2k9.club/umass-2023-last_minute_pwn

  
  

## **rev**

### diamond

### java_jitters

- https://ctf.cve2k9.club/umass-2023-java_jitters

### java_jitters2

- https://ctf.cve2k9.club/umass-2023-java_jitters_2

### pipelining

### sapphire

- https://ctf.cve2k9.club/umass-2023-sapphire

### welcome_to_hell

  
  

## **crypto**

### wrathsweatingbuddha

{{< details title="Lofer#5814" open=false >}}

```python

# Phase 1: The hell is this?

# OSINT Polymero, see what types of schemes he usually works with

# Notice Paillier, look it up - oh hey, it matches our cryptographic scheme!

# https://en.wikipedia.org/wiki/Paillier_cryptosystem

  

# Phase 2: Our problem!

# Comparing the encryption scheme with Wikipedia, we assure ourselves that it works.

# We take note that the scheme is "additiveley homomorphic". Might come in useful later.

# Connecting to the server and analyzing the code, we notice we get an (encrypted) LSB of a chosen input.

# Right, how can we decrypt that?

# Well, as soon as we're dealing with single bits, the Jacobi (and thusly the Legendre) symbols should come to mind!

  

# def barter(self, cip: int) -> int:

# k = self.decrypt(cip) & 1

# r = randbelow(self.N)

# rG = pow(r, randbelow(self.N), self.N * self.N)

# g_m = pow(rG, k + 1, self.N * self.N)

# r_n = pow(r, self.N, self.N * self.N)

# return (g_m * r_n) % (self.N * self.N)

# LSB: 0

# r is a quadratic residue --> r^x * r^N is a quadratic residue for all x --> Jacobi symbol of 1

# r isn't a quadratic residue

# x is odd --> r^2k+1 * r^N --> -1 * -1 = 1

# x is even --> r^2k * r^N --> 1 * -1 = -1

# In 75% of cases, we get a Jacobi symbol of 1

  

# LSB: 1

# r is a quadratic residue --> Jacobi 1

# r isn't a quadratic residue: r^2x * r^N --> 1 * -1 = -1

# In 50% of cases, we get 1

  

from secrets import randbelow

from gmpy2 import jacobi, powmod, invert

from pwn import *

from base64 import b64decode, b64encode

from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l

  

server = b"wrath-fast.crypto.ctf.umasscybersec.org"

port = 9953

io = remote(server, port)

  

N = b2l(b64decode(io.recvline()))

G = b2l(b64decode(io.recvline()))

print(f"{N=}\n{G=}")

print(N.bit_length())

enc_flag = b2l(b64decode(io.recvline()))

curr_flag = enc_flag

  

# We need a way to remove the last bit.

# Paillier is homomorphic, so that's a good way of going about that.

# But is there a way to divide by 2 when it's odd? Subtracting might come to our rescue!

# If the LSB is 1, we subtract by 1 and then 'multiply' by 2^-1

# Otherwise, we just multiply! :)

  

def encrypt(msg: int) -> int:

g_m = powmod(G, msg, N * N)

r_n = powmod(randbelow(N), N, N * N)

return (g_m * r_n) % (N * N)

  

minus_one = invert(encrypt(1), N*N)

two = invert(2, N)

  

def reduceFlag(flag: int, bit: int) -> int:

global minus_one

global N

tmp = flag

if bit == 1:

tmp = (flag * minus_one) % (N*N)

return powmod(tmp, two, N*N) # Divide by 2

  

def bitsToChar(bits: list) -> str:

return chr(int(''.join([str(bit) for bit in bits]), 2))

  

# Now for the attack

to_remove = 'flag{l00ks_l1k3_1_h4v3_f1n4lly_b33n_b3st3d___w3_w1ll_m33t_4g41n_my_ch1ld}'  # Update this to remove known chars if connection drops

for char in to_remove:

bits = bin(ord(char))[2:]

bits = '0' * (8 - len(bits)) + bits

bit_list = [ord(b)-ord('0') for b in bits]

for bl in bit_list[::-1]:

curr_flag = reduceFlag(curr_flag, bl)

  

rebuilt_flag = to_remove

reversed_flag = to_remove

MIN_ATTEMPTS = 100

recovered_bits = []

running = True

print("[*] Running...")

while running:

residues = 0

nonresidues = 0

attempts = 0

bitVerified = False

guess = None

while attempts < MIN_ATTEMPTS or  not bitVerified:

io.sendline(str(curr_flag).encode())

lsb = b2l(b64decode(io.recvline()))

j = jacobi(lsb, N) # Jacobi of the LSB

if j == 1:

residues += 1

attempts += 1

elif j == -1:

nonresidues += 1

attempts += 1

else:

print("Jacobi wasn't found.")

try: # Bounds

if residues / attempts >= 0.71:

bitVerified = True

guess = 0

elif residues / attempts <= 0.54:

bitVerified = True

guess = 1

else:

bitVerified = False

except ZeroDivisionError:

pass

print(f"Attempts: {attempts}")

print(f"Bit recovered: {guess}")

recovered_bits.append(guess)

curr_flag = reduceFlag(curr_flag, guess)

if len(recovered_bits) % 8 == 0:

tbyte = recovered_bits[-8:]

currChar = bitsToChar(tbyte)

if currChar == '}':

running = False

rebuilt_flag += currChar

reversed_flag += bitsToChar(tbyte[::-1])

# print(rebuilt_flag)

print(reversed_flag)

  

print(recovered_bits)

```

{{< /details>}}

  
  

## **blockchain**

### csgo_but_decentralised

- https://github.com/Kaiziron/umass_ctf_2023_writeup/blob/main/csgo_but_decentralised.md
