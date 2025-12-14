from Crypto.Util.number import *
from random import randint
from math import sqrt, gcd
from secret import FLAG

def keygen():
    q = getPrime(512)
    _q = int(sqrt(q // 2))
    __q = int(sqrt(q // 4))
    f = randint(2, _q)
    while True:
        g = randint(__q, _q)
        if gcd(f, g) == 1:
            break
    h = (inverse(f, q) * g) % q
    return ((q, h), (f, g))

def encrypt(m: int, h, q):
    assert m < int(sqrt(q // 2))
    r = randint(2, int(sqrt(q // 2)))
    c = (r * h + m) % q
    return c

def decrypt(c, f, g):
    a = (f * c) % q
    b = (inverse(f, g) * a) % g
    return b


pk, sk = keygen()
q, h = pk
f, g = sk

FLAG = bytes_to_long(FLAG)

assert FLAG < sqrt(q / 4)
c = encrypt(FLAG, h, q)

print(f"q = {q}\nh = {h}\nc = {c}")