from Crypto.Util.number import getPrime, getRandomNBitInteger
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from secret import flag

p = 81663996540811672901764249733343363790991183353803305739092974199965546219729
a = 1
b = 7
G = (14023374736200111073976017545954000619736741127496973904317708826835398305431, 23173384182409394365116200040829680541979866476670477159886520495530923549144)
E = EllipticCurve(GF(p), [a, b])
G = E(G)

n = G.order()
x = getRandomNBitInteger(64)
P = x*G

sha1 = hashlib.sha1()
sha1.update(str(x).encode('ascii'))
key = sha1.digest()[:16]
iv = urandom(16)

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext = cipher.encrypt(pad(flag, 16))

print(f"a = {a}\nb = {b}\np = {p}\nG = {G.xy()}\nP = {P.xy()}\nciphertext = '{ciphertext.hex()}'\niv = '{iv.hex()}'")