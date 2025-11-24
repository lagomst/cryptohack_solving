from pprint import pprint
from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import hashlib
import numpy as np
import math
import json

class ModPow:
    def __init__(self, p:int, q:int, e:int):
        self.p = p
        self.q = q
        self.e = e
        # calculating d (inverse of e mod phi_euler_n)
        self.d = extended_euclid_prime(self.e, self.phi_euler_n)
    
    @property
    def n(self)->int:
        return self.p * self.q
    
    @property
    def phi_euler_n(self)->int:
        return (self.p - 1) * (self.q - 1)
    

def gcd_euclid(big: int, small: int):
    if big < small:
        return gcd_euclid(small, big)
    a = big
    b = small
    while (b > 0):
        q = a // b
        r = a % b
        if r == 0:
            break
        a = b
        b = r 
    return b

def extended_euclid_prime(a: int, b:int):
    if a > b:
        a %= b
    small = a
    big = b
    q_list = []
    while(True):
        q = big // small
        r = big % small
        
        big = small
        small = r
        q_list.append(q)
        
        if r == 1:
            break
        if r < 1:
            raise ValueError("a and b might not have inverse my_modulo!")
    # pprint(q_list)
    p_two = 0
    p_one = 1
    p_i = None
    for i in range(len(q_list)+2):
        if i < 2:
            continue
        p_i = (p_two - p_one * q_list[i - 2]) % b
        p_two = p_one
        p_one = p_i
        
    return p_i

def mod_inverse_gcd_one(A, M):
    m0 = M
    y = 0
    x = 1

    if (M == 1):
        return 0

    while (A > 1):

        # q is quotient
        q = A // M

        t = M

        # m is remainder now, process
        # same as Euclid's algo
        M = A % M
        A = t
        t = y

        # Update x and y
        y = x - q * y
        x = t

    # Make x positive
    if (x < 0):
        x = x + m0

    return x

def nthroot_newtons(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

def get_combination_from_dict(d: dict)->list[list[int]]:
    # turn the dictionary into arrays:
    arr = []
    for k, v in d.items():
        for _ in range(v):
            arr.append(k)
    
    def get_combination_recursive(arr: list[int], k=len(arr)) -> list[list[int]]:
        # Generate combinations of k-elements sets from arr
        if k == 0 or not arr:
            return []
        if k <= 1:
            return [[ele] for ele in arr]
        result = []
        # For every character in array
        for i in range(len(arr)):
            # Get every subset from this element forward
            base_set = [arr[i]]
            subsets = get_combination_recursive(arr[i+1:], k-1)
            # Get a set from this character + sub-set
            for s in subsets:
                result.append([arr[i]] + s)
        
        return result
    
    combinations = []
    for comb_len in range(len(arr)+1):
        combinations.extend(get_combination_recursive(arr, comb_len))
    
    return combinations

def is_prime_naive(n):
    if (n == 1):
        return False
    if (n == 2 or n == 3):
        return True
    if (n % 2 == 0 or n % 3 == 0):
        return False
    # A prime that is not 2 or 3
    # must be in a form of 6k + 1 or 6k + 5
    d = 5
    while(d * d <= n):
        if (n % d == 0 or n % (d + 2) == 0): # check for 6k - 1 aka 6k + 5 and 6k + 1
            return False
        d += 6 # skipping 6k + 2/3/4 (6k + 5 is actually 6k - 1, and we start at 5 aka 6 * 1 - 1)
    return True



def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

def parameter_injection(filepath):
    from my_modulo import get_prime_factor
    with open(filepath, "r") as f:
        content: dict = json.loads(f.read())
        p = content["p"]
        g = content["g"]
        A = content["A"]
    
    return p, g, A
          
def main():
    return parameter_injection('./interceptor.txt')

if __name__ == "__main__":
    print(main())
    