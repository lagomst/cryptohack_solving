# Note: to find the main atttack code, press ctrl+f and search for "Attack code"
# The reason why this code is so long is that I resused old code from
# my cryptohack solver that I've implemented to solve them (you can verify it by checking my github)
# GPT is mostly used to generate header comments

import hashlib
import sys
import traceback
import math
import os
import random
from Crypto.Util import number
# from sage.all import EllipticCurve, GF

# =====================
# Class definitions
# ---------------------
# This section contains the core elliptic-curve classes used by the rest
# of the module: EC (curve parameters/operations helpers) and PointEC
# (point arithmetic using projective coordinates). These classes do the
# heavy lifting for point addition, doubling and scalar multiplication.
# =====================

class EC:
    # Elliptic curve funciton class, 
    # represnteded as y^2 = x^3 + ax + b 
    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b

    def __eq__(self, value):
        # TODO: compares weights for matching exponent
        # of two dicts dict[exponent, weight]
        if not isinstance(value, self.__class__):
            raise NotImplemented("unsupported operand type(s) for ==: '{}' and '{}'").format(self.__class__, type(value))
        return self.a == value.a and self.b == value.b
    
    def func(self) -> str:
        # TODO: return a dict of polynominal for proper function comparision
        # where wegihts of matching exponent are compared 
        return f"y^2=x^3+{self.a}*x+{self.b}"
    
    def negative(self, a: int) -> int:
        return (self.p - a) % self.p

    def inverse_modulo(self, a: int) -> int:
        return pow(a, -1, self.p)
    
    def left_term(self, y:int):
        return (y*y)%self.p
    
    def right_term(self, x:int):
        return (x*x*x + self.a*x + self.b)%self.p
        
class PointEC:
    # store as projective coordinate
    def __init__(self, curve: EC, x: int, y: int, z:int=1):
        self.curve = curve
        self.x = x % curve.p
        self.y = y % curve.p
        self.z = z
    
    def is_infinity(self):
        return self.z == 0
        
    def on_curve(self) -> bool:
        curve = self.curve
        x, y = self.get_affine_coordinate()
        return curve.left_term(y) == curve.right_term(x)
    
    def get_affine_coordinate(self):
        # WARNING: currently return None when z==0
        if self.is_infinity():
            return None
        
        p = self.curve.p
        inverse_z = pow(self.z, -1, p)
        x = (self.x*inverse_z)%p
        y = (self.y*inverse_z)%p
        return x, y
    
    def get_projective_coordinate(self):
        if self.is_infinity():
            return 0, 1, 0
        return self.x, self.y, self.z
    
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplemented("unsupported operand type(s) for ==: '{}' and '{}'").format(self.__class__, type(other))
        if self.curve != other.curve:
            raise ValueError("Comparing two points belonging to different curve contexts")
        
        if self.is_infinity():
            return other.is_infinity()
        if other.is_infinity():
            return self.is_infinity()
        
        return self.get_affine_coordinate() == other.get_affine_coordinate()

    def double_projective(self):
        if self.is_infinity():
            return PointEC(self.curve,0,1,0)
        
        x1, y1, z1 = self.get_projective_coordinate()
        # Double reference from this site: https://hackmd.io/@cailynyongyong/HkuoMtz6o
        p = self.curve.p
        a = self.curve.a
        w = (a*z1*z1 + 3*x1*x1)%p
        s = (y1*z1)%p
        B = (x1*y1*s)%p
        h= (w*w - 8*B)%p
        
        x = (2*h*s)%p
        y = (w*(4*B-h) - 8*s*s*y1*y1)%p
        z = (8*pow(s,3,p))%p
        
        return PointEC(self.curve,x,y,z)
    
    def phi_dp(self, n:int):
        if n < 0:
            raise ValueError("Division polynominal order must not be negative!")
        if self.is_infinity():
            return None
        p = self.curve.p
        a = self.curve.a
        b = self.curve.b
        if n == 0:
            return 0
        if n == 1:
            return 1
        x, y = self.get_affine_coordinate()
        if n == 2:
            return (2*y)%p
        if n == 3:
            return (3*pow(x,4,p)+ 6*a*x*x + 12*b*x - a * a)%p
        if n == 4:
            return (4*y * (pow(x,6,p) + 5*a*pow(x,4,p) + 20*b*pow(x,3,p)
                    -5*a*a*pow(x,2,p) - 4*a*b*x - 8*b*b - 3*pow(a,3,p)))%p
        
        if n % 2 == 1:
            # n = 2m + 1
            m = (n-1)//2
            return (self.phi_dp(m+2)*pow(self.phi_dp(m),3,p) 
                    - self.phi_dp(m-1)*pow(self.phi_dp(m+1),3,p)
                    )%p

        # n = 2m
        m = n//2
        return (self.phi_dp(m)*pow(2*y,-1,p)*
                    (self.phi_dp(m+2)*pow(self.phi_dp(m-1),2,p)
                    - self.phi_dp(m-2)*pow(self.phi_dp(m+1),2,p))
                )%p
    
    # Overloading add operators (+) helps us type A + B much easier
    def __add__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplemented("unsupported operand type(s): '{}' and '{}'").format(self.__class__, type(other))
        if self.curve != other.curve:
            raise ValueError("Performing operator on two points belonging to different curve contexts")
        
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        
        curve = self.curve
        p = curve.p
        
        x1, y1, z1 = self.get_projective_coordinate()
        x2, y2, z2 = other.get_projective_coordinate()
        # Addition reference from this site: https://hackmd.io/@cailynyongyong/HkuoMtz6o
        u = (y2*z1 - y1*z2)%p
        v = (x2*z1 - x1*z2)%p
        if v==0:
            if u != 0:
                return PointEC(curve,0,1,0)
            return self.double_projective()
        
        z3 = (pow(v,3,p)*z1*z2)%p
        if z3 == 0:
            return PointEC(curve,0,1,0)
        
        A = (u*u*z1*z2 - pow(v,3,p)-2*v*v*x1*z2)%p
        
        x3 = (v*A)%p
        y3 = (u*(v*v*x1*z2-A)-pow(v,3,p)*y1*z2)%p
        
        return PointEC(curve,x3,y3,z3)
        
    def __radd__(self, other):
        return self.__add__(other)
    
    def __iadd__(self, other):
        return self + other
    
    def __mul__(self, k):
        if isinstance(k, self.__class__):
            # TODO: write a good explaination for this
            # ok hear me out: how would you define e^k of e 
            # belong to field F, in the context of EC?
            # e^k ~ k * G, with G is a point on the curve
            # Now what about a^k * a to EC context?
            # a^k * a ~ a^(k+1)
            #  
            # k*G * G ~ (k+1)*G
            return self + k # hence this return
        if not isinstance(k, int):
            raise ValueError("Multiplication only works for a PointEC and a integer or another PointEC")
        
        curve = self.curve
        if (k == 0):
            return PointEC(curve,0,1,0)
        if (k < 0):
            return (-self) * (-k)
        
        q = PointEC(curve, self.x, self.y, self.z)
        r = PointEC(curve, 0, 1, 0)
        while k > 0:
            if k%2 == 1:
                r = r + q
            q += q
            k //= 2
        # print(f"PointEC mul = {r}")
        if r.is_infinity():
            return PointEC(self.curve,0,1,0)
        return r
    
    def __imul__(self, p:int):
        return self * p

    def __rmul__(self, p:int):
        return self * p
    
    def __neg__(self):
        if self.is_infinity():
            return PointEC(self.curve, 0, 1, 0)
        p = self.curve.p
        x = self.x
        y = (-self.y)%p
        z = self.z
        return PointEC(self.curve,x,y,z)
    
    def __sub__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError("unsupported operand type(s): '{}' and '{}'".format(self.__class__, type(other)))
        return self + (-other)
    
    def __isub__(self, other):
        return self - other
    
    def __rsub__(self,other):
        return other - self
    
    def __pow__(self, other:int, modulo:int=None):
        if modulo and modulo != self.curve.p:
            raise ValueError("Modulo does not match with interal curve's modulo")
        if not isinstance(other, int):
            raise ValueError("Powers on PointEC can only be called with integer!")
        if other < 0:
            return (-self) * (-other)
        return self * other
    
    def __mod__(self, other:int):
        # TODO: figure out what to do with this
        return self
    
    def __str__(self):
        t = (self.x, self.y, self.z)
        return str(t)
    
    def __repr__(self):
        return repr(self.get_affine_coordinate())

# =====================
# Attack code
# ---------------------
# Contains implementations of discrete-log attacks (baby-step/giant-step)
# that work on integer groups or elliptic-curve groups represented by
# PointEC. These functions are intended to be generic and used by the
# higher-level Pohlig-Hellman routine below.
# =====================
# Attack code
# Main implementation here
def attack_baby_step_giant_step(g:int|PointEC, a:int|PointEC, p:int, known_order:int=None):
    # assuming p is prime
    print(f"{g=} {a=} {p=}")
    if known_order:
        n = known_order
    else:
        n = order(g, p)
    m = math.ceil(math.sqrt(n))
    gj_table: dict[str, list[int]] = {}
    print(f"Constructing lookup table jG {m=} ...")
    log_step = max(1, m//10) # after log_step steps, print out the progess
    for j in range(m):
        gj = repr(pow(g, j, p))
        if gj in gj_table:
            gj_table[gj].append(j)
        else:
            gj_table[gj] = [j]
        if (j % log_step == 0):
            print(f"Progress: {j / m * 100:.0f}% ({j}/{m})")
    print(f"Lookup table JG constructed, length={len(gj_table)}")
    g_m_neg: int|PointEC = pow(g, -m, p) 
    gamma = a%p # a * (g^-m)^i, i currently i=0
    for i in range(m):
        key = repr(gamma)
        # print(f"Checking {key} in table...")
        if key in gj_table:
            j = gj_table[key][0]
            print(f"Found matching {gamma=}, {j=} {i=} x={j + m*i}")
            return j + m*i
        gamma *= g_m_neg
        if isinstance(gamma, int):
            gamma %= p
    
    return None


def pohlig_hellman(g:int|PointEC, a:int|PointEC, p:int):
    # TODO: implement cardinality count for EC and any arbitary modulo
    n = order(g, p)
    prime_factors = get_prime_factor(n)
    print(f"Pohllig-Hellman: {n=} factor={prime_factors}")
    crt_terms = []
    for prime, prime_exp in prime_factors.items():
        exp:int = pow(prime, prime_exp)
        gi = pow(g, n//exp, p)
        ai = pow(a, n//exp, p)
        xi = attack_baby_step_giant_step(gi, ai, p, exp)
        if xi is None:
            return None
        crt_terms.append((xi, exp))
    print(f"{crt_terms=}")
    return crt_solver(crt_terms)

def order(g, p:int):
    if isinstance(g, int):
        n = mult_order(p, g)
        assert pow(g, n, p) == 1
        return n
    if isinstance(g, PointEC):
        # TODO: implement EC order calculation
        return p - 1

    raise NotImplementedError("unsupported order for type: ", type(g))

# Helper function
# =====================
# Helper functions
# ---------------------
# Utility routines used by the attack code: CRT solver, primality
# tests, factoring helpers and Tonelli-Shanks. Note: some helper
# functions may be slow for very large inputs and some rely on
# probabilistic algorithms (Pollard Rho, Miller-Rabin).
# =====================
def schoof_algo(curve:EC, b:int=1):
    pass
    

def crt_solver(terms:list[tuple[int,int]]):
    # assuming every point inside is co-prime moduli
    product = 1
    for _, modulo in terms:
        product *= modulo
    x = 0
    for remainder, modulo in terms:
        N = product // modulo
        M = pow(N, -1, modulo)
        x += remainder * N * M
    return x%product

def is_prime(n: int):
    if n > 360_000_000_000:
        return is_prime_miller_rabin(n)
    return is_prime_naive(n)

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

def is_prime_miller_rabin(n, rounds:int=250):
    # Miller-Rabin can ensure if a number is not a prime (if False => confidence = 100%),
    # but cannot ensure if a number is prime (if True => confidence != 100%)
    if n % 2 == 0:
        return False
    # Factor two out
    temp = n -1
    s = 0
    while (temp > 1 and temp % 2 == 0):
        temp = temp // 2
        s += 1
    d = temp
    # print(f"{n-1=} {d=} {s=}" )
    # Hybrid approrach with some deterministic bases for number < 2^64 bits
    bases = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 44}
    num_bases_to_generate = rounds - len(bases)
    for _ in range(num_bases_to_generate):
        # Append random bases into base
        random_base = random.randint(2, n -2)
        bases.add(random_base)
    
    # test for primes
    for base in bases:
        x = pow(base, d, n)
        for i in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n-1:
                return False
            x = y
        if y != 1:
            return False
    
    return True

def mult_order(p : int, a: int):
    # Return the order of a^k mod p
    # aka smallest k where a^k = 1 mod p
    n = phi_euler(p)
    factors = get_prime_factor(n)  # {prime: exponent}
    # assert pow(a,n,p) == 1
    print(f"{n=} {factors=}")
    order = n
    for q in factors.keys():
        # print(f"{order=} {q=}")
        # print(f"Mult_order step: {a=} {order//q=}")

        while order % q == 0 and pow(a, order // q, p) == 1:
            order //= q
    print(f"{order=}")
    return order

def phi_euler(p: int):
    # Find numbers of co-primes of p from 1 to p
    prime_factors = get_prime_factor(p)
    # print(f"{p=} {prime_factors=}")
    product = 1
    for prime, prime_exponent in prime_factors.items():
        product *= pow(prime-1, prime_exponent)
    return product

def get_prime_factor(n: int) -> dict[int, int]:
    temp = n
    n_factors: dict[int, int] = {}
    while (temp > 1):
        # Check if it's prime 
        if is_prime(temp):
            n_factors[temp] = 1
            break
        # Find a factor
        while (True):
            if temp < (2 << 32):
                factor = smallest_prime_factor(temp)
            else:
                factor = polland_factor(temp)
            if not factor:
                print("Retrying the function...!")
            else:
                break
        # Factor that number out of temp
        exp = 0
        while(temp > 1 and temp % factor == 0):
            temp //= factor
            exp += 1
        # Recursive factorization if the factor is not prime
        if is_prime(factor):
            n_factors[factor] = exp
        else:
            factor_primes = get_prime_factor(factor)
            # Update primes inside factors accordingly
            # to the number of factor's exponent
            if exp > 1:
                for prime in factor_primes.keys():
                    factor_primes[prime] *= exp 
            n_factors.update(factor_primes)
    return n_factors

def smallest_prime_factor(n: int):
    if n <= 1 or not isinstance(n, int):
        raise ValueError("Value must be a positive integer >=2!")
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    d = 5
    while d * d <= n:
        if n % d == 0:
            return d
        if (n % (d + 2)) == 0:
            return d + 2
        d += 6
    return d

def polland_factor(n :int):    
    b = random.randint(2, n-2)
    print("Polland Rho algo!")
    print(f"{n=}\t{b=}")
    
    def g(a: int):
        return (a * a + b) % n
    
    d = 1
    hare_step_advance = 1
    x0 = 2
    hare = x0
    
    global_step = 0
    max_global_step = 24
    while (d == 1 and global_step < max_global_step):
        tortoise = hare
        # Advance hare for some step
        for _ in range(hare_step_advance):
            hare = g(hare)
        saved_hare = hare 
        
        k = 0
        product = 1
        steps_size = random.randint(50, 1000) # recommended range of steps
        
        while(k < hare_step_advance and d==1):
            for _ in range(min(steps_size, hare_step_advance - k)):
                hare = g(hare)
                # Catch-up! Revert to steps_size = 1
                if (tortoise == hare):
                    print("Hare and Tortoise have caught up!\nRevert to step=1")
                    steps_size = 1
                    hare = g(saved_hare)
                    continue
                
                product = (product * abs(tortoise - hare))% n
            d = gcd_euclid(product, n)
            k += steps_size
        # print(f"{d=} {hare_step_advance=}")
        hare_step_advance *= 2
        global_step += 1
    
    if d == 1:
        print("Not found d!")
        return None
    
    if d == n or d == 0:
        print("Degeneracy found!")
        while(True):
            saved_hare = g(saved_hare)
            d = gcd_euclid(abs(tortoise - saved_hare), n)
            print(f"{d=}")
            if d > 1:
                break
    
    print(f"Found d! {d=}")
    return d

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

def factor_out_two_powers(n : int):
    if n < 0 or not isinstance(n, int):
        raise ValueError("Value must be a positive integer!")
    
    q: int = n
    exp: int = 0
    # n = q * 2^exp where q must be odd integer
    while(q > 1 and q & 1 == 0): 
        exp += 1
        q = q >> 1
    return q, exp

def tonelli_shanks(p: int, n: int):
    # if smallest_prime_factor(p) == p:
    #     raise ValueError("p must be a prime!")
    # print(f"{p=} {n=}")
    q, s = factor_out_two_powers(p-1)
    z = None
    for i in range(2, p):
        if pow(i, (p-1)//2, p) == p-1:
            z = i
            break
    if not z:
        return None
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q+1)//2, p)
    while(True):
        if t == 0:
            return 0
        if t == 1:
            return r
        
        step = None
        for i in range(1, m):
            temp = pow(t, 1 << i, p)
            if temp == 1:
                step = i
                break    
        if not step:
            return None
        b_pow = 1 << (m - step - 1)
        b = pow(c, b_pow, p)
        m = step
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
        
    return r

# =====================
# Test code
# ---------------------
# The following functions are simple tests and sanity checks for the
# EC/PointEC classes and attack implementations. They rely on both the
# pure-Python EC code and Sage for exact cardinality when needed. They
# are intended for local development and demonstration rather than as
# production-grade unit tests.
# =====================
def test_ec_class():
    def point_addition():
        # cryptohack example
        n=9739
        a=497
        b=1768
        curve = EC(n,a,b)


        X=PointEC(curve, 5274,2841) 
        Y=PointEC(curve, 8669,740)

        assert X + Y==PointEC(curve, 1024,4440) 
        assert X + X==PointEC(curve,7284,2107)
        P=PointEC(curve, 493,5564)
        Q=PointEC(curve, 1539,4742)
        R=PointEC(curve, 4403,5202)
        S = P + P + Q + R
        assert S.on_curve()
        return S

    def point_multiplication():
        # cryptohack example
        n=9739
        a=497
        b=1768
        curve = EC(n,a,b)
        
        X=PointEC(curve, 5323,5438)
        assert 1337 * X == PointEC(curve, 1089, 6931)
        P=PointEC(curve, 2339,2213)
        Q = 7863 * P
        assert Q.on_curve()
        return Q
    
    try:
        point_addition()
        point_multiplication()
    except AssertionError as e:
        _, _, tb = sys.exc_info()
        traceback.print_tb(tb) # Fixed format
        tb_info = traceback.extract_tb(tb)
        filename, line, func, text = tb_info[-1]

        print('An error occurred on line {} in statement {}'.format(line, text))
    
    print("Done testing!")

def test_baby_attack_int(num_bytes:int=6):
    p = number.getPrime(num_bytes*8)
    g = int.from_bytes(os.urandom(num_bytes))
    x = int.from_bytes(os.urandom(num_bytes))
    print(f"Initializing test: {g=} {x=} {p=}")
    
    a = pow(g, x, p)
    print(f"Trying to attack BSGS, {a=} ...")
    guessed_x = attack_baby_step_giant_step(g,a,p)
    if not guessed_x:
        print("Test failed! x not found!")
    else:
        assert a == pow(g,guessed_x,p)

def test_baby_attack_int(num_bytes:int=6):
    p = number.getPrime(num_bytes*8)
    g = int.from_bytes(os.urandom(min(num_bytes-2, 4)))
    x = int.from_bytes(os.urandom(num_bytes))
    print(f"Initializing test: {g=} {x=} {p=}")
    
    a = pow(g, x, p)
    print(f"Trying to attack BSGS, {a=} ...")
    guessed_x = attack_baby_step_giant_step(g,a,p)
    if not guessed_x:
        print("Test failed! x not found!")
    else:
        assert a == pow(g,guessed_x,p)
    
def test_baby_attack_ec(a:int,b:int ,num_bytes:int=6):
    p = number.getPrime((a+b).bit_length())
    curve = EC(p, a, b)
    j = None
    while(j is None):
        i = random.randint(0, p)
        j = tonelli_shanks(p, curve.right_term(i))
    G = PointEC(curve, i, j)  
    assert G.on_curve()
    
    x = int.from_bytes(os.urandom(num_bytes))
    print(f"Initializing test: {curve.func()} {p=} {G=}")
    A = x*G
    print(f"Trying to attack BSGS, {x=} {A=} ...")
    guessed_x = attack_baby_step_giant_step(G, A, p)
    
    if not guessed_x:
        print("Test failed! x not found!")
    else:
        assert A == guessed_x*G
    
def test_pohlig_hellman_int(num_bytes:int=6):
    p = number.getPrime(num_bytes*8)
    g = int.from_bytes(os.urandom(min(num_bytes-2, 4)))
    x = int.from_bytes(os.urandom(num_bytes))
    print(f"Initializing test: {g=} {x=} {p=}")
    
    a = pow(g, x, p)
    print(f"Trying to attack pohlig_hellman, {a=} ...")
    guessed_x = pohlig_hellman(g, a, p)
    # print(f"Found {x=}")
    assert a == pow(g, guessed_x, p)

def test_pohlig_hellman_ec(a:int,b:int,num_bytes:int=5):
    p = number.getPrime(num_bytes*8)
    curve = EC(p, a, b)
    
    j = None
    while(j is None):
        i = random.randint(0, p)
        j = tonelli_shanks(p, curve.right_term(i))
    print(f"{i=} {j=}")
    G = PointEC(curve, i, j)
    assert G.on_curve()
    
    x = int.from_bytes(os.urandom(num_bytes))
    print(f"Initializing test: {curve.func()} {p=} {G=}")
    A = x*G
    print(f"Trying to attack Pohllig-Hellman, {x=} {A=} ...")
    guessed_x = pohlig_hellman(G, A, p)
    
    if not guessed_x:
        print("Test failed! x not found!")
    else:
        assert A == guessed_x*G

if __name__ == "__main__":
    # Command-line interface:
    # - If --test is provided, run the built-in tests.
    # - Otherwise expect three integers: p g a and an optional algorithm name
    #   (alg can be 'bsgs' or 'ph' / 'pohlig' for Pohlig-Hellman).
    import argparse

    parser = argparse.ArgumentParser(description="Run BSGS or Pohlig-Hellman or tests")
    parser.add_argument("p", nargs="?", type=int, help="modulus or curve prime p (integer)")
    parser.add_argument("g", nargs="?", type=int, help="generator g (integer) or encoded PointEC not supported here")
    parser.add_argument("a", nargs="?", type=int, help="target a such that a = g^x (integer)")
    parser.add_argument("alg", nargs="?", default="bsgs", help="algorithm: bsgs (default) or ph (pohlig)")
    parser.add_argument("--test", action="store_true", help="run internal tests instead of CLI attack")

    args = parser.parse_args()

    if args.test:
        ec_tuple = (486662, 1)  # for passing convenience
        test_ec_class()
        # test_baby_attack_int(6)
        test_baby_attack_ec(*ec_tuple)
        # test_pohlig_hellman_int(6)
        test_pohlig_hellman_ec(*ec_tuple, 4)
    else:
        if args.p is None or args.g is None or args.a is None:
            parser.error("When not using --test you must provide p, g and a as integers\nList of available alg: pohlig-hellman, bsgs")
            
        p = int(args.p)
        g = int(args.g)
        a = int(args.a)
        alg = args.alg.lower()

        if alg in ("ph", "pohlig", "pohlig-hellman", "pohlig_hellman"):
            print("Running Pohlig-Hellman...")
            res = pohlig_hellman(g, a, p)
        else:
            # default to baby-step giant-step
            print("Running baby-step giant-step (BSGS)...")
            res = attack_baby_step_giant_step(g, a, p)

        print(f"Result: {res}")