from my_modulo import extended_euclid_prime, sqrt_residue_three_mod_four, factor_out_two_powers, get_prime_factor, mult_order, is_prime, gcd_euclid
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from os import urandom
import math

def point_negation():
    n=9739
    a=497
    b=1768
    def y_squared(x):
        return (x**3 + b*x + a ) % n
    def negative(x):
        return (-x)%n
    x=8045
    y=6936
    # the line from P and -P never cut through esclipe again
    return negative(y)

class NumberOnFiniteField:
    def __init__(self, value, modulo):
        self.modulo = modulo
        self.value = value % modulo
        
    def __eq__(self, o):
        return self.value == o.value
    
    def __add__(self, o):
        return (self.value + o.value) % self.modulo
    
    def __sub__(self, o):
        return (self.value - o.value) % self.modulo
    
    def __mul__(self, o):
        return (self.value * o.value) % self.modulo
    
    

class EC:
    # Elliptic curve funciton class, 
    # represnteded as y^2 = x^3 + ax + b 
    def __init__(self, n: int, a: int, b: int):
        self.n = n
        self.a = a
        self.b = b

    def __eq__(self, value):
        return self.func == value.func
    
    def func(self) -> str:
        return f"y^2=x^3+{self.a}*x+{self.b}"
    
    def negative(self, a: int) -> int:
        return (self.n - a) % self.n

    def inverse_modulo(self, a: int) -> int:
        return pow(a, -1, self.n)
    
    def left_term(self, y:int):
        return (y*y)%self.n
    
    def right_term(self, x:int):
        return (x*x*x + self.a*x + self.b)%self.n
    
    def xAdd(self, XP_tuple: tuple[int,int], XQ_tuple: tuple[int,int], XMinus_tuple: tuple[int,int]):
        # expected op time: 3add + 3sub + 6mul
        xP, zP = XP_tuple[0], XP_tuple[1]
        xQ, zQ = XQ_tuple[0], XQ_tuple[1]
        xSub, zSub = XMinus_tuple[0], XMinus_tuple[1]
        n = self.n
        v0 = (xP + zP)%n # 1add
        v1 = (xQ - zQ)%n # 1sub
        v1 = (v1 * v0)%n # 1mul; v1 = (xP + zP)(xQ - zQ)
        v0 = (xP - zP)%n # 1sub
        v2 = (xQ + zQ)%n 
        v2 = (v2 * v0)%n # v2 = (xP - zP)(xQ + zQ)
        v3 = ((v1 + v2) ** 2)%n
        v4 = ((v1 - v2) ** 2)%n
        xAdd = (zSub * v3)%n
        zAdd = (xSub * v4)%n
        return (xAdd, zAdd)

    def xDBL(self, XP_tuple: tuple[int,int]):
        # 4add + 1sub + 5mul + 1 inverse_modulo 
        xP, zP = XP_tuple[0], XP_tuple[1]
        n = self.n
        v1 = ((xP + zP)**2)%n
        v2 = ((xP - zP)**2)%n
        xDouble = (v1 * v2)%n
        v1 = (v1 - v2)%n # 4*xP*zP
        a24 = ((self.a + 2) * self.inverse_modulo(4)) % n
        v3 = ( a24 *v1)%n # a24 * 4*xP*zP 
        v3 = (v3 + v2)%n # (xP - zP)^2 + a24 * 4*xP*zP = term
        zDouble = (v1 * v3)%n # 4*xP*zP * term
        return (xDouble, zDouble)

    def swap_constant_time(self, b: int, x0: tuple[int,int], x1: tuple[int,int]):
        # expected: 8 bitwise
        one_mask = (1 << self.n.bit_length()) - 1 
        mask = -b & one_mask
        # print(mask, bin(mask))
        x0X, x0Z = x0
        x1X, x1Z = x1
        tX = mask & (x0X ^ x1X)
        tZ = mask & (x0Z ^ x1Z)
        return (x0X ^ tX, x0Z ^ tZ), (x1X ^ tX, x1Z ^ tZ)

    def uniform_montgomery_ladder(self, k:int, XP:int):
        # TODO: implement constant time montgomery ladder
        xP, zP= XP, 1
        x0, x1 = self.xDBL((xP, zP)), (xP, zP)
        print(f"My Ladder init: {x0=} {x1=}")
        length = k.bit_length()
        if length == 0:
            return 0
        for i in range(length-2, -1, -1):
            
            ki = (k >> i) & 1
            ki1 = (k >> (i+1)) & 1 # get i+1-th bit
            
            x0, x1 = self.swap_constant_time(ki ^ ki1, x0, x1)
            x1 = self.xAdd(x0, x1, (xP, zP))
            x0 = self.xDBL(x0)
            print(f"My Ladder step {i}: {x0=} {x1=}")
            # x1 = self.xAdd(x0, x1, (xP, zP))
            # here x0 - x1 always equals to XP
        
        k_zero = k & 1
        x0, x1 = self.swap_constant_time(k_zero, x0, x1)  
        X, Z = x0
        print(f"My Ladder Final value; {X=} {Z=} {k=} {self.n=}")
        x_affine = (X * self.inverse_modulo(Z) ) % self.n
        print(f"{x_affine=}")
        return x_affine  
    
    def order(self):
        n = self.n
        lower_bound = n + 1 - 2 * math.ceil(math.sqrt(n))
        upper_bound = n + 1 + 2 * math.floor(math.sqrt(n))
        return lower_bound, upper_bound, upper_bound - lower_bound

def get_bit_length(n:int):
    length = 0
    while (n >= 1):
        n >>= 1
        length += 1
    return length

class PointEC:
    def __init__(self, curve: EC, x: int, y: int):
        self.curve = curve
        self.x = x % curve.n
        self.y = y % curve.n

    def on_curve(self) -> bool:
        a, b, n = self.curve.a, self.curve.b, self.curve.n
        return (self.y ** 2 - (self.x ** 3 + a * self.x + b)) % n == 0
    
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplemented("unsupported operand type(s) for ==: '{}' and '{}'").format(self.__class__, type(other))
        if self.curve != other.curve:
            raise ValueError("Comparing two points belonging to different curve contexts")
        return self.x == other.x and self.y == other.y

    
    # Overloading add operators (+) helps us type A + B much easier
    # Note: "O" is represented as None
    def __add__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplemented("unsupported operand type(s): '{}' and '{}'").format(self.__class__, type(other))
        if self.curve != other.curve:
            raise ValueError("Performing operator on two points belonging to different curve contexts")
        
        curve = self.curve
        if other is None:
            return self
        if self.x == other.x and self.y == curve.negative(other.y):
            return None

        if self == other:
            num = (3 * pow(self.x, 2, curve.n) + curve.a) % curve.n # tu
            den = (2 * self.y) % curve.n # mau
        else:
            num = (other.y - self.y) % curve.n
            den = (other.x - self.x) % curve.n

        lamb = (num * curve.inverse_modulo(den)) % curve.n # num/den
        x3 = (pow(lamb, 2, curve.n) - self.x - other.x) % curve.n
        y3 = (lamb * (self.x - x3) - self.y) % curve.n
        
        return PointEC(curve, x3, y3)
    
    def __radd__(self, other):
        # Handles reversed addition, e.g., sum() or None + Point
        if other is None:
            return self
        return self.__add__(other)
    
    def __iadd__(self, other):
        return self + other
    
    def __mul__(self, n:int):
        if not isinstance(n, int):
            raise ValueError("Multiplication only works for a PointEC and a integer")
        if (n == 0):
            return None
        if (n < 0):
            return -self * n
        
        q = PointEC(self.curve, self.x, self.y)
        r = None
        while n > 0:
            if n%2 == 1:
                r = r + q
            q += q
            n //= 2
        # print(f"PointEC mul = {r}")
        return r
    
    def __imul__(self, n:int):
        return self * n

    def __rmul__(self, n:int):
        return self * n
    
    def __sub__(self, other):
        if other is None:
            return self
        if self.x == other.x and self.y == other.y:
            return None
        curve = self.curve
        negative_other = PointEC(curve, other.x, curve.negative(other.y))
        return self + negative_other
    
    def __isub__(self, other):
        return self - other
    
    def __rsub__(self,other):
        if other is None:
            return self
        return other - self
    
    def __pow__(self, other:int, modulo:int=None):
        if modulo and modulo != self.curve.n:
            raise ValueError("Modulo does not match with interal curve's modulo")
        return self * other
    
    def __str__(self):
        t = (self.x, self.y)
        return str(t)
    
    def get_coordinate(self):
        return self.x, self.y
    
    def mul_montgomery_ladder(self, k:int):
        length = k.bit_length()
        r0, r1 = PointEC(self.curve, self.x, self.y), 2 * PointEC(self.curve, self.x, self.y)
        print(f"Original Ladder init: r0={(r0.x, r0.y)} r1={(r1.x, r1.y)}")
        for i in range(length-2, -1, -1):
            ki = (k >> i) & 1 # get k-th bit
            if not ki:
                r0, r1 = 2 * r0, r0 + r1
            else:
                r0, r1 = r0 + r1, 2 * r1
            assert r1 == r0 + self
            # print(f"Original Ladder step {i}: r0={(r0.x, r0.y)} r1={(r1.x, r1.y)}")
        print(f"{r0.x=} {r1.x=}")
        return r0

def point_addition():
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

def curves_and_log():
    n=9739
    a=497
    b=1768
    curve = EC(n,a,b)
    
    g=PointEC(curve, 1804,5368)
    
    # Our (Bob's) private key
    nB = 1829
    qB = nB * g
    
    # Alice sent us qA
    qA=PointEC(curve, 815,3190)
    
    shared_secret = nB * qA # shared_secret = nA * nB * g    
    print(shared_secret)
    x_as_str_encoded = str(shared_secret.x).encode()
    final_hash = hashlib.sha1(x_as_str_encoded)
    return final_hash.hexdigest()
    
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
    
def efficient_exchange():
    n=9739
    a=497
    b=1768
    curve = EC(n,a,b)

    g=PointEC(curve, 1804,5368)
    
    iv = 'cd9da9f1c60925922377ea952afc212c'
    encrypted_flag = 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'
    # Looking at the equation,
    # one can easily see that there are only two possible y
    # y1 = sqrt(...) and y2 = -sqrt(...)
    # so we only need to send the sign bit to know which y we have used
    
    nB=6534
    qB = nB * g
    
    qA_x = 4726
    y_squared = curve.right_term(qA_x)
    
    
    
    qA_y = pow(y_squared, (curve.n+1)//4, curve.n) # fast sqrt due to n % 4 = 3
    
    print(f"{qA_x=} {qA_y=} {y_squared=}")
    assert qA_y is not None
    assert curve.left_term(qA_y) == curve.right_term(qA_x)
    
    qA = PointEC(curve, qA_x, qA_y)
    shared_secret = nB * qA
    # passing x to shared secret
    return decrypt_flag(shared_secret.x, iv, encrypted_flag)


class MontegomeryCurve(EC):
    # By^2 = x(x^2 + Ax + 1)
    def left_term(self, y):
        return self.b * pow(y, 2)
    def right_term(self, x):
        return x * (x*x + self.a*x + 1)

        

def montgomery_ladder():
    n=(1 << 255) - 19
    a=486662
    b=1
    curve = EC(n,a,b)
    
    # Testing your own montgomery ladder implementation:
    X=PointEC(curve, 5323,5438)
    target = PointEC(curve, 1089, 6931) 
    k = 1337
    assert (k * X)  == X.mul_montgomery_ladder(k)
    # assert 1089 == curve.uniform_montgomery_ladder(1337, X.x)
    const = 0x1337c0decafe
    return X.mul_montgomery_ladder(const)
    


    
def attack_baby_step_giant_step(g:int, a:int, p:int):
    m = math.ceil(math.sqrt(p -1))
    gj_table: dict[int, list[int]] = {}
    for j in range(m):
        gj = pow(g, j, p)
        if gj in gj_table:
            gj_table[gj].append(j)
        else:
            gj_table[gj] = [j]
    g_m_neg = pow(g, -m, p) 
    gamma = a # a * (g^-m)^i, i currently i=0
    for i in range(m):
        if gamma in gj_table:
            j = gj_table[gamma][0]
            return i + m*j
        gamma *= g_m_neg
        gamma %= p
    
    return None

def attack_baby_step_giant_step_EC(G:PointEC, P:PointEC, p:int):
    m:int = math.ceil(math.sqrt(p -1))
    gj_table: dict[tuple[int,int], list[int]] = {}
    # xG = P
    # => (j + im)G = P
    # => jG = P - imG
    # => jG = P - i * gamma
    print(f"Constructing lookup table jG {m=} ...")
    log_step = max(1, m//10) # after log_step steps, print out the progess
    for j in range(1, m):
        gj = (j * G).get_coordinate() # operators +, * returns a PointEC object
        if gj in gj_table:
            gj_table[gj].append(j)
        else:
            gj_table[gj] = [j]
        if (j % log_step == 0):
            print(f"Progress: {i / m * 100:.0f}% ({i}/{m})")
    print(f"Lookup table JG constructed, length={len(gj_table)}")
    mG_const = m*G # constant
    gamma = 0 # gamma = imG, i currently i=0
    for i in range(m):
        rhs = (P - gamma).get_coordinate()
        print(f"Checking if {rhs=} is in table...")
        if rhs in gj_table:
            j = gj_table[rhs][0]
            print(f"Found matching {j=} {rhs=}")
            return i + m*j
        gamma += mG_const
    
    return None

def extra_excercises():
    a = 1
    b = 7
    p = 81663996540811672901764249733343363790991183353803305739092974199965546219729
    G_coordinates = (14023374736200111073976017545954000619736741127496973904317708826835398305431, 23173384182409394365116200040829680541979866476670477159886520495530923549144)
    P_coordinates = (45277951688968912485631557795066607843633896482130484276521452596515645125170, 33416418291776817124002088109454937261688060362650609033690500364258401702752)
    ciphertext = '44af53c95092c86c04b67358aad3911282347862fec02f8943ea2eb5297780a7098faef27b2d2dbab7cf29bec5e32adcc7be6f4b57370aa2b6f6d1eafc5c3f3a07db1162d00b0037b757450b6fd405e0'
    iv = '29d6bba244e66a562969a6dae8e61449'
    
    Ellipsis
    curve = EC(p, a, b)
    G = PointEC(curve, G_coordinates[0], G_coordinates[1])
    P = PointEC(curve, P_coordinates[0], P_coordinates[1])
    
    print(G.on_curve())
    print(P.on_curve())
    # After fooling around a bit with p, I discover two things:
    # 1. p is big as hell, constructing lookup table of sqrt(p-1) length is a chore
    # 2. p can be factorizable, albeit with a certain probability.
    
    return get_prime_factor(43623929776074611592822782977213335358435461193270996655498383653827749049-1)

def schoof_algorithm(curve:EC, p:int):
    # assume p is prime
    # assert is_prime(p)
    N = 4 * math.ceil(math.sqrt(p))
    # Let's try to factorize it
    l_factors = get_prime_factor(N)
    # Find t mod l
    
    

def main():
    return montgomery_ladder()

if __name__ == "__main__":
    print(main())