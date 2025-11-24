import base64
import math
import random
from pprint import pprint

def naive_order(p:int, a: int):
    temp = 1
    for exp in range(1, p):
        temp = (temp * a) % p
        if temp == 1:
            return exp
    raise ValueError("Found no order for a!")
    return -1

def mult_order(p : int, a: int):
    factors =  get_prime_factor(p - 1)
    g = a
    e = p - 1
    for prime, prime_exp in factors.items():
        e //= pow(prime, prime_exp)
        g  = pow(a, e, p)      
        while(g != 1):
            g = pow(g, prime, p)
            e = (e * prime)
    return e
    return pow(p, 2*p - 2, p)
        

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
    # print(f"{a=} {b=}")
    if a==1:
        return a
    
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
            raise ValueError("a and b might not have inverse modulo!")
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
    

def inverse_modulo(a: int, b: int):
    # Find a*x + b*y = 1
    # Also mean b % (a*x) = 1 
    common_divisor = gcd_euclid(a, b)
    j = a // common_divisor
    k = b // common_divisor
    return extended_euclid_prime(j , k)
    

def xor_two_bytes(a: bytes, b: bytes):
    a_len = len(a)
    b_len = len(b)
    output = bytearray()
    for i in range(max(a_len, b_len)):
        a_byte = a[i] if i < a_len else 0
        b_byte = b[i] if i < b_len else 0
        result = a_byte ^ b_byte
        output.extend(result.to_bytes())
    return output


def xor_final_byte_a_with_single_byte_b(a: bytes, b: bytes):
    a_len = len(a)
    b_len = len(b)
    if b_len != 1:
        raise ValueError("b should be a single bytes")
    output = a
    output[-1] = output[-1] ^ b[0]
    return output 

def xor_every_bytes_with_b(a: bytes, b: bytes):
    a_len = len(a)
    b_len = len(b)
    output = bytearray()
    for i in range(a_len):
        a_byte = a[i] 
        b_byte = b[i % b_len]
        result = a_byte ^ b_byte
        output.extend(result.to_bytes())
    return output

def xor_with_number(input: str, number: int):
    result = ""
    for char in input:
        output_bytes = xor_two_bytes(char.encode("utf-8"), number.to_bytes())
        result += output_bytes.decode()
    return result
        

def big_num_to_msg(big_num: int) -> str:
    hex_numb = hex(big_num).split("0x")[1]
    hex_bytes = bytes.fromhex(hex_numb).decode()
    return hex_bytes

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
# if sqrt(n) exists, for p%4=3
# sqrt(n) = n^( (p+1)/4 )
def sqrt_residue_three_mod_four(n:int, p:int):
    if p % 4 != 3:
        raise ValueError("Invalid input! p+1 must be divisiable by 4")
    n %= p

    x = pow(n, (p+1)//4, p) # +sqrt
    if pow(x, 2, p) == n:
        return x
    
    x = p - x # -sqrt
    if pow(x, 2, p) == n:
        return x
    
    return None

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
    if t == 0:
        return 0
    r = pow(n, (q+1)//2, p)
    while t != 1:
        step = 1
        temp = pow(t, 2, p)
        while temp != 1:
            temp = pow(temp, 2, p)
            step += 1
            if step == m:
                return None
        b_pow = 1 << (m - step - 1)
        b = pow(c, b_pow, p)
        m = step
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return r

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
                factor = pollard_rho_factor(temp)
            if not factor:
                pprint("Retrying the function...!")
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

def decrypt(p: int, a: int, keys: list[int]):
    a_order = mult_order(p, a)
    binary_str: str = ""
    # The crux of the question is whether to tell 
    # an integer c is corruguent with either
    # a^e or -a^e
    for i in keys:
        temp = pow(i, a_order, p)
        # If c corruguent with a^e => c^k corruguent with a^ek = 1
        # with k as order of a ie how many power k until a^k stops at 1
        # If we test for -a^e, check (-c^k) == 1
        if temp == 1:
            binary_str += "1"
        elif temp == p-1:
            binary_str += "0"
        else:
            raise ValueError(f"This key does not compute to +- 1! {i^a_order=}")
    return binary_str

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

def is_prime_miller_rabin(n, rounds:int=500):
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
    # Hybrid approach with some deterministic bases for number < 2^64 bits
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 44] 
    num_bases_to_generate = rounds - len(bases)
    for _ in range(num_bases_to_generate):
        # Append random bases into base
        random_base = random.randint(2, n-2)
        if random_base not in bases:
            bases.append(random_base)
    
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

def is_prime(n: int):
    if n > 360_000_000_000:
        return is_prime_miller_rabin(n)
    return is_prime_naive(n)

def pollard_rho_factor(n :int):    
    b = random.randint(2, n-2)
    print("Pollard Rho algo!")
    print(f"{n=}\t{b=}")
    
    def g(a: int):
        return (a * a + b) % n
            
    d = 1
    steps = 100
    max_outer_loop = 1_000_000
    found_d = False
    
    last_x = x = random.randint(2, n-2)
    last_y = y = x
    
    for loop in range(max_outer_loop):
        if (d != 1):
            found_d = True
            break
        product = 1
        steps_failed = False
        
        for i in range(steps):
            x = g(x) # turtle
            y = g(g(y)) # hare
            if x == y:
                # Algo failed, fall back to step = 1
                print(f"Multiple step failed at {i}! Reverting to step 1!")
                steps_failed = True
                break
            product = (product * abs(x - y)) % n
        
        # Termination condition
        if steps_failed and steps == 1:
            print("x and y converge!")
            return None
        
        # Set step to 1
        if steps != 1 and (steps_failed or loop >= max_outer_loop // 2):
            print("Setting steps to 1...")
            steps = 1
            x = last_x
            y = last_y
            continue

        last_x = x
        last_y = y
        
        d = gcd_euclid(product, n)
    
    if d == n:
        print("d meets n!")
        return None
    if not found_d:
        print("Maximum global step reached!")
        return None
    print(f"Found {d=}")
    return d

def brent(f, x0) -> tuple[int, int]:
    """Brent's cycle detection algorithm."""
    # main phase: search successive powers of two
    power = lam = 1
    tortoise = x0
    hare = f(x0)  # f(x0) is the element/node next to x0.
    # this assumes there is a cycle; otherwise this loop won't terminate
    while tortoise != hare:
        if power == lam:  # time to start a new power of two?
            tortoise = hare
            power *= 2
            lam = 0
        hare = f(hare)
        lam += 1

    # Find the position of the first repetition of length λ
    tortoise = hare = x0
    for i in range(lam):
        hare = f(hare)
    # The distance between the hare and tortoise is now λ.

    # Next, the hare and tortoise move at same speed until they agree
    mu = 0
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(hare)
        mu += 1
 
    return lam, mu

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    bytes = bytearray()
    for col in matrix:
        for ele in col:
            bytes.append(ele)
    
    return bytes

def binomial_solver(N:int, e1:int, e2:int, c1:int, c2:int, c1_weights:tuple[int,int], c2_weights:tuple[int,int]):
    # Solving two equation of the form:
    # c1 = (a1*p + b1*q)^e1 = (a1*p)^e1 + (b1*q)^e1 (mod N=p*q)
    # c2 = (a2*p + b2*q)^e2 = (a2*p)^e2 + (b2*q)^e2 (mod N=p*q)
    
    # First raise them to the same power
    c1_pow_e2 = pow(c1, e2, N) # c1 = (a1*p)^e12 + (b1*q)^e12 (e12 = e1 * e2)
    c2_pow_e1 = pow(c2, e1, N)
    
    # We want to isolate q, ie figure how to cancel p
    # So we need to make p of two equations have the same weight
    a1, b1 = c1_weights
    a2, b2 = c2_weights
    L1 = (c1_pow_e2 * pow(a1, -e1*e2, N) )%N # c1 = p^e12 + Const1 * q^e12 
    L2 = (c2_pow_e1 * pow(a2, -e1*e2, N) )%N # c2 = p^e12 + Const2 * q^e12

    Q = (L2 - L1)%N # Q = (Const2 - Const1) * q^e12
    # Const1 = a1^-e12 * b1^e12, Const2 = a2^e-12 * b2^e12
    const1 = (pow(a1, -e1*e2, N) * pow(b1, e1*e2, N))%N
    const2 = (pow(a2, -e1*e2, N) * pow(b2, e1*e2, N))%N
    X = (Q * pow(const2-const1, -1, N))%N # X = q^e12
    # X here is a multiple of q, N is also a multiple of q (N = pq)
    # AND p and q are primes
    # so gcd(X, N) = q (since N only has q^1, we can ensure that the output will always be q^1) 
    q = gcd_euclid(N, X)
    assert N % q == 0 and q != 1
    p = N // q
    return p, q

def main():
    N  = 14905562257842714057932724129575002825405393502650869767115942606408600343380327866258982402447992564988466588305174271674657844352454543958847568190372446723549627752274442789184236490768272313187410077124234699854724907039770193680822495470532218905083459730998003622926152590597710213127952141056029516116785229504645179830037937222022291571738973603920664929150436463632305664687903244972880062028301085749434688159905768052041207513149370212313943117665914802379158613359049957688563885391972151218676545972118494969247440489763431359679770422939441710783575668679693678435669541781490217731619224470152467768073
    e1 = 12886657667389660800780796462970504910193928992888518978200029826975978624718627799215564700096007849924866627154987365059524315097631111242449314835868137
    e2 = 12110586673991788415780355139635579057920926864887110308343229256046868242179445444897790171351302575188607117081580121488253540215781625598048021161675697
    c1 = 14010729418703228234352465883041270611113735889838753433295478495763409056136734155612156934673988344882629541204985909650433819205298939877837314145082403528055884752079219150739849992921393509593620449489882380176216648401057401569934043087087362272303101549800941212057354903559653373299153430753882035233354304783275982332995766778499425529570008008029401325668301144188970480975565215953953985078281395545902102245755862663621187438677596628109967066418993851632543137353041712721919291521767262678140115188735994447949166616101182806820741928292882642234238450207472914232596747755261325098225968268926580993051
    c2 = 14386997138637978860748278986945098648507142864584111124202580365103793165811666987664851210230009375267398957979494066880296418013345006977654742303441030008490816239306394492168516278328851513359596253775965916326353050138738183351643338294802012193721879700283088378587949921991198231956871429805847767716137817313612304833733918657887480468724409753522369325138502059408241232155633806496752350562284794715321835226991147547651155287812485862794935695241612676255374480132722940682140395725089329445356434489384831036205387293760789976615210310436732813848937666608611803196199865435145094486231635966885932646519
    
    c1_weights = (2, 3)
    c2_weights = (5, 7)
    
    return binomial_solver(N, e1, e2, c1, c2, c1_weights, c2_weights)

if __name__ == "__main__":
    pprint(main())
    