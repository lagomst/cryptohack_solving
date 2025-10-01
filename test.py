import base64
import math
import random
from primePy import primes
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
    pprint(q_list)
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

def fast_log_2(n : int):
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
    q, s = fast_log_2(p-1)
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
        # Check if prime is 
        if is_prime(temp):
            n_factors[temp] = 1
            break
        while (True):
            if temp < (2 << 32):
                factor = smallest_prime_factor(temp)
            else:
                factor = polland_factor(temp)
            if not factor:
                pprint("Retrying the function...!")
            else:
                break
        exp = 0
        while(temp > 1 and temp % factor == 0):
            temp //= factor
            exp += 1
        if is_prime(factor):
            n_factors[factor] = exp
        else:
            factor_primes = get_prime_factor(factor)
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

def is_prime_miller_robin(n):
    if n % 2 == 0:
        return False
    temp = n -1
    s = 0
    while (temp > 1 and temp % 2 == 0):
        temp = temp // 2
        s += 1
    d = temp
    
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 44]
    for base in bases:
        if pow(base, d, n) == 1:
            return True
        for r in range(s):
            if pow(base, (1 << r) * d, n) == -1:
                return True
    return False

def is_prime(n: int):
    if n > 360_000_000_000:
        return is_prime_miller_robin(n)
    return is_prime_naive(n)

def polland_factor(n :int):    
    last_x = x = 2
    last_y = y = x
    d = 1
    
    b = random.randint(1, n-2)
    pprint(f"Polland Rho algo! {b=}")
    def g(a: int):
        return (a * a + b) % n
    
    steps = 100
    while (d == 1):
        product = 1
        steps_failed = False
        for i in range(steps):
            x = g(x) # turtle
            y = g(g(y)) # hare
            if x == y:
                # Algo failed, fall back to step = 1
                pprint(f"Multiple step failed at {i}! Reverting to step 1!")
                steps_failed = True
                break
            product = (product * abs(x - y)) % n
        
        if steps_failed:
            if steps == 1:
                pprint("x and y converge!")
                return None
            steps = 1
            x = last_x
            y = last_y
            continue
        
        last_x = x
        last_y = y
        
        d = gcd_euclid(product, n)
    
    if d == n:
        pprint("d meets n!")
        return None
    pprint(f"Found {d=}")
    return d

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

def add_round_key(s, k):
    matrix = []
    for i in range(len(s)):
        row = []
        for j in range(len(s[i])):
            row.append(s[i][j] ^ k[i][j])
        matrix.append(row)
    return matrix

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
]


def sub_bytes(s, sbox=s_box):
    matrix = []
    for row in s:
        r = []
        for ele in row:
            r.append(sbox[ele])
        matrix.append(r)
    return matrix
        
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(len(s)):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

N_ROUNDS = 10

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


def decrypt_aes(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    # if isinstance(ciphertext, bytes):
    #     b = ciphertext
    # else:
    #     b = bytearray(ciphertext)
    state = bytes2matrix(ciphertext)
    
    # Initial add round key step
    state = add_round_key(state, round_keys[N_ROUNDS])
    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        state = sub_bytes(state, inv_s_box)
        state = add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Run final round (skips the InvMixColumns step)
    inv_shift_rows(state)
    state = sub_bytes(state, inv_s_box)
    state = add_round_key(state, round_keys[0])
    # Convert state matrix to plaintext
    final_bytes = matrix2bytes(state)

    return final_bytes.decode()

def main():
    hex_str = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
    hex_bytes = bytes.fromhex(hex_str)
    key = base64.b64encode(hex_bytes)
    print(key)

if __name__ == "__main__":

    key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
    ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'
    
    print(decrypt_aes(key, ciphertext))
    