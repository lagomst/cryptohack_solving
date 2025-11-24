from script.cryptohack.elliptic_curve import *


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

def ladder():
    a = 486662
    b = 1
    p = (1 << 255) - 19
    assert is_prime(p)
    curve = MontgomeryCurve(p, a, b)
    Gx = 9
    # Gy = tonelli_shanks(p, curve.right_term(Gx))
    G = PointMontegomery(curve, Gx)
    Q = 0x1337c0decafe * G
    return Q.get_affine_coordinate()

def smooth_criminal():
    # Define the curve
    p = 310717010502520989590157367261876774703
    a = 2
    b = 3

    curve = EC(p, a, b)
    
    # Generator
    g_x = 179210853392303317793440285562762725654
    g_y = 105268671499942631758568591033409611165
    G = PointEC(curve, g_x, g_y)
    assert G.on_curve()

    # Public key point: P = n*G
    public_x = 280810182131414898730378982766101210916
    public_y = 291506490768054478159835604632710368904
    P = PointEC(curve, public_x, public_y)
    assert P.on_curve()
    # Let's try attack it 
    curve_order = order(G, p)
    print( get_prime_factor(curve_order)) # Hey order constructed of multiple primes!
    # Time for pohlig-hellman!
    scalar = pohlig_hellman(G, P, p)
    assert scalar*G == P
    
    # Bob's public key
    b_x = 272640099140026426377756188075937988094
    b_y = 51062462309521034358726608268084433317
    B = PointEC(curve, b_x, b_y)
    
    # With shared_secret: S = n*B, we re-forge the keys
    shared_secret, _ = (scalar*B).get_affine_coordinate()
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    
    # Now that we get the key for AES, time to decrypt it
    iv = bytes.fromhex('07e2628b590095a5e332d397b8a59aa7')
    ciphertext = bytes.fromhex('8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af')
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
        
    return plaintext
    
def curveball():
    from fastecdsa.curve import P256
    

    def curveball_cli(data:dict):
        """
        Call the module's main() as if from command line.
        Pass argv as a list of tokens.
        """
        HOST = "socket.cryptohack.org"
        PORT = str(13382)

        argv = ["-H", HOST, "-P", PORT, "-d", json.dumps(data), "-o", "out_from_curveball.txt"]
        # sjc.main expects a list of argv tokens (or None to use sys.argv)
        return sjc.main(argv)
    
    # The problem can be broken down to find G, d
    # such that d*G = P with P is the public key of www.bing.com
    
    # since we have total control over G and d
    # and the server only check for d==1,
    # we can mask sending P by sending (curve_order+1)*P=P
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    curve = EC(p, a, b)
    
    Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    G = PointEC(curve, Gx, Gy)
    assert G.on_curve()
    
    # www.bing.com public key
    Px = 0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531
    Py = 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A
    P = PointEC(curve, Px, Py)
    
    curve_order = order(G, p)
    H = pow(P, curve_order+1, p)
    assert H == P
    Hx, Hy = H.get_affine_coordinate()
    
    data = {
        "private_key": curve_order+1,
        "host": "www.bing.com",
        "curve": "p256",
        "generator": (Hx, Hy)
    }

    curveball_cli(data)

def prosign3():
    host = "socket.cryptohack.org"
    port = 13381

    # Note on Challenge:
    # Private key and Public key are re-generated when socket is open (tube = remote(host, port))
    # So we must sign_time and verify in the same connection period

    # Signature review:
    # Given generator G on EC, modulo p
    # SIGNING input: z = hash(msg), pick a random k, 
    # (x, y)=kG
    # r = x mod p
    # s = k^-1 * (z+rd) mod p
    # VERIFYING input: public key Q, gen G, two var r, s
    # u1 = z*s^-1; u2 = r*s^-1
    # (x,y) = u1*G + u2*Q = k*G
    # verify by r mod p == x mod p
    
    from pwn import remote
    tube = remote(host, port)
    print(f"Fetching signature")
    print(f"Connecting to {host}:{port} ...")
    sjc.read_banner_lines(tube)
    
    sign_time_request = {
        "option": "sign_time"
    }
    
    sjc.json_send(tube, sign_time_request)
    response = sjc.json_recv(tube)
    print(f"Response received: {response}") # if it returns 'amazingly unlucky random number r', redo the process
    msg = response["msg"]
    r = response["r"]
    s = response["s"]
    
    print(f"Verifying signature")
    verify_request = {
        "option": "verify",
        "msg": msg,
        "r": r,
        "s": s
    }
    
    sjc.json_send(tube, verify_request)
    response = sjc.json_recv(tube)
    print(response)
    assert "result" in response and response["result"] == 'Message verified'
    
    # Now go read ecdsa implementation for singing and verifying (https://ecdsa.readthedocs.io/en/latest/_modules/ecdsa/ecdsa.html#)
    # Recall that: s = k^-1 * (z + d*r) modulo n
    # => z + d*r = s * k
    # => d = (s*k - z)*r^-1 modulo n
    # k can be brute forced, since r = Q.x where Q = kP is generated over k = randrange(1, n)
    # with n be the second of current time: n = int(now.strftime("%S")
    # So we need to guess for about k from 1 to 59 inclusive
    
    # challenge's hash function
    def sha1(data):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.digest()
    # p192 curve (https://neuromancer.sk/std/nist/P-192)
    p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    curve = EC(p,a,b)
    
    Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
    Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
    G = PointEC(curve, Gx, Gy)
    assert G.on_curve()
    curve_order = order(G, p)
    
    # Attack code
    s = int(s, 16)
    r = int(r, 16)
    z_msg = number.bytes_to_long(sha1(msg.encode()))
    
    unlock_msg = "unlock"
    z_unlock = number.bytes_to_long(sha1(unlock_msg.encode()))
    secret_scalars = []
    signatures = []
    for k in range(1, 60): # it should be somewhere around this range
        P = k*G
        Px, _ = P.get_affine_coordinate()
        r_new = Px % curve_order
        if r_new != r:
            continue
        
        scalar:int = ((s*k - z_msg)*pow(r,-1,curve_order))%curve_order
        secret_scalars.append(scalar)
        # Now we recalculate r and s based on z_unlock and scalar
        s_new = (pow(k,-1,curve_order) * (z_unlock + scalar * r_new)%curve_order )%curve_order
        signatures.append((r_new, s_new))
    assert len(signatures) > 0
    # Let's brute force
    for sig in signatures:
        sig_r, sig_s = sig
        verify_request = {
            "option": "verify",
            "msg": unlock_msg,
            "r": hex(sig_r),
            "s": hex(sig_s)
        }
        sjc.json_send(tube, verify_request)
        response = sjc.json_recv(tube)
        
        print(f"Signature {sig_r=} {sig_s=} response: ")
        print(response)
        if "flag" in response:
            print("Flag found!")
            tube.close()
            return response["flag"]
        # Avoid overloading request
        time.sleep(0.75)
    
    tube.close()
    return "Flag not found!"

def baitapthay():
    p = 81663996540811672901764249733343363790991183353803305739092974199965546219729
    a = 1
    b = 7
    G = (14023374736200111073976017545954000619736741127496973904317708826835398305431, 23173384182409394365116200040829680541979866476670477159886520495530923549144)
    P = (45277951688968912485631557795066607843633896482130484276521452596515645125170, 33416418291776817124002088109454937261688060362650609033690500364258401702752)
    ciphertext = '44af53c95092c86c04b67358aad3911282347862fec02f8943ea2eb5297780a7098faef27b2d2dbab7cf29bec5e32adcc7be6f4b57370aa2b6f6d1eafc5c3f3a07db1162d00b0037b757450b6fd405e0'
    iv = '29d6bba244e66a562969a6dae8e61449'
    
    curve = EC(p,a,b)
    G = PointEC(curve, *G)
    P = PointEC(curve, *P)
    assert G.on_curve()
    assert P.on_curve()
    n = order(G, p)
    primes_factor = get_prime_factor(n)
    
    
    # Here the last factor is pretty big (10^64), while other factors are small (<10^6)
    # Therefore, we can smartly attack this by dividing it by the big factor
    # And attack the small subgroup of smaller order
    biggest_prime = max(primes_factor.keys())
    subgroup_order = 1
    for prime, exp in primes_factor.items():
        if prime != biggest_prime:
            subgroup_order *= pow(prime,exp)
    
    
    small_order_G = G * subgroup_order
    small_order_P = P * subgroup_order
    x = attack_baby_step_giant_step(small_order_G, small_order_P, p, known_order=subgroup_order)
    if not x:
        return None
    # Now that we found x such that small_order_G * x = small_order_P
    # Recall that x = key (mod subgroup_order)
    # while key lie somehere in order n
    
    assert x * small_order_G == small_order_P
    assert x * G == P
    return x

def moving_problems():
    p = 1331169830894825846283645180581
    a = -35
    b = 98
    curve = EllipticCurve(GF(p), [a, b])
    original_order = int(curve.order())
    
    
    Gxyz = (479691812266187139164535778017 , 568535594075310466177352868412)
    G = curve(Gxyz)
    
    # Alice public key
    Axyz = (1110072782478160369250829345256 , 800079550745409318906383650948)
    A = curve(Axyz)
    
    # The order is kinda smooth, with the biggest prime at around 10^16, so we can do pohlig-hellman 
    # Optimizing baby step giant step with cache and parallel is recommended
    
    # However, there's a faster method: go read Supersingular curve (https://github.com/elikaski/ECC_Attacks?tab=readme-ov-file#The-curve-is-supersingular)
    
    k = mult_order(original_order, p)
    print(f"Embedding degree: {k=}")
    kembed_curve = curve.base_extend(GF(p ** k))
    kembed_G = kembed_curve(Gxyz)
    kembed_A = kembed_curve(Axyz)
    
    print("Picking a random point.")
    kembed_R = kembed_curve.random_point()
    R_order = int(kembed_R.order())
    T_order = gcd_euclid(R_order, original_order)
    kembed_T = (R_order // T_order) * kembed_R
    
    print(f"{kembed_R=} order={R_order}")
    print(f"{kembed_T=} order={T_order}")
    
    assert kembed_T.order() == T_order
    assert (original_order*kembed_T).is_zero()

    print("Find Tate pairing")
    g = kembed_G.tate_pairing(kembed_T, original_order, k)
    p = kembed_A.tate_pairing(kembed_T, original_order, k)
    print(f"{g=} {p=}")
    
    print("Solving g^n = p (mod p^k)")
    alice_key = p.log(g)
    assert alice_key * G == A
    print("Found Alice's private key: ", alice_key)
    
    def sha1(shared_secret):
        sha1 = hashlib.sha1()
        sha1.update(str(shared_secret).encode('ascii'))
        return sha1.digest()[:16]
    
    # Bob Public key: 
    Bxy = (1290982289093010194550717223760, 762857612860564354370535420319)
    B = curve(Bxy)
    
    shared_secret = alice_key * B
    shared_secret = shared_secret.xy()[0] # Get x of affine coordinate
    
    # Decrypting flag 
    encrypt = {'iv': 'eac58c26203c04f68d63dc2c58d79aca', 'encrypted_flag': 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'}
    iv = bytes.fromhex(encrypt['iv'])
    ciphertext = bytes.fromhex(encrypt['encrypted_flag'])
    
    key = sha1(shared_secret)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext



    

def main():
    print("Usage: python -c 'from solution.ec import *; print(<function>())'")
    
if __name__ == "__main__":
    main()