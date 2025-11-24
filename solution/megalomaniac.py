from script.cryptohack.symmetry import *
from script.cryptohack.elliptic_curve import *
import primefac
import utils.socket_json_client as sjc
from sage.all import discrete_log, GF
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

def send(r, req:dict):
    try:
        sjc.json_send(r, req)
    except Exception as e:
        return f"Error: {e}"
    return "Ok"

def recv(r):
    while(True):
        s = r.recvline()
        assert isinstance(s, bytes)
        print(s)
        
        s = s.decode()
        dict_start_idx = s.find('{')
        if dict_start_idx != -1:
            break
        
    response = eval(s[s.find('{'):])
    assert isinstance(response, dict)
    return response

def format_rsa_privkey(share_key):
    data = b""
    data += format_number(share_key.p)
    data += format_number(share_key.q)
    data += format_number(share_key.d)
    data += format_number(share_key.u)
    return pad(data, 16)

def format_number(num):
    num_bytes = long_to_bytes(num)
    return long_to_bytes(len(num_bytes), 2) + num_bytes

def RSA_CRT_decrypt(ciphertext, p, q, d, u):
    # p, q, d, u is parsed from share_key = decrypt(share_key_enc)
    # Decryption is in ECB mode, and each of the variables is within a block
    # so we can modify ciphertext and encrypt(p + q + d + u)
    
    ct = bytes_to_long(ciphertext)
    dp = d % (p - 1)
    dq = d % (q - 1)
    mp = pow(ct, dp, p)
    mq = pow(ct, dq, q)
    t = (mq - mp) % q
    h = (t * u) % q # here we change u to another value, so that
    # u != p^-1 mod q, to set up the oracle below 
    m = h * p + mp # Here there's two cases
    # 1. m < p, meaning mp == m, => t = (mp - m)%p = 0 => return mp
    # 2. m >= p, except for 1 case, mp will be very large and raise an error  
    return long_to_bytes(m)

def parse_rsa_privkey(share_key):
    index = 0
    elements = []
    while index < len(share_key):
        length = bytes_to_long(share_key[index:index + 2])
        index += 2
        elements.append(bytes_to_long(share_key[index:index + length]))
        index += length
    assert len(elements) == 4
    return elements

def share_key_recovery():
    host = "socket.cryptohack.org"
    port = 13408
    
    tube = sjc.remote(host, str(port))
    print(f"Connecting to {host}:{port} ...")
    
    resp = recv(tube)
        
    auth_key_hashed = int(resp["auth_key_hashed"],16)
    master_key_enc = int(resp["master_key_enc"],16)
    share_key_pub = [int(key) for key in resp["share_key_pub"]]
    share_key_enc = bytes.fromhex(resp["share_key_enc"])
    share_key_enc_hex = resp["share_key_enc"]
    
    # In order to get encyrpted flag, we need these things:
    # 1. p and q, that forms the modulo by n=p*q. 
    # 2. Both are from share_key which is the decrypted value from share_key_enc
    # 3. share_key_enc are created by encrypting X in CBC mode with master key, 
    # where X is: b"" + format(p) + format(q) + format(d) + format(u)
    # where format(x) = bytes(len(x)) + bytes(x)
    # 4. p,q,d,u again are from share_key
    
    # Go read Mega's RSA key recovery (https://mega-awry.io/#rsa-key-recovery)
    # The idea is that we want to create an oracle by guessing which values for ...
    # results in inverse modulo not exist (ie we want to fail the try block)
    request = {
        "action": "wait_login"
    }
    resp = send(tube, request)
    resp = recv(tube)
    
    # Get encrypted p
    print(f"{len(share_key_enc)=}")
    
    request = {
        "share_key_enc": share_key_enc_hex,
        "master_key_enc": hex(master_key_enc),
        "SID_enc": ""
    }
    
    return None


def demo():
    share_key = RSA.generate(2048)
    share_key_pub = (share_key.n, share_key.e)
    return format_rsa_privkey(share_key)

def main():
    print("Usage: python -c 'from solution.megalomaniac import *; print(<function>())'")
    
if __name__ == "__main__":
    main()