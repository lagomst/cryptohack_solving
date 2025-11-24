import jwt
import json
import base64
import io
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad
from sage.arith import power as sagepow
import sys
from script.cryptohack.elliptic_curve import gcd_euclid, gcd_array
import requests
import os
import hashlib
import math

BASE_URL = 'https://web.cryptohack.org'

def jwt_secrets():
    encoded = jwt.encode({"username": "admin", "admin": True}, "secret", "HS256")
    return encoded

def rsa_or_hmac():
    pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAvoOtsfF5Gtkr2Swy0xzuUp5J3w8bJY5oF7TgDrkAhg1sFUEaCMlR\nYltE8jobFTyPo5cciBHD7huZVHLtRqdhkmPD4FSlKaaX2DfzqyiZaPhZZT62w7Hi\ngJlwG7M0xTUljQ6WBiIFW9By3amqYxyR2rOq8Y68ewN000VSFXy7FZjQ/CDA3wSl\nQ4KI40YEHBNeCl6QWXWxBb8AvHo4lkJ5zZyNje+uxq8St1WlZ8/5v55eavshcfD1\n0NSHaYIIilh9yic/xK4t20qvyZKe6Gpdw6vTyefw4+Hhp1gROwOrIa0X0alVepg9\nJddv6V/d/qjDRzpJIop9DSB8qcF1X23pkQIDAQAB\n-----END RSA PUBLIC KEY-----\n"
    # On error, ctrl-click the line where it raises error 
    # and comment out the raise error block
    encoded = jwt.encode({"username": "admin", "admin": True}, pubkey, algorithm='HS256')
    return encoded

def json_in_json():
    username = 'admin", "admin": True' # Note the number of double quotes
    body = '{' \
              + '"admin": "' + "False" \
              + '", "username": "' + str(username) \
              + '"}'
    payload = json.loads(body)
    assert isinstance(payload, dict)
    return username # Use this username to sign the data in the challenge page

def base64_decoder_to_bytes(token):
    data = token.replace('-', '+').replace('_', '/')
    padding = len(data) % 4
    if padding:
        data += '=' * (4 - padding)
    return base64.b64decode(data)



def rsa_or_hmac2():
    # First grab the jwt token from this header + payload: {"typ":"JWT","alg":"RS256"}{"username":"admin","admin":false}
    # Singature from data
    SIG_HASH_PAIR_NUMS = 2
    
    signatures:list[bytes] = []
    hashes:list[bytes] = []
    used_username:list[int] = []
    def fetch_jwt_token(username)->str:
        url = BASE_URL + f'/rsa-or-hmac-2/create_session/{username}/'
        resp = requests.get(url)
        resp_str = resp.content.decode()
        print(resp_str)
        content = json.loads(resp_str)
        return content["session"]
    
    
    for _ in range(SIG_HASH_PAIR_NUMS):
        name = int.from_bytes(os.urandom(8))
        session = fetch_jwt_token(name)
        
        base64_header, base64_payload, base64_sig = session.split('.')
        
        message = (base64_header + '.' + base64_payload).encode()
        h = bytes.fromhex(hashlib.sha256(message).hexdigest())
        s = base64_decoder_to_bytes(base64_sig)
        
        used_username.append(name)
        hashes.append(h)
        signatures.append(s)   
        
        
    # Forging signatures
    # m = s**e % n
    # We want m[-32:] == h or s**e == prefix || h (mod n)
    
    # Constructing prefix
    def construct_EM_signature_sha256(hashes:bytes, key_size:int=256):
        sig_start = bytes.fromhex("0001") # Start of EM structure: 0x00 0x01
        seperator = bytes.fromhex("00")
        sha256_algo_id = bytes.fromhex("3031300d060960864801650304020105000420") 
        
        padding_length = key_size - len(sha256_algo_id) - len(hashes) - 3
        padding = bytearray(b"\xff") * padding_length
        
        return sig_start + padding + seperator + sha256_algo_id + hashes
    
    # return signatures, hashes
    # On verify step: Check s**e == prefix + h = t (mod n)
    # To find n, => s**e %n = t => k*n = s**e - t
    exponents = [3,5,17,257,65537]
    final_modulus = None
    final_exponents = None
    
    
    def n_mult(s:bytes,e:int,h:bytes)->int:
        left_term = pow(bytes_to_long(s), e)
        right_term = bytes_to_long(construct_EM_signature_sha256(h, len(s)))
        # print(f"{right_term=} {len(s)=}")
        return left_term - right_term
    
    for e in exponents:
        s0 = signatures[0]
        h0 = hashes[0]
        n0 = n_mult(s0,e,h0)
        print("Calculated n0")
        s1 = signatures[1]
        h1 = hashes[1]
        n1 = n_mult(s1,e,h1)
        print("Calculated n1")
        # Calculating gcd between the two
        
        last_gcd = math.gcd(n0, n1)
        print(f"Calculated {last_gcd=}")
        for i in range(2, SIG_HASH_PAIR_NUMS):
            if last_gcd == 1:
                break
            s = signatures[i]
            h = hashes[i]
            n = n_mult(s,e,h)
            last_gcd = math.gcd(n, last_gcd)
            
        if last_gcd != 1:
            final_modulus = last_gcd
            final_exponents = e
            break
    
    return final_modulus, final_exponents
    

def main():
    print("Usage: python -c 'from solution.json_token_web import *; print(<function>())'")
    
if __name__ == "__main__":
    main()