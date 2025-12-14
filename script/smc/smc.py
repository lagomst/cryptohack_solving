import os
from typing import Any
from curve import *
import hashlib
import hmac
from datetime import datetime
import time
import my_secret
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher.AES import MODE_GCM
from Crypto.Cipher import AES

def ecdsa_sign(message: str, generator:PointEC, privkey: int):
    curve = generator.curve
    order = curve.order
    
    while(True):
        k = random.randint(2, order-1) # random nonce
        
        P = generator * k
        Px, Py = P.get_affine_coordinate()
        if not Px or not Py:
            raise ValueError("Multiplication lands in nowhere!")
        r = Px % order
        if r == 0:
            continue
        
        hashed = hashlib.sha256(message.encode())
        z = bytes_to_long(hashed.digest())
        zk_stuff = (z + r * privkey) % order
        s = (pow(k, -1, order) * zk_stuff) % order
        if s == 0:
            continue
        break
    
    return r, s

def ecdsa_verify(message: str, generator: PointEC, pubkey_point: PointEC, r: int, s:int):
    curve = pubkey_point.curve
    order = curve.order
    if 1 <= r and r < order and 1 <= s and s < order:
        pass
    else:
        raise ValueError(f"r, s invalid! {r=} {s=}")
    if isinstance(message, str):
        hashed = hashlib.sha256(message.encode())
    else:
        raise ValueError("Unsupported message type! Expecting: str")
    z = bytes_to_long(hashed.digest())
    
    w = pow(s, -1, order)
    u1 = (z*w) % order
    u2 = (r*w) % order
    
    P = generator * u1 + pubkey_point * u2
    Px, _ = P.get_affine_coordinate()
    if not Px:
        raise ValueError("ecdsa verify failed!")
    return Px % order == r % order

def pbkdf2(password: bytes, salt: bytes, iterations:int, keyLength: int):
    result = bytearray(keyLength)
    hLen = 32 # 256-bit, 32-bytes
    offset = 0
    block_count = ((keyLength + hLen) - 1) // hLen;
    
    def hmac_sha256(msg: bytes) -> bytes: # hmac.dofinal
        return hmac.new(password, msg, hashlib.sha256).digest()
    
    for i in range(1, block_count+1):
        block = salt + bytes([
            (i >> 24) & 0xFF,
            (i >> 16) & 0xFF,
            (i >> 8) & 0xFF,
            i & 0xFF
        ])
        
        u = hmac_sha256(block)
        t = bytearray(u)
        
        for _ in range(iterations):
            u = hmac_sha256(u)
            for k in range(hLen):
                t[k] ^= u[k]
        
        block_bytes = keyLength - offset
        to_copy = min(hLen, block_bytes)

        result[offset:offset + to_copy] = t[:to_copy]
        offset += to_copy
    
    return result

def ephemeral_sign_message(message: str, generator:PointEC):
    curve = generator.curve
    order = curve.order
    # Create a key pair
    ephemeral_privkey = random.randint(2, order-1)
    ephemeral_pubkey = generator * ephemeral_privkey
    
    r, s = ecdsa_sign(message, generator, ephemeral_privkey)
    return ephemeral_pubkey, r, s

class ECDH:
    def __init__(self, algorithm:str, p:int,a:int,b:int,Gx:int,Gy:int,order:int):
        self.algorithm = algorithm
        self.order = order
        self.curve = EC(p,a,b, order)
        self.generator = PointEC(self.curve, Gx, Gy)

class Server:
    def __init__(self):
        self.ecdh: ECDH = None
        self.client_pubkey: PointEC = None
            
    def create_session(self, user_id="group-2", algo="ecdh_2"):
        sid = os.urandom(32).hex()
        created = datetime.now().timestamp()
        
        session_data = {
            "sessionId": sid,
            "algorithm": algo,
            "userId": user_id,
            "createdAt": created
        }
        return session_data
        
    def get_login_session(self, ecdh:ECDH):
        self.ecdh = ecdh
        curve = ecdh.curve
        G = ecdh.generator
        # Create session
        session_data = self.create_session()
        # Sign session
        sessionDataStr = json.dumps(session_data) # message
        ephemeral_pubkey, r, s = ephemeral_sign_message(sessionDataStr, G)
        ephe_x, ephe_y = ephemeral_pubkey.get_affine_coordinate()
        # Create a pair of private and public key for this particular client
        self.privkey = random.randint(2, curve.order-1)
        self.pubkey = G * self.privkey
        
        # print(session_data, server_sig_pubkey, (r, s))
        pubkey_xy = (self.pubkey.get_affine_coordinate())
        return session_data, pubkey_xy, (ephe_x, ephe_y), (r, s)
    
    def do_key_exchange(self, client_pubkey: tuple[int,int], client_rs: tuple[int,int], client_sig_pubkey: tuple[int,int]):
        # save client publickey
        self.client_pubkey = PointEC(self.ecdh.curve, *client_pubkey)
        # Get shared secret and AES key from user pubkey
        shared_point = self.client_pubkey * self.privkey
        self.shared_secret, _ = shared_point.get_affine_coordinate()
        secret_bytes = bytearray(long_to_bytes(self.shared_secret))
        salt = bytes(16)
        
        self.aes_key = pbkdf2(secret_bytes, salt, 1000, 32)
        
        # Verify client pubkey
        pubkey_dict = {"x":client_pubkey[0], "y":client_pubkey[1]}
        msg = json.dumps(pubkey_dict)
        
        ephe_pubkey_point = PointEC(self.ecdh.curve, *client_sig_pubkey)
        r, s = client_rs
        status = ecdsa_verify(msg, self.ecdh.generator, ephe_pubkey_point, r, s)
        return "success" if status else "error"
    
    def reply_message(self, ciphertext:bytes, client_iv:bytes, client_sig_pubkey:tuple[int,int], client_rs:tuple[int,int]):        
        curve = self.ecdh.curve
        G = self.ecdh.generator
        # verify client message
        sig_pubkey_point = PointEC(curve, *client_sig_pubkey)
        r, s = client_rs
        verified = ecdsa_verify(ciphertext.hex(), G, sig_pubkey_point, r, s)
        if not verified:
            raise ValueError("Server cannot verified client message!")
        
        # Decrypt user message
        cipher = AES.new(self.aes_key, MODE_GCM, nonce=client_iv, mac_len=16)
        
        plaintext = cipher.decrypt(ciphertext)
        print("INTERFACE: Server reads client message: ", plaintext)
        
        # Example reply message
        reply_msg = "Example reply!"
        # Encrypt with new iv
        reply_iv = os.urandom(12)
        reply_cipher = AES.new(self.aes_key, MODE_GCM, nonce=reply_iv, mac_len=16)
        encrypted_reply = reply_cipher.encrypt(reply_msg.encode())
        # Sign the encrypted reply
        ephe_pubkey, r, s = ephemeral_sign_message(encrypted_reply.hex(), G)
        return encrypted_reply, reply_iv, ephe_pubkey, (r, s)
        
class Client:
    def __init__(self, server:Server):
        self.server = server
        self.hasLogined = False
        
    
    def login(self):
        algorithm = "ecdh_2"
        print("LoginActivity: Algorithm for user: ecdh_2")
        
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        a = -3
        b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
        Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
        order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
        
        self.ecdh = ECDH(algorithm,p,a,b,Gx,Gy, order)
        print("LoginActivity: Added ECDH curve parameters")
        
        # curve = self.ecdh.curve
        # Get server details
        try:
            session_data, server_pubkey, server_sig_pubkey, sig_tuple = self.server.get_login_session(self.ecdh)
            self.session_data = session_data # update session token
        except Exception as e:
            raise e
        self.server_pubkey = PointEC(self.ecdh.curve, *server_pubkey)
        
        # Verify server session
        print("LoginActivity: Verifying session signature (MANDATORY)...")
        pubkey_point = PointEC(self.ecdh.curve, *server_sig_pubkey)
        r, s = sig_tuple
        
        sessionDataStr = json.dumps(session_data)
        verify_result = ecdsa_verify(sessionDataStr, self.ecdh.generator, pubkey_point, r, s)
        if not verify_result:
            raise RuntimeError("LoginActivity: Verifying server failed!")
        print("LoginActivity: ✅ Session signature verified successfully!")
        print("LoginActivity: Proceeding to key exchange...")
        
        return self.key_exchange()
        
    def key_exchange(self):
        curve = self.ecdh
        order = curve.order
        G = self.ecdh.generator
        
        # Long-term key generation
        self.privkey = random.randint(2, order-1)
        self.pubkey = G * self.privkey
        print("CryptoManger: Key pair generated using ECDH-P-256")
        # Compute shared secret
        sharedPoint = self.server_pubkey * self.privkey
        self.shared_secret, _ = sharedPoint.get_affine_coordinate()
        
        # Derived AES key
        print("CryptoManger: Determining byte size for algorithm: ECDH-P-256")
        # keysize = 256
        
        secret_bytes = bytearray(long_to_bytes(self.shared_secret))
        salt = bytes(16)
        key_bytes = pbkdf2(secret_bytes, salt, 1000, 32)
        self.aes_key = key_bytes
        
        print("CryptoManager: ✅ AES key derived successfully")
        
        # Ephemeral key signing
        print("LoginActivity: Signing with EPHEMERAL key (key exchange)...")
        client_pubkey_x, client_pubkey_y = self.pubkey.get_affine_coordinate()
        client_pubkey_dict = {
            "x": client_pubkey_x,
            "y": client_pubkey_y
        }
        clientPublicKeyString = json.dumps(client_pubkey_dict)
        ephemeral_pubkey, r, s = ephemeral_sign_message(clientPublicKeyString, G)
        print("CryptoManager: ✅ Message signed with EPHEMERAL key")
        print("LoginActivity: ✅ Signed with EPHEMERAL key")
        # Send to server
        client_pubkey = (client_pubkey_x, client_pubkey_y)
        client_rs = (r, s)
        client_sig_pubkey = (ephemeral_pubkey.get_affine_coordinate())
        # Send to server
        verify_status = self.server.do_key_exchange(client_pubkey, client_rs, client_sig_pubkey)
        if verify_status != "success":
            raise RuntimeError("Key exchange failed!")
        
        print("LoginActivity: ✅ Server verified client signature successfully")
        print("LoginActivity: ✅ Mutual authentication complete")
        
        self.hasLogined = True
    
    def send_message(self, message:str="Example message!"):
        if not self.hasLogined:
            raise RuntimeError("Client has not logged in")
        # Encrypt message
        if not self.aes_key:
            raise RuntimeError("AES has not been init!")
        iv = os.urandom(12)
        cipher = AES.new(self.aes_key, MODE_GCM, nonce=iv, mac_len=16)
        encrypted_message = cipher.encrypt(message.encode())
        
        # Signing message with ephemeral keys
        curve = self.ecdh
        G = self.ecdh.generator
        
        print("ChatActivity: Signing message with EPHEMERAL key...")
        ephemeral_pubkey, r, s = ephemeral_sign_message(encrypted_message.hex(), G)
        print("ChatActivity: ✅ Message signed with EPHEMERAL key")
        
        # sending to server
        ephe_pubkey_xy = (ephemeral_pubkey.get_affine_coordinate())
        
        encrypted_reply, reply_iv, reply_sig_pubkey, reply_rs = self.server.reply_message(encrypted_message, iv, ephe_pubkey_xy, (r, s))
        # Verify reply signature
        print("Verifying response with server's EPHEMERAL public key...")
        verified = ecdsa_verify(encrypted_reply.hex(), G, reply_sig_pubkey, reply_rs[0], reply_rs[1])
        if not verified:
            raise RuntimeError("Client cannot verify server reply message!")
        print("✅ Response signature verified (EPHEMERAL key)")
        # Decrypt server message
        decrypt_cipher = AES.new(self.aes_key, MODE_GCM, nonce=reply_iv, mac_len=16)
        plaintext_reply = decrypt_cipher.decrypt(encrypted_reply)
        
        print("INTERFACE: Client read server reply: ", plaintext_reply) 
    
def main():
    server = Server()
    client = Client(server)
    client.login()
    client.send_message()

if __name__ == "__main__":
    main()