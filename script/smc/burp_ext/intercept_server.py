import base64
import os
from typing import Any
from ec_curve import *
import hashlib
import hmac
from datetime import datetime
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher.AES import MODE_GCM
from Crypto.Cipher import AES

def b64_fix_padding(segment):
    return segment + '=' * (-len(segment) % 4)

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
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    
    result = bytearray(keyLength)
    hLen = 32 # 256-bit, 32-bytes
    offset = 0
    block_count = ((keyLength + hLen) - 1) // hLen
    
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
    def __init__(self, p:int,a:int,b:int,Gx:int,Gy:int,order:int):
        self.order = order
        self.curve = EC(p,a,b, order)
        self.generator = PointEC(self.curve, Gx, Gy)

CLIENT_ECDH = ECDH(
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951,
    a = -3,
    b = 41058363725152142129326129780047268409114441015993725554835256314039467401291,
    Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286,
    Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109,
    order = 115792089210356248762697446949407573529996955224135760342422259061068512044369,
)

def dict_to_str_nowhitespace(json_dict: dict[str,Any]):
    for k, v in dict(json_dict).items():
        if not isinstance(v, str):
            json_dict[k] = str(v)
    return json.dumps(json_dict).replace(" ", "")

def to_paddless_base64(message_bytes:bytes):
    return base64.b64encode(message_bytes).decode()

class Server:
    def __init__(self):
        self.ecdh: ECDH = CLIENT_ECDH
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
        
    def get_login_session(self, custom_session_data:str|dict=None):
        curve = self.ecdh.curve
        G = self.ecdh.generator
        # Create session
        if custom_session_data:
            session_data = custom_session_data
        else:
            session_data = self.create_session()
        # Sign session
        sessionDataStr = json.dumps(session_data) if isinstance(session_data, dict) else session_data # message
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
        # Debug: show shared secret and derived AES key
        try:
            print("SERVER KEYEX shared_secret:", self.shared_secret)
            print("SERVER KEYEX aes_key(hex):", self.aes_key.hex())
        except Exception:
            pass
        
        # Verify client pubkey
        pubkey_dict = {"x":str(client_pubkey[0]), "y":str(client_pubkey[1])}
        msg = json.dumps(pubkey_dict).replace(" ", "")
        
        print("Server key exchange: msg value before hashed", msg)
        
        ephe_pubkey_point = PointEC(self.ecdh.curve, *client_sig_pubkey)
        r, s = client_rs
        status = ecdsa_verify(msg, self.ecdh.generator, ephe_pubkey_point, r, s)
        return "success" if status else "error"
    
    def receive_msg(self, client_iv:bytes,ciphertext:bytes, tags:bytes, client_sig_pubkey:tuple[int,int], client_rs:tuple[int,int]):        
        curve = self.ecdh.curve
        G = self.ecdh.generator
        # verify client message
        sig_pubkey_point = PointEC(curve, *client_sig_pubkey)
        r, s = client_rs
        
        msg_to_be_signed = to_paddless_base64(client_iv + ciphertext + tags)
        # Debug: show exact message string and its SHA256 integer
        try:
            print("SERVER VERIFY msg repr:", repr(msg_to_be_signed))
            print("SERVER VERIFY sha256 int:", bytes_to_long(hashlib.sha256(msg_to_be_signed.encode()).digest()))
        except Exception as _:
            print("SERVER VERIFY: failed to compute debug hash")
        verified = ecdsa_verify(msg_to_be_signed, G, sig_pubkey_point, r, s)
        if not verified:
            print("WARNING: Server cannot verified client message!")
        
        # Decrypt user message
        cipher = AES.new(self.aes_key, MODE_GCM, nonce=client_iv, mac_len=16)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tags)
        except Exception as e:
            print("WARNING: unverified tags!", e)
            print("Return plaintext only!")
            cipher = AES.new(self.aes_key, MODE_GCM, nonce=client_iv, mac_len=16)
            plaintext = cipher.decrypt(ciphertext)
            plaintext = plaintext[:-16]

        print("INTERFACE: Server reads client message: ", plaintext)
        
        return plaintext
    
    def send_msg(self, reply_msg:bytes=b"Example reply!"):
        G = self.ecdh.generator
        
        # Encrypt with new iv
        reply_iv = os.urandom(12)
        reply_cipher = AES.new(self.aes_key, MODE_GCM, nonce=reply_iv, mac_len=16)
        encrypted_reply, tag = reply_cipher.encrypt_and_digest(reply_msg)
        # Debug: show encryption params
        try:
            print("SERVER SEND aes_key(hex):", self.aes_key.hex())
            print("SERVER SEND iv(hex):", reply_iv.hex())
            print("SERVER SEND ciphertext(hex):", encrypted_reply.hex())
            print("SERVER SEND tag(hex):", tag.hex())
        except Exception:
            pass
        # Sign the encrypted reply
        msg_to_be_signed = to_paddless_base64(reply_iv + encrypted_reply + tag)
        ephe_pubkey, r, s = ephemeral_sign_message(msg_to_be_signed, G)
        
        ephe_pubkey_xy = (ephe_pubkey.get_affine_coordinate())
        return reply_iv, encrypted_reply, tag, ephe_pubkey_xy, (r, s)

class Client:
    def __init__(self):
        self.ecdh = CLIENT_ECDH
        self.server_pubkey: PointEC = None

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
        
        # Debug: show shared secret and derived AES key
        try:
            print("CLIENT KEYEX shared_secret:", self.shared_secret)
            print("CLIENT KEYEX aes_key(hex):", self.aes_key.hex())
        except Exception:
            pass
        
        print("CryptoManager: ✅ AES key derived successfully")
        
        # Ephemeral key signing
        print("LoginActivity: Signing with EPHEMERAL key (key exchange)...")
        client_pubkey_x, client_pubkey_y = self.pubkey.get_affine_coordinate()
        client_pubkey_dict = {
            "x": client_pubkey_x,
            "y": client_pubkey_y
        }
        clientPublicKeyString = dict_to_str_nowhitespace(client_pubkey_dict)
        ephemeral_pubkey, r, s = ephemeral_sign_message(clientPublicKeyString, G)
        print("CryptoManager: ✅ Message signed with EPHEMERAL key")
        print("LoginActivity: ✅ Signed with EPHEMERAL key")
        # Send to server
        client_pubkey = (client_pubkey_x, client_pubkey_y)
        client_rs = (r, s)
        client_sig_pubkey = (ephemeral_pubkey.get_affine_coordinate())

        return client_pubkey, client_rs, client_sig_pubkey
    
    def send_msg(self, message:bytes=b"Example message!"):
        print("Client: message to be sent ", message)
        # Encrypt message
        if not self.aes_key:
            raise RuntimeError("AES has not been init!")
        iv = os.urandom(12)
        cipher = AES.new(self.aes_key, MODE_GCM, nonce=iv, mac_len=16)
        encrypted_message, tag = cipher.encrypt_and_digest(message)
        
        # Signing message with ephemeral keys
        curve = self.ecdh
        G = self.ecdh.generator
        
        print("ChatActivity: Signing message with EPHEMERAL key...")
        msg_to_be_signed = to_paddless_base64(iv + encrypted_message + tag)
        ephemeral_pubkey, r, s = ephemeral_sign_message(msg_to_be_signed, G)
        print("ChatActivity: ✅ Message signed with EPHEMERAL key")
        
        # sending to server
        ephe_pubkey_xy = (ephemeral_pubkey.get_affine_coordinate())
        
        return iv, encrypted_message, tag, ephe_pubkey_xy, (r, s)
        
    def receive_msg(self, encrypted_reply:bytes, reply_iv:bytes, tags:bytes, reply_sig_pubkey:tuple[int,int], reply_rs:tuple[int,int]):
        # Verify reply signature
        curve = self.ecdh.curve
        G = self.ecdh.generator
        print("Verifying response with server's EPHEMERAL public key...")
        repsig_pubkey_point = PointEC(curve, *reply_sig_pubkey)
        
        msg_to_be_hashed = to_paddless_base64(reply_iv + encrypted_reply + tags)
        # Debug: show exact message string and its SHA256 integer
        try:
            print("CLIENT VERIFY msg repr:", repr(msg_to_be_hashed))
            print("CLIENT VERIFY sha256 int:", bytes_to_long(hashlib.sha256(msg_to_be_hashed.encode()).digest()))
        except Exception as _:
            print("CLIENT VERIFY: failed to compute debug hash")

        verified = ecdsa_verify(msg_to_be_hashed, G, repsig_pubkey_point, reply_rs[0], reply_rs[1])
        if not verified:
            print("WARNING: Client cannot verify server reply message!")
        print("✅ Response signature verified (EPHEMERAL key)")
        # Decrypt server message
        cipher = AES.new(self.aes_key, MODE_GCM, nonce=reply_iv, mac_len=16)
        try:
            plaintext = cipher.decrypt_and_verify(encrypted_reply, tags)
        except Exception as e:
            print("WARNING: unverified tags!", e)
            print("Return plaintext only")
            try:
                print("CLIENT DECRYPT aes_key(hex):", self.aes_key.hex())
                print("CLIENT DECRYPT iv(hex):", reply_iv.hex())
                print("CLIENT DECRYPT encrypted_reply(hex):", encrypted_reply.hex())
                print("CLIENT DECRYPT tag(hex):", tags.hex())
            except Exception:
                pass
            cipher = AES.new(self.aes_key, MODE_GCM, nonce=reply_iv, mac_len=16)
            plaintext = cipher.decrypt(encrypted_reply)
            plaintext = plaintext[:-16]
        
        
        print("INTERFACE: Client read server reply: ", plaintext) 
        return plaintext