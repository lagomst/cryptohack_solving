# /solution/aes_solution.py
from script.cryptohack.aes import *

def get_encrypted_flag():
    url = BASE_URL + "passwords_as_keys/encrypt_flag/"
    response = requests.get(url)
    resp_str = response.content.decode() # "{"ciphertext": "xxxx"\n}"
    content = json.loads(resp_str)
    return content.get("ciphertext")

def get_words():
    with open("./words.txt") as f:
        words = [w.strip() for w in f.readlines()]
    return words

def get_cookie():
    url = BASE_URL + '/flipping_cookie/get_cookie/'
    response = requests.get(url)
    content = json.loads(response.content.decode())
    return content.get('cookie')

def get_cookie_until_paddable_iv():
    while True:
        cookie = get_cookie()
        
        iv, p_admin, p_date = split_string(cookie, 32)
        print(f"Accquired: {iv=} {p_admin=} {p_date=}", cookie)
        try:
            ans = unpad(bytes.fromhex(iv), 16)
            # sucessfully padded
            approx_time = (datetime.today() + timedelta(days=1)).strftime("%s")
            print(f"Found paddable iv: {iv=}, {p_admin=}, {p_date=}, {approx_time=}")
            data = {
                "iv": iv,
                "p_admin": p_admin,
                "p_date": p_date,
                "approx_time": approx_time
            }
            write_cache(data, "./cache3.csv", ["iv", "p_admin", "p_date", "approx_time"])
            break
        except Exception as e:
            if str(e) not in ["Padding is incorrect.", "PKCS#7 padding is incorrect."]:
                raise e
    return iv, p_admin, p_date

def flipping_cookie():
    # notation: admin: admin block = "admin=False;expi", date: date block, iv: iv block
    
    cookie = get_cookie()
    iv_hex, admin_hex, date_hex = split_string(cookie, 32) # get_cookie return IV + cipher_admin + cipher_date
    
    # Generalize the problem:
    # get_cookie(): return IV + cipher_admin + cipher_date
    # decrypt_cbc_cipher_iv(cipher, IV): calculate P = D(cipher) ^ IV, then check if P is padded and has "admin=True", return flag or error
    
    # admin ^ iv = D(cipher_admin) (1)
    # Let text be any 16-bytes padded arbitary plaintext
    # From (1) => admin ^ iv ^ text = D(cipher_admin) ^ text
    # => D(cipher_admin) ^ admin ^ iv ^ text = text
    # equivalent to: decrypt_cbc_cipher_iv(cipher_admin, admin ^ iv ^ text) = text, then check text
    
    # so one can set the text to be "admin=True..." and exploit the result
    
    # We only need forged_p="admin=True" for condition to be true
    # However doing so will raise padding error,
    # so we fool the algorithm by also padding the forged_p
    p_admin = "admin=False;expi".encode() # already 16 bytes
    p_forged = pad("admin=True".encode(), 16)
    
    forged_iv = xor_two_bytes(p_admin, bytes.fromhex(iv_hex))
    forged_iv = xor_two_bytes(forged_iv, p_forged)
    
    content = decrypt_cbc_cipher_iv(admin_hex, forged_iv.hex())
    
    return content

def symmetry():
    def encrypt_flag():
        url = BASE_URL + '/symmetry/encrypt_flag/'
        content = send_get_request(url)
        return content.get("ciphertext")
    
    def encrypt(plaintext_hex:str, iv_hex:str):
        url = BASE_URL + f'/symmetry/encrypt/{plaintext_hex}/{iv_hex}/'
        content = send_get_request(url)
        return content.get("ciphertext")
    
    hexes = encrypt_flag()
    iv_hex = hexes[:32] # iv length is 16 bytes = 32 hex
    cipher_hexes = hexes[32:]
    print(f"{iv_hex=} {cipher_hexes=}")
    
    # In ofb: cipher_i = E^i(iv) + plain_i; E^i means applying encryption function i times
    # => E^i(iv) = cipher_i + plain_i
    # set plain_i to 0, we can get raw E^i(iv)
    # from here, we calculate plain_i = cipher_i ^ E^i(iv)
    p_zero = bytes(len(cipher_hexes))
    
    encryption_iterate = encrypt(p_zero.hex(), iv_hex)
    
    plaintext = xor_two_bytes(bytes.fromhex(cipher_hexes), bytes.fromhex(encryption_iterate))
    return plaintext

def main():
    print("Usage: python -c 'from solution.aes_solution import *; print(<function>())'")
    
if __name__ == "__main__":
    main()