import requests
import csv
import json
import hashlib
import time
import sys
import os
from typing import Dict, List, Any, Union, Optional, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
from my_modulo import matrix2bytes, bytes2matrix

BASE_URL = "https://aes.cryptohack.org/"
RESPONSE_DELAY = 0.001
BLOCK_SIZE = 16

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


def decrypt_e(cihpertext:str):
    plaintext = decrypt_online(cihpertext, '26f000508a4ea9a9fc73fb8f86cd2fe11d4df2a081215a0fecd66701f8ec9803')
    return plaintext

def decrypt_constant(ciphertext: str, constant: str):
    plaintext = decrypt_online(ciphertext, constant)
    return plaintext

def decrypt_offline(ciphertext, word):
    password_hash = hashlib.md5(word.encode()).digest().hex()
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
        print(f"{decrypted=}")
    except ValueError as e:
        return {"error": str(e)}
    try:
        plaintext = decrypted.decode()
    except:
        return decrypted.hex()
    return plaintext

def decrypt_online(ciphertext: str, word: str):
    key = hashlib.md5(word.encode()).digest()
    # key_bytes = bytes.fromhex(key)
    url = BASE_URL + f"/passwords_as_keys/decrypt/{ciphertext}/{key.hex()}/"
    response = requests.get(url)
    resp_str = response.content.decode() # "{"plaintext": "xxxx"\n}"
    print(resp_str)
    content = json.loads(resp_str)
    plaintext_hex: str = content.get("plaintext")
    try:
        plaintext = bytes.fromhex(plaintext_hex).decode()
    except:
        return plaintext
    return plaintext

def decrypt_brute_force(ciphertext: str):
    words_list = get_words()
    cache = load_cache()
    for idx, word in enumerate(words_list):
        if word in cache:
            continue
        plaintext: str = decrypt_offline(ciphertext, word)
        if plaintext.startswith("crypto"):
            print("Password found!")
            print(f"{plaintext=} {word=}")
            return plaintext
        # Write to cache
        data = {
            "ciphertext": ciphertext,
            "index": idx,
            "word": word,
            "plaintext": plaintext
        }
        write_cache(data)
        time.sleep(0.005)
    return None
    
def write_cache(data, filepath="./cache.csv", fields = ["ciphertext", "index", "word", "plaintext"]):
    with open(filepath, "a") as f:
        # Write header only if file is empty
        if f.tell() == 0:
            writer.writeheader()
        writer = csv.DictWriter(f, fieldnames=fields)
        # writer.writerow(fields)     # Write header
        writer.writerow(data)   

def _try_convert_simple(value: str) -> Union[str, int, float]:
    """
    Convert numeric-looking strings to int or float; leave other strings unchanged.
    Keep this small and safe (no complex parsing).
    """
    if value is None:
        return value
    v = value.strip()
    if v == "":
        return v
    # int
    if v.isdigit():
        return int(v)
    # float (simple)
    try:
        if "." in v:
            f = float(v)
            return f
    except ValueError:
        pass
    return v

def load_cache(
    path: str = "./cache.csv",
    key_field: str = "word",
    allow_multiple: bool = False,
    convert_simple_numbers: bool = True,
) -> Dict[str, Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """
    Load CSV produced by write_cache into a dict keyed by `key_field`.

    Args:
        path: path to CSV file.
        key_field: which CSV column to use as dictionary key (default "word").
        allow_multiple: if True, values are lists of row-dicts (for duplicate keys).
                        if False, last occurrence overwrites previous.
        convert_simple_numbers: attempt to convert digit-only fields to int and decimals to float.

    Returns:
        dict mapping key_field -> row-dict or -> list[row-dict] when allow_multiple=True.

    Example:
        >>> d = load_cache("./cache.csv", key_field="word", allow_multiple=True)
        >>> d["hello"]  # may be a list of dicts
    """
    if not os.path.exists(path):
        return {}

    result: Dict[str, Union[Dict[str, Any], List[Dict[str, Any]]]] = {}

    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        # If file has no header or no fieldnames, return empty
        if not reader.fieldnames:
            return {}

        if key_field not in reader.fieldnames:
            # Key field isn't present: raise informative error
            raise KeyError(f"Key field '{key_field}' not found in CSV headers: {reader.fieldnames}")

        for raw_row in reader:
            # Convert types if requested
            if convert_simple_numbers:
                row = {k: _try_convert_simple(v) for k, v in raw_row.items()}
            else:
                row = dict(raw_row)

            key = row.get(key_field)
            if key is None:
                # Skip rows without the key_field
                continue

            # Ensure key is string (consistent)
            if not isinstance(key, str):
                key = str(key)

            if allow_multiple:
                existing = result.get(key)
                if existing is None:
                    result[key] = [row]
                else:
                    # mypy/typing: existing is List[Dict]
                    casted = existing  # type: ignore
                    casted.append(row)
            else:
                # Overwrite or insert; last one wins
                result[key] = row

    return result

def xor_two_bytes(var: bytes, key: bytes):
    return bytes(a ^ b for a, b in zip(var, key))

def get_ecb_ciphertext(plaintext)->str:
    url = BASE_URL + f"/ecb_oracle/encrypt/{plaintext}/"
    response = requests.get(url)
    resp_str = response.content.decode() # "{"ciphertext": "xxxx"\n}"
    content = json.loads(resp_str)
    return content.get("ciphertext")
    
def decrypt_ecb_padding(initial_plaintext="crypto{p3n6u1n5",text_length=32, block_length=16):
    filling_plaintext = initial_plaintext
    remaining_len = text_length - len(initial_plaintext)
    extra_block = 0
    
    while remaining_len > 0:
        # We want the number of A just enough to "push" the unknown word at the end of bloc
        # In another word:
        # "AAAAA..." + filling = k * block_length - 1 (k is integer)
        # k = (A_padding + filling + 1) / block_length
        # A_padding + filling + 1 = 0 mod block_length
        padded_prefix = "A".encode() * ((-len(filling_plaintext) - 1) % block_length)
        if not padded_prefix:
            padded_prefix = "A".encode() * block_length
        print(padded_prefix.hex())
        target_ciphertext_hex = get_ecb_ciphertext(padded_prefix.hex())
        
        block_idx = len(padded_prefix + filling_plaintext.encode()) // block_length
        block_start_idx = block_idx * block_length * 2
        block_end_idx = block_start_idx + block_length * 2
        target_ciphertext_hex = target_ciphertext_hex[block_start_idx : block_end_idx]
        
        # return target_ciphertext_hex
        found_letter = False
        
        print(f"Begin guessing for {target_ciphertext_hex=}")
        print(f"{filling_plaintext=}")
        for i in range(20, 127): # 0x00 -> 0xff
            guess_plaintext = padded_prefix + filling_plaintext.encode() + i.to_bytes()
            # print(len(guess_plaintext))
            # assert len(guess_plaintext) == 16
            
            
            print("Guessing: ", guess_plaintext, " =?= ", target_ciphertext_hex)
            guess_ciphertext_hex: str = get_ecb_ciphertext(guess_plaintext.hex()) 
            print(f"block acquired={guess_ciphertext_hex[block_start_idx:block_end_idx]}")
            if guess_ciphertext_hex[block_start_idx:block_end_idx] == target_ciphertext_hex:
                filling_plaintext += i.to_bytes().decode()
                found_letter = True
                print("Found matching letter")
                print(f"Letter: {i.to_bytes().decode()}, {filling_plaintext=}")
                break
            
        if not found_letter:
            print("Did not found any letter matching ciphertext")
            print(f"{target_ciphertext_hex=}, {filling_plaintext=}")
            return None
        
        remaining_len -= 1
    
    return filling_plaintext

# def get_cookie():
#     expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
#     cookie = f"admin=False;expiry={expires_at}".encode()
#     wanted_cookie = f"admin=True;expire=1760000000".encode()
#     print(f"{wanted_cookie=}")
#     # iv = os.urandom(16)
#     padded = pad(cookie, 16)
#     return split_string(padded.hex(), 32)

def split_string(line:str, n:int):
    return [line[i:i+n] for i in range(0, len(line), n)]

def decrypt_cbc_cipher_iv(ciphertext, iv) -> str:
    url = BASE_URL + f'/flipping_cookie/check_admin/{ciphertext}/{iv}/'
    response = requests.get(url)
    content = json.loads(response.content.decode())
    try:
        result = content.get("flag")
        if not result:
            raise ValueError("No flag found")
        # raise ValueError("content has no flag nor error")
        
    except Exception as e:
        error: str = content.get("error")
        if not error:
            print(content)
            raise RuntimeError(f"Exception found, while response has no error flag: {e}")
        return error
        
    return result

def guess_date_last_two_digits(admin_ciphertext_hex:str, date_ciphertext_hex:str, iv_hex:str, second_last_guess:int=None):
    
    def _inner(digit:int, second_last_digit:int=None):
        if second_last_digit:
            p_date = 'ry=17593041' + str(second_last_guess) + str(digit)
        else:
            p_date = 'ry=17593041' + str(digit).zfill(2)
        padded_date = pad(p_date.encode(), BLOCK_SIZE)
            
        cipher_hex = date_ciphertext_hex
        final_iv = xor_two_bytes(bytes.fromhex(admin_ciphertext_hex), padded_date)
        final_iv = xor_two_bytes(final_iv, bytes.fromhex(iv_hex))
        final_iv_hex = final_iv.hex()
        print(f"Guessing: {padded_date=}, {final_iv_hex=}, {cipher_hex=}")
        result = decrypt_cbc_cipher_iv(cipher_hex, final_iv_hex)
        print("Response: ",result)
        # if result == "Only admin can read the flag":
        #     print(f"Last digit found: {digit}")
        #     # return digit
        return None
    
    # if second_last_guess >= 10 or second_last_guess < 0:
    #     raise ValueError("Second last guess must have one single digit")
    # if second_last_guess:
    #     for i in range(10):
    #         if _inner(i, second_last_guess):
    #             return i
    
    for i in range(0, 100):
       if _inner(i):
            return i
    
    return None
            

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

def send_get_request(url):
    response = requests.get(url)
    content = json.loads(response.content.decode())
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

def bean_counter(rand_int=int.from_bytes( os.urandom(1))):
    # Look closely at the counter code,
    # if stup = False then counter doesn't decrement or increment => value unchanged.
    # In encryption code, ctr = StepUpCounter() means ctr.stup = False
    # => c_i = E(val) ^ p_i (ecb) for every i
    # => c_i ^ c_(i+1) = p_i ^ p_(i+1)
    # This is true for every value of "val" (try it yourself!)
    
    url = BASE_URL + '/bean_counter/encrypt/'
    content = send_get_request(url)
    data_hex: str = content.get("encrypted")
    random = xor_two_bytes(bytes.fromhex(data_hex[32:64]), bytes.fromhex(data_hex[32*rand_int:64*rand_int]))
    print(int.from_bytes(random))
    # Now go read png chunk layout! (https://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html)
    # Also IHDR chunk layout (https://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html)
    # PNG starts with 8 bytes of signature and then a header chunk (IHDR)
    # We know what those 8 bytes are, and what 8 bytes of starting IHDR are
    # From here we have obtained zeroth block! => obtained E(val)
    # The rest shouldn't be difficult
    png_signature = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    ihdr_length = bytes([0x00, 0x00, 0x00, 0x0d]) # 13 bytes long
    ihdr_type = bytes([0x49, 0x48, 0x44, 0x52]) # type(IHDR)
    
    p_zero = png_signature + ihdr_length + ihdr_type
    print(p_zero.hex())
    encrypted_value = xor_two_bytes(bytes.fromhex(data_hex[:32]), p_zero)
    # step = BLOCK_SIZE * 2
    png_hex = ""
    for idx in range(0, len(data_hex), 32):
        cipher = bytes.fromhex(data_hex[idx:idx+32])
        plain = xor_two_bytes(encrypted_value, cipher)
        png_hex += plain.hex()
    # write png_hex to png
    # print(png_hex)
    import struct
    with open('./bean_counter.png', 'wb') as f:
        f.write(bytes.fromhex(png_hex))
    
    return png_hex

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
    # Main loop
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
    # ciphertext = get_encrypted_flag()
    # print(ciphertext)
    # return decrypt_brute_force(ciphertext)
    # cookie = '3889f5aaf7ec3d9f73df093cc4ab4ccace03a3641b511dfd725ba3c496ed172279d27b91769e4a9995b9be0552f2855f'
    # random_number = int.from_bytes( os.urandom(1))
    # hex_one = bean_counter(random_number)
    # hex_two = bean_counter(random_number)
    # zero = xor_two_bytes(bytes.fromhex(hex_one), bytes.fromhex(hex_two))
    return bean_counter()

if __name__ == "__main__":
    print(main())
    