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

def ecb_oracle(initial_text: str, final_ciphertext: str):
    intial_bytes = initial_text.encode()
    padded_len = 16
    
    initial_padded = intial_bytes + bytes(padded_len - len(intial_bytes))
    
    return 1 <<( (padded_len - len(intial_bytes)) * 8)
    
    cache = load_cache("./cache2.csv", "index")
    
    for idx in range(512, 1 << (padded_len - len(initial_text))):
        if idx in cache:
            continue
        padded_as_int = int.from_bytes(initial_padded) + idx
        
        padded = padded_as_int.to_bytes(padded_len)
        url = BASE_URL + f"/ecb_oracle/encrypt/{padded.hex()}/"
        response = requests.get(url)
        resp_str = response.content.decode() # "{"ciphertext": "xxxx"\n}"
        print(resp_str)
        content = json.loads(resp_str)
        ciphertext: str = content.get("ciphertext")
        
        # write to cache
        data = {
            "index": idx,
            "plaintext": padded,
            "ciphertext": ciphertext,
            
        }
        fields = ["index", "plaintext", "ciphertext"]
        write_cache(data, "./cache2.csv", fields)
        
        # Compare text
        if ciphertext[:32] == final_ciphertext:
            return padded

        time.sleep(0.01)
        
    return None

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

def main():
    # ciphertext = get_encrypted_flag()
    # print(ciphertext)
    # return decrypt_brute_force(ciphertext)
    # cookie = '3889f5aaf7ec3d9f73df093cc4ab4ccace03a3641b511dfd725ba3c496ed172279d27b91769e4a9995b9be0552f2855f'
    iv = '43ab18d44d7abef2a69651e738717901' # ry=17593000__
    ciphertext = ['4ed705b8636f67bd6f2100b91c7bd770', 'ae2f6c72e8ccced009f5e361d4db3193']
    approx_time = 1759307932
    # return split_string(cookie, 32)
    return guess_date_last_two_digits(ciphertext[0], ciphertext[1], iv, 3)
    

if __name__ == "__main__":
    print(main())
    