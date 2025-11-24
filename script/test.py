import numpy





def letter_to_number(s:list[int]):
    first_byte = 'A'.encode('ascii')
    numbers = []
    for char in s:
        char_byte = char.encode('ascii')
        num = int.from_bytes(char_byte) - int.from_bytes(first_byte)
        numbers.append(num)
    return numbers

def number_to_letter(numbers:list[int]):
    s = ""
    first_byte = 'A'.encode('ascii')
    for num in numbers:
        char_byte = (num + int.from_bytes(first_byte)).to_bytes()
        s += char_byte.decode('ascii')
    return s

def letter_bucket(s:str):
    bucket: dict[str, int] = {}
    for char in s:
        if char in bucket:
            bucket[char] += 1
        else:
            bucket[char] = 1
    sorted_bucket = sorted(bucket.items(), key=lambda item: item[1])
    return sorted_bucket

a = 'KNXMNSLKWJXMBFYJWGJSIXFIRNYXBTWIKNXMWFSITAJWMJQRNSLFSDIFD'
a_freq = letter_bucket(a)
print(a_freq)

print("Guessing character A and E:...")
a_numbers = letter_to_number(a)
E_idx = letter_to_number('E')[0]
A_idx = letter_to_number('A')[0]

def guess_A_and_E(s:str):
    freq = letter_bucket(s)
    numbers = letter_to_number(s)
    for i in range(len(freq)):
        # Here the freq dictionary has been sorted from lowest to highest frequency
        A_guess, E_guess = letter_to_number(freq[i-1][0])[0], letter_to_number(freq[i][0])[0]
        
        if E_guess - E_idx == A_guess - A_idx:
            k = E_guess - E_idx
            plaintext_numbers = [(num - k)%26 for num in numbers]
            print(k, number_to_letter(plaintext_numbers))
        
guess_A_and_E(a)

cipher = "asvphgyt".upper()
cipher_numbers = letter_to_number(cipher)
for k in range(26):
    new_cipher_nums = [(num - k)%26 for num in cipher_numbers]
    print(k, number_to_letter(new_cipher_nums))