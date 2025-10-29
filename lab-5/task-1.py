from string import ascii_lowercase

alphabet_length = len(ascii_lowercase)

def encrypt(plaintext: str, key: int):
    ciphertext = ""
    for ch in plaintext:
        index = ascii_lowercase.index(ch)
        cipherletter = ascii_lowercase[(index + key) % alphabet_length]
        ciphertext += cipherletter
    return ciphertext

def decrypt(ciphertext: str, key: int):
    plaintext = ""
    for ch in ciphertext:
        index = ascii_lowercase.index(ch)
        plainletter = ascii_lowercase[(index - key) % alphabet_length]
        plaintext += plainletter
    return plaintext


"""
Ключ було підібрано за допомогою циклу while 
та переглядом результатів:
"""
# i = 1
# while i < alphabet_length:
#     decrypted_text = decrypt("vppanlwxlyopyncjae", i)
#     print(f"String: '{decrypted_text}' - key {i}.")
#     i += 1


text_to_encrypt = "abcd"
key = 1
encrypted_text = encrypt(text_to_encrypt, key)
decrypted_text = decrypt(encrypted_text, key)
print(f"Original: {text_to_encrypt}\nEncrypted text: {encrypted_text}\nDecrypted text: {decrypted_text}")