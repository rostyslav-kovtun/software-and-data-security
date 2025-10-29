ukrainian_lowercase = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"

alphabet_length = len(ukrainian_lowercase)

def encrypt(plaintext: str, key: str):
    ciphertext = ""
    for i, ch in enumerate(plaintext.lower()):
        p_index = ukrainian_lowercase.index(ch)
        k_index = ukrainian_lowercase.index(key[i % len(key)])
        c_index = (p_index + k_index) % alphabet_length
        ciphertext += ukrainian_lowercase[c_index]
    return ciphertext


def decrypt(ciphertext: str, key: str):
    plaintext = ""
    for i, ch in enumerate(ciphertext.lower()):
        c_index = ukrainian_lowercase.index(ch)
        k_index = ukrainian_lowercase.index(key[i % len(key)])
        p_index = (c_index - k_index) % alphabet_length
        plaintext += ukrainian_lowercase[p_index]
    return plaintext

text_to_encrypt = "криптографічніметодизахистуінформації"
key = "ковтун"
encrypted_text = encrypt(text_to_encrypt, key)
decrypted_text = decrypt(encrypted_text, key)
print(f"Original: {text_to_encrypt}\nEncrypted text: {encrypted_text}\nDecrypted text: {decrypted_text}")