import secrets
import base64
from math import gcd

def is_probable_prime(n, k=8): # тест Міллера–Рабіна щоб перевірити чи є число n простим
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def gen_keys(bits=2048):
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    n = p * q
    fi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, fi) != 1:
        e = 3
        while gcd(e, fi) != 1:
            e += 2
    d = pow(e, -1, fi)
    return e, d, n

def encrypt_bytes(b_plain: bytes, e, n):
    k = (n.bit_length() + 7) // 8
    m_block = (n.bit_length() - 1) // 8
    out = bytearray()
    for i in range(0, len(b_plain), m_block):
        chunk = b_plain[i:i+m_block]
        m_int = int.from_bytes(chunk, byteorder='big')
        c_int = pow(m_int, e, n)
        c_bytes = c_int.to_bytes(k, byteorder='big')
        out += c_bytes
    return bytes(out)

def decrypt_bytes(b_cipher: bytes, d, n):
    k = (n.bit_length() + 7) // 8
    out = bytearray()
    for i in range(0, len(b_cipher), k):
        c_bytes = b_cipher[i:i+k]
        c_int = int.from_bytes(c_bytes, byteorder='big')
        m_int = pow(c_int, d, n)

        m_len = (m_int.bit_length() + 7) // 8
        if m_len == 0:
            chunk = b''
        else:
            chunk = m_int.to_bytes(m_len, byteorder='big')
        out += chunk
    return bytes(out)

def encrypt_string(plaintext: str, e, n):
    b = plaintext.encode('utf-8')
    c_bytes = encrypt_bytes(b, e, n)
    return base64.b64encode(c_bytes).decode('ascii')

def decrypt_string(b64_ciphertext: str, d, n):
    c_bytes = base64.b64decode(b64_ciphertext.encode('ascii'))
    m_bytes = decrypt_bytes(c_bytes, d, n)
    return m_bytes.decode('utf-8')

if __name__ == "__main__":
    e, d, n = gen_keys(bits=2048)
    M = ("Cryptography is fun and educational! Learning RSA encryption and "
         "decryption with Python helps understand public key cryptosystems.")
    c_b64 = encrypt_string(M, e, n)
    m = decrypt_string(c_b64, d, n)
    print(c_b64)
    print(m)
