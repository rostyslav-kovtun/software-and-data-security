import secrets
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

def gen_keys(bits=512):
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

def encrypt(m: int, e, n):
    return pow(m, e, n)

def decrypt(c: int, d, n):
    return pow(c, d, n)

if __name__ == "__main__":
    e, d, n = gen_keys(bits=512)
    M = 100
    c = encrypt(M, e, n)
    m = decrypt(c, d, n)
    print(c, m)
