import random
import math

def MRT(n, k=40):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = powmod_sm(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = powmod_sm(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def EA(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def EEA(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    if old_r != 1:
        return None
    else:
        return old_s % b

def powmod_sm(base, exponent, mod):
    result = 1
    base = base % mod
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % mod
        exponent = exponent // 2
        base = (base * base) % mod
    return result

def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if MRT(candidate):
            return candidate

def RSA_keygen(s):
    p = generate_prime(s)
    q = generate_prime(s)
    while p == q:
        q = generate_prime(s)
    n = p * q
    phi = (p - 1) * (q - 1)
    required_bits = math.ceil(0.3 * s)
    while True:
        e = random.randint(1, phi - 1)
        if EA(e, phi) == 1:
            d = EEA(e, phi)
            if d is None:
                continue
            if d.bit_length() >= required_bits:
                break
    return (n, e), (d, n)

def RSA_encrypt(kPub, x):
    n, e = kPub
    if x < 0 or x >= n:
        raise ValueError("Plaintext x must be in [0, n-1]")
    return powmod_sm(x, e, n)

def RSA_decrypt(kPr, y):
    d, n = kPr
    return powmod_sm(y, d, n)

if __name__ == "__main__":
    s = 512
    kPub, kPr = RSA_keygen(s)
    n, e = kPub
    d, n_priv = kPr
    print("Public Key (n, e):")
    print("n =", hex(n))
    print("e =", hex(e))
    print("\nPrivate Key (d):")
    print("d =", hex(d))
    x = 0x123456789ABCDEF  # Sample plaintext (hexadecimal)
    print("\nOriginal Plaintext (hex):", hex(x))
    y = RSA_encrypt(kPub, x)
    print("\nCiphertext (hex):", hex(y))
    x_decrypted = RSA_decrypt(kPr, y)
    print("\nDecrypted Plaintext (hex):", hex(x_decrypted))
    assert x == x_decrypted, "Decryption failed"
    print("\nDecryption successful!")