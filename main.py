import secrets

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
        a = secrets.randbelow(n - 3) + 2
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

def generate_prime(s):
    while True:
        p = secrets.randbits(s)
        p |= (1 << (s - 1)) | 1
        if MRT(p):
            return p

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

def powmod_sm(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def generate_rsa_keys():
    s = 512
    p = generate_prime(s)
    q = generate_prime(s)
    while p == q:
        q = generate_prime(s)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    required_d_bits = int(0.3 * s)
    while True:
        e = secrets.randbelow(phi_n - 2) + 2
        if EA(e, phi_n) == 1:
            d = EEA(e, phi_n)
            if d is not None and d.bit_length() >= required_d_bits:
                break
    kPub = (n, e)
    kPr = (d, n)
    return kPub, kPr

def rsa_encrypt(kPub, x):
    n, e = kPub
    if x < 0 or x >= n:
        raise ValueError("Plaintext must be in range [0, n-1]")
    return powmod_sm(x, e, n)

def rsa_decrypt(kPr, y):
    d, n = kPr
    return powmod_sm(y, d, n)

# Example usage:
if __name__ == "__main__":
    kPub, kPr = generate_rsa_keys()
    print("Public Key (n, e):", kPub)
    print("Private Key (d, n):", kPr)
    
    # Example plaintext (should be less than n)
    x = 123456789
    print("\nOriginal plaintext:", x)
    
    y = rsa_encrypt(kPub, x)
    print("Ciphertext:", y)
    
    x_decrypted = rsa_decrypt(kPr, y)
    print("Decrypted plaintext:", x_decrypted)
    
    print("\nDecryption successful?", x == x_decrypted)