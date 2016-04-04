import random
import sys

sys.setrecursionlimit(2 ** 12)


def power(g_base, a, p_mod):
    x = 1
    bits = "{0:b}".format(a)
    for i, bit in enumerate(bits):
        if bit == '1':
            x = (((x ** 2) * g_base) % p_mod)
        elif bit == '0':
            x = ((x ** 2) % p_mod)
    return x % p_mod


def is_probable_prime(n):
    assert n >= 2

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    s = 0
    d = n - 1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert (2 ** s * d == n - 1)

    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    for i in range(5):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True


def get_primes(length):
    start = 2 ** (length - 1)
    stop = 2 ** length - 1
    counter = 0
    primes = []
    while len(primes) < 2:
        num = random.randint(start, stop)
        if is_probable_prime(num):
            counter += 1
            primes.append(num)
    return primes


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modular_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
