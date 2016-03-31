import random
import util


class PublicKey(object):
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def __repr__(self):
        return '{0}:{1}'.format(self.e, self.n)

    @classmethod
    def fromstring(cls, string):
        e, n = string.split(':')
        return cls(int(e), int(n))

    def encrypt(self, message):
        return util.power(message, self.e, self.n)


class PrivateKey(object):
    def __init__(self, d, n):
        self.d = d
        self.n = n

    def __repr__(self):
        return '{0}:{1}'.format(self.d, self.n)

    @classmethod
    def fromstring(cls, string):
        d, n = string.split(':')
        return cls(int(d), int(n))

    def decrypt(self, message):
        return util.power(message, self.d, self.n)


def get_key_pair(length):
    def get_d(e, phi):
        d = 0
        while True:
            d += 1
            if (d * e) % phi == 1:
                return d

    def get_e(phi):
        assert phi > 3

        coprimes = []
        for num in range(3, phi):
            if gcd(num, phi) == 1:
                coprimes.append(num)

        return random.choice(coprimes)

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def get_primes(length):
        start = 2 ** (length - 1)
        stop = 2 ** (length - 1) + (2 ** (length - 2))
        return random.sample(list(filter(lambda x: x > start, util.get_primes_limit(stop))), 2)

    p, q = get_primes(length)
    n = p*q
    phi = (p-1) * (q-1)
    e = get_e(phi)
    d = get_d(e, phi)

    return PublicKey(e, n), PrivateKey(d, n)

