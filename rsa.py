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
    def get_e(phi):
        while True:
            x = random.randint(3, phi)
            if gcd(x, phi) == 1:
                return x

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    p, q = util.get_primes(length)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = get_e(phi)
    d = util.modular_inverse(e, phi)

    return PublicKey(e, n), PrivateKey(d, n)
