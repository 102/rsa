import random
import util


def div(x):
    return x // 8 - 1


class PublicKey(object):
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def __repr__(self):
        return '{:0x}:{:1x}'.format(self.e, self.n)

    @classmethod
    def fromstring(cls, string):
        e, n = string.split(':')
        return cls(int(e, 16), int(n, 16))

    def encrypt(self, message):
        return util.power(message, self.e, self.n)

    def key_size(self):
        return div(len('{:0b}'.format(self.n)))


class PrivateKey(object):
    def __init__(self, d, n):
        self.d = d
        self.n = n

    def __repr__(self):
        return '{:0x}:{:1x}'.format(self.d, self.n)

    @classmethod
    def fromstring(cls, string):
        d, n = string.split(':')
        return cls(int(d, 16), int(n, 16))

    def decrypt(self, message):
        return util.power(message, self.d, self.n)

    def key_size(self):
        return div(len('{:0b}'.format(self.n)))


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
