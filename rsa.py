import random
import util
from functools import reduce
from collections import deque


class Key(object):
    n = 0

    def chunk_size(self):
        return len('{:0b}'.format(self.n)) - 1


class PublicKey(Key):
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def __repr__(self):
        return '{:0x}:{:1x}'.format(self.e, self.n)

    @classmethod
    def fromstring(cls, string):
        e, n = string.split(':')
        return cls(int(e, 16), int(n, 16))

    def __encrypt_chunk(self, message):
        return util.power(message, self.e, self.n)

    def encrypt(self, message):
        message = '{:0b}'.format(reduce(lambda acc, char: (acc << 8) + ord(char), message, 0))
        while not len(message) % self.chunk_size() == 0:
            message = '0' + message
        chunked_message = []
        for i in range(0, len(message), self.chunk_size()):
            chunked_message.append(message[i:i + self.chunk_size()])
        result = ''
        for message in chunked_message:
            x = '{:0b}'.format(self.__encrypt_chunk(int(message, 2)))
            while not len(x) % (self.chunk_size() + 1) == 0:
                x = '0' + x
            result += x
        while not len(result) % 8 == 0:
            result = '0' + result
        return result


class PrivateKey(Key):
    def __init__(self, d, n):
        self.d = d
        self.n = n

    def __repr__(self):
        return '{:0x}:{:1x}'.format(self.d, self.n)

    @classmethod
    def fromstring(cls, string):
        d, n = string.split(':')
        return cls(int(d, 16), int(n, 16))

    def __decrypt_chunk(self, message):
        return util.power(message, self.d, self.n)

    def decrypt(self, message):
        chunk_size = self.chunk_size()

        chunked_message = deque()
        for i in range(0, len(message), chunk_size + 1):
            chunked_message.append(message[i:i + chunk_size + 1])

        num = ''
        for message in chunked_message:
            x = '{:0b}'.format(self.__decrypt_chunk(int(message, 2)))
            while not len(x) % chunk_size == 0:
                x = '0' + x
            num += x
        num = int(num, 2)
        result = ''
        while num:
            result = chr(num % 0x100) + result
            num >>= 8
        return result


def get_key_pair(length):
    length /= 2

    def get_e(phi):
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a

        while True:
            x = random.randint(3, phi)
            if gcd(x, phi) == 1:
                return x

    p, q = util.get_primes(length)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = get_e(phi)
    d = util.modular_inverse(e, phi)

    return PublicKey(e, n), PrivateKey(d, n)
