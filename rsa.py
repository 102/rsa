import random
import util
from functools import reduce
from functools import partial
from collections import deque
from math import log, ceil


to_bin = partial(int, base=2)
to_hex = partial(int, base=16)


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
        return cls(to_hex(e), to_hex(n))

    def __encrypt_chunk(self, message):
        return util.power(message, self.e, self.n)

    def encrypt(self, message):
        chunk_size = self.chunk_size()
        chunk_map = reduce(lambda x, y: 2 ** y + x, range(0, chunk_size), 0)
        message = reduce(lambda acc, byte: (acc << 8) + byte, message, 0)
        result = 0
        for i in range(0, ceil(log(message, 2)), chunk_size):
            m = message & chunk_map
            message >>= chunk_size
            m = self.__encrypt_chunk(m)
            result = (result << chunk_size) + m
        d = deque()
        while result:
            d.appendleft(result % 0x100)
            result >>= 8
        return bytearray(d)


class PrivateKey(Key):
    def __init__(self, d, n):
        self.d = d
        self.n = n

    def __repr__(self):
        return '{:0x}:{:1x}'.format(self.d, self.n)

    @classmethod
    def fromstring(cls, string):
        d, n = string.split(':')
        return cls(to_hex(d), to_hex(n))

    def __decrypt_chunk(self, message):
        return util.power(message, self.d, self.n)

    def decrypt(self, message):
        chunk_size = self.chunk_size()

        chunked_message = deque()
        for i in range(len(message), 0, -chunk_size - 1):
            chunked_message.appendleft(message[i-chunk_size-1:i])
        chunked_message = filter(lambda msg: not msg == '', chunked_message)

        result = []
        for message in chunked_message:
            x = '{:0b}'.format(self.__decrypt_chunk(to_bin(message)))
            while not len(x) % chunk_size == 0:
                x = '0' + x
            result.append(x)
        result = int(''.join(result), 2)
        _r = deque()
        while result:
            x = result % 0x100
            _r.appendleft(x)
            result >>= 8
        return bytearray(_r)


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
