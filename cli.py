import argparse
import rsa
from functools import reduce

"""
    python3 cli.py -f key generate -l 8
    python3 cli.py -f message encode -k key_public -d encoded
    python3 cli.py -f encoded decode -k key_private -d decoded
"""


def generate(args):
    public, private = rsa.get_key_pair(int(args.length))
    with open(args.file + '_public', 'w+') as f:
        f.write(str(public))
    with open(args.file + '_private', 'w+') as f:
        f.write(str(private))


def encode(args):
    with open(args.public_key, 'r') as f:
        public = rsa.PublicKey.fromstring(f.readline().replace('\n', ''))
    with open(args.file, 'r') as f:
        message = f.read()
        message = '{:0b}'.format(reduce(lambda acc, char: (acc << 8) + ord(char), message, 0))
        chunk_size = public.chunk_size()
        while not len(message) % chunk_size == 0:
            message = '0' + message
        chunked_message = []
        for i in range(0, len(message), chunk_size):
            chunked_message.append(message[i:i + chunk_size])
    with open(args.destination_file, 'wb') as f:
        result = ''
        for message in chunked_message:
            x = '{:0b}'.format(public.encrypt(int(message, 2)))
            while not len(x) % chunk_size == 0:
                x = '0' + x
            result += x
        while not len(result) % 8 == 0:
            result = '0' + result
        f.write(bytearray([int(result[i:i+8], 2) for i in range(0, len(result), 8)]))


def decode(args):
    with open(args.private_key, 'r') as f:
        private = rsa.PrivateKey.fromstring(f.readline().replace('\n', ''))
    with open(args.file, 'rb') as f:
        message = ''.join(map(lambda x: '{:08b}'.format(x), f.read()))
        chunk_size = private.chunk_size()
        while not len(message) % chunk_size == 0:
            message = '0' + message
        chunked_message = []
        for i in range(0, len(message), chunk_size):
            chunked_message.append(message[i:i + chunk_size])
    with open(args.destination_file, 'w') as f:
        num = ''
        for message in chunked_message:
            x = '{:0b}'.format(private.decrypt(int(message, 2)))
            while not len(x) % chunk_size == 0:
                x = '0' + x
            num += x
            print(len(x))
        num = int(num, 2)
        result = ''
        while num:
            result = chr(num % 0x100) + result
            num >>= 8

        f.write(result)

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', default='key')

subparsers = parser.add_subparsers()

generate_keys = subparsers.add_parser('generate')
generate_keys.add_argument('-l', '--length', required=True, type=int)
generate_keys.set_defaults(func=generate)

encode_parser = subparsers.add_parser('encode')
encode_parser.add_argument('-k', '--public-key', help='File with public key', required=True)
encode_parser.add_argument('-d', '--destination-file', help='Destination file', required=True)
encode_parser.set_defaults(func=encode)

decode_parser = subparsers.add_parser('decode')
decode_parser.add_argument('-k', '--private-key', help='File with private key', required=True)
decode_parser.add_argument('-d', '--destination-file', help='Destination file', required=True)
decode_parser.set_defaults(func=decode)

args = parser.parse_args()

args.func(args)
