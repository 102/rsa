import argparse
import rsa
from functools import reduce
import struct

"""
    python3 cli.py -f key generate -l 8
    python3 cli.py -f message encode -k key_public -d encoded
    python3 cli.py -f encoded decode -k key_private -d decoded
"""

CHUNK_SIZE = 256


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
        messages = f.read()
        while not len(messages) % public.key_size() == 0:
            messages += ' '

        messages = [messages[i:i+public.key_size()] for i in range(0, len(messages), public.key_size())]

        messages = map(lambda msg: reduce(lambda acc, x: (acc << 8) + ord(x), msg, 0), messages)
    with open(args.destination_file, 'wb') as f:
        for message in messages:
            line = hex(public.encrypt(int(message)))[2:]
            while not len(line) % 8 == 0:
                line += '0'
            for x in range(0, len(line), 8):
                f.write(struct.pack('I', int(line[x:x+8], 16)))


def decode(args):
    with open(args.private_key, 'r') as f:
        private = rsa.PrivateKey.fromstring(f.readline().replace('\n', ''))
    with open(args.file, 'rb') as f:
        message = f.read()
    with open(args.destination_file, 'w+') as f:
        line = ''
        for x in range(0, len(message), 4):
            s = str(struct.unpack('I', message[x:x+4])[0])
            _ms = '{:08x}'.format(int(s))
            line += _ms

        res = hex(private.decrypt(int(line, 16)))[2:]
        r = ''
        for x in range(0, len(res), 2):
            r += chr(int(res[x:x+2], 16))
        f.write(r)
        #messages = hex(private.decrypt(int(line)))[2:]
        #res = ''
        #for x in range(0, len(messages), 2):
        #    res += chr(int(messages[x:x+2], 16))

        #f.write(res)


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
