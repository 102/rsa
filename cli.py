import argparse
import rsa

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
    with open(args.file, 'r') as f:
        message = f.readline().replace('\n', '')
    with open(args.public_key, 'r') as f:
        public = rsa.PublicKey.fromstring(f.readline().replace('\n', ''))
    with open(args.destination_file, 'w+') as f:
        f.write('{:0x}'.format(public.encrypt(int(message))))


def decode(args):
    with open(args.file, 'r') as f:
        message = f.readline().replace('\n', '')
    with open(args.private_key, 'r') as f:
        private = rsa.PrivateKey.fromstring(f.readline().replace('\n', ''))
    with open(args.destination_file, 'w+') as f:
        f.write(str(private.decrypt(int(message, 16))))


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
