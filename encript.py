__version__ = '1.3.0'

import os
import argparse
from math import ceil
from getpass import getpass
from hashlib import blake2b, new
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class dummy_hash:
    def update(self, data):
        pass
    def digest(self):
        return b''
    def hexdigest(self):
        return ''
    def copy(self):
        return dummy_hash()

class chunker:
    # note: the filesplit library ain't good cz Split.bysize goes by
    # size on disk and not absolute size
    def __init__(self, path, chunk_sz):
        # prep
        sz = os.path.getsize(path)
        chunk_cnt = int(ceil(sz / chunk_sz))
        # save to attributes
        self.path = path
        self.sz = sz
        self.chunk_sz = chunk_sz
        self.chunk_cnt = chunk_cnt # number of chunks

    @property
    def chunks(self):
        with open(self.path, mode = 'rb') as f:
           for i in range(self.chunk_cnt):
               yield f.read(self.chunk_sz)

    @staticmethod
    def _hash_fn_resolver(hash_fn):
        if hash_fn in [None, 'None', 'none', '']:
            return dummy_hash
        elif isinstance(hash_fn, str):
            return lambda: new(hash_fn)
        elif not callable(hash_fn):
            raise TypeError('Invalid hash function, see hashlib for options')
        return hash_fn

    def do(self, op, output_path, hash_fn = None):
        # prep hash objects
        hash_fn = chunker._hash_fn_resolver(hash_fn)
        ihash = hash_fn()
        ohash = hash_fn()
        # split, do + hash (in memory), merge
        fname = os.path.basename(self.path)
        with open(output_path, 'wb') as f:
            progress_bar = tqdm(
                unit = 'B', unit_scale = True, unit_divisor = 1024,
                miniters = 1, desc = fname, total = self.sz
                )
            for chunk in self.chunks:
                # apply operation
                # hash input and output
                n = len(chunk)
                ihash.update(chunk)
                data = op(chunk)
                f.write(data)
                ohash.update(data)
                progress_bar.update(n)
        return ihash.hexdigest(), ohash.hexdigest()

def chunk_encrypt(data, password, tag = b''):
    # convergence encryption
    # the encryption key is hash of the data
    # duplicated chunks will be encrypted the same, allowing deduplication
    password_bytes = bytes(password, encoding = 'utf-8')
    # first make a salt from the password
    # salt is used to add consistent randomness to the encryption key
    # that way confirmation attacks are difficult
    salt = blake2b(password_bytes, digest_size = 16).digest()
    # calculate the hash of the data, which is the key
    key = blake2b(data, digest_size = 32, salt = salt).digest()
    # encrypt the data
    nonce = b'\x00' * 12
    chacha = ChaCha20Poly1305(key)
    enc_data = chacha.encrypt(nonce, data, tag)
    # encrypt the key with the password also
    pw = blake2b(password_bytes, digest_size = 32).digest()
    chacha = ChaCha20Poly1305(pw)
    enc_key = chacha.encrypt(nonce, key, tag)
    # stick them together
    enc_data += enc_key
    return enc_data

def chunk_decrypt(enc_data, password, tag = b''):
    password_bytes = bytes(password, encoding = 'utf-8')
    # decrypt key
    enc_key = enc_data[-48:]
    nonce = b'\x00' * 12
    pw = blake2b(password_bytes, digest_size = 32).digest()
    chacha = ChaCha20Poly1305(pw)
    key = chacha.decrypt(nonce, enc_key, tag)
    # decrypt data
    chacha = ChaCha20Poly1305(key)
    data = chacha.decrypt(nonce, enc_data[:-48], tag)
    return data

def encrypt(path, password, chunk_sz, output_path = None):
    if output_path in [None, '', '.']:
        output_path = path + '.enc'
    chunk = chunker(path, chunk_sz)
    encryptor = lambda data: chunk_encrypt(data, password)
    ih, oh = chunk.do(encryptor, output_path, hash_fn = 'sha1')
    return ih, oh

def decrypt(path, password, chunk_sz, output_path = None):
    if output_path in [None, '', '.']:
        output_path = path + '.dec'
    chunk = chunker(path, chunk_sz + 64)
    decryptor = lambda data: chunk_decrypt(data, password)
    ih, oh = chunk.do(decryptor, output_path, hash_fn = 'sha1')
    return ih, oh

if __name__ == '__main__':

    _MB = pow(2, 20)
    _128_MB = 128 * _MB

    parser = argparse.ArgumentParser(
        prog = 'encript',
        description = 'allows secure deduplication with convergent encryption',
        )
    parser.add_argument('path')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-e', '--encrypt', action = 'store_true')
    group.add_argument('-d', '--decrypt', action = 'store_true')
    parser.add_argument('-c', '--chunksize', type = int, default = _128_MB)
    parser.add_argument('-o', '--outputpath', default = '')
    args = parser.parse_args()

    pw = getpass('password:')
    if args.encrypt:
        ih, oh = encrypt(args.path, pw, args.chunksize, args.outputpath)
        print(ih, '>', oh)
    if args.decrypt:
        ih, oh = decrypt(args.path, pw, args.chunksize, args.outputpath)
        print(ih, '>', oh)
