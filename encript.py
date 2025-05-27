import math
import os
import argparse
import getpass
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def argsort(arr):
    return sorted(range(len(arr)), key = arr.__getitem__)

class chunker:
    # note: the filesplit library ain't good cz Split.bysize goes by
    # size on disk and not absolute size
    _delim = '.c'

    def __init__(self, path, chunk_sz):
        # prep
        chunk_cnt = int(math.ceil(os.path.getsize(path) / chunk_sz))
        chunk_digits = int(math.floor(math.log10(chunk_cnt))) + 1
        # save to attributes
        self.path = path
        self.chunk_sz = chunk_sz
        self.chunk_cnt = chunk_cnt # number of chunks
        self.chunk_digits = chunk_digits # how many digits the chunk count is

    @property
    def chunks(self):
        with open(self.path, mode = 'rb') as f:
           for i in range(self.chunk_cnt):
               yield f.read(self.chunk_sz)

    def split(self, output_dir, encryptor = None):
        fname = os.path.basename(self.path)
        for i, chunk in enumerate(self.chunks):
            n = '{}{}{:0{}}'.format(fname, self._delim, i, self.chunk_digits)
            ofname = os.path.join(output_dir, n)
            with open(ofname, mode = 'wb') as f:
                if callable(encryptor):
                    f.write(encryptor(chunk))
                else:
                    f.write(chunk)
            #print(i + 1, '/', self.chunk_cnt, ofname)

    @staticmethod
    def merge(input_dir, output_path, decryptor = None, delim = _delim):
        parts = []
        part_nb = []
        for fn in os.listdir(input_dir):
            if delim in fn:
                pn = fn.split(delim)[-1]
                if pn.isdigit():
                    parts += [fn]
                    part_nb += [int(pn)]
        parts = [parts[i] for i in argsort(part_nb)]
        N = len(parts)
        with open(output_path, 'wb') as of:
            for i, p in enumerate(parts):
                path = os.path.join(input_dir, p)
                #print(i + 1, '/', N, path)
                with open(path, 'rb') as f:
                    chunk = f.read()
                if callable(decryptor):
                    of.write(decryptor(chunk))
                else:
                    of.write(chunk)

def chunk_encrypt(data, password, tag = b''):
    # convergence encryption
    # the encryption key is hash of the data
    # duplicated chunks will be encrypted the same, allowing deduplication
    password_bytes = bytes(password, encoding = 'utf-8')
    # first make a salt from the password
    # salt is used to add consistent randomness to the encryption key
    # that way confirmation attacks are difficult
    salt = hashlib.blake2b(password_bytes, digest_size = 16).digest()
    # calculate the hash of the data, which is the key
    key = hashlib.blake2b(data, digest_size = 32, salt = salt).digest()
    # encrypt the data
    nonce = b'\x00' * 12
    chacha = ChaCha20Poly1305(key)
    enc_data = chacha.encrypt(nonce, data, tag)
    # encrypt the key with the password also
    pw = hashlib.blake2b(password_bytes, digest_size = 32).digest()
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
    pw = hashlib.blake2b(password_bytes, digest_size = 32).digest()
    chacha = ChaCha20Poly1305(pw)
    key = chacha.decrypt(nonce, enc_key, tag)
    # decrypt data
    chacha = ChaCha20Poly1305(key)
    data = chacha.decrypt(nonce, enc_data[:-48], tag)
    return data

##

def prep_folder(path):
    # create temp folder
    if not os.path.exists(path):
        os.mkdir(path)
    # clear stuff there
    for f in os.listdir(path):
        fp = os.path.join(path, f)
        os.remove(fp)

def encrypt(path, password, chunk_sz):
    prep_folder('temp')
    c = chunker(path, chunk_sz)
    encryptor = lambda data: chunk_encrypt(data, password)
    c.split('temp', encryptor)
    chunker.merge('temp', path + '.enc')

def decrypt(path, password, chunk_sz):
    prep_folder('temp')
    c = chunker(path, chunk_sz + 64)
    c.split('temp')
    decryptor = lambda data: chunk_decrypt(data, password)
    chunker.merge('temp', path + '.dec', decryptor)

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
    parser.add_argument('-c', '--chunksize', default = _128_MB)
    args = parser.parse_args()

    pw = getpass.getpass('password:')
    if args.encrypt:
        encrypt(args.path, pw, args.chunksize)
        prep_folder('temp')
    if args.decrypt:
        decrypt(args.path, pw, args.chunksize)
        prep_folder('temp')
