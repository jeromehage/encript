if __name__ == '__main__':

    from encript import *
    import os, shutil
    import hashlib

    def print_hash(path):
        checksum = hashlib.sha1()
        with open(path, 'rb') as f:
            checksum.update(f.read())
        h = checksum.hexdigest()
        print(path, h)
        return h

    # start by making two test files with duplicate parts
    input_file = 'Win10_20H2_v2_EnglishInternational_x64.iso'

    _MB = pow(2, 20)
    _128_MB = 128 * _MB

    # 1GB file
    prep_folder('data')
    c = chunker(input_file, 1024 * _MB)
    c.split('data')
    file = [f for f in os.listdir('data') if f.endswith('.c0')][0]
    shutil.copy(os.path.join('data', file), 'testfile.db')
    # 1GB and a bit more
    c = chunker(input_file, 1200 * _MB)
    c.split('data')
    file = [f for f in os.listdir('data') if f.endswith('.c0')][0]
    shutil.copy(os.path.join('data', file), 'testfile2.db')

    # encrypt and decrypt
    password = 'shawarma_djej'

    # first test file
    encrypt('testfile.db', password, _128_MB)
    file = os.path.join('temp', os.listdir('temp')[0])
    h1 = print_hash(file)
    decrypt('testfile.db.enc', password, _128_MB)
    file = os.path.join('temp', os.listdir('temp')[0])
    h2 = print_hash(file)
    # the other file
    encrypt('testfile2.db', password, _128_MB)
    file = os.path.join('temp', os.listdir('temp')[0])
    h3 = print_hash(file)
    decrypt('testfile2.db.enc', password, _128_MB)
    file = os.path.join('temp', os.listdir('temp')[0])
    h4 = print_hash(file)
    assert(h1 == h2 == h3 == h4)

    # compare hashes
    h1 = print_hash('testfile.db')
    h2 = print_hash('testfile.db.enc.dec')
    h3 = print_hash('testfile2.db')
    h4 = print_hash('testfile2.db.enc.dec')
    assert(h1 == h2)
    assert(h3 == h4)

    print('Success!')
