if __name__ == '__main__':

    from encript import *
    import os
    import hashlib

    def hash_file(path):
        checksum = hashlib.sha1()
        with open(path, 'rb') as f:
            checksum.update(f.read())
        return checksum.hexdigest()

    def hash_bytes(b):
        checksum = hashlib.sha1()
        checksum.update(b)
        return checksum.hexdigest()

    chunk_sz = 32 * pow(2, 20)
    password = 'shawarma_djej'

    h1_inp_1, h1_enc_1 = encrypt('testfile.db', password, chunk_sz)
    h1_enc_2, h1_dec_1 = decrypt('testfile.db.enc', password, chunk_sz)
    h2_inp_1, h2_enc_1 = encrypt('testfile2.db', password, chunk_sz)
    h2_enc_2, h2_dec_1 = decrypt('testfile2.db.enc', password, chunk_sz)

    # compare final hashes
    h1_inp_2 = hash_file('testfile.db')
    h1_dec_2 = hash_file('testfile.db.enc.dec')
    h2_inp_2 = hash_file('testfile2.db')
    h2_dec_2 = hash_file('testfile2.db.enc.dec')
    assert(h1_inp_1 == h1_dec_1 == h1_inp_2 == h1_dec_2)
    assert(h2_inp_1 == h2_dec_1 == h2_inp_2 == h2_dec_2)
    assert(h1_enc_1 == h1_enc_2)
    assert(h2_enc_1 == h2_enc_2)

    # compare encrypted chunk hashes
    t1 = chunker('testfile.db.enc', chunk_sz + 64)
    t2 = chunker('testfile2.db.enc', chunk_sz + 64)
    t3 = chunker('testfile.db', chunk_sz)
    t4 = chunker('testfile2.db', chunk_sz)
    for c1, c2, c3, c4 in zip(t1.chunks, t2.chunks, t3.chunks, t4.chunks):
        h1 = hash_bytes(c1)
        h2 = hash_bytes(c2)
        assert(h1 == h2)
        h3 = hash_bytes(c3)
        h4 = hash_bytes(c4)
        h5 = hash_bytes(chunk_decrypt(c1, password))
        h6 = hash_bytes(chunk_decrypt(c2, password))
        assert(h3 == h4 == h5 == h6)

    print('Success!')
