## What's this

Convergence encryption tool for secure deduplication.

## How it works

- Split the input file into fixed sized chunks.
- Calculates the hash of the data of each chunk.
- Salt the hash with the password to create the chunk's encryption key.
- Encrypt the chunk data with this key.
- Encrypt the key with the password as well.
- Write each chunk + encrypted key back into a big .enc ouput file.
- Decryption is similar: split, decrypt keys, decrypt chunks, write to .dec file.

## How to use

```
usage: encript [-h] (-e | -d) [-c CHUNKSIZE] [-o OUTPUTPATH] path

allows secure deduplication with convergent encryption

positional arguments:
  path

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt
  -d, --decrypt
  -c CHUNKSIZE, --chunksize CHUNKSIZE
  -o OUTPUTPATH, --outputpath OUTPUTPATH
```
