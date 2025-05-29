import os
import tkinter as tk
import tkinter.filedialog as fd
from encript import encrypt, decrypt, chunker

ip = '127.0.0.1'
archive = ip + '\\archive'
data = ip + '\\data\\temp'
chunk_sz = 32 * pow(2, 20) - 64 # 4MB allign

root = tk.Tk()
files = fd.askopenfilenames(parent = root, title = 'select files')
root.destroy()

if len(files) > 0:
    pw = input('password:')

for ifile in files:
    fname = os.path.basename(ifile)
    # encrypt and send to /archive
    ofile = os.path.join(archive, fname + '.enc')
    h1, h2 = encrypt(ifile, pw, chunk_sz, ofile)
    # decrypt back to /data/temp
    tfile = os.path.join(data, fname + '.dec')
    h3, h4 = decrypt(ofile, pw, chunk_sz, tfile)
    # check if both files match
    os.remove(tfile)
    if h1 != h4 or h2 != h3:
        print('verification failed')
        os.remove(ofile)
    else:
        # save hashes
        with open(ofile + '.sha1', 'w') as f:
            f.write('{} {} {}'.format(h2, fname, h1))
        print('saved')
