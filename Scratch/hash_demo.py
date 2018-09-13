import hashlib

# sha256calc = hashlib.sha256()
# sha256calc.update('hello')
# print sha256calc.hexdigest()

def hashAFile(filename, hash_block=1024):
    sha256calc = hashlib.sha256()
    fin = open(filename)
    curByte = fin.read(hash_block)
    while curByte!=b'':
        sha256calc.update(curByte)
        curByte = fin.read(hash_block)
    hashvalue = sha256calc.hexdigest()
    print "SHA-256 of ", filename, " = ", hashvalue
    return hashvalue

print type(int(hashAFile("1.mp4", 512), base=16))
# hashAFile("1.mp4", 256)