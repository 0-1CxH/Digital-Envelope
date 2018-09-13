from ecc import Key, eccrypt
import random
import struct
ECC_keylen = 192

def packBigInt(bigint, bitlength =192):
    packedstream = b''
    bytelength = int(bitlength/8)
    for i in range(int(bitlength/32)):
        packedstream += struct.pack('>L',((bigint>>(bitlength-(i+1)*32))&0xFFFFFFFF))
    if len(packedstream) < bitlength:
        packedstream = b'\x00'*(bytelength-len(packedstream)) + packedstream
    assert len(packedstream) == bytelength
    return packedstream


def newKey(keylen, writeTofile=True):
    serial = int(random.getrandbits(32))
    ecc_key = Key.Key.generate(keylen)
    print "Serial Number = ", serial

    ecc_pubkey = ecc_key._pub
    print "PUBKEY = ", ecc_pubkey
    if writeTofile==True:
        fout = open(str(serial)+".PUK", 'wb')
        fout.write(struct.pack('>L',ecc_pubkey[0]))
        fout.write(packBigInt(ecc_pubkey[1][0]))
        fout.write(packBigInt(ecc_pubkey[1][1]))
        fout.close()

    ecc_privkey = ecc_key._priv
    print "PRIVKEY = ", ecc_privkey
    if writeTofile==True:
        fout = open(str(serial)+".PRK", 'wb')
        fout.write(struct.pack('>L',ecc_privkey[0]))
        fout.write(packBigInt(ecc_privkey[1]))
        fout.close()

    return ecc_pubkey, ecc_privkey




# newKey(ECC_keylen)