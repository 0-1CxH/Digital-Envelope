# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import Crypto.Random

KEY = '\x01\x12\x23\x34\x45\x56\x67\x78\x89\x90\x01\x12\x23\x34\x45\x56'

def AESencrypt(x, key, working_mode=AES.MODE_CBC):
    print AES.block_size
    iv = Crypto.Random.new().read(AES.block_size)
    AESObj = AES.new(key, working_mode, iv)
    paded_x = x + b'\x00'*(AES.block_size - (len(x)%AES.block_size))
    print paded_x
    cipher = iv + AESObj.encrypt(paded_x)
    return cipher

def AESdecrypt(x, key, working_mode = AES.MODE_CBC):
    iv = x[0:AES.block_size]
    AESObj = AES.new(key, working_mode, iv)
    realcipher = x[AES.block_size:]
    print realcipher
    plain = AESObj.decrypt(realcipher)
    return plain

plaintext = 'Hello World'
print AESdecrypt(AESencrypt(plaintext, KEY), KEY)