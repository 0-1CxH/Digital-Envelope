# python 2.7

from ecc import Key, eccrypt

ECC_keylen = 192
ecc_key = Key.Key.generate(ECC_keylen)

ecc_pubkey = ecc_key._pub
print ecc_pubkey
ecc_privkey = ecc_key._priv
print ecc_privkey

message = "Hello World"
ciphertext, temp_ecc_pubkey = eccrypt.encrypt(message,ecc_pubkey)
print ciphertext, temp_ecc_pubkey
result = eccrypt.decrypt(ciphertext,temp_ecc_pubkey,ecc_privkey)

print result
