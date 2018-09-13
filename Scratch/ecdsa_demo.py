from ecc import ecdsa, Key

ECC_keylen = 192
ecc_key = Key.Key.generate(ECC_keylen)

ecc_pubkey = ecc_key._pub
print ecc_pubkey
print type(ecc_pubkey)
ecc_privkey = ecc_key._priv
print ecc_privkey

numeric_to_sign = 0x882da7b

sign_r, sign_s = ecdsa.sign(numeric_to_sign,ecc_privkey)
print sign_r, sign_s
res = ecdsa.verify(numeric_to_sign, (sign_r, sign_s), ecc_pubkey)
print res

