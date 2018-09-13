# Digital Envelope
## Introduction
This is an implementation of digital envelope. AES is used to encrypt the file which is compression of a whole directory,
and use ECC to encrypt the AES key, to ensure its secrecy; For the integrity guarantee, ECDSA signed HASH vaule is used, 
in which SHA-256 is used as the HASH function.

## Libraries Used
- CRYPTO (pycrypto) Library, provides a great amount of cipher, hash, random and pubkey algorithms, in this project, AES in Crypto.cipher is used.
- ECC Library, includes functions like getting Ellipse Curves, generating EC keys and sophiscated algorithms like ECC, ECDSA and so on.
- HASHLIB Library, a built-in Python lib, contains fast and easy hash implementations.
- ZIPFILE Library, a built-in Python lib, is used to compress and decompress files.
- TKINTER LIbrary, a well-known GUI lib.

**Python Version 2.7**



## Module Explaination

### Sender

### Reciever

### ECC key generator
In the ECKey Generator dir are some sample Key file that stores Public key (.PUK) and Private key (.PRK) seprately, a key pair is noted by the same serial number.<br>
The python program contains functions that generate new key pair with assigned key length.<br>
Proto of the function is **def newKey(keylen, writeTofile=True)**, which write keys to file defaultly.
## Scratch Part
In the scratch dir are 4 demostrations of how basic functions in lib are used, giving a crash course to understand the unclear lines in this project.