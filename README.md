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
Default keys (Recv_ECC_Pubkey and Send_ECDSA_Privkey) are written in the code lines, which is used for package generating, and keys are certainly replacable by clicking the button on the GUI.<br>
By clicking on the "Choose dir to proceed" button, a whole directory is chosen for subsequent processing.<br>
Following the procedure declared in code lines, the "Execute" button is the core function of this project. This function takes a dir as input, 
by creating temp files like .AES .compressed, and finally output a .package file.<br>
### Reciever
Default keys (Recv_ECC_Privkey and Send_ECDSA_Pubkey) are written in the code lines, which is used for package generating, and keys are certainly replacable by clicking the button on the GUI.<br>
By clicking on the "Select package file" button, a package file which generated by sender(using same kit) is chosen for subsequent processing.<br>
Following the procedure declared in code lines, the "Execute" button is the core function of this project. This function takes a package as input, 
by creating temp files like .unpack, finally output a .zip file.<br>
### ECC key generator
In the ECKey Generator dir are some sample Key file that stores Public key (.PUK) and Private key (.PRK) seprately, a key pair is noted by the same serial number.<br>
The python program contains functions that generate new key pair with assigned key length.<br>
Proto of the function is **def newKey(keylen, writeTofile=True)**, which write keys to file defaultly.
## Scratch Part
In the scratch dir are 4 demostrations of how basic functions in lib are used, giving a crash course to understand the unclear lines in this project.


## Future Work
Add Kit Select Module for Sender and Reciever to negotiate for a common kit.<br>
Add Verification to check the imported keys' anthentication. <br>
