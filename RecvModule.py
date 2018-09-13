# Receive a file using following procedure:
# 1.Extract ciphered AES key (AESkeylen/16bytes/128bits + ECC_keylen/192bits+ ECCKeylen/192bits) + signature(ECDSAkeylen/192bits + ECDSAkeylen/192bits) + ciphered file
# 2.Use ecc_decrypt to decrypt the AESkey (with Receiver's ENCRY Priv_key)
# 3.Calculate HASH of AESed file, and use against ECDSA_veryfy (with Sender's Pub_key)
# 4.Use AES key to decrypt AEDed file
# 5.Decompress the zip

from Tkinter import *
import zipfile, os
from Crypto.Cipher import AES
import Crypto.Random
import tkFileDialog
from ecc import Key, eccrypt, ecdsa
import hashlib
import struct
#from aesDe import aesDecryptFile

ECC_keylen = 192
ECC_keybytelen = 24
ECDSA_keylen = 192
ECDSA_keybytelen = 24
currentFilePath = '.\\TEST_DIR.compressed.AES.package'
Recv_ECC_Privkey = (192, 488965617570866280541449855668585716274269733753725296414L)
Send_ECDSA_Pubkey = (192, (1652641959512693167801567474152286909102073199171147860793L, 2449718803400012546250470137060022587523287610693902862968L))


winroot = Tk()
winroot.geometry("550x300")
winroot.resizable(width = True,height = True)
winroot.title('FilePGP Receiver')
fm1= Frame(winroot)
statue_listbox = Listbox(winroot)
statue_listbox.pack(side = TOP, fill=BOTH,expand =YES)
fm1.pack(side= TOP, fill = BOTH, expand = YES)

def selectFile():
    global currentFilePath
    currentFilePath = tkFileDialog.askopenfilename(initialdir='.\\', defaultextension='.package')

def bitSize(N):
    bits = 0
    while N >> bits:
        bits += 1
    return bits

def unpackStream(packedstream, bitlength=192):
   bigint = 0
   bytelength = int(bitlength / 8)
   for i in range(bytelength/4):
       if i==0:
           curM = packedstream[bytelength-((i+1)*4):]
       else :
           curM = packedstream[bytelength-((i+1)*4):bytelength-i*4]
       #print type(curM)
       #print (struct.unpack('>L', curM))
       bigint += ((struct.unpack('>L',curM))[0])<<(32*i)
   return bigint


def ChangeSendECDSAPubkey():
    global Send_ECDSA_Pubkey

    filename = tkFileDialog.askopenfilename(initialdir='.', defaultextension='.PUK')
    fin = open(filename, 'rb')
    P1 = struct.unpack(">L", fin.read(4))[0]
    P2 = unpackStream(fin.read(24))
    P3 = unpackStream(fin.read(24))

    KeyNow = (P1,(P2,P3))
    Send_ECDSA_Pubkey = KeyNow
    print Send_ECDSA_Pubkey


def ChangeRecvECCPrivkey():
    global Recv_ECC_Privkey
    filename = tkFileDialog.askopenfilename(initialdir='.', defaultextension='.PRK')
    fin = open(filename, 'rb')
    P1 = struct.unpack(">L", fin.read(4))[0]
    P2 = unpackStream(fin.read(24))
    KeyNow = (P1,P2)
    Recv_ECC_Privkey = KeyNow
    print Recv_ECC_Privkey

def eccDecryptAESkey(ECCAESkey, temp_ecc_pubkey,receiver_ecc_priv_key):
    result = eccrypt.decrypt(ECCAESkey, temp_ecc_pubkey, receiver_ecc_priv_key)
    #print "Decrypted AES key = ", result
    return result

def aesDecryptFile(filename, iv, key, working_mode=AES.MODE_CBC):
    AESObj = AES.new(key,working_mode, iv)
    fin = open(filename, 'rb')
    curText = fin.read(AES.block_size)
    zipfilename = filename[0:(filename[1:]).index('.')+1] + '.zip'
    fout = open(zipfilename, 'wb')

    i = 0
    while curText!= b'':
        assert len(curText)==AES.block_size
        fout.write(AESObj.decrypt(curText))
        i += 1
        print "AES Processing Block ", i
        curText = fin.read(AES.block_size)
    fin.close()
    fout.close()
    return  zipfilename

def hashAFile(filename, hash_block=1024):
    sha256calc = hashlib.sha256()
    fin = open(filename)
    curByte = fin.read(hash_block)
    while curByte!=b'':
        sha256calc.update(curByte)
        curByte = fin.read(hash_block)
    hashvalue = sha256calc.hexdigest()
    #print "SHA-256 of ", filename, " = ", hashvalue
    return int(hashvalue, base=16)


def veritfyANumber(numeric_to_verify, sign_r, sign_s, sender_ecc_pubkey):
    return ecdsa.verify(numeric_to_verify, (sign_r, sign_s), sender_ecc_pubkey)

def Execute():
    fin = open(currentFilePath, 'rb')

    ECC_AES_KEY = fin.read(16)
    TEMPECCPUBKEY1 = fin.read(ECC_keybytelen)
    UNPACKED_TEMPPUBKEY1 = unpackStream(TEMPECCPUBKEY1)
    TEMPECCPUBKEY2 = fin.read(ECC_keybytelen)
    UNPACKED_TEMPPUBKEY2 = unpackStream(TEMPECCPUBKEY2)
    TEMPPUBKEY = (UNPACKED_TEMPPUBKEY1,UNPACKED_TEMPPUBKEY2)

    AESKEY = eccDecryptAESkey(ECC_AES_KEY, TEMPPUBKEY, Recv_ECC_Privkey)
    statue_listbox.insert(END, "AES Key = "+bytes(AESKEY))
    statue_listbox.insert(END, "")

    SIGNR = fin.read(ECDSA_keybytelen)
    UNPACKED_SIGNR = unpackStream(SIGNR)
    SIGNS = fin.read(ECDSA_keybytelen)
    UNPACKED_SIGNS = unpackStream(SIGNS)


    AESIV = fin.read(AES.block_size)

    UNPACKAGEFILEPATH =  currentFilePath+'.unpack'
    fout = open(UNPACKAGEFILEPATH, 'wb')
    curByte = fin.read(1)
    while curByte != b'':
        fout.write(curByte)
        curByte = fin.read(1)
    fin.close()
    fout.close()
    #print UNPACKAGEFILEPATH


    TEMPFILEFORHASH = currentFilePath+'.temp'
    tempout = open(TEMPFILEFORHASH, 'wb')
    tempin = open(UNPACKAGEFILEPATH, 'rb')
    tempout.write(AESIV)
    curByte = tempin.read(1)
    while curByte != b'':
        tempout.write(curByte)
        curByte = tempin.read(1)
    tempin.close()
    tempout.close()

    AESFILEHASH = hashAFile(TEMPFILEFORHASH)
    statue_listbox.insert(END, "SHA-256 =")
    statue_listbox.insert(END, str(AESFILEHASH))
    statue_listbox.insert(END, "")
    VERIFICATION = veritfyANumber(AESFILEHASH, UNPACKED_SIGNR, UNPACKED_SIGNS,Send_ECDSA_Pubkey)
    #print "Verification = ", VERIFICATION
    statue_listbox.insert(END, "Verification of the Signature = "+str(VERIFICATION))
    statue_listbox.insert(END, "")

    if VERIFICATION==True:
        ZIPFILE = aesDecryptFile(UNPACKAGEFILEPATH, AESIV, AESKEY)
        statue_listbox.insert(END, "Zip File Path = "+ZIPFILE)
        statue_listbox.insert(END, "")
        statue_listbox.insert(END, "Done Successfully")
    elif VERIFICATION==False:
        statue_listbox.insert(END, "Wrong Signature, Process Terminated")

    os.remove(TEMPFILEFORHASH)
    os.remove(UNPACKAGEFILEPATH)

    return



fm2 = Frame(winroot, height=20)
file_select_button = Button(fm2, text='Select Package File', command=selectFile)
file_select_button.pack(side=LEFT, fill=Y, expand=YES)

change_rec_pubkey_button = Button(fm2, text='Change My Private Key', command=ChangeRecvECCPrivkey)
change_rec_pubkey_button.pack(side=LEFT, fill=Y,expand = YES)

change_send_pubkey_button = Button(fm2, text='Change Sender\'s Public Key', command=ChangeSendECDSAPubkey)
change_send_pubkey_button.pack(side=LEFT, fill=Y,expand = YES)

fm2.pack(side=TOP, fill=X)

fm3 = Frame(winroot, height=20)
exectue_button  = Button(fm3, text='Execute', command= Execute)
exectue_button.pack(side=TOP , fill=BOTH)
fm3.pack(side=TOP, fill=X)

winroot.mainloop()
