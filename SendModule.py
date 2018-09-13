# -*- coding: utf-8 -*-

# Send a file using following procedure:
# 1.Compress the whole file/dir
# 2.Use AES to encrypt the compressed file
# 3.Use ecc_crypt to encrypt the AES key (with Receiver's ENCRY Pub_key)
# 4.Hash the AESed file and use ecdsa to sign (with Sender's SIGN Priv_key)
# 5.Send package: ciphered AES key (AESkeylen/16bytes/128bits + ECC_keylen/192bits+ ECCKeylen/192bits) + signature(ECDSAkeylen/192bits + ECDSAkeylen/192bits) + ciphered file


from Tkinter import *
import zipfile, os
from Crypto.Cipher import AES
import Crypto.Random
import tkFileDialog
from ecc import Key, eccrypt, ecdsa
import hashlib
import struct
import os

ECC_keylen = 192
ECDSA_keylen = 192
currentFilePath = '.\\TEST_DIR'
AESkey = Crypto.Random.new().read(16)
Recv_ECC_Pubkey = (192, (3347401160401947993199772070920382431429772945504390472434L, 2664954915783597140303354331330081498672065581549143174308L))
Send_ECDSA_Privkey =(192, 4091654447737102809476448758526854067387234329447323516404L)





winroot = Tk()
winroot.geometry("550x350")
winroot.resizable(width = True,height = True)
winroot.title('FilePGP Sender')
fm1= Frame(winroot)
statue_listbox = Listbox(winroot)
statue_listbox.pack(side = TOP, fill=BOTH,expand =YES)
fm1.pack(side= TOP, fill = BOTH, expand = YES)

def selectDir():
    global currentFilePath
    currentFilePath = tkFileDialog.askdirectory(initialdir='.\\TEST_DIR')

def bitSize(N):
    bits = 0
    while N >> bits:
        bits += 1
    return bits


def compressFolder(dirname, zipAlgo=zipfile.ZIP_DEFLATED):
    compressedFile = dirname+'.compressed'
    f = zipfile.ZipFile(compressedFile, 'w', zipAlgo)  # add new file to zip file, with zip algo deflated
    if not f:
        raise RuntimeError, "Wrong @ Open File, File does not exist."
    for dirpath, dirnames, filenames in os.walk(dirname):  # for every file/dir in the path
        fpath = dirpath.replace(dirname, '')
        fpath = fpath and fpath + os.sep or ''
        for filename in filenames:
            f.write(os.path.join(dirpath, filename), fpath + filename)  # write all files into the zip file
    f.close()

    return compressedFile

def aesEncryptFile(filename, key, working_mode=AES.MODE_CBC):
    fin = open(filename, 'rb')
    fout = open(filename+'.AES', 'wb')
    iv = Crypto.Random.new().read(AES.block_size)
    fout.write(iv)
    AESObj = AES.new(key, working_mode, iv)
    curText = fin.read(AES.block_size)
    i= 0
    while curText:
        if(len(curText)<AES.block_size):
            paded_curtext = curText + b'\x00'*(AES.block_size - (len(curText)%AES.block_size))
        elif len(curText)==AES.block_size:
            paded_curtext = curText
        elif len(curText)>AES.block_size:
            raise RuntimeError, "Block Size Wrong"
        assert len(paded_curtext)==AES.block_size
        fout.write(AESObj.encrypt(paded_curtext))
        i+=1
        print "AES Processing Block ", i
        #statue_listbox.insert(TOP, "AES Processing Block "+str(i))
        curText = fin.read(AES.block_size)
    fin.close()
    fout.close()
    return filename+'.AES'

def eccEncryptAESkey(AESkey, reciever_ecc_pub_key):
    ciphertext, temp_ecc_pubkey = eccrypt.encrypt(AESkey, reciever_ecc_pub_key)
    #print "ECC Encrypt AES key = ", ciphertext,temp_ecc_pubkey
    #print "length of ecc-aes", len(ciphertext), "bitsize of temp_ecc_pubkey", bitSize(temp_ecc_pubkey[0]), " and ",bitSize(temp_ecc_pubkey[1])
    return ciphertext, temp_ecc_pubkey

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

def signANumber(numberic, sender_ecc_priv_key):
    sign_r, sign_s = ecdsa.sign(numberic, sender_ecc_priv_key)
    #print "Signature of HASH = ", sign_r, sign_s
    #print "bitsize of sign:", bitSize(sign_r)," and ", bitSize(sign_s)
    return sign_r, sign_s

def packBigInt(bigint, bitlength =192):
    packedstream = b''
    bytelength = int(bitlength/8)
    for i in range(int(bitlength/32)):
        packedstream += struct.pack('>L',((bigint>>(bitlength-(i+1)*32))&0xFFFFFFFF))
    if len(packedstream) < bitlength:
        packedstream = b'\x00'*(bytelength-len(packedstream)) + packedstream
    assert len(packedstream) == bytelength
    return packedstream

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

def ChangeRecvECCPubkey():
    global Recv_ECC_Pubkey

    filename = tkFileDialog.askopenfilename(initialdir='.', defaultextension='.PUK')
    fin = open(filename, 'rb')
    P1 = struct.unpack(">L", fin.read(4))[0]
    P2 = unpackStream(fin.read(24))
    P3 = unpackStream(fin.read(24))

    KeyNow = (P1,(P2,P3))
    Recv_ECC_Pubkey = KeyNow
    print Recv_ECC_Pubkey


def ChangeSendECDSAPrivkey():
    global Send_ECDSA_Privkey
    filename = tkFileDialog.askopenfilename(initialdir='.', defaultextension='.PRK')
    fin = open(filename, 'rb')
    P1 = struct.unpack(">L", fin.read(4))[0]
    P2 = unpackStream(fin.read(24))
    KeyNow = (P1,P2)
    Send_ECDSA_Privkey = KeyNow
    print Send_ECDSA_Privkey


def Execute():
    global AESkey
    CMPRSDFILE = compressFolder(currentFilePath)
    statue_listbox.insert(END, "Compress Done")
    AESEDFILE = aesEncryptFile(CMPRSDFILE, AESkey)
    ECCAESKEY, TEMPECCPUBKEY = eccEncryptAESkey(AESkey, Recv_ECC_Pubkey)
    FILEHASH = hashAFile(AESEDFILE)
    statue_listbox.insert(END, "SHA-256 =")
    statue_listbox.insert(END, str(FILEHASH))
    statue_listbox.insert(END, "")
    SIGNFILEHASH_R,  SIGNFILEHASH_S=  signANumber(FILEHASH, Send_ECDSA_Privkey)
    statue_listbox.insert(END, "Signature =")
    statue_listbox.insert(END, "R: "+str(SIGNFILEHASH_R))
    statue_listbox.insert(END, "S: "+str(SIGNFILEHASH_S))
    statue_listbox.insert(END, "")

    FINALFILENAME = AESEDFILE+'.package'
    fout = open(FINALFILENAME, 'wb')
    fout.write(ECCAESKEY)
    #print ECCAESKEY
    statue_listbox.insert(END, "Writing ECC-AES Key to Package "+FINALFILENAME)


    PACKED_TEMPECCPUBKEY1 = packBigInt(TEMPECCPUBKEY[0])
    #print PACKED_TEMPECCPUBKEY1
    fout.write(PACKED_TEMPECCPUBKEY1)
    PACKED_TEMPECCPUBKEY2 = packBigInt(TEMPECCPUBKEY[1])
    #print PACKED_TEMPECCPUBKEY2
    fout.write(PACKED_TEMPECCPUBKEY2)
    statue_listbox.insert(END, "Writing ECC Temp Pubkey to Package "+FINALFILENAME)

    PACKED_SIGNR = packBigInt(SIGNFILEHASH_R)
    #print PACKED_SIGNR
    fout.write(PACKED_SIGNR)
    PACKED_SIGNS = packBigInt(SIGNFILEHASH_S)
    #print PACKED_SIGNS
    fout.write(PACKED_SIGNS)
    statue_listbox.insert(END, "Writing Signature to Package "+FINALFILENAME)
    statue_listbox.insert(END, "")

    fin = open(AESEDFILE, 'rb')
    curByte = fin.read(1)
    while curByte!=b'':
        fout.write(curByte)
        curByte = fin.read(1)
    fin.close()
    fout.close()

    statue_listbox.insert(END ,"Done Successfully")
    statue_listbox.insert(END, "")

    os.remove(CMPRSDFILE)
    os.remove(AESEDFILE)





fm2 = Frame(winroot, height=20)
file_select_button = Button(fm2, text='Choose Dir Path to  Proceed', command=selectDir)
file_select_button.pack(side=LEFT, fill=Y, expand = YES)

change_rec_pubkey_button = Button(fm2, text='Change Reciever\'s Public Key', command=ChangeRecvECCPubkey)
change_rec_pubkey_button.pack(side=LEFT, fill=Y,expand = YES)

change_send_pubkey_button = Button(fm2, text='Change My Private Key', command=ChangeSendECDSAPrivkey)
change_send_pubkey_button.pack(side=LEFT, fill=Y,expand = YES)

fm2.pack(side=TOP, fill=X)


fm3 = Frame(winroot, height=20)
exectue_button  = Button(fm3, text='Execute', command= Execute)
exectue_button.pack(side=TOP , fill=BOTH)
fm3.pack(side=TOP, fill=X)

winroot.mainloop()
