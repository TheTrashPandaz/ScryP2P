import asyncio
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import ECC



username = ""
password = ""
encryptionPass = ""
GUID = ""
keylist = []


def hasher(plainWord):

    hashyGuy = ""

    hashyGuy = hashlib.sha256(hashyGuy.encode()).hexdigest()

    return hashyGuy


def getUserName():
    
    uname = ""
    
    print("Please input a username")
    
    uname = input()
    
    print(uname)
    
    return uname



def passwordMake():

    passWd = ""

    print(f"\nEnter a unique password, PROTIP: Combine 3 random words EG. PlungerMasterLamp")

    passWd = input()

    passWd = hasher(passWd)

    return passWd


def makeKeyFile():
    ##to be encrypted using password later
    ## we will use JSON to build this file
    ToServerPubkeys = {"5/5/2020": "EccKey(curve= 'NIST P-521', point_x=1486465573938105822939004727077225179207099868113689171560681110264144705867423089183409181099797550085162698222601473208419282328197990992286367867277705139, point_y=5654383155596243396760237022173794653643096895890268988991343331019372753219888195890427812417285738948770838211075050279059652646721707744785732717512902299)"}
    fromServerPrivKey = {"5/5/2020" : "ECC private KEY PLACEHOLDER"}
    json_out = {'GUID': GUID, 'happy' : password, "ToServerCommsPkey" : ToServerPubkeys,
     "privateKeysFromServer": fromServerPrivKey, 
     "sessionPubKeys": "NESTED DICTIONARY OF KEYS IDed by DestinationGUID, containting a NESTED DICTIONARY OF KEYS WITH THEIR 64 bit token key and the value as the pubkey ", 
     "sessionPrivKeys": "a key value nested dictionary with the 64 bit sesion tokens+Destination GUID" }

    with open('clientsideData.txt', 'w+') as keyFile:
        json.dump(json_out, keyFile)

    

    

def EncryptKeyFile(keyString):
    
    
    output_file = 'encrypted.owo'

    dataFile = open("clientsideData.txt", "r")

    if dataFile.mode == 'r':
        print("success")
        data = dataFile.read()
        print("byte conversion")

        data = data.encode('utf-8')

    else:
         print("error. We will need to get public key from server first and sync you up.")
        ##We will call function here later to do this

    key = keyString

    cipher = AES.new(key, AES.MODE_EAX) # EAX mode
    
    ciphered_data, tag = cipher.encrypt_and_digest(data) # Encrypt and digest to get the ciphered data and tag

    file_out = open(output_file, "wb")
    
    file_out.write(cipher.nonce) # Write the nonce to the output file (will be required for decryption - fixed size)
    
    file_out.write(tag) # Write the tag out after (will be required for decryption - fixed size)
    
    file_out.write(ciphered_data)
    
    file_out.close()

     ##note write nonce to a file for later




async def sendActive():
    #this is a fucntion that will send the username to bluzelle every 5 mins to let them know we are in the swarm, what node we are
    #on and the whole 9. Will be using our tunneling/encryption scheme in a pretty funtion
    sleep(5)
    print(f"sending key {username} to bluezelle")

def getSalty():
    #for when we need to generate a salt
    #this funtion is not for normal use currently, but exists in the spirit of modular code
    print(get_random_bytes(32))


def AESkeygen(password):
    salt = b"\x94)\xba\x92\xe4|\x81\xdf\x0e< \x9eBX\xe1\xdb#\xf3>!(\x0c\x1eU\x1az\xbcB\x1e"
    key = PBKDF2(password, salt, dkLen=32) # Your key that you can encrypt with
    ## we return a saltes hash
    return key

def decryptKeyFile(keyString):
    #this will decrypt our keyfile to ram(using an array) (not to disk) so that 
    print("I exist for later, not for the now")

def addToKeyfile():
    #this funciton decrypts the keyfile to disk, appends new keys to it, and overwrites old keyfile,
    #then deletes the decrypted copy.
    print("no you wont")


def ECCkeygen():
    #we use 521 bit ECC keys Yielding us great security for minimal overhead
    key = ECC.generate(curve='P-521')
    print("heres what the keygen made youuu")
    print(key)
    pkey = key.public_key()
    print("your Public key is")
    print(pkey)
    if pkey == key:
        print("FAIL")
    else:
        print("success")
    #index 0 is private, then public is index 1
    keylist = [key, pkey]

    return keylist

def encryptWithEcc():
    print("I need new modules")



def ECCSignThings(signee):
    print("I DOnt DO anything")



username = getUserName()

GUID = hasher(username)

password = passwordMake()

encryptionPass = AESkeygen(password)

#Index 0 is private index 1 is public

keylist = ECCkeygen()

makeKeyFile()

EncryptKeyFile(encryptionPass)
