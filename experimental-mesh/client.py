import asyncio
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2



username = ""
password = ""
encryptionPass = ""
GUID = ""

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
    keyFile= open("clientsideData.txt","w+")

    keyFile.write(f"GUID = {GUID}")

    keyFile.write(f"\n Public Key For comms TO server below")

    keyFile.write(f"\n Private/ public key pairs for comms from server below")

    keyFile.write(f"\n session public keys in format Destination GUID = Public key ")


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


def keygen(password):
    salt = b"\x94)\xba\x92\xe4|\x81\xdf\x0e< \x9eBX\xe1\xdb#\xf3>!(\x0c\x1eU\x1az\xbcB\x1e"
    key = PBKDF2(password, salt, dkLen=32) # Your key that you can encrypt with
    ## we return a saltes hash
    return key




username = getUserName()

GUID = hasher(username)

password = passwordMake()

encryptionPass = keygen(password)


makeKeyFile()

EncryptKeyFile(encryptionPass)