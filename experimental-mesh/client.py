import asyncio

import os #we use this library to handle keyfile operations with storing keys and other things locally

import hashlib #handles our hashing

from Crypto.Cipher import AES #aes is only used to encrypt the keyfile with the users hashed password

from Crypto.Random import get_random_bytes

from Crypto.Protocol.KDF import PBKDF2

import json #I encode stuff to be stored nicely in the keyfile, both before enc and after for storing nonce

import secrets #This module gets very rdm numbers

from base64 import b64encode, b64decode #this module encodes and decodes to comms with bluzelle

from Crypto.PublicKey import ECC #this handles pubkey/privkey generatinon and signing with ecc

from Crypto.Cipher import Salsa20 #this handles Sym enc of our chats



keyfileChecksum = ""
#this holds a checksum of the keyfile
username = ""
##this is our plaintext username
password = ""
##this is our hashed password
encryptionPass = ""
#sha256 hashed aes ecrtuption pass

GUID = ""
#GUID is our Globally Unique Identifier (A hashed usrname) that we use instead of IP
keylist = []
##keyList holds our public and Private keys in use for the current session
activeKeyDict = {}
#this is a dictionary of our keyfile, that will hold all of our stuff

activeKeyFileChecksum = ""
## This is a hash of the current key dictionary in ram, to be compared to the stored hash of the stored keyfile before dewcryption
##the keyfile on disk hash is in the encrypted keyfile json under "checksum" is != an a sync funciton will update it
keyfileChecksum = ""


def MOTD():
    print("*******************************************************")
    print(f"\n####################################################")
    print(f"\n________-____________ScryP2P____________________-________")
    print("\n")
    print("\n  _________                    ____________________________ ")
    print("\n /   _____/ ___________ ___.__.\______   \_____  \______   \ ")
    print('\n \_____  \_/ ___\_  __ <   |  | |     ___//  ____/|     ___/')
    print('\n /        \  \___|  | \/\___  | |    |   /       \|    |    ')
    print('\n/_______  /\___  >__|   / ____| |____|   \_______ \____|    ')
    print('\n        \/     \/       \/                       \/         ')
    print('\n##############################################################')
    print('\n__________Free speech is the Way To a Better Tommorrow________')
    ###print('\n$$$$$$$$$$$$$$&&&&&&&&&&&&&&&&&&&&&&&&$$$$$$$$$$$$$$$$$$$$$$$$')



def AESkeygen(password):
    salt = b"\x94)\xba\x92\xe4|\x81\xdf\x0e< \x9eBX\xe1\xdb#\xf3>!(\x0c\x1eU\x1az\xbcB\x1e"
    key = PBKDF2(password, salt, dkLen=32) # Your key that you can encrypt with
    ## we return a saltes hash
    return key

def hasher(plainWord):
    #this function will hash any string input with sha256
    hashyGuy = AESkeygen(plainWord)

    hashyGuy = hashyGuy.hex()
    
    return hashyGuy


def login():
    # THis fucniton gets a username + password from the user and appends it to a list obj
    uname = ""
    
    print("Please input a username")
    
    uname = input()
    
    print("Please input your password")

    passWd = input()

    loginCreds = []
    #logincreds 0 is username, logincreds 1 is password
    loginCreds.append(uname)
    #passWd = hasher(passWd)
    loginCreds.append(passWd)

    return loginCreds



def acctMake():
    #this function gets the password from the user and hashes it
    uname= ""
    passWd = ""

    print('Please Enter a unique UserName. Randomize your handles fool!')
    
    uname = input()


    passWd = ""

    print(f"\nEnter a unique password, PROTIP: Combine 3 random words EG. PlungerMasterLamp")

    passWd = input()

    #passWd = hasher(passWd)

    acctCreds = []
    ## acctcreds holds acct details with 0 bring username and 1 being hashed pasword
    
    acctCreds.append(uname)

    acctCreds.append(passWd)

    return acctCreds


def makeKeyFile():

    #TODO make a funciton that checks if this exists before launching this

    ##to be encrypted using password later
    ## we will use JSON to build this file
    ToServerPubkeys = {"5/5/2020": "EccKey(curve= 'NIST P-521', point_x=1486465573938105822939004727077225179207099868113689171560681110264144705867423089183409181099797550085162698222601473208419282328197990992286367867277705139, point_y=5654383155596243396760237022173794653643096895890268988991343331019372753219888195890427812417285738948770838211075050279059652646721707744785732717512902299)"}
    fromServerPrivKey = {"5/5/2020" : "ECC private KEY PLACEHOLDER"}
    json_out = {'GUID': GUID, 'happy' : password, "ToServerCommsPkey" : ToServerPubkeys,
     "privateKeysFromServer": fromServerPrivKey, 
     "sessionPubKeys": "NESTED DICTIONARY OF KEYS IDed by DestinationGUID, containting a NESTED DICTIONARY OF KEYS WITH THEIR 64 bit token key and the value as the pubkey ", 
     "sessionPrivKeys": "a key value nested dictionary with the 64 bit sesion tokens+Destination GUID" }
     
    global activeKeyDict

    activeKeyDict = json_out
     
     #this stores this copy in ram for working with for our initial startup

    global keyfileChecksum

    FormattedJson = str(json_out)
    

    keyfileChecksum = hasher(FormattedJson)

    with open('clientsideData.txt', 'w+') as keyFile:
        json.dump(json_out, keyFile)

    keyFile.close()

def KeyCompare():
    #load the keyfileChecksum from then end of the encrypted file
    with open('encrypted.owo') as infile:
        input_json = json.load(infile)

    keyfileChecksum = input_json["plaintextChecksum"]

    print(f"keyfileChecksum from file reads {keyfileChecksum}")
    
    ActiveCopyChecksum = str(activeKeyDict)
    
    activeKeyFileChecksum = hasher(ActiveCopyChecksum)

    if keyfileChecksum == activeKeyFileChecksum:
        #checksum of the keyfile in ram is compared to the checksum loaded from the encrypted file representing its keyfile
        print("everything is equal")
    
    else:
        print("nothing is the same")
    #checksum of the one in ram is compared to the checksum loaded from the encrypted file

def EncryptKeyFile(keyString):
    
    
    output_file = 'encrypted.owo'

    dataFile = open("clientsideData.txt", "r")

    if dataFile.mode == 'r':

        data = dataFile.read()
        #byte conversion below

        data = data.encode('utf-8')

    else:
        print("error. We will need to get public key from server first and sync you up.")
        ##We will call function here later to do this

    key = keyString

    cipher = AES.new(key, AES.MODE_EAX) # EAX mode
    
    ciphered_data, tag = cipher.encrypt_and_digest(data) # Encrypt and digest to get the ciphered data and tag

    file_out = open(output_file, "wb")
    
    ciphered_data = ciphered_data.hex()
    cipher.nonce = (cipher.nonce).hex()
    tag = tag.hex()
    ##here we are converting all  byte arrays to hex for json encoding

    contents = {"IV": cipher.nonce,"plaintextChecksum": keyfileChecksum, "tag": tag, "Data": ciphered_data}
    ##this is out dict where we store our hex encoded datda for json storage
    with open(output_file, 'w+') as encryptedFile:
        json.dump(contents, encryptedFile)
    
    file_out.close()

    os.remove('clientsideData.txt')
    ##here we remove the plaintext file

     
def decryptKeyFile(keyString):
    # I decrypt the key file so we can copy its decrypted contents to a local 
    with open('encrypted.owo') as infile:
        input_json = json.load(infile)

    # Get all the fields from the dictionary read from the JSON file
    ciphered_data = input_json['Data']
    nonce = input_json['IV']
    tag = input_json['tag']

    ciphered_data = bytes.fromhex(ciphered_data)
    nonce = bytes.fromhex(nonce)
    tag = bytes.fromhex(tag)
    ##here we are converting the hex string to byte arrays for use in the decryption
    key = keyString

    # Decrypt and verify
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    
    original_data = cipher.decrypt_and_verify(ciphered_data, tag) # Decrypt and verify with the tag
    
    print("Password Success")

    #print(original_data)

    ##TODO convert OG data to dictionary for local use in ram

    return original_data



async def sendActive():
    #this is a fucntion that will send the username to bluzelle every 5 mins to let them know we are in the swarm, what node we are
    #on and the whole 9. Will be using our tunneling/encryption scheme in a pretty funtion
    sleep(5)
    print(f"sending key {username} to bluezelle")

def getSalty():
    #for when we need to generate a salt
    #this funtion is not for normal use currently, but exists in the spirit of modular code
    print(get_random_bytes(32))



def addToKeyfile():
    #this funciton pulls the checksum from the encrypted text, compares against ram copies checksum, then if !=
    # decrypts the keyfile to disk, appends new keys to it, and overwrites old keyfile,
    # then deletes the decrypted copy.
    print("no you wont")


def ECCkeygen():
    #we use 521 bit ECC keys Yielding us great security for minimal overhead
    key = ECC.generate(curve='P-521')
    
    pkey = key.public_key()

    if pkey == key:
        print("FAIL")
    else:
        print("successful ECC Keypair Generation")
    #index 0 is private, then public is index 1
    keylist = [key, pkey]

    return keylist

def encryptWithEcc():
    print("I need new modules")



def ECCSignThings(signee):
    print("I DOnt DO anything")


def EncryptText(plaintext):
    plaintext = plaintext.encode('utf-8')
    

def SecureKeyGen():
    #This func generates a symetric salsa 20 key that will later be encrypted using destination public key
    #symkey is generated
    symKey = (f"{secrets.randbits(104)}")
    #Symkey length must be 32 bytes for the salsa20 lib. we regenerate till it is 32 consitantly

    symKey = bytes(symKey, encoding= 'utf-8')
    # the above code changes the format into a bitstream so that it can be passed to library

    while len(symKey) != 32:
        #this while loop regenerates key if it is not 32 byte, 
        # because unlike C python has dificulty with bits
        symKey = (f"{secrets.randbits(104)}")
        symKey = bytes(symKey, encoding= 'utf-8')
        #diagnostic to check key length as 32 bytes after conversion below
        #print(f"the key length is {len(symKey)}")

    #print(f"your secure symetric salsa20 key is {symKey}") 
    
    return symKey


def symCrypt(plaintext, symKey):

    plaintext = bytes(plaintext, encoding= 'utf-8')
    #this function generates a new class and makes a nonce
    cipher = Salsa20.new(key=symKey)
    #the nonce is then added to the front of the encrypted msg. first 8 bytes
    msg = cipher.nonce + cipher.encrypt(plaintext)
    

    #print(f"Your Nonce is {len(cipher.nonce)}")
    
    #print(f'Your encrypted salsa20 Message is {msg}')

    return msg
 

def Launcher():
    MOTD()
    global GUID
    global username
    global password
    global encryptionPass
    global keylist
    global activeKeyDict
    jsonHolder =  ""
    storageArray = []
    if os.path.exists("encrypted.owo"):
        #we test if a keyvault exists
        print("You are not a new user")
        
        storageArray = login()
        username = storageArray[0]
        password = storageArray[1]
        GUID = hasher(username)

        encryptionPass = AESkeygen(password)
        try:
            jsonHolder = decryptKeyFile(encryptionPass)

        except ValueError:
            print("Incorrect Password")
            Launcher()

        activeKeyDict = json.loads(jsonHolder)
        
        
      
        if GUID != activeKeyDict["GUID"]:
            print("Wrong Username")
            Launcher()

        elif GUID == activeKeyDict["GUID"]:
            print("Correct Username")

        KeyCompare()
        
    else:
        print("You are new.")
        
        print("Making new account")

    
        storageArray = acctMake()

        username = storageArray[0]

        password = storageArray[1]

        GUID = hasher(username)

        keylist = ECCkeygen()
        #this generates ECC keys

        makeKeyFile()
        ## this funciton makes a new keyfile and writes to it.

        encryptionPass = AESkeygen(password)
        #this turns our password into a key for our keybault

        EncryptKeyFile(encryptionPass)

Launcher()

#username = getUserName()

#GUID = hasher(username)

#password = passwordMake()

#encryptionPass = AESkeygen(password)

#Index 0 is private index 1 is public

#keylist = ECCkeygen()

#EncryptKeyFile(encryptionPass) ## also deletes the plaintext keyfile #todo elim the plaintext from existing as a thing in disk

symKey = SecureKeyGen() #symKey is our one time use symetric salsa20 key

symCrypt('I am a jelly donut', symKey)


decryptKeyFile(encryptionPass)
##this function loads a copy of the keyfile from disk into ram. must build a perent funditon to convert json to a disciotnary



##Test Our functions before we organize them into a beautiful flow. This is the stage we are in. 
##TODO decrypt salsa20 messages. Also make the salsa20 into nice organized JSON files for transfer over the 'Net