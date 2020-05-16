import asyncio

from urllib.request import urlopen

import re


from datetime import datetime
#this module enables us to get a timestamp

import random

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

from termcolor import colored #Lets Us print pretty colors


keyfileChecksum = ""
#this holds a checksum of the keyfile
username = ""
##this is our plaintext username
password = ""
##this is our hashed password
encryptionPass = ""
#sha256 hashed aes ecrtuption pass
bucketNumber = []
##bucket number is the bucket we belong to defaults to. We will store our bucket ID in the keyFile
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

SimulatedBluezelle = {}
##This Is a simulatede bluezelle



def MOTD():
    print("*******************************************************")
    print(colored("\n####################################################", 'red'))
    print(colored("\n________-____________ScryP2P____________________-________", 'green'))
    print("\n")
    print(colored("\n  _________                    ____________________________ ", 'red'))
    print(colored("\n /   _____/ ___________ ___.__.\______   \_____  \______   \ ", 'red'))
    print(colored('\n \_____  \_/ ___\_  __ <   |  | |     ___//  ____/|     ___/', 'red'))
    print(colored('\n /        \  \___|  | \/\___  | |    |   /       \|    |    ', 'red'))
    print(colored('\n/_______  /\___  >__|   / ____| |____|   \_______ \____|    ', 'red'))
    print(colored('\n        \/     \/       \/                       \/         ', 'red'))
    print(colored('\n##############################################################', 'red'))
    print(colored('\n__________Free speech is the Way To a Better Tommorrow________', 'green'))
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
    
    print(colored("Please input a username", "yellow"))
    
    uname = input()
    
    print(colored("Please input your password", "yellow"))

    passWd = input()

    loginCreds = []
    #logincreds 0 is username, logincreds 1 is password
    loginCreds.append(uname)
    #passWd = hasher(passWd)
    loginCreds.append(passWd)

    return loginCreds

def setPass():


    passWd = ""
    tempVar = ""
    print(colored("\nEnter a unique password, PROTIP: Combine 3 random words EG. PlungerMasterLamp", 'yellow'))
    passWd= input()

    print(colored("\nEnter your password again to Confirm", 'yellow'))

    tempVar = input()

    if tempVar == passWd:
        
        return passWd

    else:
        print(colored("ERROR: Passwords do not match", 'red'))
        passWd = setPass()
        return passWd


def acctMake():
    #this function gets the password from the user and hashes it
    uname= ""
    passWd = ""

    print(colored('Please Enter a unique UserName. Randomize your handles fool!', 'yellow'))
    
    uname = input()

    while userNameCheck(uname):
        #this should check if the username exists
        print(colored("ERROR USERNAME IN USE", 'green'))

        print(colored('Please Enter a unique UserName. Randomize your handles fool!', 'yellow'))
    
        uname = input()

    passWd = ""

    passWd = setPass()
    
    if passWd == "":
        setPass()

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
    json_out = {'GUID': GUID, 'BucketNumber' : bucketNumber[0], "ToServerCommsPkey" : ToServerPubkeys,
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

    #print(f"keyfileChecksum from file reads {keyfileChecksum}")
    
    ActiveCopyChecksum = str(activeKeyDict)
    
    activeKeyFileChecksum = hasher(ActiveCopyChecksum)

    if keyfileChecksum == activeKeyFileChecksum:
        #checksum of the keyfile in ram is compared to the checksum loaded from the encrypted file representing its keyfile
        print(colored("*", "yellow"))
        #print("everything is equal")
        
    else:
        print("Mismatch, Updating keyfile")
    #checksum of the one in ram is compared to the checksum loaded from the encrypted file

def EncryptKeyFile(keyString, bucketNumber):
    
    output_file = 'encrypted.owo'
    ToServerPubkeys = {"5/5/2020": "EccKey(curve= 'NIST P-521', point_x=1486465573938105822939004727077225179207099868113689171560681110264144705867423089183409181099797550085162698222601473208419282328197990992286367867277705139, point_y=5654383155596243396760237022173794653643096895890268988991343331019372753219888195890427812417285738948770838211075050279059652646721707744785732717512902299)"}
    
    fromServerPrivKey = {"5/5/2020" : "ECC private KEY PLACEHOLDER"}
    
    data = {'GUID': GUID, 'BucketNumber' : bucketNumber[0], "ToServerCommsPkey" : ToServerPubkeys,
     "privateKeysFromServer": fromServerPrivKey, 
     "sessionPubKeys": "NESTED DICTIONARY OF KEYS IDed by DestinationGUID, containting a NESTED DICTIONARY OF KEYS WITH THEIR 64 bit token key and the value as the pubkey ", 
     "sessionPrivKeys": "a key value nested dictionary with the 64 bit sesion tokens+Destination GUID" }
     
    global activeKeyDict

    activeKeyDict = data
     
     #this stores this copy in ram for working with for our initial startup

    

    FormattedJson = str(data)
    #here we make the data into a string so we can hash it

    keyfileChecksum = hasher(FormattedJson)

    data = json.dumps(data)
    #data = FormattedJson

    data = data.encode('utf-8')



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

    #os.remove('clientsideData.txt')
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

    #OGdata = original_data.decode('utf-8').replace("'", '"')

    
    return original_data



async def sendActive():
    
    #this is a fucntion that will send the username to bluzelle every 5 mins to let them know we are in the swarm, what node we are
    #on and the whole 9. Will be using our tunneling/encryption scheme in a pretty funtion
    sleep(300)
    global bucketNumber

    global keylist
    timestamp = generateTimestamp()
    #this generates a timestamp in seconds since unix epoch
    stringKeys = str(keylist[1])
    print("Now appending public Key and GUID with timestamp to the dictionary")
    #TODO include way to count entries and add our number here eg users(guid) or user1, user2
    users = {"GUID": GUID, "PublicKey": stringKeys, "TimeStamp": timestamp, "BucketNumber": bucketNumber[0]}
    
    container = {f"user{GUID}": users}

    ## we will call a func to see if this entry exists. This will determine if we can connect. 
    # on the make we must check GUID against usrers
    if os.path.exists("FakeBlu.txt"):

        with open('FakeBlu.txt') as FileLoad:
            input_json = json.load(FileLoad)
            #DebuggingStat  print(f'heres input_json {input_json}')

            input_json.update(container)
            ##DebuggingStatment print(f"inside update = {input_json}")
        FileLoad.close()

        with open('FakeBlu.txt', 'w') as FakeBlu:
            json.dump(input_json, FakeBlu)
        FakeBlu.close()
            #FileLoad.write(updatedJson)
            ##json.dump(container, FakeBlu)
        print(f"sending key {username}'s update timetamp to bluezelle")

    else:
        print('Network Connection Lost')

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
 
def userNameCheck(username):
    AlreadyInUse = False
    #this is the varible to return based on if we can use the username or not false means we can use it
    if os.path.exists("FakeBlu.txt"):
        testGUID = hasher(username)
        #we hash the username into a GUID

        with open('FakeBlu.txt') as FileLoad:
            input_json = json.load(FileLoad)
        
        try:

            Localkey = input_json[f"user{testGUID}"]
            print("Username In use")
            return True

        except KeyError:
            
            print("username not in use")

            return False

        except json.decoder.JSONDecodeError:
            print("Network Corruption, Contact a SysAdmin")
            return True

    else:
        print("Nobody currently on network/ network unavailible")

        return False


def Launcher():
    #this is our initialization it detects if the keyvault exist and logs in and decrypts 
    MOTD()
    global GUID
    global username
    global password
    global encryptionPass
    global keylist
    global activeKeyDict
    global bucketNumber
    
    jsonHolder =  ""
    storageArray = []
    if os.path.exists("encrypted.owo"):
        #we test if a keyvault exists
        print("You are not a new user. Please Login.")
        
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
        #print(f"jsonHolder is {jsonHolder}")

        activeKeyDict = json.loads(jsonHolder)

        
        
      
        if GUID != activeKeyDict["GUID"]:
            print("Wrong Username")
            Launcher()

        GUID = activeKeyDict["GUID"]
        bucketNumber.append(activeKeyDict["BucketNumber"])

        NetworkAnnounce(bucketNumber)
        BucketAnnounce(bucketNumber)

        KeyCompare()
        #this tests if the copy in memory is newer than the file on disk
        
    else:
        print("You are new. Welcome to ScryP2P.")
        
        print("Making new account")
        
        
        bucketNumber = GetBucket()

        
        storageArray = acctMake()

        
        

        username = storageArray[0]

        password = storageArray[1]

        GUID = hasher(username)

        keylist = ECCkeygen()
        #this generates ECC keys

        #makeKeyFile()
        ## this funciton makes a new keyfile and writes to it.
        NetworkAnnounce(bucketNumber)
        #Here we use this func to add our user to the swarm, under one simulated NOSQL key
        BucketAnnounce(bucketNumber)
        #here we add our Bucket info to the NoSQL DB and add our IP to the bucket
        encryptionPass = AESkeygen(password)
        #this turns our password into a key for our keybault

        EncryptKeyFile(encryptionPass, bucketNumber)

def GetBucket():
    #here we read availible "buckets" and their populations from the network.
    # if network population is above 150 we make a new bucket, and become a member of 2 buckets until our new active bucket
    # population is at least 50.  When we make a new Bucket the 2nd bucket will only list GUIDS until pop = 50. If no bucket is found we make a new one. When we generate a bucket code we use a 64Bit
    #Random Number and return it in an array. The array will only have one index if we are not members of 2 buckets. 
    #security can be further enhanced by connecting via a VPN/Mullvad/I2P (future improvment)
    AlreadyBucket = False
    #this is a boolean we use to test if we already belong to a bucket
    finalBucket = []
    #this is the array we use to return the bucket we are going to use
    BucketList = []
    global bucketNumber
    #this is the bucket that we belong to
    try:
        bucketNumber.append(activeKeyDict["BucketNumber"])

        print("Found bucket number within keyfile")
        #todo check
        AlreadyBucket = True

    except KeyError:
        print(colored("~~~~~~~~~~~~~", "yellow"))

    except IndexError:
        print(activeKeyDict["BucketNumber"])
        print("No bucket ID found from the keyfile")
        
    if len(bucketNumber) != 0:


        AlreadyBucket = True

    while AlreadyBucket == True:
        print(colored("You already belong to bucket. Do you want to join a new one? (Y/N).", "yellow"))
        userResponse = input()
        if userResponse == "Y":
            AlreadyBucket = False
        else:
            print(colored("Using your current bucket.", "green"))
            finalBucket.append(bucketNumber)
            return finalBucket
    if os.path.exists("FakeBlu.txt"):
        print(colored("***********", 'red'))

    else:
         ## if no buckets are found we will generate a 64 bit bucket ID, test to make sure it is not in use and use it.
        ## we will use another function to fill out a "buckets section" in the key value store"
            randomID = (get_random_bytes(32))
            bucketID = randomID.hex()
            #bucketID = (hasher(bucketID))
            #print(f"New bucket ID before testing for conflicts is {bucketID}")
            #print(f"Characters in ID is {len(bucketID)}")
        
            finalBucket.append(bucketID)

            return finalBucket

    if AlreadyBucket == False:
        


        with open('FakeBlu.txt', 'r') as UserList:
            #here we would be openiong our file containing json data (Fake Bluzelle)
            data = json.load(UserList)
            #here we load the json data
            UserList.close()

        for key in data:
            #we iteratew thru the toplevel keys her
            scope = data[key]
            try:
            #here we narrow the scop so we can get inside nested dictionaries
                stamp = scope["BucketNumber"]
                time = scope['TimeStamp']
        
                currentTime = generateTimestamp()
                # here we Look for buckets with users online in them
                if time < (currentTime - 5000):
                ## here we are documenting what users are online
                    print(colored(f"Bucket number {stamp} found with offline users", 'blue'))

                else:
                    print(colored(f"Bucket number {stamp} is found with online useres", 'yellow'))
                    BucketList.append(stamp)
                    #this appends active users to a list
            except KeyError:
                continue

        #print(onlineUserList)
        print(colored(f"There are {len(BucketList)} availible buckets", 'blue'))
        if len(BucketList) == 0:
        ## if no buckets are found we will generate a 64 bit bucket ID, test to make sure it is not in use and use it.
        ## we will use another function to fill out a "buckets section" in the key value store"
            randomID = (get_random_bytes(32))
            bucketID = randomID.hex()
            #bucketID = (hasher(bucketID))
            print(f"New bucket ID before testing for conflicts is {bucketID}")
            #print(f"Characters in ID is {len(bucketID)}")
        
            finalBucket.append(bucketID)

        if len(BucketList) > 1:
        #here we will also refine the bucketList to only buckets with populations between 50 and 100, if none are found,
        #we will simply use the bucket with the highest population availible
            contents = (len(BucketList) - 1)
            usefulNumber = random.randint(0,contents)
            finalBucket.append(BucketList[usefulNumber])

        elif len(BucketList) == 1:
            finalBucket = BucketList
    #no matter if we find a Bucket to belong to we will either use an existing one or return one
    
    return finalBucket

def generateTimestamp():
    TimeStamp = datetime.now().timestamp()
    #this function outputs a timestamp in seconds since unix epoch

    return TimeStamp


def getPublicIp():
    #this function gets our pulic ip by hitting a webpage

    data = str(urlopen('http://checkip.dyndns.com/').read())
    

    ipstring = re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1)

    return ipstring


def getBucketIPArray(bucketNumber):
    #TODO make list called IpArray, for us to send to. also Do not allow duplicate IPs within the list
    ipList = []
    onlineMemberList = []
    if os.path.exists("BluBucket.txt"):
        #here we open the file
        with open('BluBucket.txt') as FileLoad:
            input_json = json.load(FileLoad)
            #DebuggingStat  print(f'heres input_json {input_json}')
            FileLoad.close()#new

            refined = input_json[f"bucket{bucketNumber[0]}"]
            scope = refined["Members"]
            print("hey bro heres scope stuff")
            currentTime = generateTimestamp()
            for x in scope:

                ipList.append(x)
                
                
                time = x["TimeStamp"]
                onlineIPs = x["ip"]

                if time > (currentTime -3000):
                    onlineMemberList.append(onlineIPs)
            

            print(f"\nIn bucket {bucketNumber} there are currently {len(onlineMemberList)}/{len(ipList)} members online")
            print(f"the following IPs are online: {onlineMemberList}")
            return ipList
    else:
        print("try Again broski, nobody else has been here")
        return ipList

def BucketAnnounce(bucketNumber):
    global GUID
    global keylist
    
    #print(bucketNumber)
    #print(f"len of bucketNumber is {len(bucketNumber)}")
    

    if len(keylist) == 0:
        keylist = ECCkeygen()

    if len(bucketNumber) == 0:
        bucketNumber.append(activeKeyDict['BucketNumber'])

    timestamp = generateTimestamp()
    #print(keylist)
    #this generates a timestamp in seconds since unix epoch
    #print(f'this is keylist1 {keylist[1]}')
    stringKeys = str(keylist[1])
    print("Adding Bucket Info to Bucket-Block")
    #TODO include way to count entries and add our number here eg users(guid) or user1, user2
    print(f'bucket number is {bucketNumber}')
    ip = getPublicIp()
    
    #this function gets our publicly facing IP even behind a SOHO/ NAT

    
    MemberInfo = {"ip": ip, "TimeStamp": timestamp}

    MemList= []

    MemList = getBucketIPArray(bucketNumber)
    
    MemList.append(MemberInfo)

    bucketJson = {"BucketNumber": bucketNumber[0], "Members": MemList}
    bucketContainer = {f"bucket{bucketNumber[0]}": bucketJson}

    #this is going to be written to our FakeBluZelleBucket.txt, this is simalating another key in the value store being used
    #for this part be ause this is a second json object. When we get what bucket A user belongs to we can search for key
    # "bucket{DestinationBucketNumber}" we can count population by kounting how many values are stored under key "members"
    #like this. Searchbucket = bucketContainer[f"bucket{bucketNumber}"]
    # populationList = (Searchbucket["Members"]).count()
    # This should return how many are in the bucket to build the local bucket file from. We will save the IPs+ timestamps locally in ram
    # and update every 5 minutes we will add a 1 minute degree of randomness to how we update our 
    # timestamp to help security when we logout. We might also make buckets bigger depending on latency


    ## we will call a func to see if this entry exists. This will determine overwrite or not. 
    # on the make we must check GUID against usrers
    if os.path.exists("BluBucket.txt"):

        with open('BluBucket.txt') as FileLoad:
            input_json = json.load(FileLoad)
            #DebuggingStat  print(f'heres input_json {input_json}')

            input_json.update(bucketContainer)
            ##DebuggingStatment print(f"inside update = {input_json}")
        FileLoad.close()
       ##debuggingStatment print(f"here is outside {input_json}")

        with open('BluBucket.txt', 'w') as BucketBlu:
            json.dump(input_json, BucketBlu)
        BucketBlu.close()
            #FileLoad.write(updatedJson)
            ##json.dump(container, FakeBlu)
        print("Successful Network Update")
        
    else:
        with open('BluBucket.txt', 'w+') as BucketBlu:
            json.dump(bucketContainer, BucketBlu)
        BucketBlu.close()
    
    print("We have Updated the Bucket Data")

def NetworkAnnounce(bucketNumber):
    #this function announces us to the network. We will use the Bluzelle announce function to continually update timestamp
    #we will also pull all of our data from here for other nodes
    global GUID
    global keylist
    
    #print(bucketNumber)
    #print(f"len of bucketNumber is {len(bucketNumber)}")
    

    if len(keylist) == 0:
        keylist = ECCkeygen()

    if len(bucketNumber) == 0:
        bucketNumber.append(activeKeyDict['BucketNumber'])

    timestamp = generateTimestamp()
    #print(keylist)
    #this generates a timestamp in seconds since unix epoch
    #print(f'this is keylist1 {keylist[1]}')
    stringKeys = str(keylist[1])
    print("Now appending public Key and GUID with timestamp to the dictionary")
    #TODO include way to count entries and add our number here eg users(guid) or user1, user2
    #print(f'bucket number is {bucketNumber}')

    users = {"GUID": GUID, "PublicKey": stringKeys, "TimeStamp": timestamp, "BucketNumber": bucketNumber[0]}
    container = {f"user{GUID}": users}

    ## we will call a func to see if this entry exists. This will determine overwrite or not. 
    # on the make we must check GUID against usrers
    if os.path.exists("FakeBlu.txt"):

        with open('FakeBlu.txt') as FileLoad:
            input_json = json.load(FileLoad)
            #DebuggingStat  print(f'heres input_json {input_json}')

            input_json.update(container)
            ##DebuggingStatment print(f"inside update = {input_json}")
        FileLoad.close()
       ##debuggingStatment print(f"here is outside {input_json}")

        with open('FakeBlu.txt', 'w') as FakeBlu:
            json.dump(input_json, FakeBlu)
        FakeBlu.close()
            #FileLoad.write(updatedJson)
            ##json.dump(container, FakeBlu)
        print("Successful Network Update")
        
    else:
        with open('FakeBlu.txt', 'w+') as FakeBlu:
            json.dump(container, FakeBlu)
        FakeBlu.close()
    
    print("we are now on network")

def GetOnlineUsers():
    #this is a procces that will be async and check if a user is online within the swarm and return a list of onlineUsers in swarm

    onlineUserList = []
    #this is a list of our online users

    with open('FakeBlu.txt', 'r') as UserList:
        #here we would be openiong our file containing json data (Fake Bluzelle)
        data = json.load(UserList)
        #here we load the json data
        UserList.close()

    for key in data:
        #we iteratew thru the toplevel keys her
        scope = data[key]
        #here we narrow the scop so we can get inside nested dictionaries
        stamp = scope["TimeStamp"]
        userID = scope['GUID']
        currentTime = generateTimestamp()
        if stamp < (currentTime - 5000):
           ## here we are documenting what users are online
            print(colored(f"User {userID} is offline", 'red'))

        else:
            print(colored(f"User {userID} is online", 'green'))
            onlineUserList.append(userID)
    #this appends active users to a list

    #print(onlineUserList)
    print(colored(f"there are {len(onlineUserList)} users in swarm", 'blue'))
    #these are debugging statments but they show how many users in swarm this canbe used for an interface in our website.
    #in prod this func will be async.
    return(onlineUserList)


Launcher()

GetOnlineUsers()
#username = getUserName()

#GUID = hasher(username)

#password = passwordMake()

#encryptionPass = AESkeygen(password)

#Index 0 is private index 1 is public

keylist = ECCkeygen()

#EncryptKeyFile(encryptionPass) ## also deletes the plaintext keyfile #todo elim the plaintext from existing as a thing in disk

symKey = SecureKeyGen() #symKey is our one time use symetric salsa20 key

symCrypt('I am a jelly donut', symKey)

#NetworkAnnounce()

#GetBucket()
##Test Our functions before we organize them into a beautiful flow. This is the stage we are in. 
##TODO decrypt salsa20 messages. Also make the salsa20 into nice organized JSON files for transfer over the 'Net