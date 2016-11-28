import binascii
import os
import random
import io
import re
from Crypto.Cipher import AES

def pkcs7Padding(data, blockSize):
    modulus = blockSize - (len(data) % blockSize)
    if modulus != 0:
        for i in range(modulus):
            data = data + bytes([modulus])
    return data


def splitData (data) :
    splittedData = []
    n=16
    for i in range(0, len(data), n):
        splittedData.append(data[i:i+n])
    return splittedData


def decryptECBAESFromBase64(key, data):
    cipher =  AES.new(key, AES.MODE_ECB)
    byteInput = bytearray.fromhex(base64ToHex(data))
    return cipher.decrypt(bytes(byteInput))


def decryptECBAES(key, data):
    cipher =  AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(bytes(data))

def encryptEBCAES(key, data):
    cipher =  AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def encryptCBCAES(IV, key, data):
    cipher =  AES.new(key, AES.MODE_ECB)
    splittedData = splitData(data)
    encryptedSegmentedData = []
    previousBlock = IV
    for segment in splittedData:
        xord = fixedXor(previousBlock, segment)
        previousBlock = cipher.encrypt(bytes(xord))
        encryptedSegmentedData.append(previousBlock)

    return b''.join(encryptedSegmentedData)


def decryptCBCAES(IV, key, data):
    cipher =  AES.new(key, AES.MODE_ECB)
    splittedEncryptedData = splitData(data)
    decryptedSegmentedData = []
    previousBlock = IV
    for segment in splittedEncryptedData:
        decryptedSegmentedData.append(fixedXor(cipher.decrypt(segment), previousBlock))
        previousBlock = segment

    return b''.join(decryptedSegmentedData)

def generateRandomAESKey():
    """Generates random key of 16 bytes"""
    return os.urandom(16)

def encryptionOracle (data):
    key = generateRandomAESKey()
    dataPrepared = pkcs7Padding(os.urandom(random.randint(5,10)) + data + os.urandom(random.randint(5,10)), 16)
    encrypted = ''
    if random.randrange(2) == 0:
        print("Encrypt with ECB")
        encrypted = encryptEBCAES(key, dataPrepared)
    else:
        print("Encrypt with CBC")
        IV = generateRandomAESKey()
        encrypted = encryptCBCAES(IV, key, dataPrepared)

    return encrypted


def getEBCScore(trace, keySize):
    currentBlock = 0
    score = 0
    while currentBlock < len(trace):
        currentCipher = trace[currentBlock:(2*keySize)+currentBlock]
        currentBlock+=2*keySize
        for n in re.finditer(re.escape(currentCipher), trace):
            score+=1
        # score-=1
    return score

def detectECB(encrypted, blockSize):
    if getEBCScore(encrypted, blockSize) > 0:
        return "EBC"
    else:
        return "CBC"



def findECBTrace2(inputFile):
    buf = io.StringIO(inputFile)
    keySize = 16
    traceScore = {}
    for line in buf:
        line = line.replace('\n','')
        traceScore[line] = getEBCScore(line, keySize)
    return(traceScore)

if __name__ == '__main__':
    print(getEBCScore("datadatadatadatadatadatadatadata1234567890123456datadatadatadatadatadatadatadata1234567890123456", 16))
    # print(EBCScore("datadatadatadatadatadatadatadata1234567890123456", 8))
