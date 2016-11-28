from Crypto.Cipher import AES
from SimpleEncryption.Utils import Utils
from SimpleEncryption.XOR import XOR
from Encoding.Pkcs7 import Pkcs7
from enum import Enum
import io
import os
import random


class AESCrypto:
    keySize = 16
    oracle2key = None

    def decryptECBAES(key, data):
        cipher = AES.new(key, AES.MODE_ECB)
        return Pkcs7.removePkcs7Padding(cipher.decrypt(data), AESCrypto.keySize)

    def encryptEBCAES(key, data):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(Pkcs7.pkcs7Padding(data, AESCrypto.keySize))

    def getEBCScore(trace, keySize):
        score = 0
        dataList = Utils.splitData(trace, keySize)
        for dataBlock in dataList:
            score += dataList.count(dataBlock) -1
        return score


    def findAESECBFromFile (inputFile):
        buf = io.StringIO(inputFile)
        traceScore = {}
        for line in buf:
            line = bytes.fromhex(line.replace('\n', ''))
            traceScore[line] = AESCrypto.getEBCScore(line, AESCrypto.keySize)
        return (max(traceScore, key=traceScore.get))

    def encryptCBCAES(IV, key, data):
        paddedData = Pkcs7.pkcs7Padding(data, AESCrypto.keySize)
        cipher = AES.new(key, AES.MODE_ECB)
        splittedData = Utils.splitData(paddedData, AESCrypto.keySize)
        encryptedSegmentedData = []
        previousBlock = IV
        for segment in splittedData:
            xord = XOR.fixedXor(previousBlock, segment)
            previousBlock = cipher.encrypt(bytes(xord))
            encryptedSegmentedData.append(previousBlock)

        return b''.join(encryptedSegmentedData)

    def decryptCBCAES(IV, key, data):
        cipher = AES.new(key, AES.MODE_ECB)
        splittedEncryptedData = Utils.splitData(data, AESCrypto.keySize)
        decryptedSegmentedData = []
        previousBlock = IV
        for segment in splittedEncryptedData:
            decryptedSegmentedData.append(XOR.fixedXor(cipher.decrypt(segment), previousBlock))
            previousBlock = segment

        return Pkcs7.removePkcs7Padding(b''.join(decryptedSegmentedData), AESCrypto.keySize)

    def generateRandomAESKey(size):
        """Generates random key of 16 bytes"""
        return os.urandom(size)

    def encryptionOracle(data):
        key = AESCrypto.generateRandomAESKey(AESCrypto.keySize)
        dataPrepared = Pkcs7.pkcs7Padding(os.urandom(random.randint(5, 10)) + data + os.urandom(random.randint(5, 10)), 16)
        encrypted = ''
        mode = None
        if random.randrange(2) == 0:
            mode = AES.MODE_ECB
            encrypted = AESCrypto.encryptEBCAES(key, dataPrepared)
        else:
            mode = AES.MODE_CBC
            IV = AESCrypto.generateRandomAESKey(AESCrypto.keySize)
            encrypted = AESCrypto.encryptCBCAES(IV, key, dataPrepared)

        return {'data': encrypted, 'mode': mode}

    def detectECB(encrypted):
        if AESCrypto.getEBCScore(encrypted, AESCrypto.keySize) > 0:
            return AES.MODE_ECB
        else:
            return AES.MODE_CBC

    def encryptionOracleNumber2(self, data):
        if self.oracle2key == None:
            self.oracle2key = AESCrypto.generateRandomAESKey(AESCrypto.keySize)
        dataPrepared = Pkcs7.pkcs7Padding(data, self.keySize)
        mode = AES.MODE_ECB
        encrypted = AESCrypto.encryptEBCAES(self.oracle2key, dataPrepared)
        return {'data': encrypted, 'mode': mode}

    def detectBlockSizeAES(self, unknownData):
        blockSize = 1
        previousEncryptedBlock = ""
        while blockSize < 200:
            toBeEncrypted = b"A" * blockSize + unknownData
            newBlock = self.encryptionOracleNumber2(self, toBeEncrypted)
            if newBlock["data"][0:blockSize-1] == previousEncryptedBlock[0:blockSize-1]:
                return blockSize - 1
            previousEncryptedBlock = newBlock["data"]
            blockSize += 1

    def findOutFirstByte(self, knownData, unknownData, blockSize):
        numberOfUpfrontPadding = blockSize - (len(knownData) % blockSize) - 1
        myBlock = b"A" * numberOfUpfrontPadding
        toBeEncrypted = myBlock + unknownData
        encryptedInputBlock = self.encryptionOracleNumber2(self, toBeEncrypted)["data"]
        for i in range(256):
            potentialCharacter = bytes([i])
            potentialMatchingBlock = self.encryptionOracleNumber2(self, myBlock+knownData+potentialCharacter)["data"][0: len(myBlock+knownData+potentialCharacter)]
            if (potentialMatchingBlock in encryptedInputBlock ):
                return potentialCharacter



    def breakAESECBSimple(self, unknownData):
        blockSize = self.detectBlockSizeAES(self, unknownData)
        detectedString = b""
        while len(detectedString) < len(unknownData):
            detectedString += self.findOutFirstByte(self, detectedString, unknownData, blockSize)
        return detectedString

