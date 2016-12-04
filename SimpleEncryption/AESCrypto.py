from Crypto.Cipher import AES
from SimpleEncryption.Utils import Utils
from SimpleEncryption.XOR import XOR
from Encoding.Pkcs7 import Pkcs7
from Encoding.Json import Json
import io
import os
import random


class AESCrypto:
    keySize = 16
    oracle2key = None
    unknownData12 = None
    prefixDataCh14 = None
    oracle = None
    cookieCh16Key = None
    cookieCh16IV = None

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
        """Generates random key of size bytes"""
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

    def encryptionOracleCh12(self, data):
        if self.oracle2key == None:
            self.oracle2key = AESCrypto.generateRandomAESKey(AESCrypto.keySize)
        dataPrepared = Pkcs7.pkcs7Padding(data + AESCrypto.unknownData12, self.keySize)
        mode = AES.MODE_ECB
        encrypted = AESCrypto.encryptEBCAES(self.oracle2key, dataPrepared)
        return {'data': encrypted, 'mode': mode}

    def detectBlockSizeAES(self):
        count = 1
        lengthCleanBlock = len(self.oracle(self, b"")["data"])
        while True:
            toBeEncrypted = b"A" * count
            newBlock = self.oracle(self, toBeEncrypted)
            if  lengthCleanBlock != len(newBlock["data"]):
                return len(newBlock["data"]) - lengthCleanBlock
            count += 1

    def findOutFirstByte(self, knownData, blockSize, prefixLength):
        component1 =  blockSize - (prefixLength%blockSize)
        component2 = blockSize - (len(knownData) % blockSize) -1
        component3 = prefixLength - (prefixLength % blockSize)

        myBlock = b"A" * (component1 + component2)
        toBeEncrypted = myBlock
        encryptedInputBlock = self.oracle(self, toBeEncrypted)["data"]
        for i in range(256):
            potentialCharacter = bytes([i])
            potentialMatchingBlock = self.oracle(self, myBlock + knownData + potentialCharacter)["data"]\
                [component3+component1:component3+component1+component2 + len(knownData) + 1]#+ len(myBlock + knownData + potentialCharacter)]
            if (potentialMatchingBlock in encryptedInputBlock[component3+component1:] ):
                return potentialCharacter
        return b""

    def breakAESECBSimple(self):
        blockSize = self.detectBlockSizeAES(self)
        detectedPrefixLenght = AESCrypto.detectInitialBytesLength(AESCrypto, blockSize)
        detectedString = b""
        detectedByte = None
        while detectedByte != b"":
            detectedByte = self.findOutFirstByte(self, detectedString, blockSize, detectedPrefixLenght)
            detectedString = detectedString + detectedByte
        return Pkcs7.removePkcs7Padding(detectedString, AESCrypto.keySize)


    def generateRandomSizedRandomBytes(self):
        return os.urandom(random.randrange(8,300))

    def encryptionOracleCh14(self, data):
        if self.oracle2key == None:
            self.oracle2key = AESCrypto.generateRandomAESKey(AESCrypto.keySize)

        if self.prefixDataCh14 == None:
            self.prefixDataCh14 = AESCrypto.generateRandomSizedRandomBytes(self)

        dataPrepared = Pkcs7.pkcs7Padding(self.prefixDataCh14 + data + self.unknownData12, self.keySize)
        mode = AES.MODE_ECB
        encrypted = AESCrypto.encryptEBCAES(self.oracle2key, dataPrepared)
        return {'data': encrypted, 'mode': mode}

    def hasEqualBlock(self, blocks, blockCount):
        for i in range (blockCount + 3):
            if blocks[i] == blocks[i+1]:
                return True
        return False



    def detectInitialBytesLength(self, blockSize):
        Blockcount = 0
        cleanBlock = self.oracle(self, b"")["data"]
        newBlock = self.oracle(self, b"A")["data"]
        #find out total blocks
        while cleanBlock[blockSize*Blockcount : blockSize * (Blockcount+1)] == newBlock[blockSize*Blockcount : blockSize * (Blockcount+1)]:
            Blockcount += 1

        length = Blockcount * blockSize

        #Detect length of bytes within the fragmented block.
        for i in range (blockSize):
            toBeEncrypted = b"A" * (2* blockSize + i)
            newBlock = self.oracle(self, toBeEncrypted)
            blocks = Utils.splitData(newBlock["data"], blockSize)
            if self.hasEqualBlock(self, blocks, Blockcount):
                if i == 0:
                    break
                length +=  blockSize - i
                break
        return length


    def encryptCookieString(self, myString):
        cookieString = Utils.appendCookieStringAround(Utils, myString)
        self.cookieCh16Key = self.generateRandomAESKey(AESCrypto.keySize)
        self.cookieCh16IV = self.generateRandomAESKey(AESCrypto.keySize)
        return self.encryptCBCAES(self.cookieCh16IV, self.cookieCh16Key, bytes(cookieString, "ascii"))

    def decryptDetectAdminTrue(self, encryptedData):
        decryptedData = self.decryptCBCAES(self.cookieCh16IV, self.cookieCh16Key, encryptedData)
        return False if decryptedData.find(b";admin=true;") == -1 else  True

