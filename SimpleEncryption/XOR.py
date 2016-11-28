from SimpleEncryption.Utils import *
import binascii

class XOR:

    def fixedXor(firstString, secondString):
        xorResult = bytearray()
        if (len(firstString) != len(secondString)):
            raise ValueError("firstString and secondString have different Lengths")
        i = 0
        while i < len(firstString):
            xorResult.append(firstString[i] ^ secondString[i])
            i = i + 1
        return xorResult

    def decypherXor(data):
        resultMap = {}
        i = 0x00
        while i <= 0xff:
            decyphered = bytearray()
            for byte in data:
                decyphered.append(byte ^ i)
            i = i + 1
            try:
                resultMap[decyphered.decode("ascii")] = Utils.characterFrequency(decyphered.decode("ascii").upper())
            except UnicodeDecodeError:
                pass
        if (len(resultMap) > 0):
            resultString = max(resultMap, key=resultMap.get)
            return {resultString: resultMap[resultString]}
        else:
            return {}

    def getDecryptedStringFromFile(encryptedFile):
        aggregatedResults = {}
        for line in encryptedFile:
            aggregatedResults.update(XOR.decypherXor(bytearray.fromhex(line.replace('\n', ''))))
        resultString = (max(aggregatedResults, key=aggregatedResults.get))
        return resultString

    def xorEncrypt(key, data):
        i = 0
        dataByte = data
        keyByte = key
        encryptedData = bytearray()
        while i < len(dataByte):
            for char in keyByte:
                if i < len(dataByte):
                    encryptedData.append(dataByte[i] ^ char)
                i += 1
        return encryptedData

    def breakXor(byteInput):
        resultString = ""
        keySize = Utils.getKeySize(byteInput)
        print(keySize)
        decryptedColumn = {}
        for keyByte in range(keySize):
            charIndex = 0
            transposedColumn = bytearray()
            while charIndex < len(byteInput):
                try :
                    transposedColumn.append(byteInput[charIndex+keyByte])
                except IndexError:
                    break
                charIndex+=keySize
            decryptedColumn[keyByte]=list(XOR.decypherXor(transposedColumn))[0]
        for i in range(len(decryptedColumn[0])):
            for keyIndex in range(keySize):
                try:
                    resultString+=decryptedColumn[keyIndex][i]
                except IndexError:
                    pass
        return (resultString)