class Utils:
    def characterFrequency(textToCheck):
        frequentChars = "ETAOIN SHRDLU"
        result = 0
        for letter in frequentChars:
            result += textToCheck.count(letter)
        return result / len(textToCheck)

    def hammingDistance(firstBytearray, secondBytearray):
        resultHamming = 0
        if (len(firstBytearray) != len(secondBytearray)):
            raise ValueError("The length of the two arguments was not the same")
        for first, second in zip(firstBytearray, secondBytearray):
            xorResult = first ^ second
            mask = 0x80
            for i in range(8):
                if (mask & xorResult):
                    resultHamming += 1
                mask = mask >> 1
        return resultHamming

    def getAvgHammingDist(byteArray, keySize):
        hammDists = []
        numberOfBlocks = int(len(byteArray) / keySize)
        for i in range(numberOfBlocks - 1):
            subTrace1 = byteArray[i * keySize:(i * keySize) + keySize]
            subTrace2 = byteArray[(i * keySize) + keySize:(i * keySize) + (2 * keySize)]
            hammDists.append(Utils.hammingDistance(subTrace1, subTrace2) / keySize)
        return sum(hammDists) / len(hammDists)

    def getKeySize(byteInput):
        keySize = 2
        avgDistMap = {}
        while keySize <= 40:
            avgDistMap[keySize] = Utils.getAvgHammingDist(byteInput, keySize)
            keySize += 1
        return min(avgDistMap, key=avgDistMap.get)

    def splitData(data, size):
        splittedData = []
        for i in range(0, len(data), size):
            splittedData.append(data[i:i + size])
        return splittedData