class Pkcs7:

    def pkcs7Padding(data, blockSize):
        modulus = blockSize - (len(data) % blockSize)
        if modulus != 0:
            for i in range(modulus):
                data = data + bytes([modulus])
        return data

    def removePkcs7Padding(data, blockSize):
        potentialSize = data[-1]
        for i in range(potentialSize):
            if data[-1-i] != potentialSize:
                raise ValueError("The data was not padded correctly")
        return data[0: -potentialSize]