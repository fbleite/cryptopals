import binascii

class Base64:
    base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def hex2base64(dataByte):
        """Encodes bytes into base 64 format"""
        base64result = ""
        padding = ""
        # try:
        #     dataByte = bytearray.fromhex(data)
        # except ValueError:
        #     return -1
        c = len(dataByte) % 3
        if c > 0:
            for i in range(c, 3):
                padding += "="
                dataByte.append(0x00)
        i = 0
        while i < len(dataByte):
            n = (dataByte[i] << 16) + (dataByte[i + 1] << 8) + (dataByte[i + 2])
            n1 = (n >> 18) & 0x3f
            n2 = (n >> 12) & 0x3f
            n3 = (n >> 6) & 0x3f
            n4 = n & 0x3f
            base64result += Base64.base64chars[n1]
            base64result += Base64.base64chars[n2]
            base64result += Base64.base64chars[n3]
            base64result += Base64.base64chars[n4]
            i += 3
        if len(padding):
            return base64result[:-len(padding)] + padding
        else:
            return base64result

    def base64ToHex(inputData):
        data = inputData.replace('\n','')
        resultHex = bytearray()
        if ((len(data) % 4) != 0):
            raise ValueError("The length of the string was not multiple of 4")
        paddingIndex=0
        if data[-1:] == "=":
            paddingIndex+=1
            if data[-2:] == "==":
                paddingIndex+=1
            data = data[:-paddingIndex]
            for i in range (paddingIndex):
                data+="A"
        index = 0
        while index < len(data):
            stringToDecode = data[index:index+4]
            convertedBytes = (Base64.base64chars.index(stringToDecode[0]) << 18)+(Base64.base64chars.index(stringToDecode[1]) << 12)+\
                (Base64.base64chars.index(stringToDecode[2]) << 6)+(Base64.base64chars.index(stringToDecode[3]))
            resultHex.append((convertedBytes >> 16) & 0xFF)
            resultHex.append((convertedBytes >> 8) & 0xFF)
            resultHex.append((convertedBytes) & 0xFF)
            index+=4
        if paddingIndex != 0:
            resultHex = resultHex[:-paddingIndex]
        # return binascii.b2a_hex(resultHex).decode("ascii")
        return resultHex