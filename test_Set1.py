import unittest
from Encoding.Base64 import *
from SimpleEncryption.AESCrypto import *
from SimpleEncryption.XOR import *
from SimpleEncryption.Utils import *
import binascii

class MyTestCase(unittest.TestCase):

    def test_challenge1(self):
        #One way of converting hex representation into Bytes, not bytearray, slightly different objects
        hexString = binascii.a2b_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        expectedBase64String = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

        print("\nConvert to Base 64 test")
        base64String = Base64.hex2base64(hexString)
        print("hexString: {}".format(hexString))
        print("base64String: {}".format(base64String))
        print("expectedBase64String: {}".format(expectedBase64String))
        self.assertEqual(expectedBase64String, base64String)


        print("\nConvert from Base 64 test")
        hexStringReconverted = Base64.base64ToHex(base64String)
        print("hexString: {}".format(hexString))
        print("hexStringReconverted: {}".format(hexStringReconverted))
        self.assertEqual(hexString, hexStringReconverted)


    def test_challenge2_1(self):
        #Another way of converting hex representation this time into bytearray
        input1 = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
        input2 = bytearray.fromhex("686974207468652062756c6c277320657965")
        expectedOutput = bytearray.fromhex("746865206b696420646f6e277420706c6179")
        output = XOR.fixedXor(input1, input2)

        print("\nXOR Bytes test")
        print("input1: {}".format(input1))
        print("input2: {}".format(input2))
        print("output: {}".format(output))
        print("expectedOutput: {}".format(expectedOutput))
        self.assertEqual(expectedOutput, output)

    def test_challenge2_2_incorrectXorLength(self):
        input1 = bytearray.fromhex("1c0111001f010100061a024b5353500918")
        input2 = bytearray.fromhex("686974207468652062756c6c277320657965")
        self.assertRaises(ValueError, XOR.fixedXor, input1, input2)


    def test_challenge3(self):
        toBeDeciphered = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        decipheredData = XOR.decypherXor(toBeDeciphered)
        expectedDecipheredData = {"Cooking MC's like a pound of bacon": 0.6764705882352942}

        print("\nDeciphering XOR test")
        print("toBeDeciphered: {}".format(toBeDeciphered))
        print("decipheredData: {}".format(decipheredData))
        print("expectedDecipheredData: {}".format(expectedDecipheredData))

        self.assertEqual(expectedDecipheredData, decipheredData)

    def test_challenge4(self):
        f = open('InputFiles/Set1Ch4.txt', 'r')
        decryptedString = XOR.getDecryptedStringFromFile(f)
        f.close()
        expectedDecryptedString = "Now that the party is jumping\n"

        print("\nFinding encrypted XOR string test")

        print("Usign InputFiles/Set1Ch4.txt")
        print("decryptedString: {}".format(decryptedString))
        print("expectedDecryptedString: {}".format(expectedDecryptedString))
        self.assertEqual(expectedDecryptedString, decryptedString)

    def test_challenge5(self):
        key = "ICE"
        inputString = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        expectedEncrypted = bytearray.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        xorEncrypted = XOR.xorEncrypt(bytes(key, "ascii"), bytes(inputString, "ascii"))

        print("\nXOR encrypt string")
        print("inputString: {}".format(inputString))
        print("xorEncrypted: {}".format(xorEncrypted))
        print("expectedEncrypted: {}".format(expectedEncrypted))
        self.assertEqual(expectedEncrypted, xorEncrypted)

    def test_challenge6_1_hammingDistance(self):
        string1 = b"this is a test"
        string2 = b"wokka wokka!!!"
        expectedDistance = 37
        actualDistance = Utils.hammingDistance(string1, string2)


        print("\nHamming distance test")
        print("string1: {}".format(string1))
        print("string2: {}".format(string2))
        print("actualDistance: {}".format(actualDistance))
        print("expectedDistance: {}".format(expectedDistance))
        self.assertEqual(expectedDistance, actualDistance)

    def test_challenge6_2_avgHammingDistance(self):

        f = open('InputFiles/Set1Ch6.txt', 'r')
        expectedDistance = 3.1652690426275334
        actualAvgDistance = Utils.getAvgHammingDist(Base64.base64ToHex(f.read()), 9)

        print("\nAverage hamming distance test")
        print("Usign InputFiles/Set1Ch6.txt")
        print("actualAvgDistance: {}".format(actualAvgDistance))
        print("expectedDistance: {}".format(expectedDistance))
        self.assertEqual(expectedDistance, actualAvgDistance)

    def test_challenge6_3_getKeySize(self):
        f = open('InputFiles/Set1Ch6.txt', 'r')
        expectedKeySize = 29
        actualKeySize = Utils.getKeySize(Base64.base64ToHex(f.read()))
        f.close()
        print("\nKey size test")
        print("Usign InputFiles/Set1Ch6.txt")
        print("actualKeySize: {}".format(actualKeySize))
        print("expectedKeySize: {}".format(expectedKeySize))
        self.assertEqual(expectedKeySize, actualKeySize)

    def test_challenge6_4_breakXor(self):
        fresuls = open('InputFiles/Set1Ch6_result.txt', 'r')
        expectedResult = fresuls.read()
        fresuls.close()
        f = open('InputFiles/Set1Ch6.txt', 'r')
        actualResult = XOR.breakXor(Base64.base64ToHex(f.read()))
        f.close()
        print("\nBreak XOR variable key length test")
        print("Usign InputFiles/Set1Ch6.txt")
        print("actualResult: {}".format(actualResult))
        print("expectedResult: {}".format(expectedResult))
        self.assertEqual(expectedResult, actualResult)

    def test_challenge7(self):
        fresult = open('InputFiles/Set1Ch7_result.txt','rb')
        expectedEncryptedValue = fresult.read()
        fresult.close()
        key = b"YELLOW SUBMARINE"
        f = open('InputFiles/Set1Ch7.txt', 'r')
        decryptedValue = AESCrypto.decryptECBAES(key, bytes(Base64.base64ToHex(f.read())))
        f.close()
        print("\nDecrypt AES ECB 128 bits key")
        print("Usign InputFiles/Set1Ch7.txt")
        print("decryptedValue: {}".format(decryptedValue))
        print("expectedEncryptedValue: {}".format(expectedEncryptedValue))
        self.assertEqual(expectedEncryptedValue, decryptedValue)

    def test_challenge8_1_ECBScore(self):
        hexArray = bytes.fromhex("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
        ECBScore = AESCrypto.getEBCScore(hexArray,16)
        ExpectedECBScore = 12
        print("\nFind the ECB Score test")
        print("hexArray: {}".format(hexArray))
        print("ECBScore: {}".format(ECBScore))
        print("ExpectedECBScore: {}".format(ExpectedECBScore))
        self.assertEqual(ExpectedECBScore, ECBScore)

    def test_challenge8_2_GetECBEncryptedTraceFromFile(self):
        f = open('InputFiles/Set1Ch8.txt', 'r')
        ECBTrace = AESCrypto.findAESECBFromFile(f.read())
        f.close()
        ExpectedECBTrace = bytes.fromhex("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
        print("\nFind EBC Trace in File")
        print("Usign InputFiles/Set1Ch8.txt")
        print("ECBTrace: {}".format(ECBTrace))
        print("ExpectedECBTrace: {}".format(ExpectedECBTrace))
        self.assertEqual(ExpectedECBTrace, ECBTrace)

        
if __name__ == '__main__':
    unittest.main()
