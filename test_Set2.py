import unittest
from Encoding.Pkcs7 import Pkcs7
from Encoding.Base64 import Base64
from SimpleEncryption.AESCrypto import AESCrypto
from Encoding.Json import Json
import json
from collections import OrderedDict

class MyTestCase(unittest.TestCase):
    def test_challenge09_1_addPkcs7Padding(self):
        toBeEncoded = b"YELLOW SUBMARINE"
        blockSize = 20
        expectedEncoded = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        encodedData = Pkcs7.pkcs7Padding(toBeEncoded, blockSize)

        print("\nPkcs7 Encoding")
        print("toBeEncoded: {}".format(toBeEncoded))
        print("blockSize: {}".format(blockSize))
        print("encodedData: {}".format(encodedData))
        print("expectedEncoded: {}".format(expectedEncoded))
        self.assertEqual(expectedEncoded, encodedData)

    def test_challenge09_2_removePkcs7Padding(self):
        paddedData = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        expectedNotPadded = b"YELLOW SUBMARINE"
        blockSize = 20
        notPadded = Pkcs7.removePkcs7Padding(paddedData, blockSize)

        print("\nPkcs7 Encoding")
        print("paddedData: {}".format(paddedData))
        print("blockSize: {}".format(blockSize))
        print("notPadded: {}".format(notPadded))
        print("expectedNotPadded: {}".format(expectedNotPadded))
        self.assertEqual(expectedNotPadded, notPadded)

    def test_challenge10_1_simpleEncryption(self):
        IV=bytes([0]*16)
        toBeEncrypted = b"YELLOW SUBMARINES"
        key = b"YELLOW SUBMARINE"
        expectedDecrypted = b"YELLOW SUBMARINES" #No Padding
        encryptedData = AESCrypto.encryptCBCAES(IV, key, toBeEncrypted)
        decryptedData = AESCrypto.decryptCBCAES(IV, key, encryptedData)

        print("\nEcrypt/Decrypt AES CBC test")
        print("toBeEncrypted: {}".format(toBeEncrypted))
        print("key: {}".format(key))
        print("decryptedData: {}".format(decryptedData))
        print("expectedDecrypted: {}".format(expectedDecrypted))

        self.assertEqual(expectedDecrypted, decryptedData)

    def test_challenge10_2_decryptFile(self):

        IV=bytes([0]*16)
        key = b"YELLOW SUBMARINE"
        f = open('InputFiles/Set2Ch10.txt', 'r')
        decryptedValue = AESCrypto.decryptCBCAES(IV, key, bytes(Base64.base64ToHex(f.read())))
        f.close()
        fresult = open("InputFiles/Set2Ch10_result.txt", "rb")
        expectedDecrypted = fresult.read()
        fresult.close()
        print("\nDecrypts AEX CBC File")
        print("key: {}".format(key))
        print("decryptedValue: {}".format(decryptedValue))
        print("expectedDecrypted: {}".format(expectedDecrypted))
        self.assertEqual(expectedDecrypted, decryptedValue)

    def test_challenge11_1_simpleDetection(self):
        toBeEncrypted = b"datadatadatadatadatadatadatadata1234567890123456datadatadatadatadatadatadatadata1234567890123456"
        print("\nEncrypts data using encryption oracle then detects which mode was used")
        print("toBeEncrypted: {}".format(toBeEncrypted))
        for i in range(10):
            encrypted = AESCrypto.encryptionOracle(toBeEncrypted)
            self.assertEqual(encrypted['mode'], AESCrypto.detectECB(encrypted['data']))

    def test_challenge12_1_detectSameEncryptedBlock(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        unknownData = Base64.base64ToHex(f.read())
        f.close()
        data16bytes = b"A" * 16 + unknownData
        data17bytes = b"A" * 17 + unknownData
        aesCrypto = AESCrypto
        encrypted16 = aesCrypto.encryptionOracleNumber2(aesCrypto, data16bytes)
        encrypted17 = aesCrypto.encryptionOracleNumber2(aesCrypto, data17bytes)
        print("\nDetects the same encrypted block")
        print("encrypted16: {}".format(encrypted16))
        print("encrypted17: {}".format(encrypted17))
        self.assertEqual(encrypted16["data"][0:16],encrypted17["data"][0:16])

    def test_challenge12_2_detectBlockSize(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        unknownData = Base64.base64ToHex(f.read())
        f.close()
        detectedBlockSize = AESCrypto.detectBlockSizeAES(AESCrypto, unknownData)
        expectedBlockSize = 16
        print("\nDetects the same encrypted block")
        print("detectedBlockSize: {}".format(detectedBlockSize))
        print("expectedBlockSize: {}".format(expectedBlockSize))
        self.assertEqual(expectedBlockSize,detectedBlockSize )

    def test_challenge12_3_findOutFirstByteValue(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        unknownData = Base64.base64ToHex(f.read())
        knownData = b''
        f.close()
        detectedFirstByte = AESCrypto.findOutFirstByte(AESCrypto, knownData, unknownData, 16)
        expectedFirstByte = b'R'

        print("\nDetects the first byte of an unknown string")
        print("detectedFirstByte: {}".format(detectedFirstByte))
        print("expectedFirstByte: {}".format(expectedFirstByte))
        self.assertEqual(expectedFirstByte, detectedFirstByte)

    def test_challenge12_4_mathematicsOfAs(self):
        knownData = "Roll"
        blockSize = 16

        print("\nTests Math for getting padding")
        numberOfAsNeeded = blockSize - (len(knownData) % blockSize) - 1
        self.assertEqual(11, numberOfAsNeeded)

    def test_challenge12_5_BreakAESECB(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        unknownData = Base64.base64ToHex(f.read())
        f.close()
        brokenAESECB = AESCrypto.breakAESECBSimple(AESCrypto, unknownData)

        print("\nBreaks AES ECB little by little")
        print("unknownData: {}".format(unknownData))
        print("brokenAESECB: {}".format(brokenAESECB))
        self.assertEqual(unknownData, brokenAESECB)

    def test_challenge13_1_ConvertCookieToJson(self):
        inputCookie = "foo=bar&baz=qux&zap=zazzle"
        expectedJsonString = json.loads(json.dumps({"foo": "bar", "baz": "qux", "zap": "zazzle"}))
        convertedJsonCookie = Json.CookieToJson(Json, inputCookie)

        print("\nConverts cookie data to Json")
        print("inputCookie: {}".format(inputCookie))
        print("convertedJsonCookie: {}".format(convertedJsonCookie))
        print("expectedJsonString: {}".format(expectedJsonString))
        self.assertEqual(expectedJsonString, convertedJsonCookie)

    def test_challenge13_2_ConvertCookieToJsonEscapedChars(self):
        inputCookie = "foo=b\=ar&baz=qux&zap=zaz\&zle"
        print(inputCookie)
        expectedJsonString = json.loads(json.dumps({"foo": "b\=ar", "baz": "qux", "zap": "zaz\&zle"}))
        convertedJsonCookie = Json.CookieToJson(Json, inputCookie)

        print("\nConverts cookie data to Json with escaped characters")
        print("inputCookie: {}".format(inputCookie))
        print("convertedJsonCookie: {}".format(convertedJsonCookie))
        print("expectedJsonString: {}".format(expectedJsonString))
        self.assertEqual(expectedJsonString, convertedJsonCookie)

    def test_challenge13_3_sanitizeInput(self):
        email = "fo&o@ba=r.com"
        expectedSanitizedEmail = "fo\&o@ba\=r.com"
        sanitizedEmail = Json.sanitizeInput(Json, email)

        print("\nCreates cookie profile from e-mail")
        print("email: {}".format(email))
        print("expectedSanitizedEmail: {}".format(expectedSanitizedEmail))
        print("sanitizedEmail: {}".format(sanitizedEmail))
        self.assertEqual(expectedSanitizedEmail, sanitizedEmail)

    def test_challenge13_4_jsonToCookie(self):
        jsonString = json.loads(json.dumps({"foo": "bar", "baz": "qux", "zap": "zazzle"}, sort_keys=True), \
                                object_pairs_hook=OrderedDict) #Workaround to always get the right order

        convertedCookie = Json.jsonToCookie(Json, jsonString)
        expectedCookie = "baz=qux&foo=bar&zap=zazzle"

        print("\nConverts json data to cookie")
        print("jsonString: {}".format(jsonString))
        print("convertedCookie: {}".format(convertedCookie))
        print("expectedCookie: {}".format(expectedCookie))
        self.assertEqual(expectedCookie, convertedCookie)

    def test_challenge13_5_createJsonProfile(self):
        email = "foo@bar.com"
        expectedJsonProfile = json.loads(json.dumps({"email": "foo@bar.com", "uid": "10", "role": "user"}))
        jsonProfile = Json.createJsonProfile(Json, email)

        print("\nCreates Json profile from e-mail")
        print("email: {}".format(email))
        print("jsonProfile: {}".format(jsonProfile))
        print("expectedJsonProfile: {}".format(expectedJsonProfile))

        self.assertEqual(expectedJsonProfile, jsonProfile)

    def test_challenge13_6_createCookieProfile(self):
        email = "foo@bar.com"
        expectedCookieProfileList = ["email=foo@bar.com&uid=10&role=user",
                                     "email=foo@bar.com&role=user&uid=10",
                                     "uid=10&email=foo@bar.com&role=user",
                                     "uid=10&role=user&email=foo@bar.com",
                                     "role=user&email=foo@bar.com&uid=10",
                                     "role=user&uid=10&email=foo@bar.com"]
        cookieProfile = Json.createProfile(Json, email)

        print("\nCreates cookie profile from e-mail")
        print("email: {}".format(email))
        print("cookieProfile: {}".format(cookieProfile))
        print("expectedCookieProfile: {}".format(expectedCookieProfileList))

        self.assertEqual(True, cookieProfile in expectedCookieProfileList)

    def test_challenge13_7_encryptDecryptProfile(self):
        expectedJsonString = json.loads(json.dumps({'role': 'user', 'email': 'foo@bar.com', 'uid': "10"}))
        key= AESCrypto.generateRandomAESKey(16)
        email = "foo@bar.com"
        cookieProfile = Json.createProfile(Json, email)
        encryptedProfile = AESCrypto.encryptEBCAES(key, bytes(cookieProfile, "ascii"))
        decryptedProfile = AESCrypto.decryptECBAES(key, encryptedProfile)
        reconstructedJsonProfile = Json.CookieToJson(Json, str(decryptedProfile, "ascii"))

        print("\nCreates cookie profile from e-mail encrypts, decrypts and parses into json")
        print("email: {}".format(email))
        print("reconstructedJsonProfile: {}".format(reconstructedJsonProfile))
        print("expectedJsonString: {}".format(expectedJsonString))
        self.assertEqual(expectedJsonString, reconstructedJsonProfile)



if __name__ == '__main__':
    unittest.main()
