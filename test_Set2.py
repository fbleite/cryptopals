import unittest
from Encoding.Pkcs7 import Pkcs7
from Encoding.Base64 import Base64
from SimpleEncryption.AESCrypto import AESCrypto
from Encoding.Json import Json
import json
from collections import OrderedDict
from SimpleEncryption.Utils import Utils

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
        AESCrypto.unknownData12 = Base64.base64ToHex(f.read())
        f.close()
        data16bytes = b"A" * 16
        data17bytes = b"A" * 17
        aesCrypto = AESCrypto
        encrypted16 = aesCrypto.encryptionOracleCh12(aesCrypto, data16bytes)
        encrypted17 = aesCrypto.encryptionOracleCh12(aesCrypto, data17bytes)
        print("\nDetects the same encrypted block")
        print("encrypted16: {}".format(encrypted16))
        print("encrypted17: {}".format(encrypted17))
        self.assertEqual(encrypted16["data"][0:16],encrypted17["data"][0:16])

    def test_challenge12_2_detectBlockSize(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12= Base64.base64ToHex(f.read())
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh12
        detectedBlockSize = AESCrypto.detectBlockSizeAES(AESCrypto)
        expectedBlockSize = 16
        print("\nDetects the same encrypted block")
        print("detectedBlockSize: {}".format(detectedBlockSize))
        print("expectedBlockSize: {}".format(expectedBlockSize))
        self.assertEqual(expectedBlockSize,detectedBlockSize )

    def test_challenge12_3_findOutFirstByteValue(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12 = Base64.base64ToHex(f.read())
        knownData = b''
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh12
        detectedFirstByte = AESCrypto.findOutFirstByte(AESCrypto, knownData, 16, 0)
        expectedFirstByte = b'R'

        print("\nDetects the first byte of an unknown string")
        print("detectedFirstByte: {}".format(detectedFirstByte))
        print("expectedFirstByte: {}".format(expectedFirstByte))
        self.assertEqual(expectedFirstByte, detectedFirstByte)

    def test_challenge12_4_detectEndOfString(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12 = Base64.base64ToHex(f.read())
        knownData = AESCrypto.unknownData12 + b"\x01"
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh12
        detectedFirstByte = AESCrypto.findOutFirstByte(AESCrypto, knownData, 16, 0)
        expectedFirstByte = b""

        print("\nDetects the first byte of an unknown string")
        print("detectedFirstByte: {}".format(detectedFirstByte))
        print("expectedFirstByte: {}".format(expectedFirstByte))
        self.assertEqual(expectedFirstByte, detectedFirstByte)

    def test_challenge12_5_mathematicsOfAs(self):
        knownData = ""
        blockSize = 16
        prefixLength = 5

        print("\nTests Math for getting padding")
        # numberOfAsNeeded = blockSize - (len(knownData) % blockSize) - 1
        component1 =  blockSize - (prefixLength%blockSize)

        component2 = blockSize - (len(knownData) % blockSize) -1

        numberOfAsNeeded = component1 + component2# - prefixInfluence
        print(numberOfAsNeeded)
        self.assertEqual(26, numberOfAsNeeded)

    def test_challenge12_6_BreakAESECB(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12 = Base64.base64ToHex(f.read())
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh12
        brokenAESECB = AESCrypto.breakAESECBSimple(AESCrypto)

        print("\nBreaks AES ECB little by little")
        print("unknownData: {}".format(AESCrypto.unknownData12))
        print("brokenAESECB: {}".format(brokenAESECB))
        self.assertEqual(AESCrypto.unknownData12, brokenAESECB)

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
        sanitizedEmail = Utils.sanitizeInput(Utils, email)

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

        self.assertTrue(cookieProfile in expectedCookieProfileList)

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

    def test_challenge14_1_generateRandomBytes(self):
        randomBytes = AESCrypto.generateRandomSizedRandomBytes(AESCrypto)

        print("\nCreates random bytes of length 8 <= len <= 300")
        print("randomBytes: {}".format(randomBytes))
        print("len(randomBytes): {}".format(len(randomBytes)))
        self.assertGreaterEqual(len(randomBytes), 8)
        self.assertLessEqual(len(randomBytes), 300)

    def test_challenge14_2_detectBlockSize(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12= Base64.base64ToHex(f.read())
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh14
        detectedBlockSize = AESCrypto.detectBlockSizeAES(AESCrypto)
        expectedBlockSize = 16
        print("\nDetects the same encrypted block")
        print("detectedBlockSize: {}".format(detectedBlockSize))
        print("expectedBlockSize: {}".format(expectedBlockSize))
        self.assertEqual(expectedBlockSize,detectedBlockSize )

    def test_challenge14_3_detectInitialBytesLength(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12 = Base64.base64ToHex(f.read())
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh14
        detectedBlockSize = AESCrypto.detectBlockSizeAES(AESCrypto)
        detectedLenght = AESCrypto.detectInitialBytesLength(AESCrypto, detectedBlockSize)

        self.assertEqual(len(AESCrypto.prefixDataCh14), detectedLenght)

    def test_challenge14_4_breakAESHard(self):
        f = open('InputFiles/Set2Ch12.txt', 'r')
        AESCrypto.unknownData12 = Base64.base64ToHex(f.read())
        f.close()
        AESCrypto.oracle = AESCrypto.encryptionOracleCh14
        brokenAESECB = AESCrypto.breakAESECBSimple(AESCrypto)

        print("\nBreaks AES ECB little by little")
        print("unknownData: {}".format(AESCrypto.unknownData12))
        print("brokenAESECB: {}".format(brokenAESECB))
        self.assertEqual(AESCrypto.unknownData12, brokenAESECB)

    def test_challenge15_1_removePkcs7Padding(self):
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


    def test_challenge15_2_exceptionBadPadding(self):
        paddedData = b"YELLOW SUBMARINE\x05\x05\x05\x05"
        expectedNotPadded = b"YELLOW SUBMARINE"
        blockSize = 20

        print("\nPkcs7 Encoding")
        print("paddedData: {}".format(paddedData))
        print("blockSize: {}".format(blockSize))
        self.assertRaises(ValueError, Pkcs7.removePkcs7Padding, paddedData, blockSize)

    def test_challenge16_1_AppendCookieString(self):
        myString = "Whatever I want to write"
        cookieString = Utils.appendCookieStringAround(Utils, myString)
        expectedCookieString = "comment1=cooking%20MCs;userdata=Whatever I want to write;comment2=%20like%20a%20pound%20of%20bacon"

        print("\nAppend Cookie String")
        print("myString: {}".format(myString))
        print("cookieString: {}".format(cookieString))
        print("expectedCookieString: {}".format(expectedCookieString))
        self.assertEqual(expectedCookieString, cookieString)


    def test_challenge16_2_detectAdminFalse(self):
        myString= ";admin=true;"
        encryptedData = AESCrypto.encryptCookieString(AESCrypto, myString)
        found = AESCrypto.decryptDetectAdminTrue(AESCrypto, encryptedData)

        print("\nEnsures false find of Admin is correct")
        self.assertFalse(found)

    def test_challenge16_3_detectAdminTrue(self):
        #semi colon is 59 and equal is 61 both odd numbers with last bit set
        #choose the character with one less to be used as input to work around the escaping
        myString= ":admin<true:"
        encryptedData = bytearray(AESCrypto.encryptCookieString(AESCrypto, myString))

        #Based on input string flips that last bit of each of the characters that we want to change
        encryptedData[16] ^= 1
        encryptedData[22] ^= 1
        encryptedData[27] ^= 1

        encryptedData = bytes(encryptedData)
        found = AESCrypto.decryptDetectAdminTrue(AESCrypto, encryptedData)
        print("\nEnsures true find of Admin is correct")
        self.assertTrue(found)

if __name__ == '__main__':
    unittest.main()
