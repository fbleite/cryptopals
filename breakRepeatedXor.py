import CryptoSet1

__author__ = 'fbleite'


f = open('encryptedCtf.txt','r')
print(CryptoSet1.breakXor(CryptoSet1.hex2base64(f.read())))