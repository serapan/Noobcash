from Crypto.PublicKey import RSA
from collections import OrderedDict
import Crypto
import Crypto.Random
import binascii
import json


class Wallet:

    def __init__(self):
        self.publicKey, self.privateKey = self.keygen()
        self.address = self.publicKey
        # self.transactions = []

    def keygen(self):
        rand = Crypto.Random.new().read
        key = RSA.generate(1024, rand)
        private = binascii.hexlify(key.exportKey(format='DER')).decode('ascii')
        public = binascii.hexlify(key.publickey().exportKey(format='DER')).decode('ascii')
        return public, private

    def toDict(self, attributesList):
        orderedDict = OrderedDict()
        for attribute in attributesList:
            orderedDict[attribute] = self.__getattribute__(attribute)
        return orderedDict

    def toDictAll(self):
        return self.toDict(['address', 'publicKey', 'privateKey'])

    def __str__(self):
        return json.dumps(self.toDictAll(), indent=4)
