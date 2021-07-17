from wallet import Wallet
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import json
import hashlib
import binascii


class Transaction:

    # senderPrivateKey, transactionId, signature, transactionOutputs and transactionInputs in kwargs
    def __init__(self, senderAddress, receiverAddress, amount, **kwargs):
        self.retry = False
        self.remainingTries = kwargs.get('tries', 5)
        self.senderAddress = senderAddress
        self.receiverAddress = receiverAddress
        self.amount = amount
        self.transactionInputs = kwargs.get('transactionInputs', [])
        self.transactionOutputs = kwargs.get('transactionOutputs', [])
        if 'senderPrivateKey' in kwargs.keys():
            self.signature = self.signTransaction(kwargs['senderPrivateKey'])
        else:
            self.signature = kwargs['signature']
        #self.signature = kwargs.get('signature', self.signTransaction(kwargs.get('senderPrivateKey')))
        self.transactionId = kwargs.get('transactionId', self.hash())

    def listOfOutputTransactionsToDict(self):
        dictList = [
            output.toDictAll() for output in self.transactionOutputs]
        return dictList

    def toDict(self, attributesList):
        orderedDict = OrderedDict()
        for attribute in attributesList:
            orderedDict[attribute] = self.__getattribute__(attribute)
        return orderedDict

    def toDictAll(self):
        attributes = ['senderAddress', 'receiverAddress', 'amount', 'transactionInputs', 'signature', 'transactionId']
        od = self.toDict(attributes)
        od['transactionOutputs'] = self.listOfOutputTransactionsToDict()
        return od

    def hash(self):
        attributes = ['senderAddress', 'receiverAddress', 'amount', 'transactionInputs', 'signature']
        return hashlib.sha256(json.dumps(self.toDict(attributes)).encode()).hexdigest()

    def signTransaction(self, senderPrivateKey):
        attributes = ['senderAddress', 'receiverAddress', 'amount', 'transactionInputs']
        privateKey = RSA.importKey(binascii.unhexlify(senderPrivateKey))
        signer = PKCS1_v1_5.new(privateKey)
        digest = SHA256.new(json.dumps(self.toDict(attributes)).encode())
        return binascii.hexlify(signer.sign(digest)).decode('ascii')

    def __str__(self):
        return json.dumps(self.toDictAll(), indent=4)


# wallet = Wallet()
# t = Transaction(senderAddress=wallet.address, receiverAddress='0'*len(wallet.address),
#                amount=100, senderPrivateKey=wallet.privateKey)
