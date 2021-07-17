from datetime import datetime
from collections import OrderedDict
from transaction import Transaction
import json
import hashlib

CAPACITY = 10
DIFFICULTY = 4


class Block:

    # timestamp, currentHash, nonce and listOfTransactions in kwargs
    def __init__(self, previousHash, index, **kwargs):
        self.previousHash = previousHash
        self.timestamp = kwargs.get('timestamp', str(datetime.now()))
        self.currentHash = kwargs.get('currentHash', 0)
        self.nonce = kwargs.get('nonce', 0)
        self.index = index
        self.listOfTransactions = kwargs.get('listOfTransactions', [])

    def listOfTransactionsToDict(self):
        dictList = []
        for transaction in self.listOfTransactions:
            od = transaction.toDictAll()
            dictList.append(od)
        return dictList

    def toDict(self, attributesList):
        orderedDict = OrderedDict()
        for attribute in attributesList:
            orderedDict[attribute] = self.__getattribute__(attribute)
        return orderedDict

    def toDictAll(self):
        attributes = ['previousHash', 'timestamp', 'nonce', 'index', 'currentHash']
        od = self.toDict(attributes)
        od['listOfTransactions'] = self.listOfTransactionsToDict()
        return od

    def hash(self):
        attributes = ['previousHash', 'timestamp', 'nonce', 'index']
        od = self.toDict(attributes)
        od['listOfTransactions'] = self.listOfTransactionsToDict()
        self.currentHash = hashlib.sha256(json.dumps(od).encode()).hexdigest()
        return self.currentHash

    def addTransaction(self, transaction):
        self.listOfTransactions.append(transaction)

    def pow(self):
        tempHash = self.hash()
        return tempHash[:DIFFICULTY] == '0'*DIFFICULTY

    def __str__(self):
        return json.dumps(self.toDictAll(), indent=4)
