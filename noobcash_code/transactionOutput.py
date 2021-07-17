from collections import OrderedDict
import uuid
import json


class TransactionOutput:

    # id in kwargs
    def __init__(self, address, amount, transactionId, **kwargs):
        self.transactionId = transactionId
        self.address = address
        self.amount = amount
        self.id = kwargs.get('id', self.generateId())

    def generateId(self):
        return uuid.uuid5(uuid.NAMESPACE_DNS, self.transactionId+self.address).__str__()

    def toDict(self, attributesList):
        orderedDict = OrderedDict()
        for attribute in attributesList:
            orderedDict[attribute] = self.__getattribute__(attribute)
        return orderedDict

    def toDictAll(self):
        return self.toDict(['id', 'transactionId', 'address', 'amount'])

    def __str__(self):
        return json.dumps(self.toDictAll(), indent=4)
