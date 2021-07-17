from wallet import Wallet
from block import Block, CAPACITY, DIFFICULTY
from transaction import Transaction
from transactionOutput import TransactionOutput
from blockchain import Blockchain
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_256
from collections import deque
from node import Node
import requests
import json
import threading
import hashlib
import binascii
import copy
import time


class BootstrapNode(Node):

    def __init__(self, myIp, myPort, numOfNodes):
        super().__init__(myIp, myPort)
        self.numOfNodes = numOfNodes
        self.nodeId = 0
        self.idToGive = 0
        self.acks = {str(i): False for i in range(1, numOfNodes)}

    def createGenesisTransaction(self):
        transaction = Transaction(senderAddress='0' * len(self.wallet.publicKey),
                                  receiverAddress=self.wallet.address, amount=self.numOfNodes * 100,
                                  senderPrivateKey=self.wallet.privateKey)
        transactionOutput = TransactionOutput(address=self.wallet.address,
                                              amount=self.numOfNodes*100, transactionId=transaction.transactionId)

        self.money[transactionOutput.id] = transactionOutput

        transaction.transactionOutputs = [transactionOutput]
        return transaction

    def createGenesisBlock(self):
        genesisTransaction = self.createGenesisTransaction()
        genesisBlock = Block(previousHash=1, index=1)
        genesisBlock.addTransaction(genesisTransaction)
        genesisBlock.hash()
        return genesisBlock

    def genesis(self):
        self.chain.addBlock(self.createGenesisBlock())

    def createInitialTransactions(self):
        for node in self.ring:
            address = 'http://' + self.myIp + ':{0}'.format(self.myPort) + '/transactions/get'
            body = json.dumps({'amount': 100, 'receiverAddress': node['address']}, indent=4)
            reply = self.unicast(address, body)
            time.sleep(1)
            print(reply['msg'])

    def registerNodeToRing(self, ip, port, address):
        self.idToGive += 1
        self.ring.append({'ip': ip, 'port': port, 'address': address, 'nodeId': self.idToGive})
        return self.idToGive

    def broadcastInfo(self):
        toSendRing = copy.copy(self.ring)
        toSendRing.append({'ip': self.myIp, 'port': self.myPort, 'address': self.wallet.address, 'nodeId': self.nodeId})
        addressSuffix = '/bootstrap/info'
        body = json.dumps({'ring': toSendRing, 'chain': self.chain.toDictBlocks()}, indent=4)
        self.broadcast(addressSuffix, body)


# n = BootstrapNode(myIp='1', myPort='5', numOfNodes=2)
# n.genesis()
# print(n.jsonToTransaction(json.loads(str(n.chain.blocks[0].listOfTransactions[0]))))
# print(n.jsonToBlock(str(n.chain.blocks[0])))
# print(n.jsonToBlockchain(str(n.chain)))
