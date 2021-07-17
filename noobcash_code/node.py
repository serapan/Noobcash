from wallet import Wallet
from block import Block, CAPACITY, DIFFICULTY
from transaction import Transaction
from transactionOutput import TransactionOutput
from blockchain import Blockchain
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from collections import deque
import requests
import json
import threading
import hashlib
import binascii
import time

# transactionPool = [
#                    'transactionId1': transaction1,
#                    'transactionId2': transaction2,
#                     ...
#                   ]

# unspentTransactionsMap = {
#                           'address1': {'transactionOutputId11': transactionOutput11, 'transactionOutputId12': transactionOutput12, ...},
#                           'address2': {'transactionOutputId21': transactionOutput21, 'transactionOutputId22': transactionOutput22, ...},
#                           ...
#                          }

# ring = [
#         {'nodeId': nodeId1, 'ip': ipAddr1, 'port': port1, 'address': publicKey1},
#         {'nodeId': nodeId2, 'ip': ipAddr1, 'port': port1, 'address': publicKey1},
#         ...
#        ]

# tempUsedOutputs = {
#                    'transactionOutputId11': [transactionOutput11, address1],
#                    'transactionOutputId12': [transactionOutput12, address2],
#                    ...
#                   }


class Node:

    def __init__(self, myIp, myPort):
        # self.lock = threading.Lock()
        self.money = {}
        self.firstTime = 0
        self.lastTime = 0
        self.blockTimes = []
        self.legitTransactions = []
        self.tempUsedOutputs = {}
        self.isMining = False
        self.winningBlockFound = False
        self.existsConflict = False
        self.isStillAdjusting = False
        self.transactionPool = deque([])
        self.myIp = myIp
        self.myPort = myPort
        self.chain = Blockchain()
        self.wallet = self.createWallet()
        self.nodeId = -1
        self.workingBlock = None
        self.ring = []
        self.unspentTransactionsMap = {}

    def jsonToTransaction(self, jsonTransaction):
        jsonTransaction = json.loads(jsonTransaction)
        outputs = []
        transactionOutputs = jsonTransaction['transactionOutputs']
        for transactionOutput in transactionOutputs:
            output = TransactionOutput(
                address=transactionOutput['address'],
                amount=transactionOutput['amount'],
                transactionId=transactionOutput['transactionId'],
                id=transactionOutput['id'])
            outputs.append(output)
        transaction = Transaction(
            senderAddress=jsonTransaction['senderAddress'],
            receiverAddress=jsonTransaction['receiverAddress'],
            amount=jsonTransaction['amount'],
            transactionId=jsonTransaction['transactionId'],
            signature=jsonTransaction['signature'],
            transactionInputs=jsonTransaction['transactionInputs'],
            transactionOutputs=outputs)
        return transaction

    def jsonToBlock(self, jsonBlock):
        jsonBlock = json.loads(jsonBlock)
        listOfTransactions = jsonBlock['listOfTransactions']
        transactions = []
        for jsonTransaction in listOfTransactions:
            transactions.append(self.jsonToTransaction(json.dumps(jsonTransaction, indent=4)))
        block = Block(previousHash=jsonBlock['previousHash'], index=jsonBlock['index'],
                      timestamp=jsonBlock['timestamp'], currentHash=jsonBlock['currentHash'],
                      nonce=jsonBlock['nonce'], listOfTransactions=transactions)
        return block

    def jsonToBlockchain(self, jsonChain):
        blockchain = Blockchain()
        for jsonBlock in jsonChain:
            blockchain.blocks.append(self.jsonToBlock(json.dumps(jsonBlock, indent=4)))
        return blockchain

    def unicast(self, address, body):
        headers = {'Content-type': 'application/json'}
        return requests.post(url=address, data=body, headers=headers).json()

    def broadcast(self, addressSuffix, body):
        for node in self.ring:
            address = 'http://' + node['ip'] + ':{0}'.format(node['port']) + addressSuffix
            threading.Thread(target=self.unicast, args=[address, body]).start()

    def isBootstrapNode(self):
        return self.nodeId == 0

    def createUnspentTransactionsMap(self):
        for node in self.ring:
            self.unspentTransactionsMap[node['address']] = {}
        self.unspentTransactionsMap[self.wallet.address] = dict()
        genesisTransactionOutput = self.chain.blocks[0].listOfTransactions[0].transactionOutputs[0]
        self.insertIntoUnspentTransactionMap(genesisTransactionOutput.address, genesisTransactionOutput)

    def insertIntoUnspentTransactionMap(self, address, transactionOutput):
        self.unspentTransactionsMap[address][transactionOutput.id] = transactionOutput

    def createWallet(self):
        return Wallet()

    def createNewBlock(self, previousHash, index):
        return Block(previousHash, index)

    def registerNodeToRing(self, ip, port):
        address = 'http://' + ip + ':{0}'.format(port) + '/bootstrap/register'
        body = json.dumps({'ip': self.myIp, 'port': self.myPort, 'address': self.wallet.address}, indent=4)
        reply = self.unicast(address, body)
        self.nodeId = reply['nodeId']
        address = 'http://' + ip + ':{0}'.format(port) + '/bootstrap/registerAck'
        body = json.dumps({'nodeId': self.nodeId}, indent=4)
        reply = self.unicast(address, body)
        print(reply['msg'])

    def walletBalance(self, address):
        total = 0
        unspent = self.unspentTransactionsMap[address]
        for transactionOutput in unspent.values():
            total += transactionOutput.amount
        return total

    def myWalletBalance(self):
        return self.walletBalance(self.wallet.address)

    def createTransaction(self, senderAddress, amount, receiverAddress):
        if amount <= 0:
            return 'You can not give nor negative nor zero money', False
        # unspent = self.unspentTransactionsMap[senderAddress]
        # hasMoney = 0
        # transactionInputs = []
        # for id, transactionOutput in unspent.items():
        #     hasMoney += transactionOutput.amount
        #     transactionInputs.append(id)
        #     if hasMoney >= amount:
        #         break
        if receiverAddress not in [d['address'] for d in self.ring]:
            return 'Invalid address', False
        unspent = self.money
        hasMoney = 0
        transactionInputs = []
        for id, transactionOutput in unspent.items():
            hasMoney += transactionOutput.amount
            transactionInputs.append(id)
            if hasMoney >= amount:
                break

        if hasMoney < amount:
            return 'Not enough money', False
        transaction = Transaction(
            senderAddress=senderAddress, receiverAddress=receiverAddress, amount=amount,
            transactionInputs=transactionInputs, senderPrivateKey=self.wallet.privateKey)

        senderMoney = hasMoney - transaction.amount
        if not (senderMoney == 0):
            senderTransactionOutput = TransactionOutput(
                address=transaction.senderAddress, amount=senderMoney, transactionId=transaction.transactionId)
            transaction.transactionOutputs.append(senderTransactionOutput)
            self.money[senderTransactionOutput.id] = senderTransactionOutput
        for inputId in transactionInputs:
            try:
                self.money.pop(inputId)
            except:
                pass

        return transaction, True

    def verifySignature(self, transaction):
        publicKey = RSA.importKey(binascii.unhexlify(transaction.senderAddress))
        verifier = PKCS1_v1_5.new(publicKey)
        digest = SHA256.new(json.dumps(transaction.toDict(
            ['senderAddress', 'receiverAddress', 'amount', 'transactionInputs'])).encode())
        return verifier.verify(digest, binascii.unhexlify(transaction.signature))

    def validateTransaction(self, transaction):
        def doIt(id):
            elem = self.unspentTransactionsMap[transaction.senderAddress].pop(id)
            self.tempUsedOutputs[id] = [elem, transaction.senderAddress]
            return elem
        flag1 = self.verifySignature(transaction)
        availableIds = list(self.unspentTransactionsMap[transaction.senderAddress].keys())
        flag2 = all(id in availableIds for id in transaction.transactionInputs)
        if not (flag1 and flag2):
            return None, False
        unspentToUse = [doIt(id) for id in transaction.transactionInputs]
        moneyToUse = 0
        for transactionOutput in unspentToUse:
            moneyToUse += transactionOutput.amount
        senderMoney = moneyToUse - transaction.amount
        if not (senderMoney == 0):
            senderTransactionOutput = TransactionOutput(
                address=transaction.senderAddress, amount=senderMoney, transactionId=transaction.transactionId)
            transaction.transactionOutputs.append(senderTransactionOutput)
            self.unspentTransactionsMap[senderTransactionOutput.address][senderTransactionOutput.id] = senderTransactionOutput
        receiverTransactionOutput = TransactionOutput(
            address=transaction.receiverAddress, amount=transaction.amount, transactionId=transaction.transactionId)
        transaction.transactionOutputs.append(receiverTransactionOutput)
        self.unspentTransactionsMap[receiverTransactionOutput.address][receiverTransactionOutput.id] = receiverTransactionOutput

        if receiverTransactionOutput.address == self.wallet.address:
            self.money[receiverTransactionOutput.id] = receiverTransactionOutput

        return transaction, True

    def broadcastTransaction(self, transaction):
        addressSuffix = '/transactions/broadcast'
        body = json.dumps(transaction.toDictAll(), indent=4)
        self.broadcast(addressSuffix, body)

    def transact(self, senderAddress, amount, reiceverAddress):
        transaction, flag = self.createTransaction(senderAddress, amount, reiceverAddress)
        if not flag:
            return transaction, False
        # flag1 = self.verifySignature(transaction)
        # unspent = self.unspentTransactionsMap[transaction.senderAddress]
        # availableIds = list(unspent.keys())
        # flag2 = all(id in availableIds for id in transaction.transactionInputs)
        # if not (flag1 and flag2):
        #     return 'Transaction is invalid', False
        self.broadcastTransaction(transaction)
        self.transactionPool.append({transaction.transactionId: transaction})
        return 'Transaction created successfully', True

    def receiveTransaction(self, jsonTransaction):
        transaction = self.jsonToTransaction(json.dumps(jsonTransaction, indent=4))
        self.transactionPool.append({transaction.transactionId: transaction})

    def pullTransactionFromPool(self):
        if self.isMining or self.winningBlockFound or self.existsConflict or self.isStillAdjusting:
            # print(self.isMining)
            # print(self.winningBlockFound)
            # print(self.existsConflict)
            # print(self.isStillAdjusting)
            return
        if len(self.transactionPool) != 0:
            transactionDict = self.transactionPool.popleft()
            # print(transactionDict)
            pooledTransaction = list(transactionDict.values())[0]
            if pooledTransaction.transactionId in self.legitTransactions:
                return
            transaction, flag = self.validateTransaction(pooledTransaction)
            if transaction is None:
                # time.sleep(2)
                # pooledTransaction.remainingTries -= 1
                # self.transactionPool.appendleft({pooledTransaction.transactionId: pooledTransaction})
                return
            if transaction.remainingTries > 0 and flag:
                self.workingBlock.addTransaction(transaction)
                if len(self.workingBlock.listOfTransactions) >= CAPACITY:
                    self.isMining = True
                    print('==> Start Mining')
                    self.mineBlock()

    def validateBlock(self, block):
        self.lastTime = time.time()
        tempBlock = Block(previousHash=block.previousHash, index=block.index, timestamp=block.timestamp,
                          nonce=block.nonce, listOfTransactions=block.listOfTransactions)
        if tempBlock.hash() == block.currentHash and block.previousHash == self.chain.lastBlockHash():
            return True
        else:
            return False

    def mineBlock(self):
        tic = time.perf_counter()
        while (not self.workingBlock.pow()) and not self.winningBlockFound:
            self.workingBlock.nonce += 1
        toc = time.perf_counter()
        diff = toc - tic
        self.blockTimes.append(diff)
        if not self.winningBlockFound:  # check
            print('==> Found PoW. Broadcasting...')
            if self.validateBlock(self.workingBlock):
                self.isMining = False
                self.chain.addBlock(self.workingBlock)
                self.broadcastBlock()
            else:
                print('Wtf this cannot be happening --mineBlock')
        else:
            print('==> Someone else solved the puzzle')
        self.winningBlockFound = False

    def broadcastBlock(self):
        addressSuffix = '/block/broadcast'
        body = json.dumps(self.workingBlock.toDictAll(), indent=4)
        self.broadcast(addressSuffix, body)
        winningTransactionsIds = [transaction.transactionId for transaction in self.workingBlock.listOfTransactions]
        self.legitTransactions += winningTransactionsIds
        self.workingBlock = Block(previousHash=self.chain.lastBlockHash(), index=self.chain.lastBlockIndex()+1)

    def receiveBlock(self, jsonBlock):
        self.winningBlockFound = True
        self.isMining = False
        block = self.jsonToBlock(jsonBlock)
        if self.validateBlock(block):
            self.chain.addBlock(block)
        else:
            print('==> Conflict detected. Asking the others...')
            self.existsConflict = True
            self.resolveConflict()
            self.existsConflict = False
        self.isStillAdjusting = True
        self.adjust(self.chain.blocks[-1])

        self.money = dict(self.unspentTransactionsMap[self.wallet.address])

        self.tempUsedOutputs = {}
        self.workingBlock = Block(
            previousHash=self.chain.lastBlockHash(),
            index=self.chain.lastBlockIndex()+1)
        self.isStillAdjusting = False
        time.sleep(0.8)
        self.winningBlockFound = False

    # thelei akomh kai to unspentTransactionsMap klp

    def resolveConflict(self):
        addressSuffix = '/chain/conflict/length'
        ipAddress = ''
        port = -1
        headers = {'Content-type': 'application/json'}
        length = len(self.chain)
        for node in self.ring:
            address = 'http://' + node['ip'] + ':{0}'.format(node['port']) + addressSuffix
            tempLength = requests.get(url=address, headers=headers).json()['length']
            if tempLength > length:
                length = tempLength
                ipAddress = node['ip']
                port = node['port']
        if length == len(self.chain):
            return
        address = 'http://' + ipAddress + ':{0}'.format(port) + '/chain/conflict/blockchain'
        jsonChain = requests.get(url=address, headers=headers).json()
        jsonChain = json.loads(jsonChain['chain'])['chain']
        chain = self.jsonToBlockchain(jsonChain)
        if self.validateChain(chain):
            print('Conflict Resolved')
            self.legitTransactions = []
            self.chain = chain
            for node in self.ring:
                self.unspentTransactionsMap[node['address']] = {}
            self.unspentTransactionsMap[self.wallet.address] = dict()
            transactionInputsIds = []
            transactionOutputs = []
            for block in self.chain.blocks:
                for transaction in block.listOfTransactions:
                    self.legitTransactions.append(transaction.transactionId)
                    for transactionInput in transaction.transactionInputs:
                        transactionInputsIds.append(transactionInput)
                    for transactionOutput in transaction.transactionOutputs:
                        transactionOutputs.append(transactionOutput)
            toKeepTransactionOutputs = [
                transactionOutput for transactionOutput in transactionOutputs
                if transactionOutput.id not in transactionInputsIds]
            for transactionOutput in toKeepTransactionOutputs:
                self.unspentTransactionsMap[transactionOutput.address][transactionOutput.id] = transactionOutput
        else:
            print('Wtf this cannot be happening --resolveConflict')

    def validateChain(self, chain):
        genesisBlock = self.chain.blocks[0]
        self.chain.blocks = [genesisBlock]
        for i in range(1, len(chain)):
            if not self.validateBlock(chain.blocks[i]):
                # print('False')
                return False
            self.chain.addBlock(chain.blocks[i])
        # print('True')
        return True

    def adjust(self, winningBlock):
        mineTransactionsIds = [transaction.transactionId for transaction in self.workingBlock.listOfTransactions]
        winningTransactionsIds = [transaction.transactionId for transaction in winningBlock.listOfTransactions]

        self.legitTransactions += winningTransactionsIds
        # t1 --> transactions dika mou oxi sto winning block pou elava omws
        # t2 --> transactions sto winning block alla oxi se emena

        t1 = [transaction for transaction in self.workingBlock.listOfTransactions
              if transaction.transactionId not in winningTransactionsIds]
        t2 = [transaction for transaction in winningBlock.listOfTransactions
              if transaction.transactionId not in mineTransactionsIds]

        # print(mineTransactionsIds)
        # print(winningTransactionsIds)
        # print(t1)
        # print(t2)

        # t2Inputs --> ta transactionInputs pou xrhsimopoihthikan sto winning block
        # t2InputsAddresses --> h antistoixh sender address gia kathe apo ta parapanw transaction inputs

        t2Inputs = []
        t2InputsAddresses = []
        for transaction in t2:
            for transactionInput in transaction.transactionInputs:
                t2Inputs.append(transactionInput)
                t2InputsAddresses.append(transaction.senderAddress)

        # cleanTransactions --> ta transactions tou t1 pou mporoun na xrhsimopoihthoun autousia pali
        # dirtyTransactions --> ta transactions tou t1 pou eixan toulaxiston ena transaction input koino me ta transaction inputs
        #                       tou winning block, kai etsi tha prepei ek neou na desmeutoun poroi kai na ginei validate
        # toBeUsedAgainTransactionInputs --> ta transaction inputs tou sunolou t1 pou mporoun na ksanaxrhsimopoithoun

        cleanTransactions = []
        dirtyTransactions = []
        toBeUsedAgainTransactionInputs = []

        # print(t2Inputs)
        # print(t2InputsAddresses)

        # prosdiorismos twn domwn cleanTransactions, dirtyTransactions, toBeUsedAgainTransactionInputs

        for transaction in t1:
            sendBack = False
            for i in range(0, len(transaction.transactionInputs)):
                if transaction.transactionInputs[i] in t2Inputs:
                    # t2Inputs.pop(i)
                    # t2InputsAddresses.pop(i)
                    sendBack = True
                else:
                    toBeUsedAgainTransactionInputs.append(transaction.transactionInputs[i])
            if sendBack == True:
                dirtyTransactions.append(transaction)
            else:
                cleanTransactions.append(transaction)

        # print(toBeUsedAgainTransactionInputs)

        # proshtetoume sto unspentTransactionsMap ta transactionInputs pou mporoun na xrhsimopoihthoun kai pali

        # print(cleanTransactions)
        # print(dirtyTransactions)

        # print(self.unspentTransactionsMap)

        for transactionInput in toBeUsedAgainTransactionInputs:
            try:
                temp = self.tempUsedOutputs[transactionInput]
                self.unspentTransactionsMap[temp[1]][temp[0].id] = temp[0]
            except:
                pass

        # gia kathe transaction tou sunolou t2 prosthetoume ta transaction outputs ston unspentTransactionsMap mas

        for transaction in t2:
            for transactionOutput in transaction.transactionOutputs:
                self.unspentTransactionsMap[transactionOutput.address][transactionOutput.id] = transactionOutput

        # afairoume apo to unspentTransactionsMap ta transactionInputs pou anhkan sto winning block

        for i in range(0, len(t2Inputs)):
            try:
                self.unspentTransactionsMap[t2InputsAddresses[i]].pop(t2Inputs[i])
            except:
                pass

        for transaction in t1:
            for transactionOutput in transaction.transactionOutputs:
                try:
                    self.unspentTransactionsMap[transactionOutput.address].pop(transactionOutput.id)
                except:
                    pass

        # gia kathe dirty transaction pou eixame ftiaksei afairoume ta transactionOutputs pou auto eixe paragei
        # kai sthn sunexeia dokimazoume ek neou na to ftiaksoume. An ginetai to prosthetoume sta cleanTransactions,
        # alliws to petame

        # for transaction in dirtyTransactions:
        #     tempTransaction, flag = self.createTransaction(
        #         senderAddress=transaction.senderAddress, amount=transaction.amount,
        #         receiverAddress=transaction.receiverAddress)
        #     if not flag:
        #         print('Found invalid transaction')
        #     else:
        #         tempTransaction.remainingTries = transaction.remainingTries
        #         cleanTransactions.append(tempTransaction)

        # print(self.unspentTransactionsMap)

        # epanatopothetoume sto transaction pool kathe clean transaction afou meiwsoume ton deikth remaining tries

        for transaction in cleanTransactions:
            transaction.remainingTries -= 1
            transaction.transactionOutputs = []
            self.transactionPool.appendleft({transaction.transactionId: transaction})

        # for node in self.ring:
        #     print(node['nodeId'])
        #     print(self.walletBalance(node['address']))
        # print(self.nodeId)
        # print(self.myWalletBalance())
        return

    def printTransactionPool(self):
        print(len(self.transactionPool))
        print('===============================================================================')
        for transaction in self.transactionPool:
            for value in list(transaction.values()):
                print(value)
        print('===============================================================================')

    def printUnspentTransactionsMap(self):
        print(len(self.unspentTransactionsMap))
        for address, unspent in list(self.unspentTransactionsMap.items()):
            print('===============================================================================')
            print(address)
            for id, output in unspent.items():
                print('---------------------- {0} ----------------------'.format(id))
                print(output)
                print('-----------------------{0}-----------------------'.format('-'*len(id)))
            print('===============================================================================')

    def printTempUsedOutputs(self):
        for id, output in self.tempUsedOutputs.items():
            print('---------------------- {0} ----------------------'.format(id))
            print(output)
            print('-----------------------{0}-----------------------'.format('-'*len(id)))
        print('===============================================================================')


# wallet = Wallet()
# t = Transaction(senderAddress=wallet.address, receiverAddress='0'*len(wallet.address),
#                 amount=100, senderPrivateKey=wallet.privateKey)
# node = Node('192.168.11.102', 5000)
# jsonT = json.dumps(t.toDictAll(), indent=4)
# print(jsonT)
# dictT = json.loads(jsonT)
# print(dictT['transactionOutputs'])
# newT = node.jsonToTransaction(jsonT)
# print(type(newT))
