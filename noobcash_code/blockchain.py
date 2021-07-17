import json


class Blockchain():

    def __init__(self):
        self.blocks = []

    def addBlock(self, block):
        self.blocks.append(block)

    def toDictBlocks(self):
        chain = []
        for block in self.blocks:
            od = block.toDictAll()
            chain.append(od)
        return chain

    def toDictAll(self):
        chain = []
        for block in self.blocks:
            od = block.toDictAll()
            chain.append(od)
        return {'chain': chain}

    def lastBlockHash(self):
        return self.blocks[-1].currentHash

    def lastBlockIndex(self):
        return self.blocks[-1].index

    def printBlockchain(self):
        for block in self.blocks:
            print('---------------------------------------------------------------------------')
            print(block)
            print('---------------------------------------------------------------------------')

    def __str__(self):
        return json.dumps(self.toDictAll(), indent=4)

    def __len__(self):
        return len(self.blocks)
