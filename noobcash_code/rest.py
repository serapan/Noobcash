from flask import Flask, jsonify, request
from argparse import ArgumentParser
from node import Node
from block import Block, CAPACITY, DIFFICULTY
from bootstrapNode import BootstrapNode
import sys
import json
import threading
import time
import requests
import socket
import fcntl
import struct

app = Flask(__name__)

# python3 rest.py -a 192.168.11.122 -p 5000 -ba 192.168.11.251 -bp 5000
# python3 rest.py -a 192.168.11.122 -p 5000 -ba 192.168.11.122 -bp 5000 --bootstrap -n 2
# scp -r noobcash serafeim@192.168.11.102:/home/serafeim/Desktop

################################################## Testing ##################################################


def readTransactions():
    f = open('transactions{0}.txt'.format(miner.nodeId), 'r')
    transactions = f.readlines()
    miner.firstTime = time.time()
    for i in range(0, len(transactions)-1):
        transactions[i] = transactions[i][2:-1].split()
        if int(transactions[i][0]) in [3, 4]:
            continue
        else:
            address = ''
            for node in miner.ring:
                if node['nodeId'] == int(transactions[i][0]):
                    address = node['address']
                    break
            msg, flag = miner.transact(miner.wallet.address, int(transactions[i][1]), address)
            print(msg)
        time.sleep(2)


@app.route('/others', methods=['GET'])
def check():
    headers = {'Content-type': 'application/json'}
    # for node in miner.ring:
    #     ipAddress = node['ip']
    #     port = node['port']
    #     address = 'http://' + ipAddress + ':{0}'.format(port) + '/chain/conflict/blockchain'
    #     jsonChain = requests.get(url=address, headers=headers).json()
    #     jsonChain = json.loads(jsonChain['chain'])['chain']
    #     chain = miner.jsonToBlockchain(jsonChain)
    #     # print(chain)
    #     print(
    #         '-------------------------------------------- {0} --------------------------------------------'.format(node['nodeId']))
    #     for i in range(0, len(miner.chain)):
    #         print('===================================================')
    #         print(chain.blocks[i].currentHash)
    #         print(miner.chain.blocks[i].currentHash)
    #         print('===================================================')
    for node in miner.ring:
        print('===================================================')
        print(node['nodeId'])
        print(miner.walletBalance(node['address']))
        print('===================================================')
    print(miner.nodeId)
    print(miner.myWalletBalance())
    print('===================================================')
    # print(miner.befores)
    # print(miner.afters)
    # print(miner.diff)

    return jsonify({'msg': 'I hope everything is bazinga'}), 200


@app.route('/test', methods=['GET'])
def test():
    threading.Thread(target=readTransactions).start()
    return jsonify({'msg': 'I hope everything is bazinga'}), 200


@app.route('/times', methods=['GET'])
def times():
    print('Block Times: {0}'.format(miner.blockTimes))
    print('Mean Block Time: {0}'.format(sum(miner.blockTimes)/len(miner.blockTimes)))
    print('Transactions/full_time: {0}'.format((len(miner.chain)*CAPACITY)/(miner.lastTime-miner.firstTime)))
    return jsonify({'msg': 'I hope everything is bazinga'}), 200


@app.route('/', methods=['GET'])
def greet():
    def resolveAddress(address):
        for node in miner.ring:
            if node['address'] == address:
                return node['nodeId']
        return 0
    money = [300, 0, 0]
    l = []
    print(miner.chain)
    print(miner.printUnspentTransactionsMap())
    print('========================================================')
    for block in miner.chain.blocks:
        for transaction in block.listOfTransactions:
            sender = resolveAddress(transaction.senderAddress)
            receiver = resolveAddress(transaction.receiverAddress)
            print('sender {0}\t receiver {1}\t amount {2}\t id {3}'.format(
                sender, receiver, transaction.amount, transaction.transactionId))
            money[sender] -= transaction.amount
            money[receiver] += transaction.amount
            l.append(transaction.transactionId)
    print('========================================================')
    print(money)
    s = set(l)
    if len(s) == len(l):
        print('nice')
    else:
        print('not nice')
    for transaction in miner.workingBlock.listOfTransactions:
        sender = resolveAddress(transaction.senderAddress)
        receiver = resolveAddress(transaction.receiverAddress)
        print('sender {0}\t receiver {1}\t amount {2}\t id {3}'.format(
            sender, receiver, transaction.amount, transaction.transactionId))
        money[sender] -= transaction.amount
        money[receiver] += transaction.amount
        l.append(transaction.transactionId)
    print(money)
    return jsonify({'msg': 'I hope everything is bazinga'}), 200


################################################## Testing ##################################################


@app.route('/bootstrap/register', methods=['POST'])
def registerNode():
    if not miner.isBootstrapNode():
        raise Exception('In order to register a node you must be the bootstrab node')
    data = request.get_json()
    nodeId = miner.registerNodeToRing(data['ip'], data['port'], data['address'])
    return jsonify({'nodeId': nodeId}), 201


@app.route('/bootstrap/registerAck', methods=['POST'])
def receiveAck():
    def broadcast():
        time.sleep(1)
        miner.broadcastInfo()
        time.sleep(2)
        miner.createInitialTransactions()
    if not miner.isBootstrapNode():
        raise Exception('In order to receive a register ack you must be the bootstrab node')
    data = request.get_json()
    ackId = data['nodeId']
    miner.acks[str(ackId)] = True
    print('Received register acknowledgment from node{0}'.format(ackId))
    if False not in miner.acks.values():
        miner.createUnspentTransactionsMap()
        miner.workingBlock = Block(previousHash=miner.chain.blocks[0].currentHash, index=len(miner.chain)+1)
        threading.Thread(target=broadcast).start()
    return jsonify({'msg': 'Registration completed successfully'}), 201


@app.route('/bootstrap/info', methods=['POST'])
def receiveInfo():
    if miner.isBootstrapNode():
        raise Exception('How did bootstrap node get in /bootstrap/info')
    data = request.get_json()
    for i in range(0, len(data['ring'])):
        if data['ring'][i]['ip'] == miner.myIp and data['ring'][i]['port'] == miner.myPort:
            del data['ring'][i]
            break
    miner.ring = data['ring']
    miner.chain = miner.jsonToBlockchain(data['chain'])
    miner.createUnspentTransactionsMap()
    miner.workingBlock = Block(previousHash=miner.chain.blocks[0].currentHash, index=len(miner.chain)+1)
    return jsonify({'msg': 'ok'}), 200


@app.route('/transactions/broadcast', methods=['POST'])
def receiveTransaction():
    data = request.get_json()
    miner.receiveTransaction(data)
    return jsonify({'msg': 'ok'}), 200


@app.route('/transactions/get', methods=['POST'])
def getTransaction():
    data = request.get_json()
    msg, isValid = miner.transact(miner.wallet.address, data['amount'], data['receiverAddress'])
    return jsonify({'msg': msg}), 200


@app.route('/block/broadcast', methods=['POST'])
def receiveBlock():
    data = request.get_json()
    miner.receiveBlock(json.dumps(data, indent=4))
    return jsonify({'msg': 'ok'}), 200


@app.route('/chain/conflict/length', methods=['GET'])
def receiveBlockchainLength():
    return jsonify({'length': len(miner.chain)})


@app.route('/chain/conflict/blockchain', methods=['GET'])
def receiveBlockchain():
    return jsonify({'chain': json.dumps(miner.chain.toDictAll(), indent=4)})


@app.route('/ring', methods=['GET'])
def receiveRing():
    return jsonify({'ring': json.dumps({'ring': miner.ring}, indent=4)})


@app.route('/wallet', methods=['GET'])
def receiveWallet():
    return jsonify({'wallet': miner.myWalletBalance()})


@app.route('/lastBlock', methods=['GET'])
def viewTransactions():
    lastTransactions = miner.chain.blocks[-1].listOfTransactions
    return jsonify(
        {'transactions': [json.dumps(transaction.toDictAll(),
                                     indent=4) for transaction in lastTransactions]})


@app.route('/pool', methods=['GET'])
def viewTransactionPool():
    for transaction in miner.transactionPool:
        print(transaction)
    return jsonify(
        {'msg': 'i hope everything is ok'})


@app.route('/map', methods=['GET'])
def viewMap():
    for address, values in miner.unspentTransactionsMap.items():
        print('========================={0}========================='.format(address))
        for id, out in values.items():
            print(id)
            print('trans : ', out.transactionId)
            print('id : ', out.id)
            print('amount : ', out.amount)
        print('=====================================================')
    return jsonify(
        {'msg': 'i hope everything is ok'})


def poolTransactionFromBlock():
    poolingThread = threading.Timer(0.4, poolTransactionFromBlock)
    poolingThread.setDaemon(True)
    poolingThread.start()
    miner.pullTransactionFromPool()


if __name__ == "__main__":
    def get_ip_address(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode())
        )[20:24])

    try:
        ip = get_ip_address("eth1")
    except:
        ip = ''
        pass

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, required=True, help='port to listen on')
    parser.add_argument('-a', '--ip', type=str, required=False, help='ip address of this machine')
    parser.add_argument('-bp', '--bootstrapPort', default=5000, type=int,
                        required=True, help='port bootstrap node listens on')
    parser.add_argument('-ba', '--bootstrapIp', type=str, required=True, help='ip address of bootstrap node')
    parser.add_argument('-b', '--bootstrap', action='store_true', required=False,
                        help='with this flag bootstrap node is generated')
    parser.add_argument('-n', '--num', type=int, required=False,
                        help='Number of nodes. Use this onle when --bootstrap is set')
    if ('-n' in sys.argv or '--num' in sys.argv) and not ('-b' in sys.argv or '--bootstrap' in sys.argv):
        parser.error("Number of nodes must be given only to the bootstrap node")
    argsDict = vars(parser.parse_args())
    if argsDict['ip']:
        ip = argsDict['ip']
    if argsDict['bootstrap']:
        miner = BootstrapNode(ip, argsDict['port'], argsDict['num'])
        miner.genesis()
    else:
        miner = Node(ip, argsDict['port'])
        miner.registerNodeToRing(argsDict['bootstrapIp'], argsDict['bootstrapPort'])
    poolTransactionFromBlock()

    app.run(host=ip, port=argsDict['port'])
