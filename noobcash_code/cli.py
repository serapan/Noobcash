from cmd import Cmd
from argparse import ArgumentParser
import json
import requests
import socket
import fcntl
import struct

class NoobcashCli(Cmd):
    prompt = 'NoobcashCli > '
    intro = "Welcome! Type ? or help to list commands"
    def my_creds(self, ip, port):
        self.ip = ip
        self.port = port
        self.url = 'http://' + ip + ':' + str(port)
    def do_t(self,inp):
        args = inp.split()
        if len(args) == 2:
            address = args[0]
            amount = args[1]
        else:
            print("Wrong usage of 't'. Syntax : t <address> <amount>")
            return
        headers = {'Content-type': 'application/json'}
        body = json.dumps({'amount' : int(amount), 'receiverAddress' : address}, indent=4)
        reply = requests.post(url=self.url + '/transactions/get', data = body, headers=headers).json()
        print(reply['msg'])
    def do_view(self,inp):
        headers = {'Content-type': 'application/json'}
        reply = requests.get(url=self.url + '/lastBlock', headers=headers).json()
        for transaction in reply['transactions']:
            transaction = json.loads(transaction)
            print('===============================================================', '\n')
            print('Sender Address: {0}'.format(transaction['senderAddress']), '\n')
            print('Receiver Address: {0}'.format(transaction['receiverAddress']), '\n')
            print('Amount: {0}'.format(transaction['amount']), '\n')
    def do_balance(self,inp):
        headers = {'Content-type': 'application/json'}
        reply = requests.get(url=self.url + '/wallet', headers=headers).json()
        print(reply['wallet'])
    def do_ring(self, inp):
        headers = {'Content-type': 'application/json'}
        reply = requests.get(url=self.url + '/ring', headers=headers).json()
        ring = json.loads(reply['ring'])
        for node in ring['ring']:
            print('===============================================================', '\n')
            print('Id: {0}'.format(node['nodeId']), '\n')
            print('Ip: {0}'.format(node['ip']), '\n')
            print('Port: {0}'.format(node['port']), '\n')
            print('Address: {0}'.format(node['address']), '\n')
    def do_exit(self, inp):
        '''exit the application.'''
        return True
    
    def help_balance(self):
        print('Prints the current balance of wallet')
    def help_view(self):
        print('Prints the the transactions of the last confirmed chain block')
    def help_t(self):
        print('Syntax : t <recipient_address> <amount>\nSend <amount> coins to <recipient_address> user')
    def help_ring(self):
        print('Prints the addresses of all nodes connected to the network')           
    def help_exit(self):
        print("Type 'exit' to exit the application")

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
    argsDict = vars(parser.parse_args())
    if argsDict['ip']:
        ip = argsDict['ip']
    port = argsDict['port']
    noobcashCli = NoobcashCli()
    noobcashCli.my_creds(ip, port)
    noobcashCli.cmdloop()