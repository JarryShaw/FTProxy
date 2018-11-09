# -*- coding: utf-8 -*-

import getopt
import socket
import sys

def Connectionthread(*args):
    pass

def Data_Trans(clifd, servfd):
    pass


def Connect_Serv(servaddr):
    pass


def tcp_listen(port):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    if sockfd < 0:
        print('Socket failed... Abort...')
        return -1
    sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if sockfd.bind(proxyserver_addr) < 0:
        print('Bind failed... Abort...')
        return -1


def checkserver(serv_addr):
    pass


def checkclient(cki_addr):
    pass


def main():
    opt = getopt.getopt(sys.argv, 'p:')
    for key, val in opt:
        if key == 'p':
            port = int(val)
        else:
            print(f'Usage {sys.argv[0]} -p port')
            sys.exit(-1)

    sockfd = tcp_listen(port)
    print(f'listening on {sys.argv[1]}')
    while True:
        pass
