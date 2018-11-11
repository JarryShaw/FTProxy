# -*- coding: utf-8 -*-

import getopt
import socket
import sys
import traceback
import json
import multiprocessing
import struct
import select
import ipaddress
import pathlib
import time

clientBlackList = []
serverBlackList = []
SO_ORIGINAL_DST = 80
LOCK = None


def LoadClientBlackList(file):
    with open(file, 'r') as f:
        global clientBlackList
        clientBlackList = json.load(f)


def LoadServerBlackList(file):
    with open(file, 'r') as f:
        global serverBlackList
        serverBlackList = json.load(f)


def Connectionthread(clientConn, clientAddress, serverAddress, dataPool):
    exchangeFlag = False
    if ipaddress.ip_address(serverAddress[0]).is_private:
        clientAddress, serverAddress = serverAddress, clientAddress
        exchangeFlag = True
    print(f"Accept connection from {clientAddress[0]}:{clientAddress[1]} to {serverAddress[0]}:{serverAddress[1]}")

    if not checkclient(clientAddress[0]):
        print(f"Client {clientAddress[0]} has been blocked.")
        clientConn.close()
        return
    elif not checkserver(serverAddress[0]):
        print(f"Server {serverAddress[0]} has been blocked.")
        clientConn.close()
        return

    socketKey = (clientAddress[0], serverAddress[0])
    if not exchangeFlag:
        remoteConn = Connect_Serv((serverAddress[0], serverAddress[1]))
        localConn = clientConn
    else:
        remoteConn = clientConn
        localConn = Connect_Serv((serverAddress[0], serverAddress[1]))

    # If communicate with port 21
    if serverAddress[1] == 21:
        timestamp = time.time()
        if socketKey in dataPool:
            dataPool[socketKey].append([timestamp, None])
        else:
            dataPool[socketKey] = [[timestamp, None]]
        TCP_Control_Trans(localConn, remoteConn, socketKey, timestamp, dataPool)
        localConn.close()
        remoteConn.close()
        return

    else:
        # Check if the port is set for data transfer
        for i in range(10):
            if socketKey in dataPool:
                for j in range(len(dataPool[socketKey])):
                    if dataPool[socketKey][j][1] == serverAddress[1]:
                        timestamp = dataPool[socketKey][j][0]
                        del dataPool[socketKey][j]
                        TCP_Data_Trans(localConn, remoteConn, socketKey, timestamp, dataPool)
                        localConn.close()
                        remoteConn.close()
                        return
            time.sleep(0.01)

    # Other Data Transfer
    Other_Data_Trans(localConn, remoteConn)
    localConn.close()
    remoteConn.close()
    return


def TCP_Control_Trans(clifd, servfd, socketKey, timestamp, dataPool):
    client = clifd.getpeername()
    server = servfd.getpeername()
    readfd = [clifd, servfd]
    while True:
        rfd, wfd, xfd = select.select(readfd, [], [])
        if clifd in rfd:
            recvData = clifd.recv(1024)
            if recvData:
                print(f"{client} said: {recvData}")
                servfd.sendall(recvData)
        if servfd in rfd:
            recvData = servfd.recv(1024)
            if b'227 Entering Passive Mode' in recvData:
                a, b, c, d, e, f = recvData[27:-4].split(b',')
                e, f = eval(e), eval(f)
                dataPort = e * 256 + f
                for j in dataPool[socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
            if recvData:
                print(f"{server} said: {recvData}")
                clifd.sendall(recvData)


def TCP_Data_Trans(clifd, servfd, socketKey, timestamp, dataPool):
    client = clifd.getpeername()
    server = servfd.getpeername()
    readfd = [clifd, servfd]
    while True:
        rfd, wfd, xfd = select.select(readfd, [], [])
        if clifd in rfd:
            recvData = clifd.recv(1024)
            if recvData:
                print(f"{client} said: {recvData}")
                servfd.sendall(recvData)
        if servfd in rfd:
            recvData = servfd.recv(1024)
            if recvData:
                print(f"{server} said: {recvData}")
                clifd.sendall(recvData)


def Other_Data_Trans(clifd, servfd):
    client = clifd.getpeername()
    server = servfd.getpeername()
    readfd = [clifd, servfd]
    while True:
        rfd, wfd, xfd = select.select(readfd, [], [])
        if clifd in rfd:
            recvData = clifd.recv(1024)
            if recvData:
                print(f"{client} said: {recvData}")
                servfd.sendall(recvData)
        if servfd in rfd:
            recvData = servfd.recv(1024)
            if recvData:
                print(f"{server} said: {recvData}")
                clifd.sendall(recvData)


def Connect_Serv(serverAddr):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    print("Server socket creation succeeded.")

    serverSocket.connect(serverAddr)
    return serverSocket


def tcp_listen(port):
    # create a socket
    tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    print("Socket creation succeeded.")

    # set option
    tcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket options set.")

    # bind socket with all local IP address and port [port]
    tcpSocket.bind(("0.0.0.0", port))
    print(f"Socket bind with all local IP address and port {port}.")

    # start listening
    tcpSocket.listen(20)
    print(f"Start listening on port {port}.")

    return tcpSocket


def checkserver(serv_addr):
    global serverBlackList
    if serv_addr in serverBlackList:
        return False
    else:
        return True


def checkclient(cki_addr):
    global clientBlackList
    if cki_addr in clientBlackList:
        return False
    else:
        return True


def main():
    pathlib.Path("./record/").mkdir(parents=True, exist_ok=True)
    opts, args = getopt.getopt(sys.argv[1:], 'p:', ["port="])
    for key, val in opts:
        if key in ('-p', "--port"):
            port = int(val)
        else:
            print(f'Usage {sys.argv[0]} -p port')
            sys.exit(-1)

    manager = multiprocessing.Manager()
    global LOCK
    LOCK = multiprocessing.Lock()
    dataPool = manager.dict()
    tcpSocket = tcp_listen(port)
    print(f'listening on {sys.argv[2]}')
    try:
        while True:
            # accept a new connection
            try:
                newConn, clientAddress = tcpSocket.accept()
            except (socket.error, socket.gaierror, socket.herror):
                print("Failed to accept a connection.")
                traceback.print_exc()
                continue
            sockAddr = newConn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            srvPort, srvIp = struct.unpack("!2xH4s8x", sockAddr)
            srvIp = socket.inet_ntoa(srvIp)
            serverAddress = (srvIp, srvPort)
            multiprocessing.Process(target=Connectionthread,
                                        args=(newConn, clientAddress, serverAddress, dataPool)).start()
    except KeyboardInterrupt:
        print("Stop!")
    manager.shutdown()


if __name__ == '__main__':
    main()
