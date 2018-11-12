# -*- coding: utf-8 -*-

import getopt
import ipaddress
import json
import multiprocessing
import pathlib
import re
import select
import socket
import struct
import sys
import time
import traceback

from ftcap import writer

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
    print(dataPool)
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
    socketPort = (clientAddress[1], serverAddress[1])
    if not exchangeFlag:
        remoteConn = Connect_Serv((serverAddress[0], serverAddress[1]))
        localConn = clientConn
    else:
        remoteConn = clientConn
        localConn = Connect_Serv((serverAddress[0], serverAddress[1]))

    # If communicate with port 21
    if serverAddress[1] == 21:
        print(f"Connection from {clientAddress} to {serverAddress} is a Control Connection for FTP.")
        timestamp = time.time()
        if socketKey in dataPool:
            dataPool['PASV'][socketKey].append([timestamp, None])
            dataPool['ACTV'][socketKey].append([timestamp, None])
        else:
            dataPool['PASV'][socketKey] = [[timestamp, None]]
            dataPool['ACTV'][socketKey] = [[timestamp, None]]
        TCP_Control_Trans(localConn, remoteConn, socketKey, socketPort, timestamp, dataPool)
        localConn.close()
        remoteConn.close()
        return

    else:
        # Check if the port is set for data transfer
        for _ in range(10):
            if socketKey in dataPool:
                for j, item in enumerate(dataPool['PASV'][socketKey]):
                    if item[1] == serverAddress[1]:
                        print(f"Connection from {clientAddress} to {serverAddress} is a Passive Data Connection for FTP.")
                        timestamp = item[0]
                        del dataPool['PASV'][socketKey][j]
                        TCP_Data_Trans(localConn, remoteConn, socketKey, socketPort, timestamp)
                        localConn.close()
                        remoteConn.close()
                        return
                for j, item in enumerate(dataPool['ACTV'][socketKey]):
                    if item[1] == clientAddress[1]:
                        print(f"Connection from {clientAddress} to {serverAddress} is a Active Data Connection for FTP.")
                        timestamp = item[0]
                        del dataPool['ACTV'][socketKey][j]
                        TCP_Data_Trans(localConn, remoteConn, socketKey, socketPort, timestamp)
                        localConn.close()
                        remoteConn.close()
                        return
            time.sleep(0.01)

    # Other Data Transfer
    Other_Data_Trans(localConn, remoteConn)
    localConn.close()
    remoteConn.close()
    return


def TCP_Control_Trans(clifd, servfd, socketKey, socketPort, timestamp, dataPool):
    readfd = [clifd, servfd]
    fileName = f"./record/{socketKey[0]}_{socketKey[1]}_{timestamp}.ftcap"
    writer.write_header(fileName, socketKey[0], socketKey[1], timestamp)
    while True:
        rfd, _, _ = select.select(readfd, [], [])
        if clifd in rfd:
            recvData = clifd.recv(1024)
            if recvData[:4] == b'PORT':
                _, _, _, _, e, f = recvData[4:].split(b',')
                e, f = int(e.strip()), int(f.strip())
                dataPort = e * 256 + f
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Active Mode. Client Data Port is {dataPort}.")
                for j in dataPool['ACTV'][socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
                        break
            elif recvData[:4] == b'EPRT':
                port = recvData.split(b'|')[-2]
                dataPort = int(port)
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Active Mode. Client Data Port is {dataPort}.")
                for j in dataPool['ACTV'][socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
                        break
            elif recvData[:4] == b'LPRT':
                address = recvData[4:].split(b',')
                ipNum = int(address[1].strip())
                ports = address[(2+ipNum):]
                dataPort = 0
                for i in ports:
                    dataPort = dataPort * 256 + int(i.strip())
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Active Mode. Client Data Port is {dataPort}.")
                for j in dataPool['ACTV'][socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
                        break
            if recvData:
                servfd.sendall(recvData)
                writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
        if servfd in rfd:
            recvData = servfd.recv(1024)
            if recvData[:3] == b'227':
                _, _, _, _, e, f = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).split(b',')
                e, f = int(e.strip()), int(f.strip())
                dataPort = e * 256 + f
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Passive Mode. Server Data Port is {dataPort}.")
                for j in dataPool['PASV'][socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
                        break
            elif recvData[:3] == b'228':
                _, port = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).split(b',')
                dataPort = int(port.strip())
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Passive Mode. Server Data Port is {dataPort}.")
                for j in dataPool['PASV'][socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
                        break
            elif recvData[:3] == b'229':
                port = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).strip(b'|')
                dataPort = int(port)
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Passive Mode. Server Data Port is {dataPort}.")
                for j in dataPool['PASV'][socketKey]:
                    if j[0] == timestamp:
                        j[1] = dataPort
                        break
            if recvData:
                clifd.sendall(recvData)
                writer.async_write(LOCK, fileName, True, socketPort[1], socketPort[0], recvData)


def TCP_Data_Trans(clifd, servfd, socketKey, socketPort, timestamp):
    readfd = [clifd, servfd]
    fileName = f"./record/{socketKey[0]}_{socketKey[1]}_{timestamp}.ftcap"
    while True:
        rfd, _, _ = select.select(readfd, [], [])
        if clifd in rfd:
            recvData = clifd.recv(1024)
            if recvData:
                servfd.sendall(recvData)
                writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
        if servfd in rfd:
            recvData = servfd.recv(1024)
            if recvData:
                clifd.sendall(recvData)
                writer.async_write(LOCK, fileName, True, socketPort[1], socketPort[0], recvData)


def Other_Data_Trans(clifd, servfd):
    readfd = [clifd, servfd]
    while True:
        rfd, _, _ = select.select(readfd, [], [])
        if clifd in rfd:
            recvData = clifd.recv(1024)
            if recvData:
                servfd.sendall(recvData)
        if servfd in rfd:
            recvData = servfd.recv(1024)
            if recvData:
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
    opts, _ = getopt.getopt(sys.argv[1:], 'p:', ["port="])
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
    dataPool['PASV'] = {}
    dataPool['ACTV'] = {}
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
