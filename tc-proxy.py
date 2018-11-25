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
MAX_LENGTH = 4096


def LoadClientBlackList(file):
    with open(file, 'r') as f:
        global clientBlackList
        clientBlackList = json.load(f)


def LoadServerBlackList(file):
    with open(file, 'r') as f:
        global serverBlackList
        serverBlackList = json.load(f)


def Connectionthread(requesterConn, requesterAddress, responderAddress, dataPool):
    if ipaddress.ip_address(responderAddress[0]).is_private:
        localAddress, remoteAddress = responderAddress, requesterAddress
    else:
        localAddress, remoteAddress = requesterAddress, responderAddress
    print(f"Accept connection from {requesterAddress[0]}:{requesterAddress[1]} to {responderAddress[0]}:{responderAddress[1]}")

    if not checkclient(localAddress[0]):
        print(f"Client {localAddress[0]} has been blocked.")
        requesterConn.close()
        return
    elif not checkserver(remoteAddress[0]):
        print(f"Server {remoteAddress[0]} has been blocked.")
        requesterConn.close()
        return

    socketKey = (localAddress[0], remoteAddress[0])
    socketPort = (localAddress[1], remoteAddress[1])
    print(f"Connecting to {responderAddress}.")
    responderConn = Connect_Serv(responderAddress)
    print("Succeed")

    # If communicate with port 21
    if responderAddress[1] == 21:
        print(f"Connection from {requesterAddress} to {responderAddress} is a Control Connection for FTP.")
        timestamp = time.time()
        if socketKey not in dataPool['PASV']:
            dataPool['PASV'][socketKey] = []
        if socketKey not in dataPool['ACTV']:
            dataPool['ACTV'][socketKey] = []
        print(dict(dataPool['PASV']))
        print(dict(dataPool['ACTV']))
        # if socketKey in dataPool['PASV']:
        #     dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey].append([timestamp, None])
        # else:
        #     dataPool['PASV'][socketKey] = [[timestamp, None]]
        # print(dict(dataPool['PASV']))
        # if socketKey in dataPool['ACTV']:
        #     dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey].append([timestamp, None])
        # else:
        #     dataPool['ACTV'][socketKey] = [[timestamp, None]]
        # print(dict(dataPool['ACTV']))
        TCP_Control_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp, dataPool)
        requesterConn.close()
        responderConn.close()
        return

    elif responderAddress[1] == 20:
        # Check if port is set for data transfer
        print(f"Check if the connection from {requesterAddress} to {responderAddress} is an active mode data transfer")
        for _ in range(10):
            # print(dict(dataPool['PASV']))
            print(dict(dataPool['ACTV']))
            # if socketKey in dataPool['PASV']:
            #     for j, item in enumerate(dataPool['PASV'][socketKey]):
            #         if item[1] == serverAddress[1]:
            #             print(f"Connection from {clientAddress} to {serverAddress} is a Passive Data Connection for FTP.")
            #             timestamp = item[0]
            #             dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey][:j] + dataPool['PASV'][socketKey][j+1:] if len(dataPool['PASV'][socketKey]) > 1 else []
            #             # if not dataPool['PASV'][socketKey]:
            #             #     dataPool['PASV'][socketKey] = []
            #             TCP_Data_Trans(localConn, remoteConn, socketKey, socketPort, timestamp)
            #             localConn.close()
            #             remoteConn.close()
            #             return
            for socketKey in dataPool['ACTV']:
                for j, item in enumerate(dataPool['ACTV'][socketKey]):
                    if item[1] == requesterAddress[1]:
                        print(f"Connection from {requesterAddress} to {responderAddress} is a Active Data Connection for FTP.")
                        timestamp = item[0]
                        requesterConn.close()
                        requesterConn = Connect_Serv((socketKey[0], item[1]))
                        dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey][:j] + dataPool['ACTV'][socketKey][j+1:] if len(dataPool['ACTV'][socketKey]) > 1 else []
                        # if not dataPool['ACTV'][socketKey]:
                        #     dataPool['ACTV'][socketKey] = []
                        TCP_Data_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp)
                        requesterConn.close()
                        responderConn.close()
                        return
            time.sleep(0.01)

    else:
        print(f"Check if the connection from {requesterAddress} to {responderAddress} is a passive mode data transfer")
        for _ in range(10):
            print(dict(dataPool['PASV']))
            # print(dict(dataPool['ACTV']))
            if socketKey in dataPool['PASV']:
                for j, item in enumerate(dataPool['PASV'][socketKey]):
                    if item[1] == responderAddress[1]:
                        print(f"Connection from {requesterAddress} to {responderAddress} is a Passive Data Connection for FTP.")
                        timestamp = item[0]
                        dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey][:j] + dataPool['PASV'][socketKey][j+1:] if len(dataPool['PASV'][socketKey]) > 1 else []
                        # if not dataPool['PASV'][socketKey]:
                        #     dataPool['PASV'][socketKey] = []
                        TCP_Data_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp)
                        requesterConn.close()
                        responderConn.close()
                        return
            # if socketKey in dataPool['ACTV']:
            #     for j, item in enumerate(dataPool['ACTV'][socketKey]):
            #         if item[1] == clientAddress[1]:
            #             print(f"Connection from {clientAddress} to {serverAddress} is a Active Data Connection for FTP.")
            #             timestamp = item[0]
            #             dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey][:j] + dataPool['ACTV'][socketKey][j+1:] if len(dataPool['ACTV'][socketKey]) > 1 else []
            #             # if not dataPool['ACTV'][socketKey]:
            #             #     dataPool['ACTV'][socketKey] = []
            #             TCP_Data_Trans(localConn, remoteConn, socketKey, socketPort, timestamp)
            #             localConn.close()
            #             remoteConn.close()
            #             return
            time.sleep(0.01)

    # Other Data Transfer
    print("This is not a FTP connection.")
    Other_Data_Trans(requesterConn, responderConn)
    requesterConn.close()
    responderConn.close()
    return


def TCP_Control_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp, dataPool):
    readfd = [requesterConn, responderConn]
    fileName = f"./record/{socketKey[0]}_{socketKey[1]}_{timestamp}.ftcap"
    writer.write_header(fileName, socketKey[0], socketKey[1], timestamp)
    while True:
        rfd, _, _ = select.select(readfd, [], [])
        if requesterConn in rfd:
            recvData = requesterConn.recv(MAX_LENGTH)
            if recvData[:4] == b'PORT':
                _, _, _, _, e, f = recvData[4:].split(b',')
                e, f = int(e.strip()), int(f.strip())
                dataPort = e * 256 + f
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Active Mode. Client Data Port is {dataPort}.")
                recvData = ('PORT %s,%d,%d\r\n' % (eth0IP.replace('.', ','), e, f)).encode()
                if socketKey in dataPool['ACTV']:
                    dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey] + [[timestamp, dataPort]]
                else:
                    dataPool['ACTV'][socketKey] = [[timestamp, dataPort]]
                # for j, item in enumerate(dataPool['ACTV'][socketKey]):
                #     if item[0] == timestamp:
                #         tmp = dataPool['ACTV'][socketKey]
                #         tmp[j][1] = dataPort
                #         dataPool['ACTV'][socketKey] = tmp
                #         print(dict(dataPool['ACTV']))
                #         break
                print(dict(dataPool['ACTV']))
            elif recvData[:4] == b'EPRT':
                port = recvData.split(b'|')[-2]
                dataPort = int(port)
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Active Mode. Client Data Port is {dataPort}.")
                recvData = ('EPRT |1|%s|%d|\r\n' % (eth0IP, port)).encode()
                if socketKey in dataPool['ACTV']:
                    dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey] + [[timestamp, dataPort]]
                else:
                    dataPool['ACTV'][socketKey] = [[timestamp, dataPort]]
                # for j, item in enumerate(dataPool['ACTV'][socketKey]):
                #     if item[0] == timestamp:
                #         tmp = dataPool['ACTV'][socketKey]
                #         tmp[j][1] = dataPort
                #         dataPool['ACTV'][socketKey] = tmp
                #         print(dict(dataPool['ACTV']))
                #         break
                print(dict(dataPool['ACTV']))
            elif recvData[:4] == b'LPRT':
                address = recvData[4:].split(b',')
                ipNum = int(address[1].strip())
                portNum = address[1+ipNum]
                ports = address[(2+ipNum):]
                dataPort = 0
                for i in ports:
                    dataPort = dataPort * 256 + int(i.strip())
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Active Mode. Client Data Port is {dataPort}.")
                recvData = ('LPRT 4,4,%s,%s,%s\r\n' % (eth0IP.replace('.', ','), portNum, ','.join(ports))).encode()
                if socketKey in dataPool['ACTV']:
                    dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey] + [[timestamp, dataPort]]
                else:
                    dataPool['ACTV'][socketKey] = [[timestamp, dataPort]]
                # for j, item in enumerate(dataPool['ACTV'][socketKey]):
                #     if item[0] == timestamp:
                #         tmp = dataPool['ACTV'][socketKey]
                #         tmp[j][1] = dataPort
                #         dataPool['ACTV'][socketKey] = tmp
                #         print(dict(dataPool['ACTV']))
                #         break
                print(dict(dataPool['ACTV']))
            if recvData:
                responderConn.sendall(recvData)
                writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
        if responderConn in rfd:
            recvData = responderConn.recv(MAX_LENGTH)
            if recvData[:3] == b'227':
                _, _, _, _, e, f = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).split(b',')
                e, f = int(e.strip()), int(f.strip())
                dataPort = e * 256 + f
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Passive Mode. Server Data Port is {dataPort}.")
                if socketKey in dataPool['PASV']:
                    dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey] + [[timestamp, dataPort]]
                else:
                    dataPool['PASV'][socketKey] = [[timestamp, dataPort]]
                # for j, item in enumerate(dataPool['PASV'][socketKey]):
                #     if item[0] == timestamp:
                #         tmp = dataPool['PASV'][socketKey]
                #         tmp[j][1] = dataPort
                #         dataPool['PASV'][socketKey] = tmp
                #         print(dict(dataPool['PASV']))
                #         break
                print(dict(dataPool['PASV']))
            elif recvData[:3] == b'228':
                _, port = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).split(b',')
                dataPort = int(port.strip())
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Passive Mode. Server Data Port is {dataPort}.")
                if socketKey in dataPool['PASV']:
                    dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey] + [[timestamp, dataPort]]
                else:
                    dataPool['PASV'][socketKey] = [[timestamp, dataPort]]
                # for j, item in enumerate(dataPool['PASV'][socketKey]):
                #     if item[0] == timestamp:
                #         tmp = dataPool['PASV'][socketKey]
                #         tmp[j][1] = dataPort
                #         dataPool['PASV'][socketKey] = tmp
                #         print(dict(dataPool['PASV']))
                #         break
                print(dict(dataPool['PASV']))
            elif recvData[:3] == b'229':
                port = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).strip(b'|')
                dataPort = int(port)
                print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} is Passive Mode. Server Data Port is {dataPort}.")
                if socketKey in dataPool['PASV']:
                    dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey] + [[timestamp, dataPort]]
                else:
                    dataPool['PASV'][socketKey] = [[timestamp, dataPort]]
                # for j, item in enumerate(dataPool['PASV'][socketKey]):
                #     if item[0] == timestamp:
                #         tmp = dataPool['PASV'][socketKey]
                #         tmp[j][1] = dataPort
                #         dataPool['PASV'][socketKey] = tmp
                #         print(dict(dataPool['PASV']))
                #         break
                print(dict(dataPool['PASV']))
            if recvData:
                requesterConn.sendall(recvData)
                writer.async_write(LOCK, fileName, True, socketPort[1], socketPort[0], recvData)


def TCP_Data_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp):
    readfd = [requesterConn, responderConn]
    fileName = f"./record/{socketKey[0]}_{socketKey[1]}_{timestamp}.ftcap"
    while True:
        rfd, _, _ = select.select(readfd, [], [])
        if requesterConn in rfd:
            recvData = requesterConn.recv(MAX_LENGTH)
            if recvData:
                responderConn.sendall(recvData)
                writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
        if responderConn in rfd:
            recvData = responderConn.recv(MAX_LENGTH)
            if recvData:
                requesterConn.sendall(recvData)
                writer.async_write(LOCK, fileName, True, socketPort[1], socketPort[0], recvData)


def Other_Data_Trans(requesterConn, responderConn):
    readfd = [requesterConn, responderConn]
    while True:
        rfd, _, _ = select.select(readfd, [], [])
        if requesterConn in rfd:
            recvData = requesterConn.recv(MAX_LENGTH)
            if recvData:
                responderConn.sendall(recvData)
        if responderConn in rfd:
            recvData = responderConn.recv(MAX_LENGTH)
            if recvData:
                requesterConn.sendall(recvData)


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
    dataPool = dict()
    dataPool['PASV'] = manager.dict()
    dataPool['ACTV'] = manager.dict()
    tcpSocket = tcp_listen(port)
    print(f'listening on {sys.argv[2]}')
    try:
        while True:
            # accept a new connection
            try:
                newConn, requesterAddress = tcpSocket.accept()
            except (socket.error, socket.gaierror, socket.herror):
                print("Failed to accept a connection.")
                traceback.print_exc()
                continue
            sockAddr = newConn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            responderPort, responderIp = struct.unpack("!2xH4s8x", sockAddr)
            responderIp = socket.inet_ntoa(responderIp)
            responderAddress = (responderIp, responderPort)
            multiprocessing.Process(target=Connectionthread,
                                    args=(newConn, requesterAddress, responderAddress, dataPool)).start()
    except KeyboardInterrupt:
        print("Stop!")
    manager.shutdown()


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
eth0IP = s.getsockname()[0]
s.close()
if __name__ == '__main__':
    main()
