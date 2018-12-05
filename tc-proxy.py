# -*- coding: utf-8 -*-

import getopt
import ipaddress
import multiprocessing
import pathlib
import re
import select
import socket
import struct
import sys
import time
import traceback

import policyManager
from ftcap import writer

LOCK = multiprocessing.Lock()
SO_ORIGINAL_DST = 80
MAX_LENGTH = 4096

policy = policyManager.reader()

# get local IP
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    eth0IP = s.getsockname()[0]


def validateRequester(recvData, requesterConn, fileName, socketPort, sizeFlag):
    dropFlag = False
    # User login
    if b'USER' in recvData:
        # USER username
        user = recvData.decode().split(' ')[-1].strip()
        if user in policy['userBlacklist']:
            recvData = f"User {user!r} has been blocked.\r\n"
            print(recvData)
            requesterConn.sendall(recvData.encode())
            writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData.encode())
            return True, sizeFlag
    # Client checking file size
    elif b'SIZE' in recvData:
        # SIZE file
        sizeFlag = True
    # Client enter path
    elif b'CWD' in recvData:
        # CWD path
        directory = recvData[4:-2].decode()
        if directory in policy['pathBlacklist']:
            writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
            recvData = f"Directory {directory!r} is not accessible.\r\n"
            print(recvData)
            requesterConn.sendall(recvData.encode())
            writer.async_write(LOCK, fileName, False, socketPort[1], socketPort[0], recvData.encode())
            return True, sizeFlag
    # Client download file
    elif b'RETR' in recvData:
        # RETR file
        if policy['retrPolicy']:
            writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
            recvData = f"Upload is not allowed.\r\n"
            print(recvData)
            requesterConn.sendall(recvData.encode())
            writer.async_write(LOCK, fileName, False, socketPort[1], socketPort[0], recvData.encode())
            return True, sizeFlag
        filePath = recvData[5:-2].decode()
        filePath = pathlib.Path(filePath)
        name = filePath.name
        extend = filePath.suffix
        if name in policy['fileBlacklist']:
            writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
            recvData = f"File {name!r} is blocked.\r\n"
            print(recvData)
            requesterConn.sendall(recvData.encode())
            writer.async_write(LOCK, fileName, False, socketPort[1], socketPort[0], recvData.encode())
            return True, sizeFlag
        if extend in policy['extendBlacklist']:
            writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
            recvData = f"File extension {extend!r} is blocked.\r\n"
            print(recvData)
            requesterConn.sendall(recvData.encode())
            writer.async_write(LOCK, fileName, False, socketPort[1], socketPort[0], recvData.encode())
            return True, sizeFlag
    # Client upload file
    elif b'STOR' in recvData:
        if policy['storPolicy']:
            writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
            recvData = f"Download is not allowed.\r\n"
            print(recvData)
            requesterConn.sendall(recvData.encode())
            writer.async_write(LOCK, fileName, False, socketPort[1], socketPort[0], recvData.encode())
            return True, sizeFlag
    return dropFlag, sizeFlag


def activeModePort(recvData, socketKey, socketPort, dataPool, timestamp):
    if recvData[:4] == b'PORT':
        # PORT h1,h2,h3,h4,p1,p2
        _, _, _, _, e, f = recvData[4:].split(b',')
        e, f = int(e.strip()), int(f.strip())
        dataPort = e * 256 + f
        print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} "
              f"is Active Mode. Client Data Port is {dataPort}.")
        # Save in data pool
        if socketKey in dataPool['ACTV']:
            dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey] + [[timestamp, dataPort]]
        else:
            dataPool['ACTV'][socketKey] = [[timestamp, dataPort]]
        print(dict(dataPool['ACTV']))
    elif recvData[:4] == b'EPRT':
        # EPRT |||port|
        port = recvData.split(b'|')[-2]
        dataPort = int(port)
        print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} "
              f"is Active Mode. Client Data Port is {dataPort}.")
        # Save in data pool
        if socketKey in dataPool['ACTV']:
            dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey] + [[timestamp, dataPort]]
        else:
            dataPool['ACTV'][socketKey] = [[timestamp, dataPort]]
        print(dict(dataPool['ACTV']))
    elif recvData[:4] == b'LPRT':
        # LPRT ipNum,long address,portNum,port
        address = recvData[4:].split(b',')
        ipNum = int(address[1].strip())
        ports = address[(2 + ipNum):]
        dataPort = 0
        for i in ports:
            dataPort = dataPort * 256 + int(i.strip())
        print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} "
              f"is Active Mode. Client Data Port is {dataPort}.")
        # Save in data pool
        if socketKey in dataPool['ACTV']:
            dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey] + [[timestamp, dataPort]]
        else:
            dataPool['ACTV'][socketKey] = [[timestamp, dataPort]]
        print(dict(dataPool['ACTV']))


def validateReceiver(recvData, requesterConn, fileName, socketPort, sizeFlag):
    dropFlag = False
    if recvData[:3] == b'213':
        # 213 File status
        if sizeFlag:
            # Client sent 'SIZE file.'
            sizeFlag = False
            size = eval(recvData[4:-2].decode())
            if size >= eval(policy['sizeLimit']):
                writer.async_write(LOCK, fileName, False, socketPort[1], socketPort[0], recvData)
                recvData = f"File is bigger than {policy['sizeLimit']} bytes.\r\n"
                print(recvData)
                requesterConn.sendall(recvData.encode())
                return True, sizeFlag
    return dropFlag, sizeFlag


def passiveModePort(recvData, socketKey, socketPort, dataPool, timestamp):
    # Get passive mode data port
    if recvData[:3] == b'227':
        # 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        _, _, _, _, e, f = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).split(b',')
        e, f = int(e.strip()), int(f.strip())
        dataPort = e * 256 + f
        print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} "
              f"is Passive Mode. Server Data Port is {dataPort}.")
        # Save in data pool
        if socketKey in dataPool['PASV']:
            dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey] + [[timestamp, dataPort]]
        else:
            dataPool['PASV'][socketKey] = [[timestamp, dataPort]]
    elif recvData[:3] == b'228':
        # 228 Entering Long Passive Mode (long address, port).
        _, port = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).split(b',')
        dataPort = int(port.strip())
        print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} "
              f"is Passive Mode. Server Data Port is {dataPort}.")
        # Save in data pool
        if socketKey in dataPool['PASV']:
            dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey] + [[timestamp, dataPort]]
        else:
            dataPool['PASV'][socketKey] = [[timestamp, dataPort]]
    elif recvData[:3] == b'229':
        # 229 Entering Extended Passive Mode (|||port|).
        port = re.sub(rb'.*\((.*)\).*', rb'\1', recvData).strip(b'|')
        dataPort = int(port)
        print(f"Connection from {socketKey[0]}:{socketPort[0]} to {socketKey[1]}:{socketPort[1]} "
              f"is Passive Mode. Server Data Port is {dataPort}.")
        # Save in data pool
        if socketKey in dataPool['PASV']:
            dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey] + [[timestamp, dataPort]]
        else:
            dataPool['PASV'][socketKey] = [[timestamp, dataPort]]


def Connectionthread(requesterConn, requesterAddress, responderAddress, dataPool):
    # Get local address and remote address
    if ipaddress.ip_address(responderAddress[0]).is_private:
        localAddress, remoteAddress = responderAddress, requesterAddress
    else:
        localAddress, remoteAddress = requesterAddress, responderAddress
    print(f"Accept connection from {requesterAddress[0]}:{requesterAddress[1]} "
          f"to {responderAddress[0]}:{responderAddress[1]}")
    # Check client IP address
    if checkclient(localAddress[0]):
        print(f"Client {localAddress[0]} has been blocked.")
        requesterConn.close()
        return
    # Check server IP address
    elif checkserver(remoteAddress[0]):
        print(f"Server {remoteAddress[0]} has been blocked.")
        requesterConn.close()
        return
    socketKey = (localAddress[0], remoteAddress[0])
    socketPort = (localAddress[1], remoteAddress[1])
    # Connect to server
    print(f"Connecting to {responderAddress}.")
    responderConn = Connect_Serv(responderAddress)
    print("Succeed")
    # If communicate with port 21, FTP control
    if responderAddress[1] == 21:
        print(f"Connection from {requesterAddress} to {responderAddress} is a Control Connection for FTP.")
        timestamp = time.time()
        # Set key in data pool
        if socketKey not in dataPool['PASV']:
            dataPool['PASV'][socketKey] = []
        if socketKey not in dataPool['ACTV']:
            dataPool['ACTV'][socketKey] = []
        # Start transferring
        TCP_Control_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp, dataPool)
        requesterConn.close()
        responderConn.close()
        return
    # If communicate with port 20, FTP data
    elif responderAddress[1] == 20:
        # Check if port is set for data transfer
        print(f"Check if the connection from {requesterAddress} to {responderAddress} is an active mode data transfer")
        for _ in range(10):
            for socketKey in dataPool['ACTV']:
                for j, item in enumerate(dataPool['ACTV'][socketKey]):
                    if item[1] == requesterAddress[1]:
                        print(
                            f"Connection from {requesterAddress} to {responderAddress} is a Active Data Connection for FTP.")
                        timestamp = item[0]
                        # Delete port from data pool
                        dataPool['ACTV'][socketKey] = dataPool['ACTV'][socketKey][:j] + \
                            dataPool['ACTV'][socketKey][j+1:] if len(dataPool['ACTV'][socketKey]) > 1 else []
                        # Start transferring
                        TCP_Data_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp)
                        requesterConn.close()
                        responderConn.close()
                        return
            time.sleep(0.01)
    else:
        # Check if port is set for data transfer
        print(f"Check if the connection from {requesterAddress} to {responderAddress} is a passive mode data transfer")
        for _ in range(10):
            if socketKey in dataPool['PASV']:
                for j, item in enumerate(dataPool['PASV'][socketKey]):
                    if item[1] == responderAddress[1]:
                        print(f"Connection from {requesterAddress} to {responderAddress} is "
                              "a Passive Data Connection for FTP.")
                        timestamp = item[0]
                        # Delete port from data pool
                        if len(dataPool['PASV'][socketKey]) > 1:
                            dataPool['PASV'][socketKey] = dataPool['PASV'][socketKey][:j] + dataPool['PASV'][socketKey][j+1:]
                        else:
                            dataPool['PASV'][socketKey] = []
                        # Start transferring
                        TCP_Data_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp)
                        requesterConn.close()
                        responderConn.close()
                        return
            time.sleep(0.01)
    # Other Data Transfer
    print("This is not a FTP connection.")
    # Start transferring
    Other_Data_Trans(requesterConn, responderConn)
    requesterConn.close()
    responderConn.close()
    return


def TCP_Control_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp, dataPool):
    sizeFlag = False
    readfd = [requesterConn, responderConn]
    # Record file
    fileName = f"./record/{socketKey[0]}_{socketKey[1]}_{timestamp}.ftcap"
    # Write header
    writer.write_header(fileName, socketKey[0], socketKey[1], timestamp)
    while True:
        # Receive and send
        rfd, _, _ = select.select(readfd, [], [])
        if requesterConn in rfd:
            recvData = requesterConn.recv(MAX_LENGTH)
            # Filter
            dropFlag, sizeFlag = validateRequester(recvData, requesterConn, fileName, socketPort, sizeFlag)
            if dropFlag:
                return
            # Check if this connection is active mode
            activeModePort(recvData, socketKey, socketPort, dataPool, timestamp)
            if recvData:
                responderConn.sendall(recvData)
                writer.async_write(LOCK, fileName, False, socketPort[0], socketPort[1], recvData)
        if responderConn in rfd:
            recvData = responderConn.recv(MAX_LENGTH)
            # Filter
            dropFlag, sizeFlag = validateReceiver(recvData, requesterConn, fileName, socketPort, sizeFlag)
            if dropFlag:
                return
            # Check if this connection is passive mode
            passiveModePort(recvData, socketKey, socketPort, dataPool, timestamp)
            if recvData:
                requesterConn.sendall(recvData)
                writer.async_write(LOCK, fileName, True, socketPort[1], socketPort[0], recvData)


def TCP_Data_Trans(requesterConn, responderConn, socketKey, socketPort, timestamp):
    readfd = [requesterConn, responderConn]
    # Record file
    fileName = f"./record/{socketKey[0]}_{socketKey[1]}_{timestamp}.ftcap"
    while True:
        # Receive and send
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
        # Receive and send
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
    # Create socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    print("Server socket creation succeeded.")
    # Connect socket with server
    serverSocket.connect(serverAddr)
    return serverSocket


def tcp_listen(port):
    # Create a socket
    tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    print("Socket creation succeeded.")
    # Set option
    tcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket options set.")
    # Bind socket with all local IP address and port [port]
    tcpSocket.bind(("0.0.0.0", port))
    print(f"Socket bind with all local IP address and port {port}.")
    # Start listening
    tcpSocket.listen(20)
    print(f"Start listening on port {port}.")
    return tcpSocket


def checkserver(serv_addr):
    # If server in blacklist
    return serv_addr in policy['serverBlacklist']


def checkclient(cki_addr):
    # If client in blacklist
    return cki_addr in policy['clientBlacklist']


def main():
    # Make directory for recording
    pathlib.Path("./record/").mkdir(parents=True, exist_ok=True)
    # Get listening port
    opts, _ = getopt.getopt(sys.argv[1:], 'p:', ["port="])
    for key, val in opts:
        if key in ('-p', "--port"):
            port = int(val)
        else:
            print(f'Usage {sys.argv[0]} -p port')
            sys.exit(-1)
    # Setup data pool
    with multiprocessing.Manager() as manager:
        dataPool = dict()
        dataPool['PASV'] = manager.dict()
        dataPool['ACTV'] = manager.dict()
        # Listen port
        tcpSocket = tcp_listen(port)
        print(f'listening on {sys.argv[2]}')
        try:
            # Main loop
            while True:
                # Accept a new connection
                try:
                    newConn, requesterAddress = tcpSocket.accept()
                except (socket.error, socket.gaierror, socket.herror):
                    print("Failed to accept a connection.")
                    traceback.print_exc()
                    continue
                # Get original destination
                sockAddr = newConn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                responderPort, responderIp = struct.unpack("!2xH4s8x", sockAddr)
                responderIp = socket.inet_ntoa(responderIp)
                # Get source
                responderAddress = (responderIp, responderPort)
                # Start subprocess
                multiprocessing.Process(target=Connectionthread,
                                        args=(newConn, requesterAddress, responderAddress, dataPool)).start()
        except KeyboardInterrupt:
            print("Stop!")


if __name__ == '__main__':
    sys.exit(main())
