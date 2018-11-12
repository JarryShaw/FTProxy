# -*- coding: utf-8 -*-

import ipaddress

from ftcap.cst.frame import Frame
from ftcap.cst.header import Header

__all__ = ['writer']


class writer:

    def __init__(self, filename, client, server, timestamp):
        self.write_header(filename, client, server, timestamp)
        self._client = ipaddress.ip_address(client)
        self._server = ipaddress.ip_address(server)
        self._file = filename

    def __call__(self, src, dst, srcport, dstport, payload):
        srcip = ipaddress.ip_address(src)
        dstip = ipaddress.ip_address(dst)
        if (self._client == srcip) and (self._server == dstip):
            flag = True
        elif (self._client == dstip) and (self._server == srcip):
            flag = False
        else:
            raise ValueError('mismatched IP addresses')
        self.write_frame(self._file, flag, srcport, dstport, payload)

    @staticmethod
    def write_header(filename, client, server, timestamp):
        packet = Header(
            client=client,
            server=server,
            timestamp=timestamp,
        ).data

        with open(filename, 'wb') as file:
            file.write(packet)

    @staticmethod
    def write_frame(filename, flag, srcport, dstport, payload):
        packet = Frame(
            flag=flag,
            srcport=srcport,
            dstport=dstport,
            payload=payload,
        ).data

        with open(filename, 'ab') as file:
            file.write(packet)

    @classmethod
    def async_write(cls, lock, filename, flag, srcport, dstport, payload):
        with lock:
            cls.write_frame(filename, flag, srcport, dstport, payload)
