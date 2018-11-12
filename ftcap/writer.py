# -*- coding: utf-8 -*-

from ftcap.cst.frame import Frame
from ftcap.cst.header import Header

__all__ = ['writer']


class writer:

    def __init__(self, filename, client, server, timestamp):
        self.write_header(filename, client, server, timestamp)
        self._file = filename
        self._client = client
        self._server = server

    def __call__(self, src, dst, srcport, dstport, payload):
        if (self._client == src) and (self._server == dst):
            flag = True
        elif (self._client == dst) and (self._server == src):
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
