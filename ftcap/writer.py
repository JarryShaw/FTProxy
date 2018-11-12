# -*- coding: utf-8 -*-

from ftcap.cst.frame import Frame
from ftcap.cst.header import Header

__all__ = ['writer']


class writer:

    def __init__(self, filename, *, client, server, timestamp):
        self._file = filename
        self._client = client
        self._server = server

        packet = Header(
            client=client,
            server=server,
            timestamp=timestamp,
        ).data

        with open(self._file, 'wb') as file:
            file.write(packet)

    def __call__(self, src, dst, srcport, dstport, payload):
        flag = (src == self._client)

        packet = Frame(
            flag=flag,
            srcport=srcport,
            dstport=dstport,
            payload=payload,
        ).data

        with open(self._file, 'ab') as file:
            file.write(packet)
