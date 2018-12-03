# -*- coding: utf-8 -*-

import ipaddress

from ftcap.cst.frame import Frame
from ftcap.cst.header import Header

__all__ = ['writer']


class writer:

    def __init__(self, filename, client, server, timestamp):
        """Initialise a writer instance & dump Global Header.

        Args:
        - ``filename`` -- ``str``, name of output file
        - ``client`` -- c.f. ``ipaddress.ip_address``, client IP address
        - ``server`` -- c.f. ``ipaddress.ip_address``, server IP address
        - ``timestamp`` -- ``float``, UNIX-Epoch timestamp

        """
        self.write_header(filename, client, server, timestamp)
        self._client = ipaddress.ip_address(client)
        self._server = ipaddress.ip_address(server)
        self._file = filename

    def __call__(self, src, dst, srcport, dstport, payload):
        """Call the instance to dump frame (header & payload).

        Args:
        - ``src`` -- c.f. ``ipaddress.ip_address``, source IP address
        - ``dst`` -- c.f. ``ipaddress.ip_address``, destination IP address
        - ``srcport`` -- ``int``, source port
        - ``dstport`` -- ``int``, destination port
        - ``payload`` -- ``bytes``, packet payload

        """
        srcip = ipaddress.ip_address(src)
        dstip = ipaddress.ip_address(dst)
        if (self._client == srcip) and (self._server == dstip):    # from client to server
            flag = True
        elif (self._client == dstip) and (self._server == srcip):  # from server to client
            flag = False
        else:
            raise ValueError('mismatched IP addresses')
        self.write_frame(self._file, flag, srcport, dstport, payload)

    @staticmethod
    def write_header(filename, client, server, timestamp):
        """Directly dump Global Header.

        Args:
        - ``filename`` -- ``str``, name of output file
        - ``client`` -- c.f. ``ipaddress.ip_address``, client IP address
        - ``server`` -- c.f. ``ipaddress.ip_address``, server IP address
        - ``payload`` -- ``bytes``, packet payload

        """
        packet = Header(
            client=client,
            server=server,
            timestamp=timestamp,
        ).data  # construct Global Header then fetch raw packet data

        with open(filename, 'wb') as file:
            file.write(packet)

    @staticmethod
    def write_frame(filename, flag, srcport, dstport, payload):
        """Directly dump Frame (header & payload).

        Args:
        - ``filename`` -- ``str``, name of output file
        - ``flag`` -- ``bool``, direction (``True``: client->server; ``False``: server->client)
        - ``srcport`` -- ``int``, source port
        - ``dstport`` -- ``int``, destination port
        - ``payload`` -- ``bytes``, packet payload

        """
        packet = Frame(
            flag=flag,
            srcport=srcport,
            dstport=dstport,
            payload=payload,
        ).data  # construct Frame then fetch raw packet data

        with open(filename, 'ab') as file:
            file.write(packet)

    @classmethod
    def async_write(cls, lock, filename, flag, srcport, dstport, payload):
        """Directly dump Frame (header & payload) in a "process-safe" way.

        Args:
        - ``lock`` -- c.f. ``multiprocessing.Lock``, some lock
        - ``filename`` -- ``str``, name of output file
        - ``flag`` -- ``bool``, direction (``True``: client->server; ``False``: server->client)
        - ``srcport`` -- ``int``, source port
        - ``dstport`` -- ``int``, destination port
        - ``payload`` -- ``bytes``, packet payload

        """
        with lock:
            cls.write_frame(filename, flag, srcport, dstport, payload)
