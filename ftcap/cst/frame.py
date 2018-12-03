# -*- coding: utf-8 -*-

import ipaddress
import time

import pcapkit

__all__ = ['Frame']


class Frame(pcapkit.ipsuite.protocol.Protocol):
    """FTCAP frame header constructor.

    ====== ==== ===================== ================================================
    Octets Bits Name                  Description
    ====== ==== ===================== ================================================
    0      0    timestamp.second      timestamp seconds
    4      32   timestamp.microsecond timestamp microseconds
    8      64   flag                  direction (0: client->server; 1: server->client)
    8      65   length                payload length
    10     80   srcport               source port
    12     96   dstport               destination port
    14     112  payload               packet payload
    ====== ==== ===================== ================================================

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * data -- bytes, binary packet data if current instance
        * alias -- str, acronym of corresponding protocol

    Methods:
        * index -- return first index of value from a dict
        * pack -- pack integers to bytes

    Utilities:
        * __make__ -- make packet data

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Frame Header'

    ##########################################################################
    # Utilities.
    ##########################################################################

    def __make__(self):
        def __make_timestamp__():
            """Make timestamp."""
            timestamp = self.__args__.get('timestamp', time.time())     # timestamp
            ts_sec = self.__args__.get('ts_sec', int(timestamp))        # timestamp seconds
            _default_ts_usec = int((timestamp - ts_sec) * 1000000)
            ts_usec = self.__args__.get('ts_usec', _default_ts_usec)    # timestamp microseconds
            return ts_sec, ts_usec

        # fetch values
        ts_sec, ts_usec = __make_timestamp__()                          # make timestamp
        flag = self.__args__.get('flag', False)                         # direction flag (default is False)
        srcport = self.__args__.get('srcport', 0)                       # source port (default is 0)
        dstport = self.__args__.get('dstport', 0)                       # destination port (default is 0)
        payload = self.__args__.get('payload', bytes())                 # frame payload (default is b'')
        length = self.__args__.get('length', len(payload))              # length of frame payload
        flag_length = int(f'{int(flag)}{bin(length)[2:].zfill(15)}', base=2)  # flag & length bytes

        # make packet
        return b'%s%s%s%s%s%s' % (
            self.pack(ts_sec, size=4),
            self.pack(ts_usec, size=4),
            self.pack(flag_length, size=2),
            self.pack(srcport, size=2),
            self.pack(dstport, size=2),
            payload,
        )
