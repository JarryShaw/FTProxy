# -*- coding: utf-8 -*-

import datetime
import ipaddress
import time

import pcapkit

__all__ = ['Frame']


class Frame(pcapkit.ipsuite.protocol.Protocol):

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
            now = datetime.datetime.fromtimestamp(timestamp)            # timestamp datetime instance
            ts_sec = self.__args__.get('ts_sec', now.second)            # timestamp seconds
            ts_usec = self.__args__.get('ts_usec', now.microsecond)     # timestamp microseconds
            return ts_sec, ts_usec

        # fetch values
        ts_sec, ts_usec = __make_timestamp__()
        flag = self.__args__['flag']
        srcport = self.__args__['srcport']
        dstport = self.__args__['dstport']
        payload = self.__args__.get('payload', bytes())
        length = self.__args__.get('length', len(payload))
        flag_length = int(f'{int(flag)}{bin(length)[2:].zfill(15)}', base=2)

        # make packet
        return b'%s%s%s%s%s%s' % (
            self.pack(ts_sec, size=4),
            self.pack(ts_usec, size=4),
            self.pack(flag_length, size=2),
            self.pack(srcport, size=2),
            self.pack(dstport, size=2),
            payload,
        )
