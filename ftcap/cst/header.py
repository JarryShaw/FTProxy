# -*- coding: utf-8 -*-

import datetime
import ipaddress
import time

import pcapkit

__all__ = ['Header']


class Header(pcapkit.ipsuite.protocol.Protocol):

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Global Header'

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

        def __make_address__(key):
            """Make version and address."""
            address = ipaddress.ip_address(self.__args__[key])
            version = address.version
            if version == 4:
                verbit = '0100'
                packed = ipaddress.v4_int_to_packed(int(address))
            elif version == 6:
                verbit = '0110'
                packed = ipaddress.v6_int_to_packed(int(address))
            else:
                raise pcapkit.utilities.exceptions.VersionError('unknown IP version')
            return (verbit, packed)

        # fetch values
        ts_sec, ts_usec = __make_timestamp__()
        ver_cli, client = __make_address__('client')
        ver_src, server = __make_address__('server')
        version = int(f'{ver_cli}{ver_src}', base=2)

        # make packet
        return b'%s%s%s%s%s' % (
            self.pack(ts_sec, size=4),
            self.pack(ts_usec, size=4),
            self.pack(version, size=1),
            client,
            server,
        )
