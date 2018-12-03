# -*- coding: utf-8 -*-

import ipaddress
import time

import pcapkit

__all__ = ['Header']


class Header(pcapkit.ipsuite.protocol.Protocol):
    """FTCAP global header constructor.

    ====== ======= ===================== =========================
    Octets Bits    Name                  Description
    ====== ======= ===================== =========================
    0      0       timestamp.second      timestamp seconds
    4      32      timestamp.microsecond timestamp microseconds
    8      64      version.client        client IP address version
    8      68      version.server        server IP address version
    9      72      client                client IP address
    13/25  104/200 server                server IP address
    ====== ======= ===================== =========================

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
        return 'Global Header'

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

        def __make_address__(key):
            """Make version and address."""
            address = ipaddress.ip_address(self.__args__[key])
            version = address.version
            if version == 4:    # IPv4 address
                verbit = '0100'
                packed = ipaddress.v4_int_to_packed(int(address))
            elif version == 6:  # IPv6 address
                verbit = '0110'
                packed = ipaddress.v6_int_to_packed(int(address))
            else:
                raise pcapkit.utilities.exceptions.VersionError('unknown IP version')
            return (verbit, packed)

        # fetch values
        ts_sec, ts_usec = __make_timestamp__()                          # make timestamp
        ver_cli, client = __make_address__('client')                    # make client IP address
        ver_src, server = __make_address__('server')                    # make server IP address
        version = int(f'{ver_cli}{ver_src}', base=2)                    # make version byte

        # make packet
        return b'%s%s%s%s%s' % (
            self.pack(ts_sec, size=4),
            self.pack(ts_usec, size=4),
            self.pack(version, size=1),
            client,
            server,
        )
