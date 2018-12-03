# -*- coding: utf-8 -*-

import datetime
import io
import ipaddress

import pcapkit

__all__ = ['Header']


class Header(pcapkit.protocols.protocol.Protocol):
    """FTCAP file global header extractor.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * length -- int, header length of global header, i.e. 24
        * client -- ipaddress.IPv{4,6}Address, client IP address
        * server -- ipaddress.IPv{4,6}Address, server IP address

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * index -- call `ProtoChain.index`
        * read_header -- read global header of FTCAP file

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Global Header'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return len(self)

    @property
    def payload(self):
        """NotImplemented"""
        raise pcapkit.utilities.exceptions.UnsupportedCall("'Header' object has no attribute 'payload'")

    @property
    def protocol(self):
        """Name of next layer protocol."""
        raise pcapkit.utilities.exceptions.UnsupportedCall("'Header' object has no attribute 'protocol'")

    @property
    def protochain(self):
        """NotImplemented"""
        raise pcapkit.utilities.exceptions.UnsupportedCall("'Header' object has no attribute 'protochain'")

    @property
    def client(self):
        return self._info.client  # pylint: disable=E1101

    @property
    def server(self):
        return self._info.server  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_header(self):
        """Global Header

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

        """
        _ts_sec = self._read_unpack(4)
        _ts_usec = self._read_unpack(4)
        _version = self._read_binary(1)

        _version_client = int(_version[:4], base=2)
        _version_server = int(_version[4:], base=2)

        _length = 9
        if _version_client == 4:    # IPv4 address
            _length += 4
            _client = ipaddress.ip_address(self._read_fileng(4))
        elif _version_client == 6:  # IPv6 address
            _length += 16
            _client = ipaddress.ip_address(self._read_fileng(16))
        else:
            raise pcapkit.utilities.exceptions.ProtocolError('FTP: invalid version')

        if _version_server == 4:    # IPv4 address
            _length += 4
            _server = ipaddress.ip_address(self._read_fileng(4))
        elif _version_server == 6:  # IPv6 address
            _length += 16
            _server = ipaddress.ip_address(self._read_fileng(16))
        else:
            raise pcapkit.utilities.exceptions.ProtocolError('FTP: invalid version')

        _packet = self._read_packet(_length)
        self._file = io.BytesIO(_packet)    # make I/O always available

        header = dict(
            time=datetime.datetime.fromtimestamp(_ts_sec + _ts_usec / 1_000_000),
            client=_client,
            server=_server,
            packet=_packet,
        )

        return header

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, **kwargs):
        self._file = file
        self._info = pcapkit.corekit.infoclass.Info(self.read_header())

    def __length_hint__(self):
        pass
