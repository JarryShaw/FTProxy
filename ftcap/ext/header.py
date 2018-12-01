# -*- coding: utf-8 -*-

import datetime
import io
import ipaddress

import pcapkit

__all__ = ['Header']


class Header(pcapkit.protocols.protocol.Protocol):

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
        _ts_sec = self._read_unpack(4)
        _ts_usec = self._read_unpack(4)
        _version = self._read_binary(1)

        _version_client = int(_version[:4], base=2)
        _version_server = int(_version[4:], base=2)

        _length = 9
        if _version_client == 4:
            _length += 4
            _client = ipaddress.ip_address(self._read_fileng(4))
        elif _version_client == 6:
            _length += 16
            _client = ipaddress.ip_address(self._read_fileng(16))
        else:
            raise pcapkit.utilities.exceptions.ProtocolError('FTP: invalid version')

        if _version_server == 4:
            _length += 4
            _server = ipaddress.ip_address(self._read_fileng(4))
        elif _version_server == 6:
            _length += 16
            _server = ipaddress.ip_address(self._read_fileng(16))
        else:
            raise pcapkit.utilities.exceptions.ProtocolError('FTP: invalid version')

        _packet = self._read_packet(_length)
        self._file = io.BytesIO(_packet)

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
