# -*- coding: utf-8 -*-

import collections
import datetime

import pcapkit

__all__ = ['Frame']

address = collections.namedtuple('address', ['ip', 'port'])


class Frame(pcapkit.protocols.protocol.Protocol):

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return f'Frame {self._frameno}'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 14

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_frame(self):
        _ts_sec = self._read_unpack(4, quiet=True)
        if _ts_sec is None:
            raise EOFError
        _ts_usec = self._read_unpack(4)
        _flag_length = self._read_binary(2)

        _flag = bool(int(_flag_length[0], base=2))
        _length = int(_flag_length[1:], base=2)

        _srcport = self._read_unpack(2)
        _dstport = self._read_unpack(2)

        if _flag:
            _srcip, _dstip = self._server, self._client
        else:
            _srcip, _dstip = self._client, self._server

        _src = address(ip=_srcip, port=_srcport)
        _dst = address(ip=_dstip, port=_dstport)

        frame = dict(
            time=datetime.datetime.fromtimestamp(_ts_sec + _ts_usec / 1_000_000),
            src=_src,
            dst=_dst,
        )
        self._length = 14 + _length

        return self._decode_next_layer(frame, _length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, *, frameno, client, server):
        self._frameno = frameno
        self._client = client
        self._server = server

        self._file = file
        self._info = pcapkit.corekit.infoclass.Info(self.read_frame())

    def __len__(self):
        return self._length

    def __length_hint__(self):
        return 14

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _import_next_layer(self, proto, length):
        if length == 0:
            next_ = pcapkit.protocols.null.NoPayload()
        else:
            next_ = pcapkit.foundation.analysis.analyse(self._file, length)
        return next_
