# -*- coding: utf-8 -*-

import collections
import datetime
import io

import pcapkit

__all__ = ['Frame']

address = collections.namedtuple('address', ['ip', 'port'])


class Frame(pcapkit.protocols.protocol.Protocol):
    """Per packet frame header extractor.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current frame

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * index -- call `ProtoChain.index`
        * read_frame -- read each block after global header

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
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
        """Frame Header

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

        """
        _ts_sec = self._read_unpack(4, quiet=True)
        if _ts_sec is None:  # if unpack failed, then EOF
            raise EOFError
        _ts_usec = self._read_unpack(4)
        _flag_length = self._read_binary(2)

        _flag = bool(int(_flag_length[0], base=2))
        _length = int(_flag_length[1:], base=2)

        _srcport = self._read_unpack(2)
        _dstport = self._read_unpack(2)

        if _flag:  # server -> client
            _srcip, _dstip = self._server, self._client
        else:      # client -> server
            _srcip, _dstip = self._client, self._server

        _src = address(ip=_srcip, port=_srcport)
        _dst = address(ip=_dstip, port=_dstport)

        _pkt = self._read_fileng(_length)
        self._file = io.BytesIO(_pkt)  # load frame payload

        frame = dict(
            time=datetime.datetime.fromtimestamp(_ts_sec + _ts_usec / 1_000_000),
            src=_src,
            dst=_dst,
            packet=_pkt,
        )

        # recursively extract payload
        return self._decode_next_layer(frame, None, _length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, *, frameno, client, server):
        self._frameno = frameno
        self._client = client
        self._server = server

        self._file = file
        self._info = pcapkit.corekit.infoclass.Info(self.read_frame())

    def __length_hint__(self):
        return 14

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _import_next_layer(self, proto, length):
        if length == 0:  # if no length, then no payload
            next_ = pcapkit.protocols.null.NoPayload()
        else:            # else analyse application layer protocol
            next_ = pcapkit.foundation.analysis.analyse(self._file, length)
        return next_
