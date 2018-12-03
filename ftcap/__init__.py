# -*- coding: utf-8 -*-
"""FTP Packet Capture File Specification

Global Header
=============

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

Frame Header
============

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

from ftcap.reader import reader
from ftcap.writer import writer

__all__ = ['reader', 'writer']
