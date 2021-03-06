=====================================
FTP Packet Capture File Specification
=====================================

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

API - writer
============

.. code:: python

    @staticmethod
    writer.write_header(filename, client, server, timestamp)

    # create a writer instance
    >>> wrt = writer(filename, *, client, server, timestamp)

- ``filename`` -- ``str``, name of output file
- ``client`` -- c.f. ``ipaddress.ip_address``, client IP address
- ``server`` -- c.f. ``ipaddress.ip_address``, server IP address
- ``timestamp`` -- ``float``, UNIX-Epoch timestamp

.. code:: python

    @staticmethod
    writer.write_frame(filename, flag, srcport, dstport, payload)

    @classmethod
    writer.async_write(lock, filename, flag, srcport, dstport, payload)

    # then directly call on the instance
    >>> wrt(src, dst, srcport, dstport, payload)

- ``flag`` -- ``bool``, direction (``True``: client->server; ``False``: server->client)
- ``srcport`` -- ``int``, source port
- ``dstport`` -- ``int``, destination port
- ``payload`` -- ``bytes``, packet payload

- ``lock`` -- c.f. ``multiprocessing.Lock``, some lock

- ``src`` -- c.f. ``ipaddress.ip_address``, source IP address
- ``dst`` -- c.f. ``ipaddress.ip_address``, destination IP address

API - reader
============

.. code:: python

    >>> reader(filename)

Args:
    ``filename`` -- ``str``, name of file to be read

Returns:
    a 2-element tuple with ``ext.header.Header`` and list of ``ext.frame.Frame``
