# -*- coding: utf-8 -*-

from ext.frame import Frame     # pylint: disable=E0401
from ext.header import Header   # pylint: disable=E0401

__all__ = ['reader']


def reader(filename):
    with open(filename, 'rb') as file:
        header = Header(file)
        frames = list()
        frameno = 1
        while True:
            try:
                frames.append(Frame(file, frameno=frameno,
                                    client=header.client,
                                    server=header.server))
            except (EOFError, StopIteration):
                # quit when EOF
                break
            frameno += 1
    return header, frames
