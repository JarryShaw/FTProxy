# -*- coding: utf-8 -*-

from ftcap.ext.frame import Frame
from ftcap.ext.header import Header

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
