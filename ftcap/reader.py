# -*- coding: utf-8 -*-

from ftcap.ext.frame import Frame
from ftcap.ext.header import Header

__all__ = ['reader']


def reader(filename):
    """Extract a record file (*.ftcap).

    Args:
        ``filename`` -- ``str``, name of file to be read

    Returns:
        a 2-element tuple with ``ext.header.Header`` and list of ``ext.frame.Frame``

    """
    with open(filename, 'rb') as file:
        header = Header(file)  # extract Global Header
        frames = list()        # frame list
        frameno = 1            # frame number
        while True:            # loop until EOF
            try:
                frames.append(Frame(file, frameno=frameno,
                                    client=header.client,
                                    server=header.server))  # extract Frame
            except EOFError:
                # quit when EOF
                break
            frameno += 1
    return header, frames      # returns extracted Global Header & Frames
