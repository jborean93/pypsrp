# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import paramiko
import socket


class SSH(object):

    def __init__(self, server, port=22, username=None, password=None,
                 buffer=32768):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.buffer = buffer

        self._connected = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._transport = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self):
        self.close()

    def open(self):
        if self._connected:
            return

        self._sock.connect((self.server, self.port))
        self._transport = paramiko.Transport(self._sock)
        self._transport.connect(username=self.username, password=self.password)
        self._connected = True

    def close(self):
        if self._transport:
            self._transport.close()
        self._sock.close()
        self._connected = False
