# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""
WSMan library for Python.

This is an internal library for WSMan for use with pypsrp. I'm trying to
separate all the logic into it's own package so I could eventually split it
out into it's own library.

The HTTP library used is based on `httpx`_ but uses it's own transport and
connection implementation to support WSMan specific components. The goal is to
remove the custom connection code and use what is provided in `httpcore`_.
There are 2 things that need to happen before we can do that:

* Make the HTTPConnection classes public `#272`_.
* Expose a public way to connect the socket before sending a request `#273`_.

.. _httpx:
    https://github.com/encode/httpx

.. _httpcore:
    https://github.com/encode/httpcore

.. _#272:
    https://github.com/encode/httpcore/issues/272

.. _#273:
    https://github.com/encode/httpcore/issues/273
"""
