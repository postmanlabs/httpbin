# -*- coding: utf-8 -*-

"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""


from flask import request

from .structures import CaseInsensitiveDict



def get_files():
    """Returns files dict from request context."""

    files = dict()

    for k, v in request.files.items():
        files[k] = v.read()

    return files



def get_headers():
    """Returns headers dict from request context."""

    return CaseInsensitiveDict(request.headers.items())