# -*- coding: utf-8 -*-

"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""


from flask import request, make_response

from .structures import CaseInsensitiveDict


ASCII_ART = r"""
    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
        `\"\"\"`
"""


def get_files():
    """Returns files dict from request context."""

    files = dict()

    for k, v in request.files.items():
        files[k] = v.read()

    return files


def get_headers():
    """Returns headers dict from request context."""

    return CaseInsensitiveDict(request.headers.items())


def status_code(code):
    """Returns response object of given status code."""

    code_map = {
        418: dict(data=ASCII_ART),
    }

    r = make_response()
    r.status_code = code

    if code in code_map:
        if 'data' in code_map[code]:
            r.data = code_map[code]['data']

    print code_map.get(code)
    return r