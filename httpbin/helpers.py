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

REDIRECT_LOCATION = 'http://httpbin.org/redirect/1'



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
        301: dict(headers=dict(location=REDIRECT_LOCATION)),
        302: dict(headers=dict(location=REDIRECT_LOCATION)),
        303: dict(headers=dict(location=REDIRECT_LOCATION)),
        304: dict(data=''),
        305: dict(headers=dict(location=REDIRECT_LOCATION)),
        307: dict(headers=dict(location=REDIRECT_LOCATION)),
        401: dict(headers={'WWW-Authenticate': 'Basic realm="Fake Realm"'}),
        407: dict(headers={'Proxy-Authenticate': 'Basic realm="Fake Realm"'}),
        418: dict(
            data=ASCII_ART,
            headers={
                'x-more-info': 'http://tools.ietf.org/html/rfc2324'
            }
        ),

    }

    r = make_response()
    r.status_code = code

    if code in code_map:

        m = code_map[code]

        if 'data' in m:
            r.data = m['data']
        if 'headers' in m:
            r.headers = m['headers']

    return r