# -*- coding: utf-8 -*-

"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""


from flask import request, make_response

from .structures import CaseInsensitiveDict


ASCII_ART = """
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


def get_dict(*keys, **extras):
    """Returns request dict of given keys."""

    _keys = ('url', 'args', 'form', 'data', 'origin', 'headers', 'files')

    assert all(map(_keys.__contains__, keys))

    d = dict(
        url=request.url,
        args=request.args,
        form=request.form,
        data=request.data,
        origin=request.remote_addr,
        headers=get_headers(),
        files=get_files()
    )

    out_d = dict()

    for key in keys:
        out_d[key] = d.get(key)

    out_d.update(extras)

    return out_d


def status_code(code):
    """Returns response object of given status code."""

    redirect = dict(headers=dict(location=REDIRECT_LOCATION))

    code_map = {
        301: redirect,
        302: redirect,
        303: redirect,
        304: dict(data=''),
        305: redirect,
        307: redirect,
        401: dict(headers={'WWW-Authenticate': 'Basic realm="Fake Realm"'}),
        407: dict(headers={'Proxy-Authenticate': 'Basic realm="Fake Realm"'}),
        418: dict( # I'm a teapot!
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


def check_basic_authorization():
    """Checks user authentication using HTTP Basic Auth."""

    auth = request.authorization
    return auth and auth.username == "httpbin" and auth.password == "secret"
