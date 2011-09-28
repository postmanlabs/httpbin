# -*- coding: utf-8 -*-

"""
httpbin.filters
~~~~~~~~~~~~~~~

This module provides response filter decorators.
"""

import gzip as gzip2

from cStringIO import StringIO
from decimal import Decimal
from time import time as now

import omnijson
from decorator import decorator
from flask import Flask, Response


app = Flask(__name__)



@decorator
def x_runtime(f, *args, **kwargs):
    """X-Runtime Flask Response Decorator."""

    _t0 = now()
    r = f(*args, **kwargs)
    _t1 = now()
    r.headers['X-Runtime'] = '{0}s'.format(Decimal(str(_t1-_t0)))

    return r

@decorator
def json(f, *args, **kwargs):
    """JSON Flask Response Decorator."""

    data = f(*args, **kwargs)

    # we already have a formatted response, move along
    if isinstance(data, Response):
        return data

    dump = omnijson.dumps(data)

    r = app.make_response(dump)
    r.headers['Content-Type'] = 'application/json'

    return r


@decorator
def gzip(f, *args, **kwargs):
    """GZip Flask Response Decorator."""


    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    gzip_buffer = StringIO()
    gzip_file = gzip2.GzipFile(
        mode='wb',
        compresslevel=4,
        fileobj=gzip_buffer
    )
    gzip_file.write(content)
    gzip_file.close()

    gzip_data = gzip_buffer.getvalue()

    if isinstance(data, Response):
        data.data = gzip_data
        data.headers['Content-Encoding'] = 'gzip'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return gzip_data

