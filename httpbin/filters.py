# -*- coding: utf-8 -*-

"""
httpbin.filters
~~~~~~~~~~~~~~~

This module provides response filter decorators.
"""

import gzip as gzip2
from io import BytesIO
import zlib

import brotli as _brotli

try:  # Python 3.14 and later
    from compression import zstd as _zstd
except ImportError:  # older Pythons, with the backports.zstd package installed
    try:
        from backports import zstd as _zstd
    except ImportError:
        _zstd = None

from decimal import Decimal
from time import time as now

from decorator import decorator
from flask import Flask, Response


app = Flask(__name__)


@decorator
def x_runtime(f, *args, **kwargs):
    """X-Runtime Flask Response Decorator."""

    _t0 = now()
    r = f(*args, **kwargs)
    _t1 = now()
    r.headers['X-Runtime'] = '{0}s'.format(Decimal(str(_t1 - _t0)))

    return r


@decorator
def gzip(f, *args, **kwargs):
    """GZip Flask Response Decorator."""

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    gzip_buffer = BytesIO()
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


@decorator
def deflate(f, *args, **kwargs):
    """Deflate Flask Response Decorator."""

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    deflater = zlib.compressobj()
    deflated_data = deflater.compress(content)
    deflated_data += deflater.flush()

    if isinstance(data, Response):
        data.data = deflated_data
        data.headers['Content-Encoding'] = 'deflate'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return deflated_data


@decorator
def brotli(f, *args, **kwargs):
    """Brotli Flask Response Decorator"""

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    deflated_data = _brotli.compress(content)

    if isinstance(data, Response):
        data.data = deflated_data
        data.headers['Content-Encoding'] = 'br'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return deflated_data


@decorator
def zstd(f, *args, **kwargs):
    """Zstandard Flask Response Decorator"""

    if _zstd is None:
        return Response(
            'zstd compression is not available: use Python 3.14 or newer, or '
            'install backports.zstd\n',
            status=501, content_type='text/plain')

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    compressed_data = _zstd.compress(content)

    if isinstance(data, Response):
        data.data = compressed_data
        data.headers['Content-Encoding'] = 'zstd'
        data.headers['Content-Length'] = str(len(data.data))

        return data

    return compressed_data
