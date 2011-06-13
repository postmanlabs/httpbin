# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""


import json
import gzip
import os
from cStringIO import StringIO
from decimal import Decimal
from time import time as now

from decorator import decorator
from flask import Flask, Response, request, render_template, redirect, g

from .helpers import get_files, get_headers, status_code, get_dict


app = Flask(__name__)


# --------------
# Output Filters
# --------------


@decorator
def json_resource(f, runtime=True, *args, **kwargs):

    _t0 = now()
    data = f(*args, **kwargs)
    _t1 = now()

    dump = json.dumps(data, sort_keys=True, indent=3)

    r = app.make_response(dump)
    r.headers['Content-Type'] = 'application/json'
    r.headers['X-Runtime'] = '{0}s'.format(Decimal(str(_t1-_t0)))

    return r



@decorator
def gzip_response(f, *args, **kwargs):

    data = f(*args, **kwargs)

    if isinstance(data, Response):
        content = data.data
    else:
        content = data

    gzip_buffer = StringIO()
    gzip_file = gzip.GzipFile(
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





# ------
# Routes
# ------


@app.route('/')
def view_landing_page():
    """Generates Landing Page."""
    return render_template('httpbin.1.html')


@app.route('/ip')
@json_resource
def view_origin():
    """Returns Origin IP."""

    return dict(origin=request.remote_addr)


@app.route('/headers')
@json_resource
def view_headers():
    """Returns HTTP HEADERS."""

    return get_dict('headers')


@app.route('/user-agent')
@json_resource
def view_user_agent():
    """Returns User-Agent."""

    headers = get_headers()

    return {'user-agent': headers['user-agent']}


@app.route('/get', methods=('GET',))
@json_resource
def view_get():
    """Returns GET Data."""

    return get_dict('url', 'args', 'headers', 'origin')



@app.route('/post', methods=('POST',))
@json_resource
def view_post():
    """Returns POST Data."""

    return get_dict('url', 'args', 'form', 'data', 'origin', 'headers', 'files')


@app.route('/put', methods=('PUT',))
@json_resource
def view_post():
    """Returns PUT Data."""

    return get_dict('url', 'args', 'form', 'data', 'origin', 'headers', 'files')


@app.route('/delete', methods=('DELETE',))
@json_resource
def view_post():
    """Returns DETLETE Data."""

    return get_dict('url', 'args', 'form', 'data', 'origin', 'headers')


@app.route('/gzip')
@gzip_response
@json_resource
def view_gzip_encoded_content():
    """Returns GZip-Encoded Data."""

    return get_dict('origin', 'headers', method=request.method, gzipped=True)


@app.route('/redirect/<int:n>')
def redirect_n_times(n):
    """301 Redirects n times."""

    assert n > 0

    n += -1

    if (n == 0):
        return redirect('/')

    return redirect('/redirect/{0}'.format(n))


@app.route('/status/<int:code>')
def view_status_code(code):
    """Returns given status code."""

    return status_code(code)


if __name__ == '__main__':
    app.run()