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
from time import time as now
from decimal import Decimal

import redi
from decorator import decorator
from flask import Flask, Response, request, render_template, redirect, g

from .db import redis_connect
from .helpers import get_files, get_headers, status_code


app = Flask(__name__)


# ------
# Config
# ------

def logging_is_enabled():
    """Returns bool to determine if logging is enabled or not."""

    return os.environ.get('HTTPBIN_LOG_REQUESTS', False)



# --------------
# Pre-Processing
# --------------

if logging_is_enabled:

    @app.before_request
    def db_connect():
        """Connects Redis to g object."""

        # redis connect
        if not getattr(g, 'r', None):
            g.r = redis_connect()
            redi.config.init(r=g.r)



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





def log_request(key):
    """Logging Decorator."""

    def log_request(f, *args, **kwargs):

        response = f(*args, **kwargs)

        if logging_is_enabled():
            # store request in redis list
            redi.s.httplib._(key, 'list').append(response)

        return response

    return decorator(log_request)




# ------
# Routes
# ------


@app.route('/')
def view_landing_page():
    """Generates Landing Page."""
    return render_template('httpbin.1.html')


@app.route('/ip')
@json_resource
@log_request(key='httpbin:ip')
def view_origin():
    """Returns Origin IP."""

    return dict(origin=request.remote_addr)


@app.route('/headers')
@json_resource
@log_request(key='httpbin:headers')
def view_headers():
    """Returns HTTP HEADERS."""

    headers = get_headers()

    return dict(headers=headers)


@app.route('/user-agent')
@json_resource
@log_request(key='httpbin:user-agent')
def view_user_agent():
    """Returns User-Agent."""

    headers = get_headers()

    return dict(useragent=headers['user-agent'])


@app.route('/get', methods=('GET',))
@json_resource
@log_request(key='httpbin:get')
def view_get():
    """Returns GET Data."""

    return dict(
        url=request.url,
        args=request.args,
        headers=get_headers(),
        origin=request.remote_addr
    )



@app.route('/post', methods=('POST',))
@json_resource
@log_request(key='httpbin:post')
def view_post():
    """Returns POST Data."""

    return dict(
        url=request.url,
        args=request.args,
        form=request.form,
        data=request.data,
        origin=request.remote_addr,
        headers=get_headers(),
        files=get_files()
    )


@app.route('/put', methods=('PUT',))
@json_resource
@log_request(key='httpbin:put')
def view_post():
    """Returns PUT Data."""

    return dict(
        url=request.url,
        args=request.args,
        form=request.form,
        data=request.data,
        origin=request.remote_addr,
        headers=get_headers(),
        files=get_files()
    )


@app.route('/delete', methods=('DELETE',))
@json_resource
@log_request(key='httpbin:delete')
def view_post():
    """Returns DETLETE Data."""

    return dict(
        url=request.url,
        args=request.args,
        form=request.form,
        data=request.data,
        origin=request.remote_addr,
        headers=get_headers(),
        files=get_files()
    )


@app.route('/gzip')
@gzip_response
@json_resource
@log_request(key='httpbin:gzip')
def view_gzip_encoded_content():
    """Returns GZip-Encoded Data."""

    return dict(
        origin=request.remote_addr,
        headers=get_headers(),
        method=request.method,
        gzipped=True
    )


@app.route('/redirect/<int:n>')
def redirect_n_times(n):
    """301 Redirects n times."""

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