# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""

from flask import Flask, request, render_template, redirect

from . import filters
from .helpers import get_headers, status_code, get_dict, check_basic_auth


app = Flask(__name__)


# ------
# Routes
# ------


@app.route('/')
def view_landing_page():
    """Generates Landing Page."""

    return render_template('index.html')


@app.route('/ip')
@filters.json
def view_origin():
    """Returns Origin IP."""

    return dict(origin=request.remote_addr)


@app.route('/headers')
@filters.json
def view_headers():
    """Returns HTTP HEADERS."""

    return get_dict('headers')


@app.route('/user-agent')
@filters.json
def view_user_agent():
    """Returns User-Agent."""

    headers = get_headers()

    return {'user-agent': headers['user-agent']}


@app.route('/get', methods=('GET',))
@filters.json
def view_get():
    """Returns GET Data."""

    return get_dict('url', 'args', 'headers', 'origin')



@app.route('/post', methods=('POST',))
@filters.json
def view_post():
    """Returns POST Data."""

    return get_dict('url', 'args', 'form', 'data', 'origin', 'headers', 'files')


@app.route('/put', methods=('PUT',))
@filters.json
def view_put():
    """Returns PUT Data."""

    return get_dict('url', 'args', 'form', 'data', 'origin', 'headers', 'files')


@app.route('/patch', methods=('PATCH',))
@filters.json
def view_patch():
    """Returns PATCH Data."""

    return get_dict('url', 'args', 'form', 'data', 'origin', 'headers', 'files')



@app.route('/delete', methods=('DELETE',))
@filters.json
def view_delete():
    """Returns DETLETE Data."""

    return get_dict('url', 'data', 'origin', 'headers')


@app.route('/gzip')
@filters.gzip
@filters.json
def view_gzip_encoded_content():
    """Returns GZip-Encoded Data."""

    return get_dict('origin', 'headers', method=request.method, gzipped=True)


@app.route('/redirect/<int:n>')
def redirect_n_times(n):
    """301 Redirects n times."""

    assert n > 0

    if (n == 1):
        return redirect('/')

    return redirect('/redirect/{0}'.format(n-1))


@app.route('/status/<int:code>')
def view_status_code(code):
    """Returns given status code."""

    return status_code(code)


@app.route('/cookies')
@filters.json
def view_cookies():
    """Returns cookie data."""

    return dict(cookies=request.cookies)


@app.route('/cookies/set/<name>/<value>')
def set_cookie(name, value):
    """Sets a cookie and redirects to cookie list."""

    r = app.make_response(redirect('/cookies'))
    r.set_cookie(key=name, value=value)

    return r


@app.route('/basic-auth/<user>/<passwd>')
@filters.json
def basic_auth(user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""

    if not check_basic_auth(user, passwd):
        return status_code(401)
    return dict(authenticated=True, user=user)



if __name__ == '__main__':
    app.run()
