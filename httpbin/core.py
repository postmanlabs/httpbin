# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""
import os
import time
from flask import Flask, request, render_template, redirect
from werkzeug.datastructures import WWWAuthenticate


from . import filters
from .helpers import get_headers, status_code, get_dict, check_basic_auth, check_digest_auth, H


ENV_COOKIES = (
    '_gauges_unique',
    '_gauges_unique_year',
    '_gauges_unique_month',
    '_gauges_unique_day',
    '_gauges_unique_hour',
    '__utmz',
    '__utma',
    '__utmb'
)

app = Flask(__name__)


# ------
# Routes
# ------

@app.errorhandler(500)
def page_not_found(e):
    return ':(', 200

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

    return get_dict('url', 'args', 'data', 'origin', 'headers')


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
        return redirect('/get')

    return redirect('/redirect/{0}'.format(n-1))


@app.route('/relative-redirect/<int:n>')
def relative_redirect_n_times(n):
    """301 Redirects n times."""

    assert n > 0

    response = app.make_response('')
    response.status_code = 302

    if (n == 1):
        response.headers['Location'] = '/get'
        return response

    response.headers['Location'] = '/relative-redirect/{0}'.format(n-1)
    return response


@app.route('/status/<int:code>')
def view_status_code(code):
    """Returns given status code."""

    return status_code(code)


@app.route('/cookies')
@filters.json
def view_cookies(hide_env=True):
    """Returns cookie data."""

    cookies = dict(request.cookies.items())

    if hide_env and ('show_env' not in request.args):
        for key in ENV_COOKIES:
            try:
                del cookies[key]
            except KeyError:
                pass

    return dict(cookies=cookies)


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


@app.route('/hidden-basic-auth/<user>/<passwd>')
@filters.json
def hidden_basic_auth(user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""

    if not check_basic_auth(user, passwd):
        return status_code(404)
    return dict(authenticated=True, user=user)


@app.route('/digest-auth/<qop>/<user>/<passwd>')
@filters.json
def digest_auth(qop=None, user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Digest auth"""
    if qop not in ('auth', 'auth-int'):
        qop = None
    if not request.headers.get('Authorization'):
        response = app.make_response('')
        response.status_code = 401

        nonce = H("%s:%d:%s" % (request.remote_addr,
                                  time.time(),
                                  os.urandom(10)))
        opaque = H(os.urandom(10))

        auth = WWWAuthenticate("digest")
        auth.set_digest('Fake Realm', nonce, opaque=opaque,
                        qop=('auth', 'auth-int') if qop is None else (qop, ))
        response.headers['WWW-Authenticate'] = auth.to_header()
        return response
    elif not check_digest_auth(user, passwd):
        return status_code(403)
    return dict(authenticated=True, user=user)



if __name__ == '__main__':
    app.run()
