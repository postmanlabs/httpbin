# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""

import base64
import json
import os
import time

import librato

from flask import Flask, Response, request, render_template, redirect, jsonify, make_response
from raven.contrib.flask import Sentry
from werkzeug.datastructures import WWWAuthenticate

from . import filters
from .helpers import get_headers, status_code, get_dict, check_basic_auth, check_digest_auth, H, ROBOT_TXT, ANGRY_ASCII
from .utils import weighted_choice
from .structures import CaseInsensitiveDict

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

# Setup error collection
sentry = Sentry(app)

metrics = librato.connect(
    os.environ.get('LIBRATO_USER'),
    os.environ.get('LIBRATO_TOKEN')
    ).get_gauge('httpbin-requests')

# ------
# Routes
# ------

@app.after_request
def log_metrics(*args, **kwargs):
    metrics.add(1)

@app.route('/')
def view_landing_page():
    """Generates Landing Page."""

    return render_template('index.html')


@app.route('/html')
def view_html_page():
    """Simple Html Page"""

    return render_template('moby.html')


@app.route('/robots.txt')
def view_robots_page():
    """Simple Html Page"""

    response = make_response()
    response.data = ROBOT_TXT
    response.content_type = "text/plain"
    return response


@app.route('/deny')
def view_deny_page():
    """Simple Html Page"""
    response = make_response()
    response.data = ANGRY_ASCII
    response.content_type = "text/plain"
    return response
    # return "YOU SHOULDN'T BE HERE"


@app.route('/ip')
def view_origin():
    """Returns Origin IP."""

    return jsonify(origin=request.remote_addr)


@app.route('/headers')
def view_headers():
    """Returns HTTP HEADERS."""

    return jsonify(get_dict('headers'))


@app.route('/user-agent')
def view_user_agent():
    """Returns User-Agent."""

    headers = get_headers()

    return jsonify({'user-agent': headers['user-agent']})


@app.route('/get', methods=('GET',))
def view_get():
    """Returns GET Data."""

    return jsonify(get_dict('url', 'args', 'headers', 'origin'))


@app.route('/post', methods=('POST',))
def view_post():
    """Returns POST Data."""

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


@app.route('/put', methods=('PUT',))
def view_put():
    """Returns PUT Data."""

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


@app.route('/patch', methods=('PATCH',))
def view_patch():
    """Returns PATCH Data."""

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


@app.route('/delete', methods=('DELETE',))
def view_delete():
    """Returns DETLETE Data."""

    return jsonify(get_dict('url', 'args', 'data', 'origin', 'headers', 'json'))


@app.route('/gzip')
@filters.gzip
def view_gzip_encoded_content():
    """Returns GZip-Encoded Data."""

    return jsonify(get_dict(
        'origin', 'headers', method=request.method, gzipped=True))


@app.route('/redirect/<int:n>')
def redirect_n_times(n):
    """301 Redirects n times."""

    assert n > 0

    if (n == 1):
        return redirect('/get')

    return redirect('/redirect/{0}'.format(n - 1))


@app.route('/relative-redirect/<int:n>')
def relative_redirect_n_times(n):
    """301 Redirects n times."""

    assert n > 0

    response = app.make_response('')
    response.status_code = 302

    if (n == 1):
        response.headers['Location'] = '/get'
        return response

    response.headers['Location'] = '/relative-redirect/{0}'.format(n - 1)
    return response


@app.route('/stream/<int:n>')
def stream_n_messages(n):
    """Stream n JSON messages"""
    response = get_dict('url', 'args', 'headers', 'origin')
    n = min(n, 100)

    def generate_stream():
        for i in range(n):
            response['id'] = i
            yield json.dumps(response) + '\n'

    return Response(generate_stream(), headers={
        "Transfer-Encoding": "chunked",
        "Content-Type": "application/json",
        })


@app.route('/status/<codes>')
def view_status_code(codes):
    """Return status code or random status code if more than one are given"""

    if not ',' in codes:
        code = int(codes)
        return status_code(code)

    choices = []
    for choice in codes.split(','):
        if not ':' in choice:
            code = choice
            weight = 1
        else:
            code, weight = choice.split(':')

        choices.append((int(code), float(weight)))

    code = weighted_choice(choices)

    return status_code(code)


@app.route('/response-headers')
def response_headers():
    """Returns a set of response headers from the query string """
    headers = CaseInsensitiveDict(request.args.items())
    response = jsonify(headers.items())

    while True:
        content_len_shown = response.headers['Content-Length']
        response = jsonify(response.headers.items())
        for key, value in headers.items():
            response.headers[key] = value
        if response.headers['Content-Length'] == content_len_shown:
            break
    return response


@app.route('/cookies')
def view_cookies(hide_env=True):
    """Returns cookie data."""

    cookies = dict(request.cookies.items())

    if hide_env and ('show_env' not in request.args):
        for key in ENV_COOKIES:
            try:
                del cookies[key]
            except KeyError:
                pass

    return jsonify(cookies=cookies)


@app.route('/cookies/set/<name>/<value>')
def set_cookie(name, value):
    """Sets a cookie and redirects to cookie list."""

    r = app.make_response(redirect('/cookies'))
    r.set_cookie(key=name, value=value)

    return r


@app.route('/cookies/set')
def set_cookies():
    """Sets cookie(s) as provided by the query string and redirects to cookie list."""

    cookies = dict(request.args.items())
    r = app.make_response(redirect('/cookies'))
    for key, value in cookies.items():
        r.set_cookie(key=key, value=value)

    return r


@app.route('/basic-auth/<user>/<passwd>')
def basic_auth(user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""

    if not check_basic_auth(user, passwd):
        return status_code(401)

    return jsonify(authenticated=True, user=user)


@app.route('/hidden-basic-auth/<user>/<passwd>')
def hidden_basic_auth(user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""

    if not check_basic_auth(user, passwd):
        return status_code(404)
    return jsonify(authenticated=True, user=user)


@app.route('/digest-auth/<qop>/<user>/<passwd>')
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
        auth.set_digest('me@kennethreitz.com', nonce, opaque=opaque,
                        qop=('auth', 'auth-int') if qop is None else (qop, ))
        response.headers['WWW-Authenticate'] = auth.to_header()
        return response
    elif not check_digest_auth(user, passwd):
        return status_code(401)
    return jsonify(authenticated=True, user=user)


@app.route('/delay/<int:delay>')
def delay_response(delay):
    """Returns a delayed response"""
    delay = min(delay, 10)

    time.sleep(delay)

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files'))


@app.route('/base64/<value>')
def decode_base64(value):
    """Decodes base64url-encoded string"""
    encoded = value.encode('utf-8')
    return base64.urlsafe_b64decode(encoded).decode('utf-8')


if __name__ == '__main__':
    app.run()
