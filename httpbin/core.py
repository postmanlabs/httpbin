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
import uuid
import random
import base64

from flask import Flask, Response, request, render_template, redirect, jsonify, make_response
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.http import http_date
from werkzeug.wrappers import BaseResponse

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

# Prevent WSGI from correcting the casing of the Location header
BaseResponse.autocorrect_location_header = False

app = Flask(__name__)


# -----------
# Middlewares
# -----------
@app.after_request
def set_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')

    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response.headers['Access-Control-Max-Age'] = '3600'  # 1 hour cache
    return response


# ------
# Routes
# ------

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

    return jsonify(origin=request.headers.get('X-Forwarded-For', request.remote_addr))


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


@app.route('/deflate')
@filters.deflate
def view_deflate_encoded_content():
    """Returns Deflate-Encoded Data."""

    return jsonify(get_dict(
        'origin', 'headers', method=request.method, deflated=True))


@app.route('/redirect/<int:n>')
def redirect_n_times(n):
    """301 Redirects n times."""

    assert n > 0

    if (n == 1):
        return redirect('/get')

    return redirect('/redirect/{0}'.format(n - 1))


@app.route('/redirect-to')
def redirect_to():
    """302 Redirects to the given URL."""

    args = CaseInsensitiveDict(request.args.items())

    # We need to build the response manually and convert to UTF-8 to prevent
    # werkzeug from "fixing" the URL. This endpoint should set the Location
    # header to the exact string supplied.
    response = app.make_response('')
    response.status_code = 302
    response.headers['Location'] = args['url'].encode('utf-8')

    return response


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


@app.route('/cookies/delete')
def delete_cookies():
    """Deletes cookie(s) as provided by the query string and redirects to cookie list."""

    cookies = dict(request.args.items())
    r = app.make_response(redirect('/cookies'))
    for key, value in cookies.items():
        r.delete_cookie(key=key)

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
        response.headers['Set-Cookie'] = 'fake=fake_value'
        return response
    elif not (check_digest_auth(user, passwd) and
              request.headers.get('Cookie')):
        return status_code(401)
    return jsonify(authenticated=True, user=user)


@app.route('/delay/<int:delay>')
def delay_response(delay):
    """Returns a delayed response"""
    delay = min(delay, 10)

    time.sleep(delay)

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files'))

@app.route('/drip')
def drip():
    """Drips data over a duration after an optional initial delay."""
    args = CaseInsensitiveDict(request.args.items())
    duration = float(args.get('duration', 2))
    numbytes = int(args.get('numbytes', 10))
    pause = duration / numbytes

    delay = float(args.get('delay', 0))
    if delay > 0:
        time.sleep(delay)

    def generate_bytes():
        for i in xrange(numbytes):
            yield bytes(chr(42))
            time.sleep(pause)

    return Response(generate_bytes(), headers={
        "Content-Type": "application/octet-stream",
        })

@app.route('/base64/<value>')
def decode_base64(value):
    """Decodes base64url-encoded string"""
    encoded = value.encode('utf-8')
    return base64.urlsafe_b64decode(encoded).decode('utf-8')


@app.route('/cache', methods=('GET',))
def cache():
    """Returns a 304 if an If-Modified-Since header or If-None-Match is present. Returns the same as a GET otherwise."""
    is_conditional = request.headers.get('If-Modified-Since') or request.headers.get('If-None-Match')

    if is_conditional is None:
        response = view_get()
        response.headers['Last-Modified'] = http_date()
        response.headers['ETag'] = uuid.uuid4().hex
        return response
    else:
        return status_code(304)


@app.route('/cache/<int:value>')
def cache_control(value):
    """Sets a Cache-Control header."""
    response = view_get()
    response.headers['Cache-Control'] = 'public, max-age={0}'.format(value)
    return response


@app.route('/bytes/<int:n>')
def random_bytes(n):
    """Returns n random bytes generated with given seed."""
    n = min(n, 100 * 1024) # set 100KB limit

    params = CaseInsensitiveDict(request.args.items())
    if 'seed' in params:
        random.seed(int(params['seed']))

    response = make_response()
    response.data = bytes().join(chr(random.randint(0, 255)) for i in xrange(n))
    response.content_type = 'application/octet-stream'
    return response


@app.route('/stream-bytes/<int:n>')
def stream_random_bytes(n):
    """Streams n random bytes generated with given seed, at given chunk size per packet."""
    n = min(n, 100 * 1024) # set 100KB limit

    params = CaseInsensitiveDict(request.args.items())
    if 'seed' in params:
        random.seed(int(params['seed']))

    if 'chunk_size' in params:
        chunk_size = max(1, int(params['chunk_size']))
    else:
        chunk_size = 10 * 1024

    def generate_bytes():
        chunks = []

        for i in xrange(n):
            chunks.append(chr(random.randint(0, 255)))
            if len(chunks) == chunk_size:
                yield(bytes().join(chunks))
                chunks = []

        if chunks:
            yield(bytes().join(chunks))

    headers = {'Transfer-Encoding': 'chunked',
               'Content-Type': 'application/octet-stream'}

    return Response(generate_bytes(), headers=headers)


@app.route('/links/<int:n>/<int:offset>')
def link_page(n, offset):
    """Generate a page containing n links to other pages which do the same."""
    n = min(max(1, n), 200) # limit to between 1 and 200 links

    link = "<a href='/links/{0}/{1}'>{2}</a> "

    html = ['<html><head><title>Links</title></head><body>']
    for i in xrange(n):
        if i == offset:
            html.append("{0} ".format(i))
        else:
            html.append(link.format(n, i, i))
    html.append('</body></html>')

    return ''.join(html)


@app.route('/links/<int:n>')
def links(n):
    """Redirect to first links page."""
    return redirect("/links/{0}/0".format(n))


@app.route('/image')
def image():
    """Returns a simple image of the type suggest by the Accept header."""

    headers = get_headers()
    if headers['accept'].lower() == 'image/png' or headers['accept'].lower() == 'image/*':
        return Response(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=='), headers={'Content-Type': 'image/png'})
    elif headers['accept'].lower() == 'image/jpeg':
        return Response(base64.b64decode('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k='), headers={'Content-Type': 'image/jpeg'})
    else:
        return status_code(404)


if __name__ == '__main__':
    app.run()
