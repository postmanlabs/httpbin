# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""

import base64
import json
import os
import random
import time
import uuid
import argparse

import werkzeug
from werkzeug import Response, Request
from six.moves import range as xrange
from werkzeug.datastructures import WWWAuthenticate, MultiDict
from werkzeug.http import http_date
from werkzeug.wrappers import BaseResponse
from werkzeug.http import parse_authorization_header
from werkzeug.exceptions import HTTPException, MethodNotAllowed
import jinja2
from raven.contrib.flask import Sentry

from . import filters
from .helpers import get_dict, check_basic_auth, status_code, get_headers, check_digest_auth, digest_challenge_response, next_stale_after_value
# from .helpers import status_code, get_dict, get_request_range, \
    # secure_cookie, H, ROBOT_TXT, ANGRY_ASCII, parse_multi_value_header,
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

def jsonify(*args, **kwargs):
    if args and kwargs:
        raise TypeError(
            'jsonify() behavior undefined when passed both args and kwargs')
    elif len(args) == 1:  # single args are passed directly to dumps()
        data = args[0]
    else:
        data = args or kwargs

    response = Response(
        (json.dumps(data), '\n'),
        mimetype="application/json")

    if not response.data.endswith(b'\n'):
        response.data += b'\n'
    return response

# Prevent WSGI from correcting the casing of the Location header
BaseResponse.autocorrect_location_header = False

# Find the correct template folder when running from a different location
tmpl_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'templates')


class UrlMap(werkzeug.routing.Map):
    def expose(self, rule, methods=['GET'], **kwargs):
        def _inner(func):
            self.add(
                werkzeug.routing.Rule(rule, methods=methods, endpoint=func))
            return func
        return _inner


jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader([tmpl_dir]))
url_map = UrlMap([])


# -----------
# Middlewares
# -----------


def set_cors_headers(request, response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Credentials'] = 'true'

    if request.method == 'OPTIONS':
        # Both of these headers are only used for the "preflight request"
        # http://www.w3.org/TR/cors/#access-control-allow-methods-response-header
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response.headers['Access-Control-Max-Age'] = '3600'  # 1 hour cache
        if request.headers.get('Access-Control-Request-Headers') is not None:
            response.headers['Access-Control-Allow-Headers'] = request.headers['Access-Control-Request-Headers']
    return response


def cors_middleware(func):
    def _inner(request):
        response = func(request)
        response = set_cors_headers(request, response)
        return response
    return _inner


@Request.application
@cors_middleware
def app(request):
    adapter = url_map.bind_to_environ(request.environ)
    map_adapter = url_map.bind_to_environ(request.environ)
    request.url_for = map_adapter.build

    try:
        endpoint, values = adapter.match()
        return endpoint(request, **values)
    except MethodNotAllowed as e:
        if request.method == "OPTIONS":
            methods = adapter.allowed_methods()
            response = Response()
            response.allow.update(methods)
            return response
        else:
            return e.get_response()
    except HTTPException as e:
        return e.get_response()


def render(request, template_name, **kwargs):
    template = jinja_env.get_template(template_name)
    body = template.render(
        request=request,
        url_for=request.url_for,
        **kwargs)
    response = Response(body, content_type="text/html; charset=utf-8")
    return response


# Send app errors to Sentry.
if 'SENTRY_DSN' in os.environ:
    sentry = Sentry(app, dsn=os.environ['SENTRY_DSN'])

# Set up Bugsnag exception tracking, if desired. To use Bugsnag, install the
# Bugsnag Python client with the command "pip install bugsnag", and set the
# environment variable BUGSNAG_API_KEY. You can also optionally set
# BUGSNAG_RELEASE_STAGE.
if os.environ.get("BUGSNAG_API_KEY") is not None:
    try:
        import bugsnag
        import bugsnag.flask
        release_stage = os.environ.get("BUGSNAG_RELEASE_STAGE") or "production"
        bugsnag.configure(api_key=os.environ.get("BUGSNAG_API_KEY"),
                          project_root=os.path.dirname(os.path.abspath(__file__)),
                          use_ssl=True, release_stage=release_stage,
                          ignore_classes=['werkzeug.exceptions.NotFound'])
        bugsnag.flask.handle_exceptions(app)
    except:
        app.logger.warning("Unable to initialize Bugsnag exception handling.")

# ------
# Routes
# ------


@url_map.expose('/user-agent')
def view_user_agent(request):
    """Returns User-Agent."""
    headers = get_headers(request)
    return jsonify({'user-agent': headers['user-agent']})


@url_map.expose('/get', methods=('GET',))
def view_get(request):
    """Returns GET Data."""
    return jsonify(get_dict(request, 'url', 'args', 'headers', 'origin'))


@url_map.expose('/anything', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
@url_map.expose('/anything/<path:anything>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def view_anything(request, anything=None):
    """Returns request data."""

    return jsonify(get_dict(request, 'url', 'args', 'headers', 'origin', 'method', 'form', 'data', 'files', 'json'))


@url_map.expose('/post', methods=('POST',))
def view_post(request):
    """Returns POST Data."""
    return jsonify(get_dict(
        request,
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


@url_map.expose('/response-headers', methods=['GET', 'POST'])
def response_headers(request):
    """Returns a set of response headers from the query string """
    headers = MultiDict(request.args.items(multi=True))
    response = jsonify(list(headers.lists()))

    while True:
        original_data = response.data
        d = {}
        for key in response.headers.keys():
            value = response.headers.get_all(key)
            if len(value) == 1:
                value = value[0]
            d[key] = value
        response = jsonify(d)
        for key, value in headers.items(multi=True):
            response.headers.add(key, value)
        response_has_changed = response.data != original_data
        if not response_has_changed:
            break
    return response


@url_map.expose('/base64/<value>')
def decode_base64(request, value):
    """Decodes base64url-encoded string"""
    encoded = value.encode('utf-8')  # base64 expects binary string as input
    response = Response(base64.urlsafe_b64decode(encoded).decode('utf-8'))
    return response


@url_map.expose('/basic-auth/<user>/<passwd>')
def basic_auth(request, user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""

    if not check_basic_auth(request, user, passwd):
        return status_code(401)

    return jsonify(authenticated=True, user=user)


@url_map.expose('/gzip')
@filters.gzip
def view_gzip_encoded_content(request):
    """Returns GZip-Encoded Data."""
    return jsonify(
        get_dict(
            request, 'origin', 'headers', method=request.method, gzipped=True))


@url_map.expose('/brotli')
@filters.brotli
def view_brotli_encoded_content(request):
    """Returns Brotli-Encoded Data."""
    return jsonify(
        get_dict(
            request, 'origin', 'headers', method=request.method, brotli=True))


@url_map.expose('/digest-auth/<qop>/<user>/<passwd>')
def digest_auth_md5(request, qop=None, user='user', passwd='passwd'):
    return digest_auth(request, qop, user, passwd, "MD5", 'never')


@url_map.expose('/digest-auth/<qop>/<user>/<passwd>/<algorithm>')
def digest_auth_nostale(request, qop=None, user='user', passwd='passwd', algorithm='MD5'):
    return digest_auth(request, qop, user, passwd, algorithm, 'never')


@url_map.expose('/digest-auth/<qop>/<user>/<passwd>/<algorithm>/<stale_after>')
def digest_auth(request, qop=None, user='user', passwd='passwd', algorithm='MD5', stale_after='never'):
    """Prompts the user for authorization using HTTP Digest auth"""
    if algorithm not in ('MD5', 'SHA-256'):
        algorithm = 'MD5'

    if qop not in ('auth', 'auth-int'):
        qop = None

    if 'Authorization' not in request.headers or \
            'Cookie' not in request.headers:
        response = digest_challenge_response(app, qop, algorithm)
        response.set_cookie('stale_after', value=stale_after)
        return response

    credentails = parse_authorization_header(request.headers.get('Authorization'))
    if not credentails:
        response = digest_challenge_response(app, qop, algorithm)
        response.set_cookie('stale_after', value=stale_after)
        return response

    current_nonce = credentails.get('nonce')
    stale_after_value = None
    if 'stale_after' in request.cookies:
        stale_after_value = request.cookies.get('stale_after')

    if 'last_nonce' in request.cookies and current_nonce == request.cookies.get('last_nonce') or \
            stale_after_value == '0':
        response = digest_challenge_response(app, qop, algorithm, True)
        response.set_cookie('stale_after', value=stale_after)
        response.set_cookie('last_nonce', value=current_nonce)
        return response

    if not check_digest_auth(request, user, passwd):
        response = digest_challenge_response(app, qop, algorithm, False)
        response.set_cookie('stale_after', value=stale_after)
        response.set_cookie('last_nonce', value=current_nonce)
        return response

    response = jsonify(authenticated=True, user=user)
    if stale_after_value:
        response.set_cookie('stale_after', value=next_stale_after_value(stale_after_value))

    return response


@url_map.expose('/drip')
def drip(request):
    """Drips data over a duration after an optional initial delay."""
    args = CaseInsensitiveDict(request.args.items())
    duration = float(args.get('duration', 2))
    numbytes = min(int(args.get('numbytes', 10)),(10 * 1024 * 1024)) # set 10MB limit
    code = int(args.get('code', 200))

    if numbytes <= 0:
        response = Response('number of bytes must be positive', status=400)
        return response

    delay = float(args.get('delay', 0))
    if delay > 0:
        time.sleep(delay)

    pause = duration / numbytes

    def generate_bytes():
        for i in xrange(numbytes):
            yield u"*".encode('utf-8')
            time.sleep(pause)

    response = Response(
        generate_bytes(),
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(numbytes)})

    response.status_code = code

    return response


@url_map.expose('/bytes/<int:n>')
def random_bytes(request, n):
    """Returns n random bytes generated with given seed."""
    n = min(n, 100 * 1024) # set 100KB limit

    params = CaseInsensitiveDict(request.args.items())
    if 'seed' in params:
        random.seed(int(params['seed']))

    response = Response()

    # Note: can't just use os.urandom here because it ignores the seed
    response.data = bytearray(random.randint(0, 255) for i in range(n))
    response.content_type = 'application/octet-stream'
    return response


@url_map.expose('/stream-bytes/<int:n>')
def stream_random_bytes(request, n):
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
        chunks = bytearray()

        for i in xrange(n):
            chunks.append(random.randint(0, 255))
            if len(chunks) == chunk_size:
                yield(bytes(chunks))
                chunks = bytearray()

        if chunks:
            yield(bytes(chunks))

    headers = {'Content-Type': 'application/octet-stream'}

    return Response(generate_bytes(), headers=headers)


@url_map.expose('/delete', methods=('DELETE',))
def view_delete(request):
    """Returns DELETE Data."""
    return jsonify(get_dict(
        request, 'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


@url_map.expose('/status/<codes>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def view_status_code(request, codes):
    """Return status code or random status code if more than one are given"""

    if ',' not in codes:
        try:
            code = int(codes)
        except ValueError:
            return Response('Invalid status code', status=400)
        return status_code(code)

    choices = []
    for choice in codes.split(','):
        if ':' not in choice:
            code = choice
            weight = 1
        else:
            code, weight = choice.split(':')

        try:
            choices.append((int(code), float(weight)))
        except ValueError:
            return Response('Invalid status code', status=400)

    code = weighted_choice(choices)

    return status_code(code)
