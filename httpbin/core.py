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

import werkzeug
from werkzeug import Response, Request, redirect
from six.moves import range as xrange
from werkzeug.datastructures import WWWAuthenticate, MultiDict
from werkzeug.http import http_date
from werkzeug.wrappers import BaseResponse
from werkzeug.http import parse_authorization_header
from werkzeug.exceptions import HTTPException, MethodNotAllowed
import jinja2
try:
    from raven.contrib.flask import Sentry
except ImportError:
    Sentry = None

from . import filters
from .helpers import get_dict, check_basic_auth, status_code, get_headers, check_digest_auth, digest_challenge_response, next_stale_after_value, get_request_range, parse_multi_value_header, ROBOT_TXT, ANGRY_ASCII, secure_cookie

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


def resource(filename):
    path = os.path.join(
        tmpl_dir,
        filename)
    with open(path, 'rb') as f:
        content = f.read()
    return content


# Prevent WSGI from correcting the casing of the Location header
BaseResponse.autocorrect_location_header = False

# Find the correct template folder when running from a different location
tmpl_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'templates')


class UrlMap(werkzeug.routing.Map):
    endpoints = {}

    def expose(self, rule, methods=['GET'], **kwargs):
        def _inner(func):
            endpoint = func
            endpoint_name = func.__name__
            self.endpoints[endpoint_name] = endpoint
            self.add(
                werkzeug.routing.Rule(rule, methods=methods, endpoint=endpoint_name))
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
        endpoint_name, values = adapter.match()
        endpoint = url_map.endpoints[endpoint_name]
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


def render(request, template_name, content_type="text/html; charset=utf-8", **kwargs):
    template = jinja_env.get_template(template_name)
    body = template.render(
        request=request,
        url_for=request.url_for,
        **kwargs)
    response = Response(body, content_type=content_type)
    return response


# Send app errors to Sentry.
if 'SENTRY_DSN' in os.environ:
    assert Sentry, "Must install Sentry"
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

# Methods

@url_map.expose("/<any(get, post, put, patch, delete):method>", methods=('GET', 'POST', 'PUT', 'PATCH', 'DELETE'))
def view_method(request, method):
    """Returns data for relevant method."""
    if not request.method == method.upper():
        raise werkzeug.exceptions.MethodNotAllowed([method.upper()])
    return jsonify(get_dict(
        request, 'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


@url_map.expose('/anything', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
@url_map.expose('/anything/<path:anything>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def view_anything(request, anything=None):
    """Returns request data."""
    return jsonify(get_dict(
        request, 'url', 'args', 'headers', 'origin', 'method', 'form', 'data', 'files', 'json'))

# Status codes

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

# Info

@url_map.expose('/user-agent')
def view_user_agent(request):
    """Returns User-Agent."""
    headers = get_headers(request)
    return jsonify({'user-agent': headers['user-agent']})


@url_map.expose('/ip')
def view_origin(request):
    """Returns Origin IP."""
    return jsonify(
        origin=request.headers.get('X-Forwarded-For', request.remote_addr))


@url_map.expose('/headers')
def view_headers(request):
    """Returns HTTP HEADERS."""
    return jsonify(get_dict(request, 'headers'))


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


@url_map.expose('/cookies')
def view_cookies(request, hide_env=True):
    """Returns cookie data."""
    cookies = dict(request.cookies.items())
    if hide_env and ('show_env' not in request.args):
        for key in ENV_COOKIES:
            try:
                del cookies[key]
            except KeyError:
                pass
    return jsonify(cookies=cookies)


@url_map.expose('/cookies/set/<name>/<value>')
def set_cookie(request, name, value):
    """Sets a cookie and redirects to cookie list."""
    response = redirect(request.url_for('view_cookies'))
    response.set_cookie(key=name, value=value, secure=secure_cookie(request))
    return response


@url_map.expose('/cookies/set')
def set_cookies(request):
    """Sets cookie(s) as provided by the query string and redirects to cookie list."""
    response = redirect(request.url_for('view_cookies'))
    for key, value in request.args.items():
        response.set_cookie(key=key, value=value, secure=secure_cookie(request))
    return response


@url_map.expose('/cookies/delete')
def delete_cookies(request):
    """Deletes cookie(s) as provided by the query string and redirects to cookie list."""
    response = redirect(request.url_for('view_cookies'))
    for key, value in request.args.items():
        response.delete_cookie(key=key)
    return response

# Encodings

@url_map.expose('/base64/<value>')
def decode_base64(request, value):
    """Decodes base64url-encoded string"""
    encoded = value.encode('utf-8')  # base64 expects binary string as input
    response = Response(base64.urlsafe_b64decode(encoded).decode('utf-8'))
    return response


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


@url_map.expose('/deflate')
@filters.deflate
def view_deflate_encoded_content(request):
    """Returns Deflate-Encoded Data."""
    return jsonify(get_dict(
        request, 'origin', 'headers', method=request.method, deflated=True))


@url_map.expose('/encoding/utf8')
def encoding(request):
    response = render(request, "UTF-8-demo.txt")
    return response

# Auth

@url_map.expose('/basic-auth/<user>/<passwd>')
def basic_auth(request, user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""
    if not check_basic_auth(request, user, passwd):
        return status_code(401)
    return jsonify(authenticated=True, user=user)


@url_map.expose('/hidden-basic-auth/<user>/<passwd>')
def hidden_basic_auth(request, user='user', passwd='passwd'):
    """Prompts the user for authorization using HTTP Basic Auth."""
    if not check_basic_auth(request, user, passwd):
        return status_code(404)
    return jsonify(authenticated=True, user=user)


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

# Redirects

@url_map.expose('/redirect/<int:n>')
def redirect_n_times(request, n):
    """302 Redirects n times."""
    assert n > 0

    absolute = request.args.get('absolute', 'false').lower() == 'true'

    if n == 1:
        return redirect(
            request.url_for(
                'view_method', values={'method': 'get'}, force_external=absolute))

    if absolute:
        return _redirect(request, 'absolute', n, True)
    else:
        return _redirect(request, 'relative', n, False)


def _redirect(request, kind, n, external):
    n = n - 1
    return redirect(
        request.url_for(
            '{0}_redirect_n_times'.format(kind),
            values=dict(n=n), force_external=external))


@url_map.expose('/redirect-to', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def redirect_to(request):
    """302/3XX Redirects to the given URL."""

    args = CaseInsensitiveDict(request.args.items())

    # We need to build the response manually and convert to UTF-8 to prevent
    # werkzeug from "fixing" the URL. This endpoint should set the Location
    # header to the exact string supplied.
    response = Response()
    response.status_code = 302
    if 'status_code' in args:
        status_code = int(args['status_code'])
        if status_code >= 300 and status_code < 400:
            response.status_code = status_code
    response.headers['Location'] = args['url'].encode('utf-8')

    return response


@url_map.expose('/relative-redirect/<int:n>')
def relative_redirect_n_times(request, n):
    """302 Redirects n times."""

    assert n > 0

    response = Response()
    response.status_code = 302

    if n == 1:
        return redirect(
            request.url_for(
                'view_method', values={'method': 'get'}))
        return response

    response.headers['Location'] = request.url_for(
        'relative_redirect_n_times', values=dict(n=n - 1))
    return response


@url_map.expose('/absolute-redirect/<int:n>')
def absolute_redirect_n_times(request, n):
    """302 Redirects n times."""

    assert n > 0

    if n == 1:
        return redirect(
            request.url_for(
                'view_method', values={'method': 'get'}, force_external=True))

    return _redirect(request, 'absolute', n, True)


@url_map.expose('/stream/<int:n>')
def stream_n_messages(request, n):
    """Stream n JSON messages"""
    response = get_dict(request, 'url', 'args', 'headers', 'origin')
    n = min(n, 100)

    def generate_stream():
        for i in range(n):
            response['id'] = i
            yield json.dumps(response) + '\n'

    return Response(generate_stream(), headers={
        "Content-Type": "application/json",
    })


@url_map.expose('/range/<int:numbytes>')
def range_request(request, numbytes):
    """Streams n random bytes generated with given seed, at given chunk size per packet."""

    if numbytes <= 0 or numbytes > (100 * 1024):
        response = Response(
            headers={
                'ETag': 'range%d' % numbytes,
                'Accept-Ranges': 'bytes'})
        response.status_code = 404
        response.data = 'number of bytes must be in the range (0, 10240]'
        return response

    params = CaseInsensitiveDict(request.args.items())
    if 'chunk_size' in params:
        chunk_size = max(1, int(params['chunk_size']))
    else:
        chunk_size = 10 * 1024

    duration = float(params.get('duration', 0))
    pause_per_byte = duration / numbytes

    request_headers = get_headers(request)
    first_byte_pos, last_byte_pos = get_request_range(request_headers, numbytes)
    range_length = (last_byte_pos+1) - first_byte_pos

    if first_byte_pos > last_byte_pos or first_byte_pos not in xrange(0, numbytes) or last_byte_pos not in xrange(0, numbytes):
        response = Response(headers={
            'ETag' : 'range%d' % numbytes,
            'Accept-Ranges' : 'bytes',
            'Content-Range' : 'bytes */%d' % numbytes,
            'Content-Length': '0',
            })
        response.status_code = 416
        return response

    def generate_bytes():
        chunks = bytearray()

        for i in xrange(first_byte_pos, last_byte_pos + 1):

            # We don't want the resource to change across requests, so we need
            # to use a predictable data generation function
            chunks.append(ord('a') + (i % 26))
            if len(chunks) == chunk_size:
                yield(bytes(chunks))
                time.sleep(pause_per_byte * chunk_size)
                chunks = bytearray()

        if chunks:
            time.sleep(pause_per_byte * len(chunks))
            yield(bytes(chunks))

    content_range = 'bytes %d-%d/%d' % (first_byte_pos, last_byte_pos, numbytes)
    response_headers = {
        'Content-Type': 'application/octet-stream',
        'ETag' : 'range%d' % numbytes,
        'Accept-Ranges' : 'bytes',
        'Content-Length': str(range_length),
        'Content-Range' : content_range
    }

    response = Response(generate_bytes(), headers=response_headers)

    if (first_byte_pos == 0) and (last_byte_pos == (numbytes - 1)):
        response.status_code = 200
    else:
        response.status_code = 206

    return response


@url_map.expose('/etag/<etag>', methods=('GET',))
def etag(request, etag):
    """Assumes the resource has the given etag and responds to If-None-Match and If-Match headers appropriately."""
    if_none_match = parse_multi_value_header(request.headers.get('If-None-Match'))
    if_match = parse_multi_value_header(request.headers.get('If-Match'))

    if if_none_match:
        if etag in if_none_match or '*' in if_none_match:
            return status_code(304)
    elif if_match:
        if etag not in if_match and '*' not in if_match:
            return status_code(412)

    # Special cases don't apply, return normal response
    response = view_method(request, 'get')
    response.headers['ETag'] = etag
    return response

# Pages

@url_map.expose("/xml")
def xml(request):
    response = render(
        request,
        "sample.xml",
        content_type="application/xml")
    return response


@url_map.expose('/html')
def view_html_page(request):
    """Simple Html Page"""
    return render(request, 'moby.html')


@url_map.expose('/robots.txt')
def view_robots_page(request):
    """Simple Html Page"""
    response = Response(
        ROBOT_TXT,
        content_type="text/plain")
    return response


@url_map.expose('/deny')
def view_deny_page(request):
    """Simple Html Page"""
    response = Response(
        ANGRY_ASCII,
        content_type="text/plain")
    return response


@url_map.expose('/links/<int:n>/<int:offset>')
def link_page(request, n, offset):
    """Generate a page containing n links to other pages which do the same."""
    n = min(max(1, n), 200) # limit to between 1 and 200 links

    link = "<a href='{0}'>{1}</a> "

    html = ['<html><head><title>Links</title></head><body>']
    for i in xrange(n):
        print(i, offset)
        if i == offset:
            html.append("{0} ".format(i))
        else:
            html.append(
                link.format(
                    request.url_for('link_page', values=dict(n=n, offset=i)), i))
    html.append('</body></html>')

    content = ''.join(html)
    response = Response(content)
    return response


@url_map.expose('/links/<int:n>')
def links(request, n):
    """Redirect to first links page."""
    return redirect(request.url_for('link_page', values=dict(n=n, offset=0)))


@url_map.expose('/forms/post')
def view_forms_post(request):
    """Simple HTML form."""
    return render(request, 'forms-post.html')

# Images

@url_map.expose('/image')
def image(request):
    """Returns a simple image of the type suggest by the Accept header."""

    headers = get_headers(request)
    if 'accept' not in headers:
        return image_png() # Default media type to png

    accept = headers['accept'].lower()

    if 'image/webp' in accept:
        return image_webp(request)
    elif 'image/svg+xml' in accept:
        return image_svg(request)
    elif 'image/jpeg' in accept:
        return image_jpeg(request)
    elif 'image/png' in accept or 'image/*' in accept:
        return image_png(request)
    else:
        return status_code(406) # Unsupported media type


@url_map.expose('/image/png')
def image_png(request):
    data = resource('images/pig_icon.png')
    return Response(data, headers={'Content-Type': 'image/png'})


@url_map.expose('/image/jpeg')
def image_jpeg(request):
    data = resource('images/jackal.jpg')
    return Response(data, headers={'Content-Type': 'image/jpeg'})


@url_map.expose('/image/webp')
def image_webp(request):
    data = resource('images/wolf_1.webp')
    return Response(data, headers={'Content-Type': 'image/webp'})


@url_map.expose('/image/svg')
def image_svg(request):
    data = resource('images/svg_logo.svg')
    return Response(data, headers={'Content-Type': 'image/svg+xml'})


# Utilities

@url_map.expose('/uuid')
def view_uuid(request):
    """Returns a UUID."""
    return jsonify(uuid=str(uuid.uuid4()))


@url_map.expose('/cache', methods=('GET',))
def cache(request):
    """Returns a 304 if an If-Modified-Since header or If-None-Match is present. Returns the same as a GET otherwise."""
    is_conditional = (
        "If-Modified-Since" in request.headers
        or
        "If-None-Match" in request.headers)

    if is_conditional:
        return status_code(304)
    else:
        response = view_method(request, 'get')
        response.headers['Last-Modified'] = http_date()
        response.headers['ETag'] = uuid.uuid4().hex
        return response


@url_map.expose('/delay/<delay>')
def delay_response(request, delay):
    """Returns a delayed response"""
    delay = min(float(delay), 10)
    time.sleep(delay)
    return jsonify(get_dict(
        request, 'url', 'args', 'form', 'data', 'origin', 'headers', 'files'))


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
