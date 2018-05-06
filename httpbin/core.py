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

from flask import Flask, Response, request, render_template, redirect, jsonify as flask_jsonify, make_response, url_for, abort
from six.moves import range as xrange
from werkzeug.datastructures import WWWAuthenticate, MultiDict
from werkzeug.http import http_date
from werkzeug.wrappers import BaseResponse
from werkzeug.http import parse_authorization_header
from raven.contrib.flask import Sentry

from . import filters
from .helpers import get_headers, status_code, get_dict, get_request_range, check_basic_auth, check_digest_auth, \
    secure_cookie, H, ROBOT_TXT, ANGRY_ASCII, parse_multi_value_header, next_stale_after_value, \
    digest_challenge_response
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
    response = flask_jsonify(*args, **kwargs)
    if not response.data.endswith(b'\n'):
        response.data += b'\n'
    return response

# Prevent WSGI from correcting the casing of the Location header
BaseResponse.autocorrect_location_header = False

# Find the correct template folder when running from a different location
tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

app = Flask(__name__, template_folder=tmpl_dir)
app.debug = bool(os.environ.get('DEBUG'))

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

# -----------
# Middlewares
# -----------
"""
https://github.com/kennethreitz/httpbin/issues/340
Adds a middleware to provide chunked request encoding support running under
gunicorn only.
Werkzeug required environ 'wsgi.input_terminated' to be set otherwise it
empties the input request stream.
- gunicorn seems to support input_terminated but does not add the environ,
  so we add it here.
- flask will hang and does not seem to properly terminate the request, so
  we explicitly deny chunked requests.
"""
@app.before_request
def before_request():
    if request.environ.get('HTTP_TRANSFER_ENCODING', '').lower() == 'chunked':
        server = request.environ.get('SERVER_SOFTWARE', '')
        if server.lower().startswith('gunicorn/'):
            if 'wsgi.input_terminated' in request.environ:
                app.logger.debug("environ wsgi.input_terminated already set, keeping: %s"
                                   % request.environ['wsgi.input_terminated'])
            else:
                request.environ['wsgi.input_terminated'] = 1
        else:
            abort(501, "Chunked requests are not supported for server %s" % server)

@app.after_request
def set_cors_headers(response):
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


# ------
# Routes
# ------

@app.route('/')
def view_landing_page():
    """Generates Landing Page."""
    tracking_enabled = 'HTTPBIN_TRACKING' in os.environ
    return render_template('index.html', tracking_enabled=tracking_enabled)


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


@app.route('/uuid')
def view_uuid():
    """Returns a UUID."""

    return jsonify(uuid=str(uuid.uuid4()))


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


@app.route('/anything', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
@app.route('/anything/<path:anything>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def view_anything(anything=None):
    """Returns request data."""

    return jsonify(get_dict('url', 'args', 'headers', 'origin', 'method', 'form', 'data', 'files', 'json'))


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
    """Returns DELETE Data."""

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json'))


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


@app.route('/brotli')
@filters.brotli
def view_brotli_encoded_content():
    """Returns Brotli-Encoded Data."""

    return jsonify(get_dict(
        'origin', 'headers', method=request.method, brotli=True))


@app.route('/redirect/<int:n>')
def redirect_n_times(n):
    """302 Redirects n times."""
    assert n > 0

    absolute = request.args.get('absolute', 'false').lower() == 'true'

    if n == 1:
        return redirect(url_for('view_get', _external=absolute))

    if absolute:
        return _redirect('absolute', n, True)
    else:
        return _redirect('relative', n, False)


def _redirect(kind, n, external):
    return redirect(url_for('{0}_redirect_n_times'.format(kind), n=n - 1, _external=external))


@app.route('/redirect-to', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def redirect_to():
    """302/3XX Redirects to the given URL."""

    args = CaseInsensitiveDict(request.args.items())

    # We need to build the response manually and convert to UTF-8 to prevent
    # werkzeug from "fixing" the URL. This endpoint should set the Location
    # header to the exact string supplied.
    response = app.make_response('')
    response.status_code = 302
    if 'status_code' in args:
        status_code = int(args['status_code'])
        if status_code >= 300 and status_code < 400:
            response.status_code = status_code
    response.headers['Location'] = args['url'].encode('utf-8')

    return response


@app.route('/relative-redirect/<int:n>')
def relative_redirect_n_times(n):
    """302 Redirects n times."""

    assert n > 0

    response = app.make_response('')
    response.status_code = 302

    if n == 1:
        response.headers['Location'] = url_for('view_get')
        return response

    response.headers['Location'] = url_for('relative_redirect_n_times', n=n - 1)
    return response


@app.route('/absolute-redirect/<int:n>')
def absolute_redirect_n_times(n):
    """302 Redirects n times."""

    assert n > 0

    if n == 1:
        return redirect(url_for('view_get', _external=True))

    return _redirect('absolute', n, True)


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
        "Content-Type": "application/json",
        })


@app.route('/status/<codes>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'])
def view_status_code(codes):
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


@app.route('/response-headers', methods=['GET', 'POST'])
def response_headers():
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


@app.route('/forms/post')
def view_forms_post():
    """Simple HTML form."""

    return render_template('forms-post.html')


@app.route('/cookies/set/<name>/<value>')
def set_cookie(name, value):
    """Sets a cookie and redirects to cookie list."""

    r = app.make_response(redirect(url_for('view_cookies')))
    r.set_cookie(key=name, value=value, secure=secure_cookie())

    return r


@app.route('/cookies/set')
def set_cookies():
    """Sets cookie(s) as provided by the query string and redirects to cookie list."""

    cookies = dict(request.args.items())
    r = app.make_response(redirect(url_for('view_cookies')))
    for key, value in cookies.items():
        r.set_cookie(key=key, value=value, secure=secure_cookie())

    return r


@app.route('/cookies/delete')
def delete_cookies():
    """Deletes cookie(s) as provided by the query string and redirects to cookie list."""

    cookies = dict(request.args.items())
    r = app.make_response(redirect(url_for('view_cookies')))
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


@app.route('/bearer')
def bearer_auth():
    """Authenticates using bearer authentication."""
    if 'Authorization' not in request.headers:
        response = app.make_response('')
        response.headers['WWW-Authenticate'] = 'Bearer'
        response.status_code = 401
        return response
    authorization = request.headers.get('Authorization')
    token = authorization.lstrip('Bearer ')

    return jsonify(authenticated=True, token=token)


@app.route('/digest-auth/<qop>/<user>/<passwd>')
def digest_auth_md5(qop=None, user='user', passwd='passwd'):
    return digest_auth(qop, user, passwd, "MD5", 'never')


@app.route('/digest-auth/<qop>/<user>/<passwd>/<algorithm>')
def digest_auth_nostale(qop=None, user='user', passwd='passwd', algorithm='MD5'):
    return digest_auth(qop, user, passwd, algorithm, 'never')


@app.route('/digest-auth/<qop>/<user>/<passwd>/<algorithm>/<stale_after>')
def digest_auth(qop=None, user='user', passwd='passwd', algorithm='MD5', stale_after='never'):
    """Prompts the user for authorization using HTTP Digest auth"""
    require_cookie_handling = (request.args.get('require-cookie', '').lower() in
                               ('1', 't', 'true'))
    if algorithm not in ('MD5', 'SHA-256', 'SHA-512'):
        algorithm = 'MD5'

    if qop not in ('auth', 'auth-int'):
        qop = None

    authorization = request.headers.get('Authorization')
    credentials = None
    if authorization:
        credentials = parse_authorization_header(authorization)

    if (not authorization or
            not credentials or credentials.type.lower() != 'digest' or
            (require_cookie_handling and 'Cookie' not in request.headers)):
        response = digest_challenge_response(app, qop, algorithm)
        response.set_cookie('stale_after', value=stale_after)
        response.set_cookie('fake', value='fake_value')
        return response

    if (require_cookie_handling and
            request.cookies.get('fake') != 'fake_value'):
        response = jsonify({'errors': ['missing cookie set on challenge']})
        response.set_cookie('fake', value='fake_value')
        response.status_code = 403
        return response

    current_nonce = credentials.get('nonce')

    stale_after_value = None
    if 'stale_after' in request.cookies:
        stale_after_value = request.cookies.get('stale_after')

    if ('last_nonce' in request.cookies and
            current_nonce == request.cookies.get('last_nonce') or
            stale_after_value == '0'):
        response = digest_challenge_response(app, qop, algorithm, True)
        response.set_cookie('stale_after', value=stale_after)
        response.set_cookie('last_nonce',  value=current_nonce)
        response.set_cookie('fake', value='fake_value')
        return response

    if not check_digest_auth(user, passwd):
        response = digest_challenge_response(app, qop, algorithm, False)
        response.set_cookie('stale_after', value=stale_after)
        response.set_cookie('last_nonce', value=current_nonce)
        response.set_cookie('fake', value='fake_value')
        return response

    response = jsonify(authenticated=True, user=user)
    response.set_cookie('fake', value='fake_value')
    if stale_after_value :
        response.set_cookie('stale_after', value=next_stale_after_value(stale_after_value))

    return response


@app.route('/delay/<delay>')
def delay_response(delay):
    """Returns a delayed response"""
    delay = min(float(delay), 10)

    time.sleep(delay)

    return jsonify(get_dict(
        'url', 'args', 'form', 'data', 'origin', 'headers', 'files'))


@app.route('/drip')
def drip():
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

    response = Response(generate_bytes(), headers={
        "Content-Type": "application/octet-stream",
        "Content-Length": str(numbytes),
    })

    response.status_code = code

    return response

@app.route('/base64/<value>')
def decode_base64(value):
    """Decodes base64url-encoded string"""
    encoded = value.encode('utf-8') # base64 expects binary string as input
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

@app.route('/etag/<etag>', methods=('GET',))
def etag(etag):
    """Assumes the resource has the given etag and responds to If-None-Match and If-Match headers appropriately."""
    if_none_match = parse_multi_value_header(request.headers.get('If-None-Match'))
    if_match = parse_multi_value_header(request.headers.get('If-Match'))

    if if_none_match:
        if etag in if_none_match or '*' in if_none_match:
            response = status_code(304)
            response.headers['ETag'] = etag
            return response
    elif if_match:
        if etag not in if_match and '*' not in if_match:
            return status_code(412)

    # Special cases don't apply, return normal response
    response = view_get()
    response.headers['ETag'] = etag
    return response

@app.route('/cache/<int:value>')
def cache_control(value):
    """Sets a Cache-Control header."""
    response = view_get()
    response.headers['Cache-Control'] = 'public, max-age={0}'.format(value)
    return response


@app.route('/encoding/utf8')
def encoding():
    return render_template('UTF-8-demo.txt')


@app.route('/bytes/<int:n>')
def random_bytes(n):
    """Returns n random bytes generated with given seed."""
    n = min(n, 100 * 1024) # set 100KB limit

    params = CaseInsensitiveDict(request.args.items())
    if 'seed' in params:
        random.seed(int(params['seed']))

    response = make_response()

    # Note: can't just use os.urandom here because it ignores the seed
    response.data = bytearray(random.randint(0, 255) for i in range(n))
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

@app.route('/range/<int:numbytes>')
def range_request(numbytes):
    """Streams n random bytes generated with given seed, at given chunk size per packet."""

    if numbytes <= 0 or numbytes > (100 * 1024):
        response = Response(headers={
            'ETag' : 'range%d' % numbytes,
            'Accept-Ranges' : 'bytes'
            })
        response.status_code = 404
        response.data = 'number of bytes must be in the range (0, 102400]'
        return response

    params = CaseInsensitiveDict(request.args.items())
    if 'chunk_size' in params:
        chunk_size = max(1, int(params['chunk_size']))
    else:
        chunk_size = 10 * 1024

    duration = float(params.get('duration', 0))
    pause_per_byte = duration / numbytes

    request_headers = get_headers()
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

@app.route('/links/<int:n>/<int:offset>')
def link_page(n, offset):
    """Generate a page containing n links to other pages which do the same."""
    n = min(max(1, n), 200) # limit to between 1 and 200 links

    link = "<a href='{0}'>{1}</a> "

    html = ['<html><head><title>Links</title></head><body>']
    for i in xrange(n):
        if i == offset:
            html.append("{0} ".format(i))
        else:
            html.append(link.format(url_for('link_page', n=n, offset=i), i))
    html.append('</body></html>')

    return ''.join(html)


@app.route('/links/<int:n>')
def links(n):
    """Redirect to first links page."""
    return redirect(url_for('link_page', n=n, offset=0))


@app.route('/image')
def image():
    """Returns a simple image of the type suggest by the Accept header."""

    headers = get_headers()
    if 'accept' not in headers:
        return image_png() # Default media type to png

    accept = headers['accept'].lower()

    if 'image/webp' in accept:
        return image_webp()
    elif 'image/svg+xml' in accept:
        return image_svg()
    elif 'image/jpeg' in accept:
        return image_jpeg()
    elif 'image/png' in accept or 'image/*' in accept:
        return image_png()
    else:
        return status_code(406) # Unsupported media type


@app.route('/image/png')
def image_png():
    data = resource('images/pig_icon.png')
    return Response(data, headers={'Content-Type': 'image/png'})


@app.route('/image/jpeg')
def image_jpeg():
    data = resource('images/jackal.jpg')
    return Response(data, headers={'Content-Type': 'image/jpeg'})


@app.route('/image/webp')
def image_webp():
    data = resource('images/wolf_1.webp')
    return Response(data, headers={'Content-Type': 'image/webp'})


@app.route('/image/svg')
def image_svg():
    data = resource('images/svg_logo.svg')
    return Response(data, headers={'Content-Type': 'image/svg+xml'})


def resource(filename):
    path = os.path.join(
        tmpl_dir,
        filename)
    return open(path, 'rb').read()


@app.route("/xml")
def xml():
    response = make_response(render_template("sample.xml"))
    response.headers["Content-Type"] = "application/xml"
    return response


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    app.run(port=args.port, host=args.host)
