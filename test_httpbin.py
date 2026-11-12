#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import base64
import unittest
import contextlib
import wsgiref.validate
import json
from urllib.parse import urlencode, urlparse
from werkzeug.datastructures import Headers
from werkzeug.http import parse_dict_header
from werkzeug.test import Client
from hashlib import md5, sha256, sha512
from io import BytesIO

import httpbin
from httpbin.helpers import parse_multi_value_header


# Set HTTPBIN_TEST_TARGET_URL to run the tests against any running httpbin,
# for example http://localhost:8080, instead of the in-process Flask app.
TARGET_URL = os.environ.get('HTTPBIN_TEST_TARGET_URL')


def local_only(reason):
    """Skip a test that needs the in-process app when TARGET_URL is set."""
    return unittest.skipIf(TARGET_URL, reason)


class TargetResponse(object):
    """The parts of Werkzeug's test response that these tests read."""

    def __init__(self, response):
        self.status_code = response.status_code
        # urllib3 keeps repeated headers apart; requests would join them.
        self.headers = Headers(list(response.raw.headers.items()))
        # The raw bytes, as the test client returns them: no gzip decoding.
        self.data = response.raw.read(decode_content=False)
        response.close()

    def get_data(self):
        return self.data

    @property
    def json(self):
        return json.loads(self.data.decode('utf-8'))

    @property
    def content_length(self):
        value = self.headers.get('Content-Length')
        return None if value is None else int(value)

    def close(self):
        pass


class TargetClient(object):
    """Stands in for Flask's test client, sending each request over HTTP to
    TARGET_URL. Like the test client, it keeps cookies, never follows
    redirects and sends Host: localhost unless a test sets its own."""

    def __init__(self, base_url):
        import requests
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.clear()

    def open(self, path='/', method='GET', headers=None, data=None,
             content_type=None, environ_base=None):
        # A real connection supplies REMOTE_ADDR; nothing else can be faked.
        unsupported = set(environ_base or {}) - {'REMOTE_ADDR'}
        if unsupported:
            raise unittest.SkipTest(
                'needs WSGI environ keys %s' % ', '.join(sorted(unsupported)))
        request_headers = {'Host': 'localhost'}
        request_headers.update(headers or {})
        # The test client ignores a header with no name; requests refuses it.
        request_headers.pop('', None)
        if content_type:
            request_headers['Content-Type'] = content_type
        if isinstance(data, str):
            data = data.encode('utf-8')
        response = self.session.request(
            method, self.base_url + path, headers=request_headers, data=data,
            allow_redirects=False, stream=True)
        return TargetResponse(response)

    def get(self, path='/', **kwargs):
        return self.open(path, method='GET', **kwargs)

    def post(self, path='/', **kwargs):
        return self.open(path, method='POST', **kwargs)

    def put(self, path='/', **kwargs):
        return self.open(path, method='PUT', **kwargs)

    def patch(self, path='/', **kwargs):
        return self.open(path, method='PATCH', **kwargs)

    def delete(self, path='/', **kwargs):
        return self.open(path, method='DELETE', **kwargs)

    def head(self, path='/', **kwargs):
        return self.open(path, method='HEAD', **kwargs)

    def options(self, path='/', **kwargs):
        return self.open(path, method='OPTIONS', **kwargs)


@contextlib.contextmanager
def _setenv(key, value):
    """Context manager to set an environment variable temporarily."""
    old_value = os.environ.get(key, None)
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value

    yield

    if old_value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value



def _string_to_base64(string):
    """Encodes string to utf-8 and then base64"""
    utf8_encoded = string.encode('utf-8')
    return base64.urlsafe_b64encode(utf8_encoded)

def _hash(data, algorithm):
    """Encode binary data according to specified algorithm, use MD5 by default"""
    if algorithm == 'SHA-256':
        return sha256(data).hexdigest()
    elif algorithm == 'SHA-512':
        return sha512(data).hexdigest()
    else:
        return md5(data).hexdigest()

def _make_digest_auth_header(username, password, method, uri, nonce,
                             realm=None, opaque=None, algorithm=None,
                             qop=None, cnonce=None, nc=None, body=None):
    """Compile a digest authentication header string.

    Arguments:
    - `nonce`: nonce string, received within "WWW-Authenticate" header
    - `realm`: realm string, received within "WWW-Authenticate" header
    - `opaque`: opaque string, received within "WWW-Authenticate" header
    - `algorithm`: type of hashing algorithm, used by the client
    - `qop`: type of quality-of-protection, used by the client
    - `cnonce`: client nonce, required if qop is "auth" or "auth-int"
    - `nc`: client nonce count, required if qop is "auth" or "auth-int"
    - `body`: body of the outgoing request (bytes), used if qop is "auth-int"
    """

    assert username
    assert password
    assert nonce
    assert method
    assert uri
    assert algorithm in ('MD5', 'SHA-256', 'SHA-512', None)

    a1 = ':'.join([username, realm or '', password])
    ha1 = _hash(a1.encode('utf-8'), algorithm)

    a2 = ':'.join([method, uri])
    if qop == 'auth-int':
        a2 = ':'.join([a2, _hash(body or b'', algorithm)])
    ha2 = _hash(a2.encode('utf-8'), algorithm)

    a3 = ':'.join([ha1, nonce])
    if qop in ('auth', 'auth-int'):
        assert cnonce
        assert nc
        a3 = ':'.join([a3, nc, cnonce, qop])

    a3 = ':'.join([a3, ha2])
    auth_response = _hash(a3.encode('utf-8'), algorithm)

    auth_header = \
        'Digest username="{0}", response="{1}", uri="{2}", nonce="{3}"'\
            .format(username, auth_response, uri, nonce)

    # 'realm' and 'opaque' should be returned unchanged, even if empty
    if realm != None:
        auth_header += ', realm="{0}"'.format(realm)
    if opaque != None:
        auth_header += ', opaque="{0}"'.format(opaque)

    if algorithm:
        auth_header += ', algorithm="{0}"'.format(algorithm)
    if cnonce:
        auth_header += ', cnonce="{0}"'.format(cnonce)
    if nc:
        auth_header += ', nc={0}'.format(nc)
    if qop:
        auth_header += ', qop={0}'.format(qop)

    return auth_header

class HttpbinTestCase(unittest.TestCase):
    """Httpbin tests"""

    def setUp(self):
        if TARGET_URL:
            self.app = TargetClient(TARGET_URL)
        else:
            httpbin.app.debug = True
            self.app = httpbin.app.test_client()

    def test_index(self):   
        response = self.app.get('/', headers={'User-Agent': 'test'})
        self.assertEqual(response.status_code, 200)
 
    def get_data(self, response):
        if 'get_data' in dir(response):
            return response.get_data()
        else:
            return response.data

    def test_response_headers_simple(self):
        supported_verbs = ['get', 'post']
        for verb in supported_verbs:
            method = getattr(self.app, verb)
            response = method('/response-headers?animal=dog')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get_all('animal'), ['dog'])
            assert json.loads(response.data.decode('utf-8'))['animal'] == 'dog'

    def test_response_headers_refuses_renderable_content_types(self):
        for query in (
            'Content-Type=text/html',
            'content-type=Text/HTML;%20charset=utf-8',
            'Content-Type=image/svg%2Bxml',
            'Content-Type=application/atom%2Bxml',
            'Content-Type=text/javascript',
        ):
            response = self.app.get('/response-headers?' + query)
            self.assertEqual(response.status_code, 400, query)
            self.assertEqual(
                response.headers.get('Content-Type'), 'text/plain; charset=utf-8')
            self.assertEqual(response.data, b'this Content-Type is not allowed\n')

    def test_response_headers_allows_inert_content_types(self):
        response = self.app.get('/response-headers?Content-Type=text/plain')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get_all('Content-Type'), ['text/plain'])

    def test_response_headers_drops_reserved_headers(self):
        reserved = (
            'Content-Length', 'Transfer-Encoding', 'Connection', 'Keep-Alive',
            'Proxy-Connection', 'TE', 'Trailer', 'Upgrade', 'Refresh',
            'X-Content-Type-Options', 'Proxy-Authenticate',
        )
        query = '&'.join(name + '=1' for name in reserved)
        response = self.app.get('/response-headers?animal=dog&' + query)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get_all('Content-Length'),
                         [str(len(response.data))])
        for name in ('Refresh', 'Upgrade', 'Trailer', 'TE', 'Keep-Alive',
                     'Proxy-Connection', 'Proxy-Authenticate'):
            self.assertNotIn(name, response.headers, name)
        self.assertNotIn('1', response.headers.get_all('X-Content-Type-Options'))
        echoed = json.loads(response.data.decode('utf-8'))
        self.assertEqual(echoed['animal'], 'dog')
        for name in reserved:
            if name != 'Content-Length':
                self.assertNotIn(name, echoed, name)

    def test_response_headers_refuses_content_type_lists(self):
        # A comma-separated list is not a single valid media type.
        for value in ('text/plain,text/html', 'text/plain, text/html',
                      'text/html,text/plain', 'application/json,text/html'):
            response = self.app.get(
                '/response-headers?' + urlencode({'Content-Type': value, 'x': '<b>'}))
            self.assertEqual(response.status_code, 400, value)
            self.assertEqual(
                response.data, b'the Content-Type is not a valid media type\n')
            self.assertEqual(response.headers.get_all('Content-Type'),
                             ['text/plain; charset=utf-8'])

    def test_response_headers_content_type_validation_cases(self):
        for query, message in (
            ('Content-Type=text/plain,text/html&x=%3Cb%3E1%3C/b%3E',
             b'the Content-Type is not a valid media type\n'),
            ('Content-Type=text/plain&Content-Type=text/html',
             b'only one Content-Type is allowed\n'),
            ('content-type=TEXT/HTML', b'this Content-Type is not allowed\n'),
            ('Content-Type=text/plain;x=,text/html',
             b'the Content-Type is not a valid media type\n'),
        ):
            response = self.app.get('/response-headers?' + query)
            self.assertEqual(response.status_code, 400, query)
            self.assertEqual(response.headers.get_all('Content-Type'),
                             ['text/plain; charset=utf-8'], query)
            self.assertEqual(response.data, message, query)

    def test_response_headers_refuses_repeated_content_types(self):
        for pairs in (
            [('Content-Type', 'text/plain'), ('Content-Type', 'text/plain')],
            [('Content-Type', 'text/plain'), ('content-type', 'text/html')],
            [('content-type', 'text/plain'), ('CONTENT-TYPE', 'text/csv')],
        ):
            response = self.app.get('/response-headers?' + urlencode(pairs))
            self.assertEqual(response.status_code, 400, pairs)
            self.assertEqual(response.data, b'only one Content-Type is allowed\n')

    def test_response_headers_content_type_replaces_json(self):
        for key in ('Content-Type', 'content-type', 'CONTENT-TYPE'):
            response = self.app.get(
                '/response-headers?' + urlencode({key: 'text/csv; header=present'}))
            self.assertEqual(response.status_code, 200, key)
            self.assertEqual(response.headers.get_all('Content-Type'),
                             ['text/csv; header=present'])
            echoed = json.loads(response.data.decode('utf-8'))
            self.assertEqual(echoed['Content-Type'], 'text/csv; header=present')

    def test_response_headers_refuses_invalid_content_types(self):
        for value in ('textplain', 'text/', '/plain', 'a/b/c', 'text /plain',
                      'text/plain extra', 'text/plain; =x', 'text/plain; a=',
                      'text/plain; a=1; A=2', 'text/plain; ;',
                      'text/plain\x01', u't\xebxt/plain'):
            response = self.app.get(
                '/response-headers?' + urlencode({'Content-Type': value}))
            self.assertEqual(response.status_code, 400, value)
            self.assertEqual(
                response.data, b'the Content-Type is not a valid media type\n')

    def test_response_headers_escapes_echo_for_other_types(self):
        response = self.app.get(
            '/response-headers?Content-Type=text/csv&x=%3Cb%3E%22%27%26')
        self.assertEqual(response.status_code, 200)
        echoed = json.loads(response.data.decode('utf-8'))
        self.assertEqual(echoed['x'], '&lt;b&gt;&#34;&#39;&amp;')
        self.assertEqual(response.headers.get('x'), '<b>"\'&')

    def test_response_headers_does_not_escape_inert_types(self):
        for content_type in ('text/plain', 'application/json'):
            response = self.app.get(
                '/response-headers?Content-Type=%s&x=%%3Cb%%3E' % content_type)
            echoed = json.loads(response.data.decode('utf-8'))
            self.assertEqual(echoed['x'], '<b>', content_type)
        response = self.app.get('/response-headers?x=%3Cb%3E')
        self.assertEqual(json.loads(response.data.decode('utf-8'))['x'], '<b>')

    def test_response_headers_set_cookie_domain(self):
        allowed = (
            ('Set-Cookie', ['x=1; Path=/; HttpOnly']),
            ('Set-Cookie', ['x=1; Domain=localhost']),
            ('Set-Cookie', ['x=1; Domain=.localhost']),
            ('Set-Cookie', ['x=1; DOMAIN=LOCALHOST']),
            ('set-cookie', ['x=1; Domain=localhost']),
            ('Set-Cookie', ['x="q"', 'y=1; Path=/x']),
        )
        refused = (
            ('Set-Cookie', ['x=1; Domain=.example.com']),
            ('set-cookie', ['x=1; Domain=.example.com']),
            ('SET-COOKIE', ['x=1; Domain=.example.com']),
            ('Set-Cookie', ['x=1; dOmAiN=.example.com']),
            ('Set-Cookie', ['x=1;    Domain =  .example.com']),
            ('Set-Cookie', [u'x=1; Doma\u0130n=.example.com']),
            ('Set-Cookie', ['x=1; Domain=sub.localhost']),
            ('Set-Cookie', ['x=1; Domain=..localhost']),
            ('Set-Cookie', ['x=1; Domain=localhost:8080']),
            ('Set-Cookie', ['x=1; Domain=']),
            ('Set-Cookie', ['x=1; Domain']),
            ('Set-Cookie', ['x=1; Domain=localhost; Domain=.example.com']),
            ('Set-Cookie', ['x=1; Domain=.example.com; Domain=localhost']),
            ('Set-Cookie', ['a=1', 'b=2; Domain=localhost', 'c=3; Domain=.example.com']),
            ('Set-Cookie', ['no-equals-sign']),
            ('Set-Cookie', ['; Domain=localhost']),
            ('Set-Cookie', ['x y=1']),
            ('Set-Cookie', ['x=a\\b']),
        )
        for method in ('GET', 'POST'):
            for key, values in allowed + refused:
                query = urlencode([(key, v) for v in values] + [('Foo', 'bar')])
                response = self.app.open(
                    '/response-headers?' + query, method=method,
                    headers={'X-Forwarded-Host': 'other.example'})
                if (key, values) in allowed:
                    self.assertEqual(response.status_code, 200, values)
                    self.assertEqual(response.headers.get_all(key), values)
                else:
                    self.assertEqual(response.status_code, 400, values)
                    self.assertEqual(response.headers.get_all('Set-Cookie'), [])
                    self.assertIsNone(response.headers.get('Foo'))
                    error = json.loads(response.data.decode('utf-8'))
                    self.assertEqual(error['status_code'], 400)
                    self.assertEqual(error['error'], 'Bad Request')

    def test_response_headers_set_cookie_domain_ignores_port(self):
        response = self.app.get(
            '/response-headers?Set-Cookie=x%3D1%3B%20Domain%3Dlocalhost',
            headers={'Host': 'localhost:8080'})
        self.assertEqual(response.status_code, 200)

    def test_response_headers_multi(self):
        supported_verbs = ['get', 'post']
        for verb in supported_verbs:
            method = getattr(self.app, verb)
            response = method('/response-headers?animal=dog&animal=cat')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get_all('animal'), ['dog', 'cat'])
            assert json.loads(response.data.decode('utf-8'))['animal'] == ['dog', 'cat']

    def test_get(self):
        response = self.app.get('/get', headers={'User-Agent': 'test'})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['args'], {})
        self.assertEqual(data['headers']['Host'], 'localhost')
        self.assertEqual(data['headers']['User-Agent'], 'test')
        # self.assertEqual(data['origin'], None)
        self.assertEqual(data['url'], 'http://localhost/get')
        self.assertTrue(response.data.endswith(b'\n'))

    def test_anything(self):
        response = self.app.get('/anything')
        self.assertEqual(response.status_code, 200)
        response = self.app.get('/anything/foo/bar')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['args'], {})
        self.assertEqual(data['headers']['Host'], 'localhost')
        self.assertEqual(data['url'], 'http://localhost/anything/foo/bar')
        self.assertEqual(data['method'], 'GET')
        self.assertTrue(response.data.endswith(b'\n'))

    def test_base64(self):
        greeting = u'Здравствуй, мир!'
        b64_encoded = _string_to_base64(greeting)
        response = self.app.get('/base64/' + b64_encoded.decode('ascii'))
        content = response.data.decode('utf-8')
        self.assertEqual(greeting, content)
        self.assertEqual(
            response.headers.get('Content-Type'), 'text/plain; charset=utf-8')

    def test_base64_text_decodes_as_declared(self):
        # A client decodes with the declared charset, as requests does
        greeting = u'\u0417\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439'
        response = self.app.get(
            '/base64/' + _string_to_base64(greeting).decode('ascii'))
        charset = response.headers.get('Content-Type').partition('charset=')[2]
        self.assertEqual(response.data.decode(charset), greeting)

    def test_base64_markup_is_plain_text(self):
        markup = _string_to_base64(u'<b>bold</b>')
        response = self.app.get('/base64/' + markup.decode('ascii'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get('Content-Type'), 'text/plain; charset=utf-8')
        self.assertEqual(
            response.data, b'<b>bold</b>')

    def test_post_binary(self):
        response = self.app.post('/post',
                                 data=b'\x01\x02\x03\x81\x82\x83',
                                 content_type='application/octet-stream')
        self.assertEqual(response.status_code, 200)

    def test_post_body_text(self):
        with open('httpbin/core.py') as f:
            response = self.app.post('/post', data={"file": f.read()})
        self.assertEqual(response.status_code, 200)

    def test_post_body_binary(self):
        response = self.app.post(
            '/post',
            data={"file": b'\x01\x02\x03\x81\x82\x83'})
        self.assertEqual(response.status_code, 200)

    def test_post_body_unicode(self):
        response = self.app.post('/post', data=u'оживлённым'.encode('utf-8'))
        self.assertEqual(json.loads(response.data.decode('utf-8'))['data'], u'оживлённым')

    def test_dump_request(self):
        response = self.app.get('/dump/request?a=1&b=%20x',
                                headers={'x-custom-thing': 'v1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Content-Type'),
                         'text/plain; charset=utf-8')
        self.assertTrue(response.data.startswith(
            b'GET /dump/request?a=1&b=%20x HTTP/1.1\r\nHost: localhost\r\n'),
            response.data)
        self.assertIn(b'\r\nX-Custom-Thing: v1\r\n', response.data)
        self.assertTrue(response.data.endswith(b'\r\n\r\n'))

    def test_dump_request_takes_any_method(self):
        for method in ('ARBITRARY-METHOD', 'PROPFIND', 'QUERY'):
            response = self.app.open('/dump/request', method=method)
            self.assertEqual(response.status_code, 200, method)
            self.assertTrue(response.data.startswith(
                method.encode() + b' /dump/request HTTP/1.1\r\n'), method)

    def test_dump_request_shows_each_part_type(self):
        data = (
            '--bound\r\n'
            'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
            'Content-Type: text/x-foo\r\n\r\nhello\r\n'
            '--bound--\r\n'
        )
        response = self.app.post(
            '/dump/request', data=data,
            content_type='multipart/form-data; boundary=bound')
        self.assertIn(b'\r\nContent-Type: multipart/form-data; boundary=bound\r\n',
                      response.data)
        self.assertTrue(response.data.endswith(data.encode()))
        self.assertIn(b'Content-Type: text/x-foo\r\n\r\nhello', response.data)

    def test_query_method_echoes_like_post(self):
        for path in ('/anything', '/anything/x', '/delay/0'):
            response = self.app.open(
                path + '?a=1', method='QUERY', data='{"k": "v"}',
                content_type='application/json')
            self.assertEqual(response.status_code, 200, path)
            echoed = json.loads(response.data.decode('utf-8'))
            self.assertEqual(echoed['data'], '{"k": "v"}', path)
            self.assertEqual(echoed['args'], {'a': '1'}, path)
        echoed = json.loads(self.app.open('/anything', method='QUERY').data.decode('utf-8'))
        self.assertEqual(echoed['method'], 'QUERY')
        response = self.app.open('/get', method='QUERY')
        self.assertEqual(response.status_code, 405)

    def test_post_repeated_file_field_echoes_every_file(self):
        data = (
            '--bound\r\n'
            'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
            'Content-Type: text/plain\r\n\r\nfirst\r\n'
            '--bound\r\n'
            'Content-Disposition: form-data; name="f"; filename="b.bin"\r\n'
            'Content-Type: application/x-thing\r\n\r\n\xff\xfe\r\n'
            '--bound--\r\n'
        ).encode('latin-1')
        response = self.app.post(
            '/post', data=data, content_type='multipart/form-data; boundary=bound')
        files = json.loads(response.data.decode('utf-8'))['files']
        self.assertEqual(files['f'], ['first', 'data:application/x-thing;base64,//4='])

    def test_post_file_with_missing_content_type_header(self):
        # I built up the form data manually here because I couldn't find a way
        # to convince the werkzeug test client to send files without the
        # content-type of the file set.
        data = '--bound\r\nContent-Disposition: form-data; name="media"; '
        data += 'filename="test.bin"\r\n\r\n\xa5\xc6\n--bound--\r\n'
        response = self.app.post(
            '/post',
            content_type='multipart/form-data; boundary=bound',
            data=data,
        )
        self.assertEqual(response.status_code, 200)

    """
    This is currently a sort of negative-test.
    We validate that when running Flask-only server that
    Transfer-Encoding: chunked requests are unsupported and
    we return 501 Not Implemented
    """
    @local_only('checks that the Flask development server refuses chunked bodies')
    def test_post_chunked(self):
        data = '{"animal":"dog"}'
        response = self.app.post(
            '/post',
            content_type='application/json',
            headers=[('Transfer-Encoding', 'chunked')],
            data=data,
        )
        self.assertEqual(response.status_code, 501)
        #self.assertEqual(response.status_code, 200)
        #self.assertEqual(json.loads(response.data.decode('utf-8'))['data'], '{"animal":"dog"}')
        #self.assertEqual(json.loads(response.data.decode('utf-8'))['json'], {"animal": "dog"})

    def test_nosniff_on_every_response(self):
        for path in ('/get', '/html', '/base64/SFRUUEJJTiBpcyBhd2Vzb21l',
                     '/status/404', '/nope'):
            response = self.app.get(path)
            self.assertEqual(
                response.headers.get_all('X-Content-Type-Options'), ['nosniff'],
                path)

    def test_cookies_are_secure_behind_a_tls_proxy(self):
        https_requests = (
            {'X-Forwarded-Proto': 'https'},
            {'X-Forwarded-Protocol': 'https'},
            {'X-Forwarded-Ssl': 'on'},
        )
        for headers in https_requests:
            for path in ('/cookies/set?k=v', '/cookies/set/k/v',
                         '/cookies/delete?k', '/digest-auth/auth/user/passwd'):
                response = self.app.get(path, headers=headers)
                cookies = response.headers.get_all('Set-Cookie')
                self.assertTrue(cookies, path)
                for cookie in cookies:
                    self.assertIn('; Secure', cookie, (path, headers))
        for path in ('/cookies/set?k=v', '/cookies/delete?k',
                     '/digest-auth/auth/user/passwd'):
            response = self.app.get(path, headers={'X-Forwarded-Proto': 'http'})
            for cookie in response.headers.get_all('Set-Cookie'):
                self.assertNotIn('Secure', cookie, path)

    def test_set_cors_headers_after_request(self):
        response = self.app.get('/get')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), '*'
        )

    def test_set_cors_credentials_headers_after_auth_request(self):
        response = self.app.get('/basic-auth/foo/bar')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Credentials'), 'true'
        )

    def test_set_cors_headers_after_request_with_request_origin(self):
        response = self.app.get('/get', headers={'Origin': 'origin'})
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), 'origin'
        )

    def test_set_cors_headers_with_options_verb(self):
        response = self.app.open('/get', method='OPTIONS')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), '*'
        )
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Credentials'), 'true'
        )
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Methods'),
            'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        )
        self.assertEqual(
            response.headers.get('Access-Control-Max-Age'), '3600'
        )
        # FIXME should we add any extra headers?
        self.assertNotIn(
            'Access-Control-Allow-Headers', response.headers
        )
    def test_set_cors_allow_headers(self):
        response = self.app.open('/get', method='OPTIONS', headers={'Access-Control-Request-Headers': 'X-Test-Header'})
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Headers'), 'X-Test-Header'
        )

    def test_headers(self):
        headers = {
            "Accept": "*/*",
            "Host": "localhost:1234",
            "User-Agent": "curl/7.54.0",
            "Via": "bar"
        }
        response = self.app.get('/headers', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue({'Accept', 'Host', 'User-Agent'}.issubset(set(response.json['headers'].keys())))
        self.assertNotIn('Via', response.json)

    def test_show_env_is_documented(self):
        home = self.app.get('/').data.decode('utf-8')
        self.assertIn('<h2>Proxy headers</h2>', home)
        self.assertIn('/headers?show_env=1', home)
        spec = json.loads(self.app.get('/spec.json').data.decode('utf-8'))
        for path in ('/get', '/headers'):
            names = [p['name'] for p in spec['paths'][path]['get'].get('parameters', [])]
            self.assertIn('show_env', names, path)

    FIXED_CONTENT_PATHS = (
        '/json', '/xml', '/html', '/robots.txt', '/deny', '/encoding/utf8',
        '/image', '/image/png', '/image/jpeg', '/image/webp', '/image/svg',
    )

    def test_fixed_content_takes_a_status(self):
        for path in self.FIXED_CONTENT_PATHS:
            normal = self.app.get(path)
            self.assertEqual(normal.status_code, 200, path)
            for status in (200, 201, 404, 500, 503, 599):
                response = self.app.get('%s?status=%d' % (path, status))
                self.assertEqual(response.status_code, status, path)
                self.assertEqual(response.data, normal.data, path)
                self.assertEqual(response.headers['Content-Type'],
                                 normal.headers['Content-Type'], path)
            head = self.app.head(path + '?status=500')
            self.assertEqual(head.status_code, 500, path)
            self.assertEqual(head.data, b'', path)

    def test_fixed_content_refuses_other_statuses(self):
        for path in self.FIXED_CONTENT_PATHS:
            normal = self.app.get(path).data
            refusal = None
            for value in ('100', '101', '199', '204', '205', '300', '301',
                          '302', '304', '307', '399', '0', '600', '-200',
                          '+500', '0500', '500%20', '5e2', 'abc', '',
                          '%ZZ', '500%', '99999999999999999999'):
                response = self.app.get('%s?status=%s' % (path, value))
                self.assertEqual(response.status_code, 400, (path, value))
                self.assertEqual(response.headers['Content-Type'],
                                 'text/plain; charset=utf-8')
                # one fixed answer for every refusal: the value is not repeated
                refusal = refusal or response.data
                self.assertEqual(response.data, refusal, (path, value))
                self.assertNotEqual(response.data, normal)

    def test_fixed_content_status_leaves_a_406_alone(self):
        response = self.app.get('/image?status=500',
                                headers={'Accept': 'text/plain'})
        self.assertEqual(response.status_code, 406)

    def test_response_headers_takes_a_status(self):
        response = self.app.get('/response-headers?status=503&Retry-After=5')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers['Retry-After'], '5')
        self.assertNotIn('Status', response.headers)
        self.assertNotIn('status', json.loads(response.data.decode('utf-8')))
        self.assertEqual(
            self.app.get('/response-headers?status=401&WWW-Authenticate=x'
                         ).status_code, 401)
        # another spelling is an ordinary header
        other = self.app.get('/response-headers?Status=503')
        self.assertEqual(other.status_code, 200)
        self.assertEqual(other.headers['Status'], '503')
        # no status: nothing changes
        self.assertEqual(self.app.get('/response-headers?a=b').status_code, 200)

    def test_response_headers_refuses_a_bad_status(self):
        for query in ('status=204', 'status=205', 'status=301', 'status=100',
                      'status=abc', 'status=', 'status=%ZZ', 'status=0500',
                      'status=500&status=503', 'status=600'):
            response = self.app.get('/response-headers?' + query)
            self.assertEqual(response.status_code, 400, query)
            self.assertEqual(response.headers['Content-Type'],
                             'text/plain; charset=utf-8')
            self.assertNotIn(b'500', response.data, query)
            self.assertNotIn(b'abc', response.data, query)
        # never a redirect: Location and Refresh are refused with a status
        for query in ('status=302&Location=/x', 'status=200&location=/x',
                      'status=200&Refresh=0;url=/x', 'status=200&REFRESH=1'):
            response = self.app.get('/response-headers?' + query)
            self.assertEqual(response.status_code, 400, query)
            self.assertNotIn('Location', response.headers)
        # without a status Location is still allowed
        self.assertEqual(
            self.app.get('/response-headers?Location=/x').headers['Location'],
            '/x')
        # the Content-Type rules still apply
        self.assertEqual(
            self.app.get('/response-headers?status=503&Content-Type=text/html'
                         ).status_code, 400)

    def test_headers_show_env(self):
        headers = {
            "Accept": "*/*",
            "Host": "localhost:1234",
            "User-Agent": "curl/7.54.0",
            "Via": "bar"
        }
        response = self.app.get('/headers?show_env=true', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue({'Accept', 'Host', 'User-Agent', 'Via'}.issubset(set(response.json['headers'].keys())))

    def test_user_agent(self):
        response = self.app.get(
            '/user-agent', headers={'User-Agent': 'test'}
        )
        self.assertIn('test', response.data.decode('utf-8'))
        self.assertEqual(response.status_code, 200)

    def test_gzip(self):
        response = self.app.get('/gzip')
        self.assertEqual(response.status_code, 200)

    def test_brotli(self):
        response = self.app.get('/brotli')
        self.assertEqual(response.status_code, 200)

    def test_zstd(self):
        from httpbin import filters
        if filters._zstd is None:
            self.skipTest('no zstd support in this Python')
        response = self.app.get('/zstd', headers={'User-Agent': 'test'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Content-Encoding'], 'zstd')
        self.assertEqual(response.headers['Content-Length'], str(len(response.data)))
        body = json.loads(filters._zstd.decompress(response.data))
        self.assertTrue(body['zstd'])
        self.assertEqual(body['headers']['User-Agent'], 'test')
        self.assertEqual(body['method'], 'GET')

    @local_only('simulates a Python without zstd in the in-process app')
    def test_zstd_without_support_says_so(self):
        from httpbin import filters
        saved, filters._zstd = filters._zstd, None
        try:
            response = self.app.get('/zstd')
        finally:
            filters._zstd = saved
        self.assertEqual(response.status_code, 501)

    def test_bearer_auth(self):
        token = 'abcd1234'
        response = self.app.get(
            '/bearer',
            headers={'Authorization': 'Bearer ' + token}
        )
        self.assertEqual(response.status_code, 200)
        assert json.loads(response.data.decode('utf-8'))['token'] == token

    def test_bearer_auth_with_wrong_authorization_type(self):
        """Sending an non-Bearer Authorization header to /bearer should return a 401"""
        auth_headers = (
            ('Authorization', 'Basic 1234abcd'),
            ('Authorization', ''),
            ('',  '')
        )
        for header in auth_headers:
            response = self.app.get(
                '/bearer',
                headers={header[0]: header[1]}
            )
            self.assertEqual(response.status_code, 401)

    def test_bearer_auth_with_missing_token(self):
        """Sending an 'Authorization: Bearer' header with no token to /bearer should return a 401"""
        response = self.app.get(
            '/bearer',
            headers={'Authorization': 'Bearer'}
        )
        self.assertEqual(response.status_code, 401)

    def test_digest_auth_with_wrong_password(self):
        auth_header = 'Digest username="user",realm="wrong",nonce="wrong",uri="/digest-auth/user/passwd/MD5",response="wrong",opaque="wrong"'
        response = self.app.get(
            '/digest-auth/auth/user/passwd/MD5',
            environ_base={
                # httpbin's digest auth implementation uses the remote addr to
                # build the nonce
                'REMOTE_ADDR': '127.0.0.1',
            },
            headers={
                'Authorization': auth_header,
            }
        )
        self.assertTrue('Digest' in response.headers.get('WWW-Authenticate'))
        self.assertEqual(response.status_code, 401)

    def test_digest_auth(self):
        """Test different combinations of digest auth parameters"""
        username = 'user'
        password = 'passwd'
        for qop in None, 'auth', 'auth-int',:
            for algorithm in None, 'MD5', 'SHA-256', 'SHA-512':
                for body in None, b'', b'request payload':
                    for stale_after in (None, 1, 4) if algorithm else (None,) :
                        self._test_digest_auth(username, password, qop, algorithm, body, stale_after)

    def test_digest_auth_with_wrong_authorization_type(self):
        """Sending an non-digest Authorization header to /digest-auth should return a 401"""
        auth_headers = (
            ('Authorization', 'Basic 1234abcd'),
            ('Authorization', ''),
            ('',  '')
        )
        for header in auth_headers:
            response = self.app.get(
                '/digest-auth/auth/myname/mysecret',
                headers={header[0]: header[1]}
            )
            self.assertEqual(response.status_code, 401)

    def test_digest_auth_with_incomplete_credentials(self):
        """A Digest header missing required parameters should return a 401"""
        response = self.app.get(
            '/digest-auth/auth/myname/mysecret',
            headers={'Authorization': 'Digest username="myname"'}
        )
        self.assertEqual(response.status_code, 401)

    def test_digest_auth_challenge_header(self):
        response = self.app.get('/digest-auth/auth/myname/mysecret/SHA-256')
        header = response.headers.get('WWW-Authenticate')
        self.assertRegex(
            header,
            r'^Digest realm="me@kennethreitz.com", nonce="[0-9a-f]{64}", '
            r'qop="auth", opaque="[0-9a-f]{64}", algorithm=SHA-256, stale=FALSE$'
        )

    def _test_digest_auth(self, username, password, qop, algorithm=None, body=None, stale_after=None):
        uri = self._digest_auth_create_uri(username, password, qop, algorithm, stale_after)

        unauthorized_response = self._test_digest_auth_first_challenge(uri)

        header = unauthorized_response.headers.get('WWW-Authenticate')

        authorized_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri, body)
        self.assertEqual(authorized_response.status_code, 200)

        if None == stale_after :
            return

        # test stale after scenerio
        self._digest_auth_stale_after_check(header, username, password, uri, body, qop, stale_after)

    def _test_digest_auth_first_challenge(self, uri):
        unauthorized_response = self.app.get(
            uri,
            environ_base={
                # digest auth uses the remote addr to build the nonce
                'REMOTE_ADDR': '127.0.0.1',
            }
        )
        # make sure it returns a 401
        self.assertEqual(unauthorized_response.status_code, 401)
        return unauthorized_response

    def _digest_auth_create_uri(self, username, password, qop, algorithm, stale_after):
        uri = '/digest-auth/{0}/{1}/{2}'.format(qop or 'wrong-qop', username, password)
        if algorithm:
            uri += '/' + algorithm
        if stale_after:
            uri += '/{0}'.format(stale_after)
        return uri

    def _digest_auth_stale_after_check(self, header, username, password, uri, body, qop, stale_after):
        for nc in range(2, stale_after + 1):
            authorized_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri, \
                                                                              body, nc)
            self.assertEqual(authorized_response.status_code, 200)
        stale_response, nonce = self._test_digest_response_for_auth_request(header, username, password, qop, uri, \
                                                                     body, stale_after + 1)
        self.assertEqual(stale_response.status_code, 401)
        header = stale_response.headers.get('WWW-Authenticate')
        self.assertIn('stale=TRUE', header)

    def _test_digest_response_for_auth_request(self, header, username, password, qop, uri, body, nc=1, nonce=None):
        auth_type, auth_info = header.split(None, 1)
        self.assertEqual(auth_type, 'Digest')

        d = parse_dict_header(auth_info)

        nonce = nonce or d['nonce']
        realm = d['realm']
        opaque = d['opaque']
        if qop :
            self.assertIn(qop, [x.strip() for x in d['qop'].split(',')], 'Challenge should contains expected qop')
        algorithm = d['algorithm']

        cnonce, nc = (_hash(os.urandom(10), "MD5"), '{:08}'.format(nc)) if qop in ('auth', 'auth-int') else (None, None)

        auth_header = _make_digest_auth_header(
            username, password, 'GET', uri, nonce, realm, opaque, algorithm, qop, cnonce, nc, body)

        # make second request
        return self.app.get(
            uri,
            environ_base={
                # httpbin's digest auth implementation uses the remote addr to
                # build the nonce
                'REMOTE_ADDR': '127.0.0.1',
            },
            headers={
                'Authorization': auth_header,
            },
            data=body
        ), nonce

    def test_digest_auth_wrong_user(self):
        """The right password under another username must not authenticate."""
        for qop in None, 'auth', 'auth-int':
            uri = self._digest_auth_create_uri('user', 'passwd', qop, 'MD5', None)
            header = self._test_digest_auth_first_challenge(uri).headers.get(
                'WWW-Authenticate')
            response, _ = self._test_digest_response_for_auth_request(
                header, 'someone-else', 'passwd', qop, uri, None)
            self.assertEqual(response.status_code, 401, qop)

    def test_auth_routes_take_every_method(self):
        """Basic, hidden basic, bearer and digest auth answer GET, POST, PUT,
        DELETE, PATCH and TRACE alike; other methods are refused."""
        basic = 'Basic ' + base64.b64encode(b'user:passwd').decode()
        wrong = 'Basic ' + base64.b64encode(b'user:wrong').decode()
        for method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE'):
            def call(path, auth=None, body=None):
                headers = {'Authorization': auth} if auth else {}
                return self.app.open(
                    path, method=method, headers=headers, data=body,
                    environ_base={'REMOTE_ADDR': '127.0.0.1'})

            self.assertEqual(call('/basic-auth/user/passwd', basic).status_code, 200, method)
            self.assertEqual(call('/basic-auth/user/passwd', wrong).status_code, 401, method)
            self.assertEqual(call('/hidden-basic-auth/user/passwd', basic).status_code, 200, method)
            self.assertEqual(call('/hidden-basic-auth/user/passwd', wrong).status_code, 404, method)
            self.assertEqual(call('/bearer', 'Bearer token').status_code, 200, method)
            self.assertEqual(call('/bearer').status_code, 401, method)

            for qop, body in (('auth', None), ('auth-int', b'payload'), ('none', None)):
                uri = '/digest-auth/%s/user/passwd' % qop
                challenge = call(uri)
                self.assertEqual(challenge.status_code, 401, (method, qop))
                header = challenge.headers['WWW-Authenticate']
                d = parse_dict_header(header.split(None, 1)[1])
                real_qop = None if qop == 'none' else qop
                cnonce, nc = (('abcdef', '00000001') if real_qop else (None, None))
                auth = _make_digest_auth_header(
                    'user', 'passwd', method, uri, d['nonce'], d['realm'],
                    d['opaque'], d['algorithm'], real_qop, cnonce, nc, body)
                self.assertEqual(call(uri, auth, body).status_code, 200, (method, qop))

        for path in ('/basic-auth/user/passwd', '/bearer', '/digest-auth/auth/user/passwd'):
            self.assertEqual(self.app.open(path, method='PROPFIND').status_code, 405)

    def test_digest_auth_none_sends_an_rfc_2069_challenge(self):
        uri = '/digest-auth/none/user/passwd'
        header = self._test_digest_auth_first_challenge(uri).headers['WWW-Authenticate']
        self.assertNotIn('qop', header)
        response, _ = self._test_digest_response_for_auth_request(
            header, 'user', 'passwd', None, uri, None)
        self.assertEqual(response.status_code, 200)

    def test_digest_auth_wrong_pass(self):
        """Test different combinations of digest auth parameters"""
        username = 'user'
        password = 'passwd'
        for qop in None, 'auth', 'auth-int',:
            for algorithm in None, 'MD5', 'SHA-256', 'SHA-512':
                for body in None, b'', b'request payload':
                    self._test_digest_auth_wrong_pass(username, password, qop, algorithm, body, 3)

    def _test_digest_auth_wrong_pass(self, username, password, qop, algorithm=None, body=None, stale_after=None):
        uri = self._digest_auth_create_uri(username, password, qop, algorithm, stale_after)
        unauthorized_response = self._test_digest_auth_first_challenge(uri)

        header = unauthorized_response.headers.get('WWW-Authenticate')

        wrong_pass_response, nonce = self._test_digest_response_for_auth_request(header, username, "wrongPassword", qop, uri, body)
        self.assertEqual(wrong_pass_response.status_code, 401)
        header = wrong_pass_response.headers.get('WWW-Authenticate')
        self.assertNotIn('stale=TRUE', header)

        reused_nonce_response, nonce =  self._test_digest_response_for_auth_request(header, username, password, qop, uri, \
                                                                              body, nonce=nonce)
        self.assertEqual(reused_nonce_response.status_code, 401)
        header = reused_nonce_response.headers.get('WWW-Authenticate')
        self.assertIn('stale=TRUE', header)

    def test_set_cookies_with_attributes(self):
        response = self.app.get(
            '/cookies/set?a=1&attr[HttpOnly]=true&attr[path]=/x&attr[SameSite]=lax'
            '&attr[Secure]=1&b=2')
        self.assertEqual(response.headers.getlist('Set-Cookie'), [
            'a=1; Secure; HttpOnly; Path=/x; SameSite=Lax',
            'b=2; Secure; HttpOnly; Path=/x; SameSite=Lax',
        ])

    def test_delete_cookies_with_attributes(self):
        response = self.app.get('/cookies/delete?a&attr[Path]=/x')
        cookie = response.headers['Set-Cookie']
        self.assertTrue(cookie.startswith('a=; '))
        self.assertIn('Max-Age=0', cookie)
        self.assertTrue(cookie.endswith('; Path=/x'))

    def test_cookie_domain_must_be_the_request_host(self):
        host = urlparse(self.app.get('/get').json['url']).hostname
        response = self.app.get('/cookies/set?a=1&attr[Domain]=.' + host.upper())
        self.assertEqual(response.status_code, 302)
        self.assertIn('Domain=', response.headers['Set-Cookie'])
        for path in '/cookies/set', '/cookies/delete':
            response = self.app.get(path + '?a=1&attr[Domain]=example.com')
            self.assertEqual(response.status_code, 400)
            self.assertNotIn('Set-Cookie', response.headers)
            self.assertTrue(response.json['detail'].startswith(
                'attr[Domain] must be the request host'))

    def test_delay_with_an_invalid_duration_is_a_400(self):
        for value in ('abc', '_1', '1_', '1..2', '0x1', '1e', '0b1', '1e400', '%201',
                      '-1', '-0.5'):
            response = self.app.get('/delay/' + value)
            self.assertEqual(response.status_code, 400, value)
            error = json.loads(response.data.decode('utf-8'))
            self.assertTrue(error['detail'].startswith('invalid duration: '))

    def test_delay_accepts_the_number_forms_httpbin_org_accepts(self):
        for value in ('0', '0.1', '.1', '1e-1', '+0.1', '-0', '1.', '0_0',
                      '0.0_1', '0x1p-3'):
            response = self.app.get('/delay/' + value)
            self.assertEqual(response.status_code, 200, value)

    def test_drip(self):
        response = self.app.get('/drip?numbytes=400&duration=2&delay=1')
        self.assertEqual(response.content_length, 400)
        self.assertEqual(len(self.get_data(response)), 400)
        self.assertEqual(response.status_code, 200)

    def test_delay_reports_server_timing(self):
        response = self.app.get('/delay/0.0019')
        self.assertEqual(response.headers['Server-Timing'],
                         'initial_delay;dur=1.00;desc="initial delay"')

    def test_drip_reports_server_timing(self):
        response = self.app.get('/drip?numbytes=7&duration=0.2&delay=0.1')
        self.assertEqual(len(self.get_data(response)), 7)
        self.assertEqual(response.headers['Server-Timing'], ', '.join([
            'total_duration;dur=300.00;desc="total request duration"',
            'initial_delay;dur=100.00;desc="initial delay"',
            'write_duration;dur=200.00;desc="duration of writes after initial delay"',
            'pause_per_write;dur=33.33;desc="computed pause between writes"',
        ]))

    def test_drip_with_no_duration_writes_every_byte(self):
        response = self.app.get('/drip?numbytes=5&duration=0')
        self.assertEqual(self.get_data(response), b'*****')
        self.assertIn('pause_per_write;dur=0.00;',
                      response.headers['Server-Timing'])

    def test_drip_chunked_has_no_content_length(self):
        for flag in ('1', 'true', 'TRUE'):
            response = self.app.get('/drip?numbytes=5&duration=0&chunked=' + flag)
            self.assertNotIn('Content-Length', response.headers, flag)
            self.assertEqual(self.get_data(response), b'*****')
        response = self.app.get('/drip?numbytes=5&duration=0&chunked=yes')
        self.assertEqual(response.headers['Content-Length'], '5')

    def test_drip_with_invalid_numbytes(self):
        for bad_num in -1, 0:
            uri = '/drip?numbytes={0}&duration=2&delay=1'.format(bad_num)
            response = self.app.get(uri)
            self.assertEqual(response.status_code, 400)

    def test_drip_with_custom_code(self):
        response = self.app.get('/drip?numbytes=400&duration=2&code=500')
        self.assertEqual(response.content_length, 400)
        self.assertEqual(len(self.get_data(response)), 400)
        self.assertEqual(response.status_code, 500)

    def test_get_bytes(self):
        response = self.app.get('/bytes/1024')
        self.assertEqual(len(self.get_data(response)), 1024)
        self.assertEqual(response.status_code, 200)

    @local_only("runs the in-process app under wsgiref's validator")
    def test_get_bytes_gives_the_server_bytes(self):
        # WSGI servers such as gunicorn refuse a bytearray body chunk.
        client = Client(wsgiref.validate.validator(httpbin.app))
        response = client.get('/bytes/10?seed=0')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 10)

    def test_bytes_with_seed(self):
        response = self.app.get('/bytes/10?seed=0')
        self.assertEqual(
            response.data, b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
        )

    def test_stream_bytes(self):
        response = self.app.get('/stream-bytes/1024')
        self.assertEqual(len(self.get_data(response)), 1024)
        self.assertEqual(response.status_code, 200)

    def test_stream_bytes_with_seed(self):
        response = self.app.get('/stream-bytes/10?seed=0')
        self.assertEqual(
            response.data, b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
        )

    def test_delete_endpoint_returns_body(self):
        response = self.app.delete(
            '/delete',
            data={'name': 'kevin'},
            content_type='application/x-www-form-urlencoded'
        )
        form_data = json.loads(response.data.decode('utf-8'))['form']
        self.assertEqual(form_data, {'name': 'kevin'})

    def test_ascii_art_is_unchanged(self):
        # SHA-256 of the teapot and the /deny art as they were served before
        # their source became raw strings
        teapot = self.app.get('/status/418').data
        self.assertEqual(sha256(teapot).hexdigest(),
                         '30a535fafb69211b175e917fcbed68bb055368f1509535a7bb986f2dd961bb53')
        self.assertIn(b'    \\_;`"---"`|//\n', teapot)
        deny = self.app.get('/deny').data
        self.assertEqual(sha256(deny).hexdigest(),
                         '2c1ec08e80c781038b99dcdf0d8b1f568d949a599ed2dfd9fa44c7e5d7c77505')

    def test_methods__to_status_endpoint(self):
        methods = [
            'GET',
            'HEAD',
            'POST',
            'PUT',
            'DELETE',
            'PATCH',
            'TRACE',
        ]
        for m in methods:
            response = self.app.open(path='/status/418', method=m)
            self.assertEqual(response.status_code, 418)

    def test_status_endpoint_keeps_content_type(self):
        response = self.app.get(path='/status/418')
        self.assertEqual(
            response.headers.get('Content-Type'), 'text/html; charset=utf-8'
        )
        self.assertEqual(
            response.headers.get('x-more-info'), 'http://tools.ietf.org/html/rfc2324'
        )

    def test_status_body_is_opt_in(self):
        response = self.app.get('/status/500?body=1')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.headers.get('Content-Type'), 'text/plain')
        self.assertEqual(response.data, b'500 Internal Server Error\n')
        self.assertIn('Accept', response.headers.get_all('Vary'))
        response = self.app.get('/status/404?body=true',
                                headers={'Accept': 'application/json'})
        self.assertEqual(response.headers.get('Content-Type'), 'application/json')
        self.assertEqual(json.loads(response.data.decode('utf-8')),
                         {'code': 404, 'description': 'Not Found'})
        response = self.app.get('/status/401?body=1')
        self.assertEqual(response.headers.get('WWW-Authenticate'),
                         'Basic realm="Fake Realm"')
        self.assertEqual(response.data, b'401 Unauthorized\n')
        for value in ('0', 'false', 'yes', ''):
            response = self.app.get('/status/500?body=' + value)
            self.assertEqual(response.data, b'', value)
        for code in (204, 304):
            response = self.app.get('/status/%d?body=1' % code)
            self.assertEqual(response.data, b'', code)
        response = self.app.get('/status/418?body=1')
        self.assertIn(b'teapot', response.data)

    def test_status_ignores_a_trailing_path(self):
        for method in ('GET', 'POST'):
            response = self.app.open('/status/201/foo/bar', method=method)
            self.assertEqual(response.status_code, 201, method)
        response = self.app.get('/status/abc/foo')
        self.assertEqual(response.status_code, 400)

    def test_image_accepts_any_type(self):
        for accept in ('*/*', 'text/html,image/avif,*/*;q=0.8'):
            response = self.app.get('/image', headers={'Accept': accept})
            self.assertEqual(response.status_code, 200, accept)
            self.assertEqual(response.headers.get('Content-Type'), 'image/png')
        for accept in ('*/*;q=0', 'image/avif', 'text/html'):
            response = self.app.get('/image', headers={'Accept': accept})
            self.assertEqual(response.status_code, 406, accept)

    def test_status_endpoint_invalid_code(self):
        response = self.app.get(path='/status/4!9')
        self.assertEqual(response.status_code, 400)

    def test_status_endpoint_invalid_codes(self):
        response = self.app.get(path='/status/200,402,foo')
        self.assertEqual(response.status_code, 400)

    @local_only("compares the served Swagger UI with this checkout's copy")
    def test_swagger_ui_is_the_vendored_copy(self):
        static_dir = os.path.join(
            os.path.dirname(httpbin.__file__), 'static', 'swagger-ui'
        )
        with open(os.path.join(static_dir, 'swagger-ui-bundle.js'), 'rb') as f:
            vendored = f.read()
        response = self.app.get('/flasgger_static/swagger-ui-bundle.js')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, vendored)
        response.close()
        response = self.app.get('/flasgger_static/lib/jquery.min.js')
        self.assertEqual(response.status_code, 404)

    @local_only("checks this checkout's vendored files")
    def test_swagger_ui_licence_notices_are_vendored(self):
        static_dir = os.path.join('httpbin', 'static', 'swagger-ui')
        for bundle in ('swagger-ui-bundle.js', 'swagger-ui-standalone-preset.js'):
            with open(os.path.join(static_dir, bundle)) as f:
                first_line = f.readline()
            notice = first_line.rsplit(' ', 2)[-2]
            self.assertEqual(notice, bundle + '.LICENSE.txt')
            self.assertTrue(os.path.exists(os.path.join(static_dir, notice)), notice)

    def test_swagger_ui_ignores_query_config(self):
        response = self.app.get('/')
        self.assertIn(b'queryConfigEnabled: false', response.data)

    def test_xml_endpoint(self):
        response = self.app.get(path='/xml')
        self.assertEqual(
            response.headers.get('Content-Type'), 'application/xml'
        )

    def test_x_forwarded_proto(self):
        response = self.app.get(path='/get', headers={
            'X-Forwarded-Proto':'https'
        })
        assert json.loads(response.data.decode('utf-8'))['url'].startswith('https://')

    def test_redirect_n_higher_than_1(self):
        response = self.app.get('/redirect/5')
        self.assertEqual(
            response.headers.get('Location'), '/relative-redirect/4'
        )

    def test_redirect_to_location_is_a_utf8_percent_encoded_uri(self):
        for target, location in (
            (u'/\u5c71', '/%E5%B1%B1'),
            ('/%E5%B1%B1', '/%E5%B1%B1'),
            (u'/x?q=\u5c71', '/x?q=%E5%B1%B1'),
        ):
            response = self.app.get(
                '/redirect-to?' + urlencode({'url': target.encode('utf-8')}))
            self.assertEqual(response.status_code, 302, target)
            self.assertEqual(response.headers.get('Location'), location)

    def test_redirect_to_refuses_internal_targets(self):
        blocked = (
            'http://169.254.1.1/path',
            'http://169.254.1.2/path',
            'http://2852039166/',
            'http://0xa9fea9fe/',
            'http://0251.0376.0251.0376/',
            'http://127.1/',
            'http://127.0x.0.1/',
            'http://127.0X.0.1/',
            'http://0x7f.0x.0x.1/',
            'http://[::ffff:a9fe:a9fe]/',
            'http://[::1]:8080/',
            'http://[fd00:ec2::254]/',
            'http://[64:ff9b::a9fe:a9fe]/',
            'http://[::127.0.0.1]/',
            'http://[::a9fe:a9fe]/',
            'http://[fec0::1]/',
            'http://[64:ff9b:1::a9fe:a9fe]/',
            'http://localhost:6379/',
            'http://LOCALHOST./',
            'http://foo.localhost/',
            'http://service.internal/',
            'http://ip-10-0-0-1.ec2.internal/',
            'http://10.0.0.1.nip.io/',
            '//10.0.0.1/admin',
            'http://100.64.0.1/',
            'http://0.0.0.0/',
            'file:///etc/passwd',
            'gopher://other.example/',
            'javascript:alert(1)',
            'data:text/html,hello',
            'https:other.example',
            '/\\other.example',
            'http://other.example/\r\nX-Test: 1',
            'http://other.example/ x',
            '/a b',
            u'http://b\xfccher.example/\u5c71',
            u'http://\uff11\uff12\uff17.\uff10.\uff10.\uff11/',
            'http://%31%32%37.0.0.1/',
            'http:///169.254.1.1/path',
            '///127.0.0.1/admin',
            'http:/169.254.1.1/',
            'https:/other.example/',
        )
        for target in blocked:
            response = self.app.get('/redirect-to?' + urlencode({'url': target}))
            self.assertIn(response.status_code, (400, 403), target)
            self.assertIsNone(response.headers.get('Location'), target)

    def test_redirect_to_refusal_format(self):
        response = self.app.get(
            '/redirect-to?url=http%3A%2F%2F169.254.1.1%2F')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers.get('Content-Type'), 'text/plain; charset=utf-8')
        self.assertEqual(
            response.data,
            b'Forbidden redirect target: redirect target is an internal address\n')

    def test_redirect_to_allows_public_targets(self):
        for target in (
            'http://example.com/',
            'https://example.com/path?q=1',
            '//example.com/',
            '/get',
            'http://8.8.8.8/',
            'http://[2001:4860:4860::8888]/',
        ):
            response = self.app.get('/redirect-to?' + urlencode({'url': target}))
            self.assertEqual(response.status_code, 302, target)
            self.assertEqual(response.headers.get('Location'), target)

    def test_redirect_to_needs_an_absolute_or_root_relative_target(self):
        for target in ('get', '?x=1', '#frag'):
            response = self.app.get('/redirect-to?' + urlencode({'url': target}))
            self.assertEqual(response.status_code, 403, target)
            self.assertIsNone(response.headers.get('Location'), target)

    @local_only('changes the in-process app configuration')
    def test_redirect_to_allowlist(self):
        httpbin.app.config['ALLOWED_REDIRECT_DOMAINS'] = frozenset(
            ['example.com', 'example.org'])
        try:
            for target in ('http://example.com/x', '//example.org/', '/get'):
                response = self.app.get(
                    '/redirect-to?' + urlencode({'url': target}))
                self.assertEqual(response.status_code, 302, target)
            for target in ('http://other.example/', 'http://EXAMPLE.com/', 'get'):
                response = self.app.get(
                    '/redirect-to?' + urlencode({'url': target}))
                self.assertEqual(response.status_code, 403, target)
                self.assertIsNone(response.headers.get('Location'), target)
            self.assertEqual(
                response.data,
                b'Forbidden redirect URL. Please be careful with this link.\n\n'
                b'Allowed redirect destinations:\n- example.com\n- example.org')
        finally:
            httpbin.app.config['ALLOWED_REDIRECT_DOMAINS'] = frozenset()

    def test_redirect_to_reads_a_posted_form(self):
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            response = self.app.open(
                '/redirect-to', method=method,
                data={'url': '/get', 'status_code': '307'})
            self.assertEqual(response.status_code, 307, method)
            self.assertEqual(response.headers.get('Location'), '/get', method)
        data = (
            '--bound\r\n'
            'Content-Disposition: form-data; name="f"; filename="url.txt"\r\n\r\n/x\r\n'
            '--bound\r\n'
            'Content-Disposition: form-data; name="URL"\r\n\r\n/anything\r\n'
            '--bound--\r\n'
        )
        response = self.app.post(
            '/redirect-to', data=data,
            content_type='multipart/form-data; boundary=bound')
        self.assertEqual(response.headers.get('Location'), '/anything')
        response = self.app.post('/redirect-to?url=/get', data={'url': '/anything'})
        self.assertEqual(response.headers.get('Location'), '/get')
        response = self.app.post('/redirect-to', data='{"url": "/get"}',
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_redirect_to_without_a_url_is_a_400(self):
        for path in ('/redirect-to', '/redirect-to?url=', '/redirect-to?status_code=307'):
            response = self.app.get(path)
            self.assertEqual(response.status_code, 400, path)
            error = json.loads(response.data.decode('utf-8'))
            self.assertEqual(error['detail'], 'missing required query parameter: url')
        response = self.app.post('/redirect-to', data={'other': '1'})
        self.assertEqual(response.status_code, 400)

    def test_redirect_to_with_an_invalid_status_code_is_a_400(self):
        for value in ('abc', '3.0', '1_0', '99999999999999999999'):
            response = self.app.get(
                '/redirect-to?' + urlencode({'url': '/get', 'status_code': value}))
            self.assertEqual(response.status_code, 400, value)
            self.assertIsNone(response.headers.get('Location'))
        for value, status in (('', 302), ('200', 302), ('+307', 307)):
            response = self.app.get(
                '/redirect-to?' + urlencode({'url': '/get', 'status_code': value}))
            self.assertEqual(response.status_code, status, value)

    def test_redirect_to_post(self):
        response = self.app.post('/redirect-to?url=/post&status_code=307',
                                 data=b'\x01\x02\x03\x81\x82\x83',
                                 content_type='application/octet-stream')
        self.assertEqual(response.status_code, 307)
        self.assertEqual(
            response.headers.get('Location'), '/post'
        )

    def test_redirect_absolute_param_n_higher_than_1(self):
        response = self.app.get('/redirect/5?absolute=true')
        self.assertEqual(
            response.headers.get('Location'), 'http://localhost/absolute-redirect/4'
        )

    def test_redirect_n_equals_to_1(self):
        response = self.app.get('/redirect/1')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get('Location'), '/get'
        )

    def test_relative_redirect_n_equals_to_1(self):
        response = self.app.get('/relative-redirect/1')
        self.assertEqual(
            response.headers.get('Location'), '/get'
        )

    def test_relative_redirect_n_higher_than_1(self):
        response = self.app.get('/relative-redirect/7')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get('Location'), '/relative-redirect/6'
        )

    def test_absolute_redirect_n_higher_than_1(self):
        response = self.app.get('/absolute-redirect/5')
        self.assertEqual(
            response.headers.get('Location'), 'http://localhost/absolute-redirect/4'
        )

    def test_absolute_redirect_n_equals_to_1(self):
        response = self.app.get('/absolute-redirect/1')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers.get('Location'), 'http://localhost/get'
        )

    def test_request_range(self):
        response1 = self.app.get('/range/1234')
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response1.headers.get('ETag'), 'range1234')
        self.assertEqual(response1.headers.get('Content-range'), 'bytes 0-1233/1234')
        self.assertEqual(response1.headers.get('Accept-ranges'), 'bytes')
        self.assertEqual(len(self.get_data(response1)), 1234)

        response2 = self.app.get('/range/1234')
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response2.headers.get('ETag'), 'range1234')
        self.assertEqual(self.get_data(response1), self.get_data(response2))

    def test_request_range_with_parameters(self):
        response = self.app.get(
            '/range/100?duration=1.5&chunk_size=5',
            headers={ 'Range': 'bytes=10-24' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range100')
        self.assertEqual(response.headers.get('Content-range'), 'bytes 10-24/100')
        self.assertEqual(response.headers.get('Accept-ranges'), 'bytes')
        self.assertEqual(response.headers.get('Content-Length'), '15')
        self.assertEqual(self.get_data(response), 'klmnopqrstuvwxy'.encode('utf8'))

    def test_request_range_first_15_bytes(self):
        response = self.app.get(
            '/range/1000',
            headers={ 'Range': 'bytes=0-15' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range1000')
        self.assertEqual(self.get_data(response), 'abcdefghijklmnop'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 0-15/1000')

    def test_request_range_open_ended_last_6_bytes(self):
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=20-' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(self.get_data(response), 'uvwxyz'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 20-25/26')
        self.assertEqual(response.headers.get('Content-Length'), '6')

    def test_request_range_suffix(self):
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=-5' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(self.get_data(response), 'vwxyz'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 21-25/26')
        self.assertEqual(response.headers.get('Content-Length'), '5')

    def test_request_out_of_bounds(self):
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=10-5',
            }
        )

        self.assertEqual(response.status_code, 416)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(len(self.get_data(response)), 0)
        self.assertEqual(response.headers.get('Content-range'), 'bytes */26')
        self.assertEqual(response.headers.get('Content-Length'), '0')

        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=32-40',
            }
        )

        self.assertEqual(response.status_code, 416)
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=0-40',
            }
        )
        self.assertEqual(response.status_code, 416)

    def test_etag_if_none_match_matches(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': 'abc' }
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_none_match_matches_list(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': '"123", "abc"' }
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_none_match_matches_star(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': '*' }
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_none_match_w_prefix(self):
        response = self.app.get(
            '/etag/c3piozzzz',
            headers={ 'If-None-Match': 'W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"' }
        )
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response.headers.get('ETag'), 'c3piozzzz')

    def test_etag_if_none_match_has_no_match(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': '123' }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_matches(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': 'abc' }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_matches_list(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': '"123", "abc"' }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_matches_star(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': '*' }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_etag_if_match_has_no_match(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': '123' }
        )
        self.assertEqual(response.status_code, 412)
        self.assertNotIn('ETag', response.headers)

    def test_etag_with_no_headers(self):
        response = self.app.get(
            '/etag/abc'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('ETag'), 'abc')

    def test_parse_multi_value_header(self):
        self.assertEqual(parse_multi_value_header('xyzzy'), [ "xyzzy" ])
        self.assertEqual(parse_multi_value_header('"xyzzy"'), [ "xyzzy" ])
        self.assertEqual(parse_multi_value_header('W/"xyzzy"'), [ "xyzzy" ])
        self.assertEqual(parse_multi_value_header('"xyzzy", "r2d2xxxx", "c3piozzzz"'), [ "xyzzy", "r2d2xxxx", "c3piozzzz" ])
        self.assertEqual(parse_multi_value_header('W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"'), [ "xyzzy", "r2d2xxxx", "c3piozzzz" ])
        self.assertEqual(parse_multi_value_header('*'), [ "*" ])

if __name__ == '__main__':
    unittest.main()
