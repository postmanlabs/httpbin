# -*- coding: utf-8 -*-

import base64
from hashlib import md5, sha256, sha512
import os
import contextlib
import json

import six
from six.moves.urllib.parse import urljoin

import requests
from wsgiadapter import WSGIAdapter
from werkzeug.http import parse_dict_header, parse_options_header

import httpbin

base_url = "http://localhost"

# TODO: Add tests for MethodNotAllowed, NotFound


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


class Session(requests.Session):
    def __repr__(self):
        return "<Session>"


def get_session():
    session = Session()
    session.mount(base_url, WSGIAdapter(app=httpbin.app))
    return session


def url(path):
    if isinstance(path, str):
        return urljoin(base_url, path)
    elif isinstance(path, bytes):
        return urljoin(base_url.encode('utf-8'), path)


def get_mime_type(request):
    content_type = request.headers.get('Content-Type')
    if content_type:
        return parse_options_header(content_type)[0]


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

    auth_header_template = 'Digest username="{0}", response="{1}", uri="{2}", nonce="{3}"'
    auth_header = auth_header_template.format(username, auth_response, uri, nonce)

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


def test_response_headers_simple():
    supported_verbs = ['get', 'post']

    def do_test(verb):
        session = get_session()
        method = getattr(session, verb)
        response = method(url('/response-headers?animal=dog'))
        assert response.status_code == 200
        assert response.headers.get('animal') == 'dog'
        assert response.json()['animal'] == 'dog'

    for verb in supported_verbs:
        yield do_test, verb


def test_response_headers_multi():
    supported_verbs = ['get', 'post']

    def do_test(verb):
        session = get_session()
        method = getattr(session, verb)
        response = method(url('/response-headers?animal=dog&animal=cat'))
        assert response.status_code == 200
        assert response.headers.get('animal') == 'dog, cat'
        assert response.json()['animal'] == ['dog', 'cat']

    for verb in supported_verbs:
        yield do_test, verb


def test_anything():
    session = get_session()
    response = session.get(url('/anything'))
    assert response.status_code == 200
    response = session.get(url('/anything/foo/bar'))
    assert response.status_code == 200
    data = response.json()
    assert data['args'] == {}
    # assert data['headers']['Host'] == 'localhost'
    assert data['headers']['Content-Type'] == 'text/plain'
    assert data['headers']['Content-Length'] == '0'
    assert data['url'] == 'http://localhost/anything/foo/bar'
    assert data['method'] == 'GET'
    assert response.content.endswith(b'\n')


def test_base64():
    session = get_session()
    greeting = u'Здравствуй, мир!'
    b64_encoded = _string_to_base64(greeting)
    response = session.get(url(b'/base64/' + b64_encoded))
    content = response.content.decode('utf-8')
    assert greeting == content


def test_post_binary():
    session = get_session()
    response = session.post(
        url('/post'),
        data=b'\x01\x02\x03\x81\x82\x83',
        headers=dict(
            content_type='application/octet-stream'))
    assert response.status_code == 200


def test_post_body_text():
    session = get_session()
    with open('httpbin/core.py') as f:
        response = session.post(url('/post'), data={"file": f.read()})
    assert response.status_code == 200


def test_post_body_binary():
    session = get_session()
    response = session.post(
        url('/post'),
        data={"file": b'\x01\x02\x03\x81\x82\x83'})
    assert response.status_code == 200


def test_post_body_unicode():
    session = get_session()
    response = session.post(url('/post'), data=u'оживлённым'.encode('utf-8'))
    assert response.json()['data'] == u'оживлённым'


def test_post_file_with_missing_content_type_header():
    # I built up the form data manually here because I couldn't find a way
    # to convince the werkzeug test client to send files without the
    # content-type of the file set.
    session = get_session()
    data = '--bound\r\nContent-Disposition: form-data; name="media"; '
    data += 'filename="test.bin"\r\n\r\n\xa5\xc6\n--bound--\r\n'
    response = session.post(
        url('/post'),
        headers=dict(
            content_type='multipart/form-data; boundary=bound'),
        data=data)
    assert response.status_code == 200


def test_set_cors_headers_after_request():
    session = get_session()
    response = session.get(url('/get'))
    assert response.headers.get('Access-Control-Allow-Origin') == '*'


def test_set_cors_credentials_headers_after_auth_request():
    session = get_session()
    response = session.get(url('/basic-auth/foo/bar'))
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'


def test_set_cors_headers_after_request_with_request_origin():
    session = get_session()
    response = session.get(url('/get'), headers={'Origin': 'origin'})
    assert response.headers.get('Access-Control-Allow-Origin') == 'origin'


def test_set_cors_headers_with_options_verb():
    session = get_session()
    response = session.options(url('/get'))
    assert response.headers.get('Access-Control-Allow-Origin') == '*'
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
    assert response.headers.get('Access-Control-Allow-Methods') == (
        'GET, POST, PUT, DELETE, PATCH, OPTIONS')
    assert response.headers.get('Access-Control-Max-Age'), '3600'

    # FIXME should we add any extra headers?
    assert 'Access-Control-Allow-Headers' not in response.headers


def test_set_cors_allow_headers():
    session = get_session()
    response = session.options(
        url('/get'),
        headers={'Access-Control-Request-Headers': 'X-Test-Header'})
    acah = response.headers.get('Access-Control-Allow-Headers')
    assert acah == 'X-Test-Header'


def test_user_agent():
    session = get_session()
    response = session.get(url('/user-agent'), headers={'User-Agent': 'test'})
    assert b'test' in response.content
    assert response.status_code == 200

# Encodings
# TODO: Add proper tests

def test_gzip():
    session = get_session()
    response = session.get(url('/gzip'))
    assert response.status_code == 200


def test_brotli():
    session = get_session()
    response = session.get(url('/brotli'))
    assert response.status_code == 200


def test_deflate():
    session = get_session()
    response = session.get(url('/deflate'))
    assert response.status_code == 200

def test_utf8():
    session = get_session()
    response = session.get(url('/encoding/utf8'))
    assert response.status_code == 200

# Auth

def test_basic_auth_fail_no_try():
    session = get_session()
    response = session.get(url('/basic-auth/mr-flibble/Password1'))
    assert response.status_code == 401


def test_basic_auth_fail_try():
    session = get_session()
    auth = base64.b64encode(b"mr-hacker:password").decode('utf-8')
    headers = {"Authorization": "Basic {0}".format(auth)}
    response = session.get(
        url('/basic-auth/mr-flibble/Password1'),
        headers=headers)
    assert response.status_code == 401


def test_basic_auth_success():
    session = get_session()
    auth = base64.b64encode(b"mr-flibble:Password1").decode('utf-8')
    headers = {"Authorization": "Basic {0}".format(auth)}
    response = session.get(
        url('/basic-auth/mr-flibble/Password1'),
        headers=headers)
    assert response.status_code == 200


def test_hidden_basic_auth_fail_no_try():
    session = get_session()
    response = session.get(url('/hidden-basic-auth/mr-flibble/Password1'))
    assert response.status_code == 404


def test_hidden_basic_auth_fail_try():
    session = get_session()
    auth = base64.b64encode(b"mr-hacker:password").decode('utf-8')
    headers = {"Authorization": "Basic {0}".format(auth)}
    response = session.get(
        url('/hidden-basic-auth/mr-flibble/Password1'),
        headers=headers)
    assert response.status_code == 404


def test_hidden_basic_auth_success():
    session = get_session()
    auth = base64.b64encode(b"mr-flibble:Password1").decode('utf-8')
    headers = {"Authorization": "Basic {0}".format(auth)}
    response = session.get(
        url('/hidden-basic-auth/mr-flibble/Password1'),
        headers=headers)
    assert response.status_code == 200


def test_digest_auth_with_wrong_password():
    auth_header = 'Digest username="user",realm="wrong",nonce="wrong",uri="/digest-auth/user/passwd/MD5",response="wrong",opaque="wrong"'
    session = get_session()
    response = session.get(
        url('/digest-auth/auth/user/passwd/MD5'),
        headers={'Authorization': auth_header})
    assert 'Digest' in response.headers.get('WWW-Authenticate')
    assert response.status_code == 401


def _test_digest_auth(username, password, qop, algorithm=None, body=None, stale_after=None):
    session = get_session()
    uri = _digest_auth_create_uri(username, password, qop, algorithm, stale_after)
    unauthorized_response = _test_digest_auth_first_challenge(session, uri)
    header = unauthorized_response.headers.get('WWW-Authenticate')
    authorized_response, nonce = _test_digest_response_for_auth_request(
        session, header, username, password, qop, uri, body)
    assert authorized_response.status_code == 200

    if stale_after is None:
        return

    # test stale after scenerio
    _digest_auth_stale_after_check(
        session, header, username, password, uri, body, qop, stale_after)


def _test_digest_auth_first_challenge(session, path):
    unauthorized_response = session.get(url(path))
    # make sure it returns a 401
    assert unauthorized_response.status_code == 401
    return unauthorized_response


def _digest_auth_create_uri(username, password, qop, algorithm, stale_after):
    uri = '/digest-auth/{0}/{1}/{2}'.format(qop or 'wrong-qop', username, password)
    if algorithm:
        uri += '/' + algorithm
    if stale_after:
        uri += '/{0}'.format(stale_after)
    return uri


def _digest_auth_stale_after_check(session, header, username, password, uri, body, qop, stale_after):
    for nc in range(2, stale_after + 1):
        authorized_response, nonce = _test_digest_response_for_auth_request(
            session, header, username, password, qop, uri, body, nc)
        assert authorized_response.status_code == 200
    stale_response, nonce = _test_digest_response_for_auth_request(
        session, header, username, password, qop, uri, body, stale_after + 1)
    assert stale_response.status_code == 401
    header = stale_response.headers.get('WWW-Authenticate')
    assert 'stale=TRUE' in header


def _test_digest_response_for_auth_request(session, header, username, password, qop, uri, body, nc=1, nonce=None):
    auth_type, auth_info = header.split(None, 1)
    assert auth_type == 'Digest'

    d = parse_dict_header(auth_info)

    nonce = nonce or d['nonce']
    realm = d['realm']
    opaque = d['opaque']
    algorithm = d['algorithm']

    if qop:
        expected = [x.strip() for x in d['qop'].split(',')]
        assert qop in expected, 'Challenge should contains expected qop'

    if qop in ('auth', 'auth-int'):
        cnonce, nc = (_hash(os.urandom(10), "MD5"), '{0:08}'.format(nc))
    else:
        cnonce, nc = (None, None)

    auth_header = _make_digest_auth_header(
        username, password, 'GET', uri, nonce, realm, opaque, algorithm, qop, cnonce, nc, body)

    # make second request
    response = session.get(
        url(uri),
        headers={'Authorization': auth_header},
        data=body)
    return response, nonce


def test_digest_auth():
    username = 'user'
    password = 'passwd'
    for qop in None, 'auth', 'auth-int':
        for algorithm in None, 'MD5', 'SHA-256', 'SHA-512':
            for body in None, b'', b'request payload':
                for stale_after in (None, 1, 4) if algorithm else (None,):
                    yield _test_digest_auth, username, password, qop, algorithm, body, stale_after


def test_digest_auth_wrong_pass():
    username = 'user'
    password = 'passwd'
    for qop in None, 'auth', 'auth-int':
        for algorithm in None, 'MD5', 'SHA-256', 'SHA-512':
            for body in None, b'', b'request payload':
                yield _test_digest_auth_wrong_pass, username, password, qop, algorithm, body, 3


def _test_digest_auth_wrong_pass(username, password, qop, algorithm=None, body=None, stale_after=None):
    session = get_session()
    uri = _digest_auth_create_uri(username, password, qop, algorithm, stale_after)
    unauthorized_response = _test_digest_auth_first_challenge(session, uri)
    header = unauthorized_response.headers.get('WWW-Authenticate')
    wrong_pass_response, nonce = _test_digest_response_for_auth_request(
        session, header, username, "wrongPassword", qop, uri, body)
    assert wrong_pass_response.status_code == 401
    header = wrong_pass_response.headers.get('WWW-Authenticate')
    assert 'stale=TRUE' not in header

    reused_nonce_response, nonce = _test_digest_response_for_auth_request(
        session, header, username, password, qop, uri, body, nonce=nonce)
    assert reused_nonce_response.status_code == 401
    header = reused_nonce_response.headers.get('WWW-Authenticate')
    assert 'stale=TRUE' in header

# Utilities

def test_delay_response():
    session = get_session()
    response = session.get(url("/delay/0.1"))
    assert response.status_code == 200
    assert "0.1" in response.json()['url']


def test_cache_miss():
    session = get_session()
    response = session.get(url("/cache"))
    assert response.status_code == 200


def test_cache_modified():
    session = get_session()
    response = session.get(
        url("/cache"),
        headers={"If-Modified-Since": "flibble"})
    assert response.status_code == 304


def test_cache_none_match():
    session = get_session()
    response = session.get(
        url("/cache"),
        headers={"If-None-Match": "flibble"})
    assert response.status_code == 304


def test_cache_control():
    session = get_session()
    response = session.get(url("/cache/5"))
    assert response.headers["Cache-Control"] == "public, max-age=5"


def test_cache_control_404():
    session = get_session()
    response = session.get(url("/cache/five"))
    assert response.status_code == 404


def test_drip():
    session = get_session()
    response = session.get(url('/drip?numbytes=400&duration=0.2&delay=0.1'))
    assert response.status_code == 200
    assert int(response.headers['Content-Length']) == 400
    assert len(response.content) == 400


def test_drip_with_invalid_numbytes():
    session = get_session()
    for bad_num in -1, 0:
        uri = '/drip?numbytes={0}&duration=0.2&delay=0.1'.format(bad_num)
        response = session.get(url(uri))
        assert response.status_code == 400


def test_drip_with_custom_code():
    session = get_session()
    response = session.get(url('/drip?numbytes=400&duration=0.1&code=500'))
    assert response.status_code == 500
    assert int(response.headers['Content-Length']) == 400
    assert len(response.content) == 400


def test_stream_messages():
    session = get_session()
    response = session.get(url('/stream/10'))
    assert response.status_code == 200
    lines = response.content.decode("utf-8").strip().split("\n")
    assert len(lines) == 10
    data = [json.loads(line) for line in lines]
    for datum in data:
        assert 'id' in datum
        assert datum['url'] == "http://localhost/stream/10"

def test_get_bytes():
    session = get_session()
    response = session.get(url('/bytes/1024'))
    assert len(response.content) == 1024
    assert response.status_code == 200


def test_bytes_with_seed():
    session = get_session()
    response = session.get(url('/bytes/10?seed=0'))
    # The RNG changed in python3, so even though we are
    # setting the seed, we can't expect the value to be the
    # same across both interpreters.
    if six.PY3:
        expected = b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
    else:
        expected = b'\xd8\xc2kB\x82g\xc8Mz\x95'
    assert response.status_code == 200
    assert response.content == expected


def test_stream_bytes():
    session = get_session()
    response = session.get(url('/stream-bytes/1024'))
    assert response.status_code == 200
    assert len(response.content) == 1024


def test_stream_bytes_with_seed():
    session = get_session()
    response = session.get(url('/stream-bytes/10?seed=0'))
    # The RNG changed in python3, so even though we are
    # setting the seed, we can't expect the value to be the
    # same across both interpreters.
    if six.PY3:
        expected = b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
    else:
        expected = b'\xd8\xc2kB\x82g\xc8Mz\x95'
    assert response.status_code == 200
    assert response.content == expected


def test_delete_endpoint_returns_body():
    session = get_session()
    response = session.delete(
        url('/delete'),
        data={'name': 'kevin'},
        headers = dict(
            content_type='application/x-www-form-urlencoded')
    )
    assert response.status_code == 200
    form_data = response.json()['form']
    assert form_data == {'name': 'kevin'}


def test_methods__to_status_endpoint():
    methods = [
        'GET',
        'HEAD',
        'POST',
        'PUT',
        'DELETE',
        'PATCH',
        # 'TRACE',
    ]
    for m in methods:
        session = get_session()
        response = getattr(session, m.lower())(url('/status/418'))
        assert response.status_code == 418


def test_status_endpoint_invalid_code():
    session = get_session()
    response = session.get(url('/status/4!9'))
    assert response.status_code == 400


def test_status_endpoint_invalid_codes():
    session = get_session()
    response = session.get(url('/status/200,402,foo'))
    assert response.status_code == 400


def test_xml_endpoint():
    session = get_session()
    response = session.get(url('/xml'))
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/xml'


def test_x_forwarded_proto():
    session = get_session()
    response = session.get(
        url('/get'),
        headers={'X-Forwarded-Proto':'https'})
    assert response.json()['url'].startswith('https://')


# Redirects

def test_redirect_n_higher_than_1():
    session = get_session()
    session.max_redirects = 6
    response = session.get(url('/redirect/5'), allow_redirects=False)
    assert response.headers.get('Location') == '/relative-redirect/4'


def test_redirect_to_post():
    session = get_session()
    response = session.post(
        url('/redirect-to?url=/post&status_code=307'),
        data=b'\x01\x02\x03\x81\x82\x83',
        headers={'Content-Type': 'application/octet-stream'},
        allow_redirects=False)
    assert response.status_code == 307
    assert response.headers.get('Location') == '/post'


def test_redirect_absolute_param_n_higher_than_1():
    session = get_session()
    response = session.get(url('/redirect/5?absolute=true'), allow_redirects=False)
    assert response.headers.get('Location') == 'http://localhost/absolute-redirect/4'


def test_redirect_n_equals_to_1():
    session = get_session()
    response = session.get(url('/redirect/1'), allow_redirects=False)
    assert response.status_code == 302
    assert response.headers.get('Location') == '/get'


def test_relative_redirect_n_equals_to_1():
    session = get_session()
    response = session.get(url('/relative-redirect/1'), allow_redirects=False)
    assert response.headers.get('Location') == '/get'


def test_relative_redirect_n_higher_than_1():
    session = get_session()
    response = session.get(url('/relative-redirect/7'), allow_redirects=False)
    assert response.status_code == 302
    assert response.headers.get('Location') == '/relative-redirect/6'


def test_absolute_redirect_n_higher_than_1():
    session = get_session()
    response = session.get(url('/absolute-redirect/5'), allow_redirects=False)
    assert response.headers.get('Location') == 'http://localhost/absolute-redirect/4'


def test_absolute_redirect_n_equals_to_1():
    session = get_session()
    response = session.get(url('/absolute-redirect/1'), allow_redirects=False)
    assert response.status_code == 302
    assert response.headers.get('Location') == 'http://localhost/get'


# Request ranges

def test_request_range():
    session = get_session()
    response1 = session.get(url('/range/1234'))
    assert response1.status_code == 200
    assert response1.headers.get('ETag') == 'range1234'
    assert response1.headers.get('Content-range') == 'bytes 0-1233/1234'
    assert response1.headers.get('Accept-ranges') == 'bytes'
    assert len(response1.content) == 1234

    response2 = session.get(url('/range/1234'))
    assert response2.status_code == 200
    assert response2.headers.get('ETag') == 'range1234'
    assert response1.content == response2.content


def test_request_range_with_parameters():
    session = get_session()
    response = session.get(
        url('/range/100?duration=1.5&chunk_size=5'),
        headers={'Range': 'bytes=10-24'})

    assert response.status_code == 206
    assert response.headers.get('ETag') == 'range100'
    assert response.headers.get('Content-range') == 'bytes 10-24/100'
    assert response.headers.get('Accept-ranges') == 'bytes'
    assert response.headers.get('Content-Length') == '15'
    assert response.content == 'klmnopqrstuvwxy'.encode('utf8')


def test_request_range_first_15_bytes():
    session = get_session()
    response = session.get(
        url('/range/1000'),
        headers={'Range': 'bytes=0-15'})

    assert response.status_code == 206
    assert response.headers.get('ETag') == 'range1000'
    assert response.content == 'abcdefghijklmnop'.encode('utf8')
    assert response.headers.get('Content-range') == 'bytes 0-15/1000'


def test_request_range_open_ended_last_6_bytes():
    session = get_session()
    response = session.get(
        url('/range/26'),
        headers={'Range': 'bytes=20-'})

    assert response.status_code == 206
    assert response.headers.get('ETag') == 'range26'
    assert response.content == 'uvwxyz'.encode('utf8')
    assert response.headers.get('Content-range') == 'bytes 20-25/26'
    assert response.headers.get('Content-Length') == '6'


def test_request_range_suffix():
    session = get_session()
    response = session.get(
        url('/range/26'),
        headers={'Range': 'bytes=-5'})

    assert response.status_code == 206
    assert response.headers.get('ETag') == 'range26'
    assert response.content == 'vwxyz'.encode('utf8')
    assert response.headers.get('Content-range') == 'bytes 21-25/26'
    assert response.headers.get('Content-Length') == '5'


def test_request_out_of_bounds():
    session = get_session()
    response = session.get(
        url('/range/26'),
        headers={'Range': 'bytes=10-5'})

    assert response.status_code == 416
    assert response.headers.get('ETag') == 'range26'
    assert len(response.content) == 0
    assert response.headers.get('Content-range') == 'bytes */26'
    assert response.headers.get('Content-Length') == '0'

    response = session.get(
        url('/range/26'),
        headers={'Range': 'bytes=32-40'})

    assert response.status_code == 416
    response = session.get(
        url('/range/26'),
        headers={'Range': 'bytes=0-40'})
    assert response.status_code == 416

# ETags


def test_etag_if_none_match_matches():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-None-Match': 'abc'}
    )
    assert response.status_code == 304

def test_etag_if_none_match_matches_list():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-None-Match': '"123", "abc"'}
    )
    assert response.status_code == 304

def test_etag_if_none_match_matches_star():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-None-Match': '*'}
    )
    assert response.status_code == 304

def test_etag_if_none_match_w_prefix():
    session = get_session()
    response = session.get(
        url('/etag/c3piozzzz'),
        headers={'If-None-Match': 'W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"'}
    )
    assert response.status_code == 304

def test_etag_if_none_match_has_no_match():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-None-Match': '123'}
    )
    assert response.status_code == 200

def test_etag_if_match_matches():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-Match': 'abc'}
    )
    assert response.status_code == 200

def test_etag_if_match_matches_list():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-Match': '"123", "abc"'}
    )
    assert response.status_code == 200

def test_etag_if_match_matches_star():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-Match': '*'}
    )
    assert response.status_code == 200

def test_etag_if_match_has_no_match():
    session = get_session()
    response = session.get(
        url('/etag/abc'),
        headers={'If-Match': '123'}
    )
    assert response.status_code == 412

def test_etag_with_no_headers():
    session = get_session()
    response = session.get(url('/etag/abc'))
    assert response.status_code == 200
    assert response.headers.get('ETag') == 'abc'


# Pages

def test_html_page():
    session = get_session()
    response = session.get(url('/html'))
    assert get_mime_type(response) == "text/html"
    assert b"<html>" in response.content


def test_robots_page():
    session = get_session()
    response = session.get(url('/robots.txt'))
    assert get_mime_type(response) == "text/plain"
    assert b"Disallow" in response.content


def test_deny_page():
    session = get_session()
    response = session.get(url('/deny'))
    assert get_mime_type(response) == "text/plain"
    assert b"YOU SHOULDN'T BE HERE" in response.content


def test_links_with_first_matching():
    session = get_session()
    response = session.get(url('/links/5/0'))
    content = response.content.decode()
    assert response.status_code == 200
    for i in range(5):
        assert str(i) in content
    assert len(response.content.split(b"<a href=")) == 5


def test_links_with_none_matching():
    session = get_session()
    response = session.get(url('/links/10/11'))
    content = response.content.decode()
    assert response.status_code == 200
    for i in range(10):
        assert str(i) in content
    assert len(response.content.split(b"<a href=")) == 11


def test_links_page():
    session = get_session()
    response = session.get(url('/links/10'))
    assert response.status_code == 200
    assert response.url == url("/links/10/0")


def test_forms_page():
    session = get_session()
    response = session.get(url('/forms/post'))
    assert response.status_code == 200
    assert b'''<form method="post"''' in response.content

# Info pages

def test_origin():
    session = get_session()
    response = session.get(
        url('/ip'),
        headers={'X-Forwarded-For': "flibble"})
    assert get_mime_type(response) == "application/json"
    expected = {'origin': "flibble"}
    assert response.json() == expected


def test_uuid():
    session = get_session()
    response = session.get(url('/uuid'))
    assert get_mime_type(response) == "application/json"
    assert len(response.json()['uuid']) == 36


def test_headers():
    session = get_session()
    response = session.get(
        url('/headers'),
        headers={'Flim-Flam': "flooble"})
    assert get_mime_type(response) == "application/json"
    assert response.json()['headers']['Flim-Flam'] == "flooble"


def test_cookies():
    session = get_session()
    response = session.get(
        url("/cookies"),
        headers={"Cookie": "foo=bar; __utmz=flibble"})
    assert response.json()['cookies'] == {'foo': 'bar'}


def test_set_cookie():
    session = get_session()
    response = session.get(
        url("/cookies/set/flibble/flamble"))
    assert response.json()['cookies'] == {'flibble': 'flamble'}


def test_set_cookies():
    session = get_session()
    response = session.get(
        url("/cookies/set?flooble=flumble&flim=flam&__utma=foo"))
    expected = {'flooble': 'flumble', 'flim': 'flam'}
    assert response.json()['cookies'] == expected

# TODO: FIXME
def test_delete_cookies():
    session = get_session()
    response = session.get(
        url("/cookies/set?flooble=flumble&flim=flam&__utma=foo"))
    expected = {'flooble': 'flumble', 'flim': 'flam'}
    assert response.json()['cookies'] == expected
    response = session.get(
        url("/cookies/delete?flooble=flumble"))
    expected = {'flim': 'flam'}
    assert response.json()['cookies'] == expected


# Methods

def test_methods():
    def do_passing_method(url_method, http_method):
        session = get_session()
        response = getattr(session, http_method)(
            url('/{0}'.format(url_method)), headers={'User-Agent': 'test'})
        assert response.status_code == 200
        data = response.json()
        assert data['args'] == {}
        # assert data['headers']['Host'] == 'localhost'
        assert data['headers']['Content-Type'] == 'text/plain'
        assert data['headers']['Content-Length'] == '0'
        assert data['headers']['User-Agent'] == 'test'
        assert data['url'] == 'http://localhost/{0}'.format(url_method)
        assert response.content.endswith(b'\n')

    def do_failing_method(url_method, http_method):
        session = get_session()
        response = getattr(session, http_method)(
            url('/{0}'.format(url_method)), headers={'User-Agent': 'test'})
        assert response.status_code == 405
        assert response.headers['Allow'] == url_method.upper()

    methods = set(('get', 'post', 'put', 'patch', 'delete'))
    for url_method in methods:
        for http_method in methods:
            if url_method == http_method:
                func = do_passing_method
            else:
                func = do_failing_method
            yield func, url_method, http_method

# Images

def test_images():
    cases = (
        ("webp", "image/webp"),
        ("svg", "image/svg+xml"),
        ("jpeg", "image/jpeg"),
        ("png", "image/png"),
    )

    def do_image_endpoint(mimetype):
        session = get_session()
        response = session.get(
            url("/image"),
            headers={'Accept': mimetype})
        assert response.status_code == 200
        assert response.headers['Content-Type'] == mimetype

    def do_image_type_endpoint(image_type, mimetype):
        session = get_session()
        response = session.get(url("/image/{0}".format(image_type)))
        assert response.status_code == 200
        assert response.headers['Content-Type'] == mimetype

    for image_type, mimetype in cases:
        yield do_image_endpoint, mimetype
        yield do_image_type_endpoint, image_type, mimetype

# Tracking

def test_tracking_disabled():
    session = get_session()
    with _setenv('HTTPBIN_TRACKING', None):
        response = session.get(url('/'))
    data = response.content.decode('utf-8')
    assert 'google-analytics' not in  data
    assert 'perfectaudience' not in data


def test_tracking_enabled():
    session = get_session()
    with _setenv('HTTPBIN_TRACKING', '1'):
        response = session.get(url('/'))
    data = response.content.decode('utf-8')
    assert 'perfectaudience' in data
