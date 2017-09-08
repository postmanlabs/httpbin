# -*- coding: utf-8 -*-

import base64
import urllib.parse

import requests
from wsgiadapter import WSGIAdapter

import httpbin

base_url = "http://localhost"

# TODO: Add tests for MethodNotAllowed, NotFound


def get_session():
    session = requests.session()
    session.mount(base_url, WSGIAdapter(app=httpbin.app))
    return session


def url(path):
    if isinstance(path, str):
        return urllib.parse.urljoin(base_url, path)
    elif isinstance(path, bytes):
        return urllib.parse.urljoin(base_url.encode('utf-8'), path)


def _string_to_base64(string):
    """Encodes string to utf-8 and then base64"""
    utf8_encoded = string.encode('utf-8')
    return base64.urlsafe_b64encode(utf8_encoded)


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
        print(response.headers.get('animal'))
        assert response.headers.get('animal') == 'dog, cat'
        print("json", response.json())
        assert response.json()['animal'] == ['dog', 'cat']

    for verb in supported_verbs:
        yield do_test, verb


def test_get():
    session = get_session()
    response = session.get(url('/get'), headers={'User-Agent': 'test'})
    assert response.status_code == 200
    data = response.json()
    assert data['args'] == {}
    # assert data['headers']['Host'] == 'localhost'
    assert data['headers']['Content-Type'] == 'text/plain'
    assert data['headers']['Content-Length'] == '0'
    assert data['headers']['User-Agent'] == 'test'
    assert data['url'] == 'http://localhost/get'
    assert response.content.endswith(b'\n')


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
    assert response.headers.get('Access-Control-Allow-Headers') == 'X-Test-Header'


def test_user_agent():
    session = get_session()
    response = session.get(url('/user-agent'), headers={'User-Agent': 'test'})
    assert b'test' in response.content
    assert response.status_code == 200
