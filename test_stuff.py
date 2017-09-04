# -*- coding: utf-8 -*-

import urllib.parse

import requests
from wsgiadapter import WSGIAdapter

import httpbin

base_url = "http://localhost"


def get_session():
    session = requests.session()
    session.mount(base_url, WSGIAdapter(app=httpbin.app))
    return session


def url(path):
    return urllib.parse.urljoin(base_url, path)


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
