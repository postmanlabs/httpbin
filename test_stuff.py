# -*- coding: utf-8 -*-

import requests
from wsgiadapter import WSGIAdapter

import httpbin


def get_session():
    session = requests.session()
    session.mount('http://localhost', WSGIAdapter(app=httpbin.app))
    return session


def test_response_headers_simple():
    supported_verbs = ['get', 'post']

    def do_test(verb):
        session = get_session()
        method = getattr(session, verb)
        response = method('http://localhost/response-headers?animal=dog')
        assert response.status_code == 200
        assert response.headers.get('animal') == 'dog'
        assert response.json()['animal'] == 'dog'

    for verb in supported_verbs:
        yield do_test, verb
