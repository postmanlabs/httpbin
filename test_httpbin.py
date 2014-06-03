#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import unittest
from werkzeug.http import parse_dict_header
from hashlib import md5

import httpbin


def _string_to_base64(string):
    """Encodes string to utf-8 and then base64"""
    utf8_encoded = string.encode('utf-8')
    return base64.urlsafe_b64encode(utf8_encoded)


class HttpbinTestCase(unittest.TestCase):
    """Httpbin tests"""

    def setUp(self):
        httpbin.app.debug = True
        self.app = httpbin.app.test_client()

    def test_base64(self):
        greeting = u'Здравствуй, мир!'
        b64_encoded = _string_to_base64(greeting)
        response = self.app.get(b'/base64/' + b64_encoded)
        content = response.data.decode('utf-8')
        self.assertEqual(greeting, content)

    def test_post_binary(self):
        response = self.app.post('/post',
                                 data=b'\x01\x02\x03\x81\x82\x83',
                                 content_type='application/octet-stream')
        self.assertEqual(response.status_code, 200)

    def test_post_file_text(self):
        with open('httpbin/core.py') as f:
            response = self.app.post('/post', data={"file": f.read()})
        self.assertEqual(response.status_code, 200)

    def test_post_file_binary(self):
        with open('httpbin/core.pyc', 'rb') as f:
            response = self.app.post('/post', data={"file": f.read()})
        self.assertEqual(response.status_code, 200)

    def test_set_cors_headers_after_request(self):
        response = self.app.get('/get')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_set_cors_headers_after_request_with_request_origin(self):
        response = self.app.get('/get', headers={'Origin': 'origin'})
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), 'origin')

    def test_set_cors_headers_with_options_verb(self):
        response = self.app.open('/get', method='OPTIONS')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), '*')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Credentials'), 'true')
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Methods'),
            'GET, POST, PUT, DELETE, PATCH, OPTIONS')
        self.assertEqual(
            response.headers.get('Access-Control-Max-Age'), '3600')

        # FIXME should we add any extra headers?
        self.assertNotIn(
            'Access-Control-Allow-Headers', response.headers)

    def test_user_agent(self):
        response = self.app.get(
            '/user-agent', headers={'User-Agent': 'test'})
        self.assertIn('test', response.data.decode('utf-8'))
        self.assertEqual(response.status_code, 200)

    def test_gzip(self):
        response = self.app.get('/gzip')
        self.assertEqual(response.status_code, 200)

    def test_digest_auth(self):
        # make first request
        unauthorized_response = self.app.get(
            '/digest-auth/auth/user/passwd',
            environ_base={
                'REMOTE_ADDR': '127.0.0.1',  # digest auth uses the
                                             # remote addr to build the nonce
            })

        # make sure it returns a 401
        self.assertEqual(unauthorized_response.status_code, 401)
        header = unauthorized_response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)

        # Begin crappy digest-auth implementation
        d = parse_dict_header(auth_info)
        a1 = b'user:' + d['realm'].encode('utf-8') + b':passwd'
        ha1 = md5(a1).hexdigest().encode('utf-8')
        a2 = b'GET:/digest-auth/auth/user/passwd'
        ha2 = md5(a2).hexdigest().encode('utf-8')
        a3 = ha1 + b':' + d['nonce'].encode('utf-8') + b':' + ha2
        auth_response = md5(a3).hexdigest()
        auth_header = 'Digest username="user",realm="' + \
            d['realm'] + \
            '",nonce="' + \
            d['nonce'] + \
            '",uri="/digest-auth/auth/user/passwd",response="' + \
            auth_response + \
            '",opaque="' + \
            d['opaque'] + '"'

        # make second request
        authorized_response = self.app.get(
            '/digest-auth/auth/user/passwd',
            environ_base={
                'REMOTE_ADDR': '127.0.0.1',  # httpbin's digest auth
                                             # implementation uses the remote
                                             # addr to build the nonce
            },
            headers={
                'Authorization': auth_header,
            }
        )

        # done!
        self.assertEqual(authorized_response.status_code, 200)

    def test_drip(self):
        response = self.app.get('/drip?numbytes=400&duration=2&delay=1')
        self.assertEqual(len(response.get_data()), 400)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
