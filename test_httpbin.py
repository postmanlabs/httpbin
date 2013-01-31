#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import unittest

import httpbin


def _string_to_base64(string):
    """Encodes string to utf-8 and then base64"""
    utf8_encoded = string.encode('utf-8')
    return base64.urlsafe_b64encode(utf8_encoded)


class HttpbinTestCase(unittest.TestCase):
    """Httpbin tests"""

    def setUp(self):
        self.app = httpbin.app.test_client()

    def test_base64(self):
        greeting = u'Здравствуй, мир!'
        b64_encoded = _string_to_base64(greeting)
        response = self.app.get('/base64/{0}'.format(b64_encoded))
        content = response.data.decode('utf-8')
        self.assertEquals(greeting, content)

    def test_post_binary(self):
        response = self.app.post('/post',
                                 data='\x01\x02\x03\x81\x82\x83',
                                 content_type='application/octet-stream')
        self.assertEquals(response.status_code, 200)

    def test_post_file_text(self):
        with open('httpbin/core.py') as f:
            response = self.app.post('/post', data={"file": f})
        self.assertEquals(response.status_code, 200)

    def test_post_file_binary(self):
        with open('httpbin/core.pyc') as f:
            response = self.app.post('/post', data={"file": f})
        self.assertEquals(response.status_code, 200)

    def test_set_cors_headers_after_request(self):
        response = self.app.get('/get')
        self.assertEquals(response.headers.get('Access-Control-Allow-Origin'), '*')

    def test_set_cors_headers_after_request_with_request_origin(self):
        response = self.app.get('/get', headers={'Origin': 'origin'})
        self.assertEquals(response.headers.get('Access-Control-Allow-Origin'), 'origin')

    def test_set_cors_headers_with_options_verb(self):
        response = self.app.open('/get', method='OPTIONS')
        self.assertEquals(response.headers.get('Access-Control-Allow-Origin'), '*')
        self.assertEquals(response.headers.get('Access-Control-Allow-Credentials'), 'true')
        self.assertEquals(response.headers.get('Access-Control-Allow-Methods'), 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
        self.assertEquals(response.headers.get('Access-Control-Max-Age'), '3600')
        self.assertNotIn('Access-Control-Allow-Headers', response.headers)  # FIXME should we add any extra headers?


if __name__ == '__main__':
    unittest.main()
