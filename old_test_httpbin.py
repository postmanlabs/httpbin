#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import base64
import unittest
import contextlib
import six
import json
from werkzeug.http import parse_dict_header
from hashlib import md5, sha256, sha512
from six import BytesIO

import httpbin
from httpbin.helpers import parse_multi_value_header


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


class HttpbinTestCase(unittest.TestCase):
    """Httpbin tests"""

    def setUp(self):
        httpbin.app.debug = True
        self.app = httpbin.app.test_client()

    def get_data(self, response):
        if 'get_data' in dir(response):
            return response.get_data()
        else:
            return response.data

    def test_tracking_disabled(self):
        with _setenv('HTTPBIN_TRACKING', None):
            response = self.app.get('/')
        data = response.data.decode('utf-8')
        self.assertNotIn('google-analytics', data)
        self.assertNotIn('perfectaudience', data)

    def test_tracking_enabled(self):
        with _setenv('HTTPBIN_TRACKING', '1'):
            response = self.app.get('/')
        data = response.data.decode('utf-8')
        self.assertIn('perfectaudience', data)

    def test_etag_if_none_match_matches(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': 'abc' }
        )
        self.assertEqual(response.status_code, 304)

    def test_etag_if_none_match_matches_list(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': '"123", "abc"' }
        )
        self.assertEqual(response.status_code, 304)

    def test_etag_if_none_match_matches_star(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': '*' }
        )
        self.assertEqual(response.status_code, 304)

    def test_etag_if_none_match_w_prefix(self):
        response = self.app.get(
            '/etag/c3piozzzz',
            headers={ 'If-None-Match': 'W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"' }
        )
        self.assertEqual(response.status_code, 304)

    def test_etag_if_none_match_has_no_match(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-None-Match': '123' }
        )
        self.assertEqual(response.status_code, 200)

    def test_etag_if_match_matches(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': 'abc' }
        )
        self.assertEqual(response.status_code, 200)

    def test_etag_if_match_matches_list(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': '"123", "abc"' }
        )
        self.assertEqual(response.status_code, 200)

    def test_etag_if_match_matches_star(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': '*' }
        )
        self.assertEqual(response.status_code, 200)

    def test_etag_if_match_has_no_match(self):
        response = self.app.get(
            '/etag/abc',
            headers={ 'If-Match': '123' }
        )
        self.assertEqual(response.status_code, 412)

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
