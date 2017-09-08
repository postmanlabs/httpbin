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
