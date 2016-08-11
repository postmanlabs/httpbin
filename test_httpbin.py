#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import base64
import unittest
import contextlib
import six
import json
from werkzeug.http import parse_dict_header
from hashlib import md5
from six import BytesIO

import httpbin


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


class HttpbinTestCase(unittest.TestCase):
    """Httpbin tests"""

    def setUp(self):
        httpbin.app.debug = True
        self.app = httpbin.app.test_client()

    def test_response_headers_simple(self):
        response = self.app.get('/response-headers?animal=dog')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get_all('animal'), ['dog'])
        assert json.loads(response.data.decode('utf-8'))['animal'] == 'dog'

    def test_response_headers_multi(self):
        response = self.app.get('/response-headers?animal=dog&animal=cat')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get_all('animal'), ['dog', 'cat'])
        assert json.loads(response.data.decode('utf-8'))['animal'] == ['dog', 'cat']

    def test_get(self):
        response = self.app.get('/get', headers={'User-Agent': 'test'})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['args'], {})
        self.assertEqual(data['headers']['Host'], 'localhost')
        self.assertEqual(data['headers']['Content-Type'], '')
        self.assertEqual(data['headers']['Content-Length'], '0')
        self.assertEqual(data['headers']['User-Agent'], 'test')
        self.assertEqual(data['origin'], None)
        self.assertEqual(data['url'], 'http://localhost/get')
        self.assertTrue(response.data.endswith(b'\n'))

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
    def test_user_agent(self):
        response = self.app.get(
            '/user-agent', headers={'User-Agent': 'test'}
        )
        self.assertIn('test', response.data.decode('utf-8'))
        self.assertEqual(response.status_code, 200)

    def test_gzip(self):
        response = self.app.get('/gzip')
        self.assertEqual(response.status_code, 200)

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
        assert 'Digest' in response.headers.get('WWW-Authenticate')

    def test_digest_auth(self):
        # make first request
        unauthorized_response = self.app.get(
            '/digest-auth/auth/user/passwd/MD5',
            environ_base={
                # digest auth uses the remote addr to build the nonce
                'REMOTE_ADDR': '127.0.0.1',
            }
        )
        # make sure it returns a 401
        self.assertEqual(unauthorized_response.status_code, 401)
        header = unauthorized_response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)

        # Begin crappy digest-auth implementation
        d = parse_dict_header(auth_info)
        a1 = b'user:' + d['realm'].encode('utf-8') + b':passwd'
        ha1 = md5(a1).hexdigest().encode('utf-8')
        a2 = b'GET:/digest-auth/auth/user/passwd/MD5'
        ha2 = md5(a2).hexdigest().encode('utf-8')
        a3 = ha1 + b':' + d['nonce'].encode('utf-8') + b':' + ha2
        auth_response = md5(a3).hexdigest()
        auth_header = 'Digest username="user",realm="' + \
            d['realm'] + \
            '",nonce="' + \
            d['nonce'] + \
            '",uri="/digest-auth/auth/user/passwd/MD5",response="' + \
            auth_response + \
            '",opaque="' + \
            d['opaque'] + '"'

        # make second request
        authorized_response = self.app.get(
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

        # done!
        self.assertEqual(authorized_response.status_code, 200)

    def test_drip(self):
        response = self.app.get('/drip?numbytes=400&duration=2&delay=1')
        self.assertEqual(response.content_length, 400)
        self.assertEqual(len(response.get_data()), 400)
        self.assertEqual(response.status_code, 200)

    def test_drip_with_custom_code(self):
        response = self.app.get('/drip?numbytes=400&duration=2&code=500')
        self.assertEqual(response.content_length, 400)
        self.assertEqual(len(response.get_data()), 400)
        self.assertEqual(response.status_code, 500)

    def test_get_bytes(self):
        response = self.app.get('/bytes/1024')
        self.assertEqual(len(response.get_data()), 1024)
        self.assertEqual(response.status_code, 200)

    def test_bytes_with_seed(self):
        response = self.app.get('/bytes/10?seed=0')
        # The RNG changed in python3, so even though we are
        # setting the seed, we can't expect the value to be the
        # same across both interpreters.
        if six.PY3:
            self.assertEqual(
                response.data, b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
            )
        else:
            self.assertEqual(
                response.data, b'\xd8\xc2kB\x82g\xc8Mz\x95'
            )

    def test_stream_bytes(self):
        response = self.app.get('/stream-bytes/1024')
        self.assertEqual(len(response.get_data()), 1024)
        self.assertEqual(response.status_code, 200)

    def test_stream_bytes_with_seed(self):
        response = self.app.get('/stream-bytes/10?seed=0')
        # The RNG changed in python3, so even though we are
        # setting the seed, we can't expect the value to be the
        # same across both interpreters.
        if six.PY3:
            self.assertEqual(
                response.data, b'\xc5\xd7\x14\x84\xf8\xcf\x9b\xf4\xb7o'
            )
        else:
            self.assertEqual(
                response.data, b'\xd8\xc2kB\x82g\xc8Mz\x95'
            )

    def test_delete_endpoint_returns_body(self):
        response = self.app.delete(
            '/delete',
            data={'name': 'kevin'},
            content_type='application/x-www-form-urlencoded'
        )
        form_data = json.loads(response.data.decode('utf-8'))['form']
        self.assertEqual(form_data, {'name': 'kevin'})

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
        self.assertEqual(len(response1.get_data()), 1234)
        
        response2 = self.app.get('/range/1234')
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response2.headers.get('ETag'), 'range1234')
        self.assertEqual(response1.get_data(), response2.get_data())
    
    def test_request_range_with_parameters(self):
        response = self.app.get(
            '/range/100?duration=1.5&chunk_size=5',
            headers={ 'Range': 'bytes=10-24' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range100')
        self.assertEqual(response.headers.get('Content-range'), 'bytes 10-24/100')
        self.assertEqual(response.headers.get('Accept-ranges'), 'bytes')
        self.assertEqual(response.get_data(), 'klmnopqrstuvwxy'.encode('utf8'))
    
    def test_request_range_first_15_bytes(self):
        response = self.app.get(
            '/range/1000',
            headers={ 'Range': 'bytes=0-15' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range1000')
        self.assertEqual(response.get_data(), 'abcdefghijklmnop'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 0-15/1000')
    
    def test_request_range_open_ended_last_6_bytes(self):
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=20-' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(response.get_data(), 'uvwxyz'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 20-25/26')
    
    def test_request_range_suffix(self):
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=-5' }
        )

        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(response.get_data(), 'vwxyz'.encode('utf8'))
        self.assertEqual(response.headers.get('Content-range'), 'bytes 21-25/26')
    
    def test_request_out_of_bounds(self):
        response = self.app.get(
            '/range/26',
            headers={ 'Range': 'bytes=10-5',
            }
        )

        self.assertEqual(response.status_code, 416)
        self.assertEqual(response.headers.get('ETag'), 'range26')
        self.assertEqual(len(response.get_data()), 0)
        self.assertEqual(response.headers.get('Content-range'), 'bytes */26')
        
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
        self.assertIn('google-analytics', data)
        self.assertIn('perfectaudience', data)


if __name__ == '__main__':
    unittest.main()
