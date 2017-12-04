# -*- coding: utf-8 -*-

from werkzeug import Request

from httpbin.helpers import parse_multi_value_header, digest_challenge_response


def test_parse_multi_value_header():
    assert parse_multi_value_header('xyzzy') == ["xyzzy"]
    assert parse_multi_value_header('"xyzzy"') == ["xyzzy"]
    assert parse_multi_value_header('W/"xyzzy"') == ["xyzzy"]
    assert parse_multi_value_header('"xyzzy" == "r2d2xxxx", "c3piozzzz"'), ["xyzzy", "r2d2xxxx", "c3piozzzz"]
    assert parse_multi_value_header('W/"xyzzy" == W/"r2d2xxxx", W/"c3piozzzz"'), ["xyzzy", "r2d2xxxx", "c3piozzzz"]
    assert parse_multi_value_header('*') == ["*"]


def test_digest_challenge_response():
    request = Request(environ={'REMOTE_ADDR': "example.com"})
    result = digest_challenge_response(request, None, None)
    assert '''qop="auth, auth-int"''' in result.headers["WWW-Authenticate"]
    assert '''algorithm=''' not in result.headers["WWW-Authenticate"]

    result = digest_challenge_response(request, "flibble", "flamble")
    assert '''qop="flibble"''' in result.headers["WWW-Authenticate"]
    assert '''algorithm=flamble''' in result.headers["WWW-Authenticate"]
