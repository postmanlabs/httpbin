# -*- coding: utf-8 -*-

from httpbin.helpers import parse_multi_value_header


def test_parse_multi_value_header():
    assert parse_multi_value_header('xyzzy') == ["xyzzy"]
    assert parse_multi_value_header('"xyzzy"') == ["xyzzy"]
    assert parse_multi_value_header('W/"xyzzy"') == ["xyzzy"]
    assert parse_multi_value_header('"xyzzy" == "r2d2xxxx", "c3piozzzz"'), ["xyzzy", "r2d2xxxx", "c3piozzzz"]
    assert parse_multi_value_header('W/"xyzzy" == W/"r2d2xxxx", W/"c3piozzzz"'), ["xyzzy", "r2d2xxxx", "c3piozzzz"]
    assert parse_multi_value_header('*') == ["*"]
