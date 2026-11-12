# -*- coding: utf-8 -*-

"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""

import json
import base64
import re
import time
import os
from hashlib import md5, sha256, sha512
from werkzeug.datastructures import Authorization, WWWAuthenticate
from werkzeug.http import HTTP_STATUS_CODES

from flask import request, make_response, Response
from urllib.parse import quote, urlparse, urlunparse


from .structures import CaseInsensitiveDict


ASCII_ART = r'''
    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
        `"""`
'''

REDIRECT_LOCATION = '/redirect/1'

# Media types a browser renders as a document or runs as script. A caller of
# /response-headers may not pick one, or a crafted link would show their text
# as a page on this host. Any +xml subtype is refused too.
RENDERABLE_MEDIA_TYPES = frozenset([
    'text/html', 'application/xhtml+xml', 'image/svg+xml', 'text/xml',
    'application/xml', 'application/javascript', 'application/x-javascript',
    'application/ecmascript', 'application/x-ecmascript', 'text/javascript',
    'text/ecmascript', 'text/x-ecmascript', 'text/x-javascript', 'text/jscript',
    'text/livescript', 'text/javascript1.0', 'text/javascript1.1',
    'text/javascript1.2', 'text/javascript1.3', 'text/javascript1.4',
    'text/javascript1.5',
])

ENV_HEADERS = (
    'X-Varnish',
    'X-Request-Start',
    'X-Heroku-Queue-Depth',
    'X-Real-Ip',
    'X-Forwarded-Proto',
    'X-Forwarded-Protocol',
    'X-Forwarded-Ssl',
    'X-Heroku-Queue-Wait-Time',
    'X-Forwarded-For',
    'X-Heroku-Dynos-In-Use',
    'X-Forwarded-Protocol',
    'X-Forwarded-Port',
    'X-Request-Id',
    'Via',
    'Total-Route-Time',
    'Connect-Time'
)

ROBOT_TXT = """User-agent: *
Disallow: /deny
"""

ACCEPTED_MEDIA_TYPES = [
    'image/webp',
    'image/svg+xml',
    'image/jpeg',
    'image/png',
    'image/*'
]

ANGRY_ASCII = r"""
          .-''''''-.
        .' _      _ '.
       /   O      O   \
      :                :
      |                |
      :       __       :
       \  .-"`  `"-.  /
        '.          .'
          '-......-'
     YOU SHOULDN'T BE HERE
"""


def json_safe(string, content_type='application/octet-stream'):
    """Returns JSON-safe version of `string`.

    If `string` is a Unicode string or a valid UTF-8, it is returned unmodified,
    as it can safely be encoded to JSON string.

    If `string` contains raw/binary data, it is Base64-encoded, formatted and
    returned according to "data" URL scheme (RFC2397). Since JSON is not
    suitable for binary data, some additional encoding was necessary; "data"
    URL scheme was chosen for its simplicity.
    """
    try:
        string = string.decode('utf-8')
        json.dumps(string)
        return string
    except (ValueError, TypeError):
        return b''.join([
            b'data:',
            content_type.encode('utf-8'),
            b';base64,',
            base64.b64encode(string)
        ]).decode('utf-8')


def get_files():
    """Returns files dict from request context."""

    files = dict()

    for k, v in request.files.items(multi=True):
        content_type = v.content_type or 'application/octet-stream'
        val = json_safe(v.read(), content_type)
        if files.get(k):
            if not isinstance(files[k], list):
                files[k] = [files[k]]
            files[k].append(val)
        else:
            files[k] = val

    return files


def get_headers(hide_env=True):
    """Returns headers dict from request context."""

    headers = dict(request.headers.items())

    if hide_env and ('show_env' not in request.args):
        for key in ENV_HEADERS:
            try:
                del headers[key]
            except KeyError:
                pass

    return CaseInsensitiveDict(headers.items())


def semiflatten(multi):
    """Convert a MutiDict into a regular dict. If there are more than one value
    for a key, the result will have a list of values for the key. Otherwise it
    will have the plain value."""
    if multi:
        result = multi.to_dict(flat=False)
        for k, v in result.items():
            if len(v) == 1:
                result[k] = v[0]
        return result
    else:
        return multi

def get_url(request):
    """
    Since we might be hosted behind a proxy, we need to check the
    X-Forwarded-Proto, X-Forwarded-Protocol, or X-Forwarded-SSL headers
    to find out what protocol was used to access us.
    """
    protocol = request.headers.get('X-Forwarded-Proto') or request.headers.get('X-Forwarded-Protocol')
    if protocol is None and request.headers.get('X-Forwarded-Ssl') == 'on':
        protocol = 'https'
    if protocol is None:
        return request.url
    url = list(urlparse(request.url))
    url[0] = protocol
    return urlunparse(url)


def get_dict(*keys, **extras):
    """Returns request dict of given keys."""

    _keys = ('url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json', 'method')

    assert all(map(_keys.__contains__, keys))
    data = request.data
    form = semiflatten(request.form)

    try:
        _json = json.loads(data.decode('utf-8'))
    except (ValueError, TypeError):
        _json = None

    d = dict(
        url=get_url(request),
        args=semiflatten(request.args),
        form=form,
        data=json_safe(data),
        origin=request.headers.get('X-Forwarded-For', request.remote_addr),
        headers=get_headers(),
        files=get_files(),
        json=_json,
        method=request.method,
    )

    out_d = dict()

    for key in keys:
        out_d[key] = d.get(key)

    out_d.update(extras)

    return out_d


# Headers /response-headers will not set. Framing and hop-by-hop headers would
# put a conflicting Content-Length or Transfer-Encoding on the wire (response
# desync behind a proxy), and Refresh is a browser redirect that skips
# /redirect-to. Proxy-* headers are refused too.
RESERVED_RESPONSE_HEADERS = frozenset([
    'content-length', 'transfer-encoding', 'connection', 'keep-alive',
    'proxy-connection', 'te', 'trailer', 'upgrade', 'refresh',
    'x-content-type-options',
])


def caller_may_not_set(header):
    """Return true if /response-headers must drop this header name."""
    header = header.lower()
    return header in RESERVED_RESPONSE_HEADERS or header.startswith('proxy-')


TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

MEDIA_PARAMETER = re.compile(
    r'[ \t]*;[ \t]*([%s]+)[ \t]*=[ \t]*([%s]+|"(?:[^"\\]|\\.)*")'
    % ((re.escape(''.join(sorted(TOKEN_CHARS))),) * 2)
)


def is_media_type(value):
    """Return true if value is one type/subtype with well-formed parameters.
    A comma-separated list is not: browsers would use its last valid type."""
    media_type, semicolon, rest = value.partition(';')
    kind, slash, subtype = media_type.strip().partition('/')
    if not (slash and kind and subtype
            and all(c in TOKEN_CHARS for c in kind + subtype)):
        return False
    rest = semicolon + rest
    seen = set()
    while rest.strip(' \t'):
        match = MEDIA_PARAMETER.match(rest)
        if not match:
            return rest.strip() == ';'
        name = match.group(1).lower()
        if name in seen:
            return False
        seen.add(name)
        rest = rest[match.end():]
    return True


def content_type_refusal(values):
    """Return why /response-headers must refuse the caller's Content-Type
    values, or None. One is allowed, and it must be a single valid media type
    that a browser does not render."""
    if len(values) > 1:
        return 'only one Content-Type is allowed'
    if not values:
        return None
    value = values[0]
    if (any((c < ' ' and c != '\t') or c >= '\x7f' for c in value)
            or not is_media_type(value)):
        return 'the Content-Type is not a valid media type'
    if is_renderable_media_type(value):
        return 'this Content-Type is not allowed'
    return None


# Media types whose body a browser never renders as markup. A /response-headers
# echo under any other type is HTML-escaped.
INERT_MEDIA_TYPES = frozenset([
    'text/plain', 'application/json', 'application/octet-stream',
])


def is_inert_media_type(content_type):
    """Return true if a body of this Content-Type needs no HTML escaping."""
    return content_type.split(';', 1)[0].strip().lower() in INERT_MEDIA_TYPES


def escape_html(text):
    """Escape the five HTML-special characters, as httpbin.org does."""
    return (text.replace('&', '&amp;').replace("'", '&#39;')
            .replace('<', '&lt;').replace('>', '&gt;').replace('"', '&#34;'))


def error_response(status_code, detail):
    """A JSON error in httpbin.org's format."""
    body = json.dumps({
        'status_code': status_code,
        'error': HTTP_STATUS_CODES[status_code],
        'detail': detail,
    }, indent=2)
    return Response(body + '\n', status=status_code,
                    content_type='application/json')


def request_cookie_host():
    """The request's host name, lower-cased and without its port."""
    host = request.host.lower()
    if host.startswith('['):
        return host[1:].split(']', 1)[0]
    return host.split(':', 1)[0]


def set_cookie_error(value, host):
    """Return why /response-headers must refuse this Set-Cookie value, or
    None. Every Domain attribute must name the request host; a value that is
    not a valid cookie is refused too."""
    pair, _, attributes = value.partition(';')
    name, has_equals, cookie_value = pair.partition('=')
    cookie_value = cookie_value.strip()
    if len(cookie_value) > 1 and cookie_value[0] == cookie_value[-1] == '"':
        cookie_value = cookie_value[1:-1]
    name = name.strip()
    if (not has_equals or not name or any(c not in TOKEN_CHARS for c in name)
            or any(not ' ' <= c <= '~' or c in '"\\' for c in cookie_value)):
        return 'invalid Set-Cookie "%s"' % value
    for attribute in attributes.split(';'):
        attribute_name, _, domain = attribute.partition('=')
        # U+0130 lower-cases to "i" in a simple case mapping, so "Domaİn" is
        # read as Domain, not skipped.
        if attribute_name.strip().replace(u'\u0130', 'i').lower() != 'domain':
            continue
        domain = domain.strip()
        bare = domain.lower()
        if bare.startswith('.'):
            bare = bare[1:]
        if not host or bare != host:
            return 'Set-Cookie Domain must be the request host "%s", got "%s"' % (
                host, domain)
    return None


def is_renderable_media_type(content_type):
    """Return true if a browser would render or run this Content-Type."""
    media_type = content_type.split(';', 1)[0].strip().lower()
    return media_type in RENDERABLE_MEDIA_TYPES or media_type.endswith('+xml')


# Reason phrases as httpbin.org sends them: Werkzeug's, with the five that differ
STATUS_PHRASES = dict(HTTP_STATUS_CODES)
STATUS_PHRASES.update({
    203: 'Non-Authoritative Information',
    207: 'Multi-Status',
    511: 'Network Authentication Required',
})
for unlisted in (306, 449):
    del STATUS_PHRASES[unlisted]


def is_true_param(value):
    """An opt-in query flag: "1" or "true" in any case."""
    return value == '1' or value.lower() == 'true'


def cookie_attribute_name(key):
    """The lower-cased Name of an attr[Name] query parameter, or None."""
    if key.startswith('attr[') and key.endswith(']'):
        # U+0130 lower-cases to "i" in a simple case mapping, as httpbin.org
        # reads it.
        return key[5:-1].replace(u'\u0130', 'i').lower()
    return None


def cookie_attributes():
    """set_cookie() keyword arguments from the attr[Name] query parameters:
    Domain, HttpOnly, Path, SameSite and Secure, names in any case."""
    attributes = {'path': '/', 'secure': secure_cookie()}
    for key in request.args:
        name, value = cookie_attribute_name(key), request.args[key]
        if name in ('domain', 'path'):
            attributes[name] = value or None
        elif name in ('httponly', 'secure'):
            attributes[name] = is_true_param(value)
        elif name == 'samesite' and value.lower() in ('strict', 'lax', 'none'):
            attributes[name] = value.title()
    return attributes


def cookie_domain_error():
    """Why /cookies/set or /cookies/delete must refuse the request, or None:
    an attr[Domain] must be the request host, less one leading dot."""
    host = request_cookie_host()
    for key in request.args:
        if cookie_attribute_name(key) != 'domain':
            continue
        for domain in request.args.getlist(key):
            bare = domain.lower()
            if bare.startswith('.'):
                bare = bare[1:]
            if not host or bare != host:
                return 'attr[Domain] must be the request host "%s", got "%s"' % (
                    host, domain)
    return None


def split_outside_quotes(text, separator):
    """Split a header value on separator, except inside quoted strings."""
    parts, start, quoted, i = [], 0, False, 0
    while i < len(text):
        if quoted and text[i] == '\\':
            i += 1
        elif text[i] == '"':
            quoted = not quoted
        elif text[i] == separator and not quoted:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def _quality(value, has_value=True):
    try:
        q = float(value.strip())
    except ValueError:
        return None
    return q if has_value and q == q else None


def accept_quality(params):
    """The q of an Accept entry: 1 without one, 0 if it can't be read."""
    for param in params:
        name, _, value = param.partition('=')
        if name.strip().lower() != 'q':
            continue
        q = _quality(value)
        return q if q is not None and 0 <= q <= 1 else 0
    return 1


def prefers_json(accept_values):
    """Return true if Accept ranks application/json above text/plain."""
    json_q = text_q = 0.0
    json_pos = text_pos = -1
    position = 0
    for field in accept_values:
        for entry in split_outside_quotes(field, ','):
            position += 1
            parts = split_outside_quotes(entry, ';')
            q = accept_quality(parts[1:])
            media_type = parts[0].strip().lower()
            if media_type == 'application/json' and (q > json_q or json_pos < 0):
                json_q, json_pos = q, position
            elif media_type == 'text/plain' and (q > text_q or text_pos < 0):
                text_q, text_pos = q, position
    return json_q > 0 and (json_q > text_q or (json_q == text_q and json_pos < text_pos))


def accepts_any_type(accept):
    """Return true if Accept has a */* range that is not refused (q above 0)."""
    for media_range in split_outside_quotes(accept, ','):
        parts = split_outside_quotes(media_range, ';')
        if parts[0].strip() != '*/*':
            continue
        quality = 1.0
        for param in parts[1:]:
            name, has_value, value = param.partition('=')
            if name.strip().lower() == 'q':
                q = _quality(value, bool(has_value))
                quality = 0 if q is None or q > 1 else q
        if quality > 0:
            return True
    return False


def status_code(code):
    """Returns response object of given status code."""

    redirect = dict(headers=dict(location=REDIRECT_LOCATION))

    code_map = {
        301: redirect,
        302: redirect,
        303: redirect,
        304: dict(data=''),
        305: redirect,
        307: redirect,
        401: dict(headers={'WWW-Authenticate': 'Basic realm="Fake Realm"'}),
        402: dict(
            data='Fuck you, pay me!',
            headers={
                'x-more-info': 'http://vimeo.com/22053820'
            }
        ),
        406: dict(data=json.dumps({
                'message': 'Client did not request a supported media type.',
                'accept': ACCEPTED_MEDIA_TYPES
            }),
            headers={
                'Content-Type': 'application/json'
            }),
        407: dict(headers={'Proxy-Authenticate': 'Basic realm="Fake Realm"'}),
        418: dict(  # I'm a teapot!
            data=ASCII_ART,
            headers={
                'x-more-info': 'http://tools.ietf.org/html/rfc2324'
            }
        ),

    }

    r = make_response()
    r.status_code = code

    if code in code_map:

        m = code_map[code]

        if 'data' in m:
            r.data = m['data']
        if 'headers' in m:
            r.headers.update(m['headers'])

    return r


def request_uri():
    """The request-target as the client sent it: the raw path, still
    percent-encoded, and the raw query."""
    raw = request.environ.get('RAW_URI') or request.environ.get('REQUEST_URI')
    if raw and '?' in raw:
        return raw
    uri = raw or quote(request.script_root + request.path)
    query = request.environ.get('QUERY_STRING', '')
    return uri + '?' + query if query else uri


def canonical_header_name(name):
    """x-custom-thing -> X-Custom-Thing"""
    return '-'.join(part[:1].upper() + part[1:].lower() for part in name.split('-'))


# Written on their own lines before the sorted headers, or left out
DUMP_SEPARATE_HEADERS = frozenset(['Host', 'Transfer-Encoding', 'Trailer'])


def request_dump():
    """The request in its HTTP/1.x form, as /dump/request returns it: the
    request line, Host, then the other headers sorted by name, and the body.
    It is approximate: the WSGI server has already merged repeated headers
    and lost the original case and order of the header names."""
    environ = request.environ
    lines = [
        '%s %s %s' % (request.method, request_uri(),
                      environ.get('SERVER_PROTOCOL', 'HTTP/1.1')),
        'Host: ' + request.host,
    ]
    chunked = environ.get('HTTP_TRANSFER_ENCODING', '').lower() == 'chunked'
    if chunked:
        lines.append('Transfer-Encoding: chunked')
    headers = []
    for key, value in environ.items():
        if key.startswith('HTTP_'):
            name = key[5:]
        elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH') and value:
            name = key
        else:
            continue
        name = canonical_header_name(name.replace('_', '-'))
        if name not in DUMP_SEPARATE_HEADERS:
            headers.append((name, value))
    lines += ['%s: %s' % header for header in sorted(headers, key=lambda h: h[0])]
    body = request.get_data()
    if chunked:
        body = (b'%x\r\n%s\r\n' % (len(body), body) if body else b'') + b'0\r\n\r\n'
    return ('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1') + body


def check_basic_auth(user, passwd):
    """Checks user authentication using HTTP Basic Auth."""

    auth = request.authorization
    return auth and auth.username == user and auth.password == passwd



# Digest auth helpers
# qop is a quality of protection

def H(data, algorithm):
    if algorithm == 'SHA-256':
        return sha256(data).hexdigest()
    elif algorithm == 'SHA-512':
        return sha512(data).hexdigest()
    else:
        # MD5 is what RFC 7616 names as Digest auth's default algorithm, not
        # a security choice; this also keeps it working on FIPS builds.
        return md5(data, usedforsecurity=False).hexdigest()


def HA1(realm, username, password, algorithm):
    """Create HA1 hash by realm, username, password

    HA1 = md5(A1) = MD5(username:realm:password)
    """
    if not realm:
        realm = u''
    return H(b":".join([username.encode('utf-8'),
                           realm.encode('utf-8'),
                           password.encode('utf-8')]), algorithm)


def HA2(credentials, request, algorithm):
    """Create HA2 md5 hash

    If the qop directive's value is "auth" or is unspecified, then HA2:
        HA2 = md5(A2) = MD5(method:digestURI)
    If the qop directive's value is "auth-int" , then HA2 is
        HA2 = md5(A2) = MD5(method:digestURI:MD5(entityBody))
    """
    if credentials.get("qop") == "auth" or credentials.get('qop') is None:
        return H(b":".join([request['method'].encode('utf-8'), request['uri'].encode('utf-8')]), algorithm)
    elif credentials.get("qop") == "auth-int":
        for k in 'method', 'uri', 'body':
            if k not in request:
                raise ValueError("%s required" % k)
        A2 = b":".join([request['method'].encode('utf-8'),
                        request['uri'].encode('utf-8'),
                        H(request['body'], algorithm).encode('utf-8')])
        return H(A2, algorithm)
    raise ValueError


def response(credentials, password, request):
    """Compile digest auth response

    If the qop directive's value is "auth" or "auth-int" , then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:nonceCount:clienNonce:qop:HA2)
    Else if the qop directive is unspecified, then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:HA2)

    Arguments:
    - `credentials`: credentials dict
    - `password`: request user password
    - `request`: request dict
    """
    response = None
    algorithm = credentials.get('algorithm')
    HA1_value = HA1(
        credentials.get('realm'),
        credentials.get('username'),
        password,
        algorithm
    )
    HA2_value = HA2(credentials, request, algorithm)
    if credentials.get('qop') is None:
        response = H(b":".join([
            HA1_value.encode('utf-8'),
            credentials.get('nonce', '').encode('utf-8'),
            HA2_value.encode('utf-8')
        ]), algorithm)
    elif credentials.get('qop') == 'auth' or credentials.get('qop') == 'auth-int':
        for k in 'nonce', 'nc', 'cnonce', 'qop':
            if k not in credentials:
                raise ValueError("%s required for response H" % k)
        response = H(b":".join([HA1_value.encode('utf-8'),
                               credentials.get('nonce').encode('utf-8'),
                               credentials.get('nc').encode('utf-8'),
                               credentials.get('cnonce').encode('utf-8'),
                               credentials.get('qop').encode('utf-8'),
                               HA2_value.encode('utf-8')]), algorithm)
    else:
        raise ValueError("qop value are wrong")

    return response


def parse_authorization_header(value):
    """Parse an Authorization header, treating Digest credentials that miss
    a required parameter as absent, as Werkzeug 0.14 did."""
    auth = Authorization.from_header(value)
    if auth is None or auth.type != 'digest':
        return auth
    for key in 'username', 'realm', 'nonce', 'uri', 'response':
        if key not in auth:
            return None
    if 'qop' in auth and (not auth.get('nc') or not auth.get('cnonce')):
        return None
    return auth


def check_digest_auth(user, passwd):
    """Check user authentication using HTTP Digest auth"""

    if request.headers.get('Authorization'):
        credentials = parse_authorization_header(request.headers.get('Authorization'))
        if not credentials or credentials.get('username') != user:
            return False
        request_uri = request.script_root + request.path
        if request.query_string:
            request_uri +=  '?' + str(request.query_string, 'utf-8')
        response_hash = response(credentials, passwd, dict(uri=request_uri,
                                                           body=request.data,
                                                           method=request.method))
        if credentials.get('response') == response_hash:
            return True
    return False

def secure_cookie():
    """Return true if cookie should have secure attribute"""
    return request.environ['wsgi.url_scheme'] == 'https'

def __parse_request_range(range_header_text):
    """ Return a tuple describing the byte range requested in a GET request
    If the range is open ended on the left or right side, then a value of None
    will be set.
    RFC7233: http://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7233.html#header.range
    Examples:
      Range : bytes=1024-
      Range : bytes=10-20
      Range : bytes=-999
    """

    left = None
    right = None

    if not range_header_text:
        return left, right

    range_header_text = range_header_text.strip()
    if not range_header_text.startswith('bytes'):
        return left, right

    components = range_header_text.split("=")
    if len(components) != 2:
        return left, right

    components = components[1].split("-")

    try:
        right = int(components[1])
    except:
        pass

    try:
        left = int(components[0])
    except:
        pass

    return left, right

def get_request_range(request_headers, upper_bound):
    first_byte_pos, last_byte_pos = __parse_request_range(request_headers['range'])

    if first_byte_pos is None and last_byte_pos is None:
        # Request full range
        first_byte_pos = 0
        last_byte_pos = upper_bound - 1
    elif first_byte_pos is None:
        # Request the last X bytes
        first_byte_pos = max(0, upper_bound - last_byte_pos)
        last_byte_pos = upper_bound - 1
    elif last_byte_pos is None:
        # Request the last X bytes
        last_byte_pos = upper_bound - 1

    return first_byte_pos, last_byte_pos

def parse_multi_value_header(header_str):
    """Break apart an HTTP header string that is potentially a quoted, comma separated list as used in entity headers in RFC2616."""
    parsed_parts = []
    if header_str:
        parts = header_str.split(',')
        for part in parts:
            match = re.search(r'\s*(W/)?\"?([^"]*)\"?\s*', part)
            if match is not None:
                parsed_parts.append(match.group(2))
    return parsed_parts


def next_stale_after_value(stale_after):
    try:
        stal_after_count = int(stale_after) - 1
        return str(stal_after_count)
    except ValueError:
        return 'never'


def digest_challenge_response(app, qop, algorithm, stale = False):
    response = app.make_response('')
    response.status_code = 401

    # RFC2616 Section4.2: HTTP headers are ASCII.  That means
    # request.remote_addr was originally ASCII, so I should be able to
    # encode it back to ascii.  Also, RFC2617 says about nonces: "The
    # contents of the nonce are implementation dependent"
    nonce = H(b''.join([
        getattr(request, 'remote_addr', u'').encode('ascii'),
        b':',
        str(time.time()).encode('ascii'),
        b':',
        os.urandom(10)
    ]), algorithm)
    opaque = H(os.urandom(10), algorithm)

    parameters = {
        'realm': 'me@kennethreitz.com',
        'nonce': nonce,
        'qop': 'auth, auth-int' if qop is None else qop,
        'opaque': opaque,
        'algorithm': algorithm,
        'stale': 'TRUE' if stale else 'FALSE',
    }
    if qop == '':
        # An RFC 2069 challenge, for testing a client's fallback
        del parameters['qop']
    auth = WWWAuthenticate("digest", parameters)
    response.headers['WWW-Authenticate'] = auth.to_header()
    return response
