httpbin(1): HTTP Client Testing Service
=======================================

## ENDPOINTS

- [`/`](http://httpbin.org) This page.
- [`/ip`](http://httpbin.org/ip) Returns Origin IP.
- [`/user-agent`](http://httpbin.org/user-agent) Returns user-agent.
- [`/headers`](http://httpbin.org/hearders) Returns header dict.
- [`/get`](http://httpbin.org/get) Returns GET data.
- `/post` Returns POST data.
- `/put` Returns PUT data.
- `/delete` Returns DELETE data
- [`/gzip`](http://httpbin.org/gzip) Returns gzip-encoded data.
- [`/status/:code`](http://httpbin.org/status/418) Returns given HTTP Status code.
- [`/redirect/:n`](http://httpbin.org/redirect/6) 302 Redirects *n* times.
- [`/cookies`](http://httpbin.org/cookies) Returns cookie data.
- [`/cookies/set/:name/:value`](http://httpbin.org/cookies/set/key/value) Sets a simple cookie.


## DESCRIPTION

Testing an HTTP Library can become difficult sometimes. PostBin.org is fantastic
for testing POST requests, but not much else. This exists to cover all kinds of HTTP
scenarios. Additional endpoints are being considered: `/basic-auth`, `/deflate`, *&c*.

All endpoint responses are JSON-encoded.


## EXAMPLES

### $ curl http://httpbin.org/ip

    {"origin": "::ffff:24.127.96.129"}

### $ curl http://httpbin.org/user-agent

    {"user-agent": "curl/7.19.7 (universal-apple-darwin10.0) libcurl/7.19.7 OpenSSL/0.9.8l zlib/1.2.3"}

### $ curl http://httpbin.org/get

    {
       "args": {},
       "headers": {
          "Accept": "*/*",
          "Connection": "close",
          "Content-Length": "",
          "Content-Type": "",
          "Host": "httpbin.org",
          "User-Agent": "curl/7.19.7 (universal-apple-darwin10.0) libcurl/7.19.7 OpenSSL/0.9.8l zlib/1.2.3",
          "X-Forwarded-For": "::ffff:24.127.96.129",
          "X-Forwarded-Protocol": ""
       },
       "origin": "::ffff:24.127.96.129",
       "url": "http://httpbin.org/get"
    }

### $ curl -I http://httpbin.org/status/418

    HTTP/1.1 418 I'M A TEAPOT
    Server: nginx/0.7.67
    Date: Mon, 13 Jun 2011 04:25:38 GMT
    Connection: close
    x-more-info: http://tools.ietf.org/html/rfc2324
    Content-Length: 135


## AUTHOR

A [Kenneth Reitz](http://kennethreitz.com/pages/open-projects.html)
Project.

## SEE ALSO

<https://github.com/kennethreitz/httpbin>, <http://python-requests.org>, <http://postbin.org>
