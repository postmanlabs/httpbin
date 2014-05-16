httpbin(1): HTTP Request & Response Service
===========================================

Freely hosted in [HTTP](http://httpbin.org) &
[HTTPS](https://httpbin.org) flavors.

## ENDPOINTS

- [`/`](http://httpbin.org/) This page.
- [`/ip`](http://httpbin.org/ip) Returns Origin IP.
- [`/user-agent`](http://httpbin.org/user-agent) Returns user-agent.
- [`/headers`](http://httpbin.org/headers) Returns header dict.
- [`/get`](http://httpbin.org/get) Returns GET data.
- [`/post`](http://hurl.it/hurls/190ccaa90ee1ed35d34abfa4ac6ef088bc319402/d834bcdf7718c44c4184bf914ee473b6ebd8e566) Returns POST data.
- [`/patch`](http://hurl.it/hurls/18016368fa5e5eef80db935f5dae615d5858a4a4/a512d904f5da64df9627ee998c040f7874d6436a) Returns PATCH data.
- [`/put`](http://hurl.it/hurls/18016368fa5e5eef80db935f5dae615d5858a4a4/a512d904f5da64df9627ee998c040f7874d6436a) Returns PUT data.
- [`/delete`](http://hurl.it/hurls/6faafea5191f77172fca4cfe1505739230d5f769/bc255ffc69e04c2c8b968822c59544746bbb872c) Returns DELETE data
- [`/gzip`](http://httpbin.org/gzip) Returns gzip-encoded data.
- [`/deflate`](http://httpbin.org/deflate) Returns deflate-encoded data.
- [`/status/:code`](http://httpbin.org/status/418) Returns given HTTP Status code.
- [`/response-headers?key=val`](http://httpbin.org/response-headers?Content-Type=text/plain;%20charset=UTF-8&Server=httpbin) Returns given response headers.
- [`/redirect/:n`](http://httpbin.org/redirect/6) 302 Redirects *n* times.
- [`/redirect-to?url=foo`](http://httpbin.org/redirect-to?url=http://example.com/) 302 Redirects to the *foo* URL.
- [`/relative-redirect/:n`](http://httpbin.org/relative-redirect/6) 302 Relative redirects *n* times.
- [`/cookies`](http://httpbin.org/cookies) Returns cookie data.
- [`/cookies/set?name=value`](http://httpbin.org/cookies/set?k1=v1&k2=v2) Sets one or more simple cookies.
- [`/cookies/delete?name`](http://httpbin.org/cookies/delete?k1&k2) Deletes one or more simple cookies.
- [`/basic-auth/:user/:passwd`](http://httpbin.org/basic-auth/user/passwd) Challenges HTTPBasic Auth.
- [`/hidden-basic-auth/:user/:passwd`](http://httpbin.org/hidden-basic-auth/user/passwd) 404'd BasicAuth.
- [`/digest-auth/:qop/:user/:passwd`](http://httpbin.org/digest-auth/auth/user/passwd) Challenges HTTP Digest Auth.
- [`/stream/:n`](http://httpbin.org/stream/20) Streams *n*–100 lines.
- [`/delay/:n`](http://httpbin.org/delay/3) Delays responding for *n*–10 seconds.
- [`/drip?numbytes=n&duration=s&delay=s`](http://httpbin.org/drip?numbytes=5&duration=5) Drips data over a duration after an optional initial delay.
- [`/html`](http://httpbin.org/html) Renders an HTML Page.
- [`/robots.txt`](http://httpbin.org/robots.txt) Returns some robots.txt rules.
- [`/deny`](http://httpbin.org/deny) Denied by robots.txt file.
- [`/cache`](http://httpbin.org/cache) Returns 200 unless an If-Modified-Since or If-None-Match header is provided, when it returns a 304.
- [`/cache/:n`](http://httpbin.org/cache/60) Sets a Cache-Control header for *n* seconds.
- [`/bytes/:n`](http://httpbin.org/bytes/1024) Generates *n* random bytes of binary data, accepts optional *seed* integer parameter.
- [`/stream-bytes/:n`](http://httpbin.org/stream-bytes/1024) Streams *n* random bytes of binary data, accepts optional *seed* and *chunk_size* integer parameters.
- [`/links/:n`](http://httpbin.org/links/10) Returns page containing *n* HTML links.

## DESCRIPTION

Testing an HTTP Library can become difficult sometimes. PostBin.org is fantastic
for testing POST requests, but not much else. This exists to cover all kinds of HTTP
scenarios. Additional endpoints are being considered.

All endpoint responses are JSON-encoded.


## EXAMPLES

### $ curl http://httpbin.org/ip

    {"origin": "24.127.96.129"}

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
          "User-Agent": "curl/7.19.7 (universal-apple-darwin10.0) libcurl/7.19.7 OpenSSL/0.9.8l zlib/1.2.3"
       },
       "origin": "24.127.96.129",
       "url": "http://httpbin.org/get"
    }

### $ curl -I http://httpbin.org/status/418

    HTTP/1.1 418 I'M A TEAPOT
    Server: nginx/0.7.67
    Date: Mon, 13 Jun 2011 04:25:38 GMT
    Connection: close
    x-more-info: http://tools.ietf.org/html/rfc2324
    Content-Length: 135


### $ curl https://httpbin.org/get?show_env=1

    {
      "headers": {
        "Content-Length": "",
        "Accept-Language": "en-US,en;q=0.8",
        "Accept-Encoding": "gzip,deflate,sdch",
        "X-Forwarded-Port": "443",
        "X-Forwarded-For": "109.60.101.240",
        "X-Heroku-Dynos-In-Use": "1",
        "Host": "httpbin.org",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.83 Safari/535.11",
        "X-Request-Start": "1350053933441",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        "Connection": "keep-alive",
        "X-Forwarded-Proto": "https",
        "Cookie": "_gauges_unique_day=1; _gauges_unique_month=1; _gauges_unique_year=1; _gauges_unique=1; _gauges_unique_hour=1",
        "X-Heroku-Queue-Depth": "0",
        "X-Heroku-Queue-Wait-Time": "11",
        "Content-Type": ""
      },
      "args": {
        "show_env": "1"
      },
      "origin": "109.60.101.240",
      "url": "http://httpbin.org/get?show_env=1"
    }

## AUTHOR

A [Kenneth Reitz](http://kennethreitz.com/pages/open-projects.html)
Project.

## SEE ALSO

<http://python-requests.org>

