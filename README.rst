httpbin(1): HTTP Request & Response Service
===========================================

Freely hosted in `HTTP <http://httpbin.org>`__,  `HTTPS <https://httpbin.org>`__, & `EU <http://eu.httpbin.org/>`__
flavors by `Heroku <https://www.heroku.com/>`__.

|Deploy|_

.. |Deploy| image:: https://www.herokucdn.com/deploy/button.svg
.. _Deploy: https://heroku.com/deploy?template=https://github.com/kennethreitz/httpbin

|Build Status|


DESCRIPTION
-----------

Testing an HTTP Library can become difficult sometimes.
`RequestBin <http://requestb.in>`__ is fantastic for testing POST
requests, but doesn't let you control the response. This exists to cover
all kinds of HTTP scenarios. Additional endpoints are being considered.

All endpoint responses are JSON-encoded.

EXAMPLES
--------

$ curl http://httpbin.org/ip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {"origin": "24.127.96.129"}

$ curl http://httpbin.org/user-agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {"user-agent": "curl/7.19.7 (universal-apple-darwin10.0) libcurl/7.19.7 OpenSSL/0.9.8l zlib/1.2.3"}

$ curl http://httpbin.org/get
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

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

$ curl -I http://httpbin.org/status/418
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    HTTP/1.1 418 I'M A TEAPOT
    Server: nginx/0.7.67
    Date: Mon, 13 Jun 2011 04:25:38 GMT
    Connection: close
    x-more-info: http://tools.ietf.org/html/rfc2324
    Content-Length: 135

$ curl https://httpbin.org/get?show\_env=1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    {
      "headers": {
        "Content-Length": "",
        "Accept-Language": "en-US,en;q=0.8",
        "Accept-Encoding": "gzip,deflate,sdch",
        "X-Forwarded-Port": "443",
        "X-Forwarded-For": "109.60.101.240",
        "Host": "httpbin.org",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.83 Safari/535.11",
        "X-Request-Start": "1350053933441",
        "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
        "Connection": "keep-alive",
        "X-Forwarded-Proto": "https",
        "Cookie": "_gauges_unique_day=1; _gauges_unique_month=1; _gauges_unique_year=1; _gauges_unique=1; _gauges_unique_hour=1",
        "Content-Type": ""
      },
      "args": {
        "show_env": "1"
      },
      "origin": "109.60.101.240",
      "url": "http://httpbin.org/get?show_env=1"
    }

Installing and running from PyPI
--------------------------------

You can install httpbin as a library from PyPI and run it as a WSGI app.
For example, using Gunicorn:

.. code:: bash

    $ pip install httpbin
    $ gunicorn httpbin:app

Or install and run it directly:

.. code:: bash

    $ git clone https://github.com/kennethreitz/httpbin.git
    $ pip install -e httpbin
    $ python -m httpbin.core [--port=PORT] [--host=HOST]


AUTHOR
------

A `Kenneth Reitz <http://kennethreitz.org/>`__ Project.

SEE ALSO
--------

- https://www.hurl.it
- http://requestb.in
- http://python-requests.org

.. |Build Status| image:: https://travis-ci.org/kennethreitz/httpbin.svg
   :target: https://travis-ci.org/kennethreitz/httpbin
