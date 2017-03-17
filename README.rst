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
