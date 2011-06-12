HttpBin: PostBin++
==================

Testing an HTTP Library can become difficult sometimes. PostBin is fantastic
for testing POST requests, but not much else. This will cover everything.

I would have simply forked PostBin, but it's hosted on GAE. No.

Plans at the moment are to return JSON for all responses. Request storage / aggregation may or may not exist. We'll see.




Endpoints
---------

``/user-agent``
    Returns your user agent string.

``/headers``
    Returns all Request headers.

``/get``
    Returns GET data.

``/post``
    Returns POST data.

``/put``
    Returns PUT data.

``/delete``
    Returns DELETE data.



License
-------

ISC.


Tools
-----

- Flask
- ep.io
- (maybe) Redis
