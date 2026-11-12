# httpbin(1): HTTP Request & Response Service


A [Kenneth Reitz](http://kennethreitz.org/bitcoin) Project.

![ice cream](http://farm1.staticflickr.com/572/32514669683_4daf2ab7bc_k_d.jpg)

httpbin is a small web service for testing HTTP clients. It echoes back what
you send (headers, query, body, files, cookies, your IP) and answers on demand
with the status code, delay, redirect, compression, auth challenge or data you
ask for, so you can check how your code behaves against each of them. It is
what runs at http://httpbin.org.

This project does not publish releases or Docker images. To run your own
copy, build it from this repository:
```sh
git clone https://github.com/postmanlabs/httpbin.git
cd httpbin
docker build -t httpbin . && docker run -p 80:8080 httpbin
```

See http://httpbin.org for more information.

To limit where `/redirect-to` may send clients, set `ALLOWED_REDIRECT_DOMAINS`
to a comma-separated list of hosts, for example
`docker run -p 80:8080 -e ALLOWED_REDIRECT_DOMAINS=example.com,example.org httpbin`.

## Running the tests

```sh
pip install --require-hashes -r requirements-test.txt
python test_httpbin.py
```

To run the tests against any running httpbin instead of the in-process app,
set its base URL. Tests that need the in-process app are skipped.
```sh
HTTPBIN_TEST_TARGET_URL=http://localhost:8080 python test_httpbin.py
```

## Officially Deployed at:

- http://httpbin.org
- https://httpbin.org


## SEE ALSO

- http://python-requests.org
- https://grpcb.in/

## Build Status

[![test](https://github.com/postmanlabs/httpbin/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/postmanlabs/httpbin/actions/workflows/test.yml)
