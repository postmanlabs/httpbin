# httpbin(1): HTTP Request & Response Service


A [Kenneth Reitz](http://kennethreitz.org/bitcoin) Project.

![ice cream](http://farm1.staticflickr.com/572/32514669683_4daf2ab7bc_k_d.jpg)

This project does not publish releases or Docker images. To run your own
copy, build it from this repository:
```sh
git clone https://github.com/postmanlabs/httpbin.git
cd httpbin
docker build -t httpbin . && docker run -p 80:8080 httpbin
```

See http://httpbin.org for more information.

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

- http://requestb.in
- http://python-requests.org
- https://grpcb.in/

## Build Status

[![test](https://github.com/postmanlabs/httpbin/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/postmanlabs/httpbin/actions/workflows/test.yml)
