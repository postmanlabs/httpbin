#!/bin/bash
exec /opt/httpbin/bin/gunicorn \
    -b ${HTTPBIN_HOST:-0.0.0.0}:${HTTPBIN_PORT:-80} \
    -k gevent \
    httpbin:app
